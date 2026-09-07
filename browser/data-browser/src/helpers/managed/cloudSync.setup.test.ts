import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { enableCloudSyncForDrive } from './cloudSync';

vi.mock('./session', () => ({
  getManagedAccount: vi.fn(async () => ({ email: 'owner@example.com' })),
}));
vi.mock('./enrollment', () => ({
  createManagedSyncEnrollment: vi.fn(),
  genesisCertOf: vi.fn(() => undefined),
}));
vi.mock('@tomic/react', () => ({
  signRequest: vi.fn(async () => ({ Authorization: 'signed' })),
}));
import { createManagedSyncEnrollment } from './enrollment';

const drive = 'did:ad:existing-drive';
const agentSubject = 'did:ad:agent:owner';

function setup(local = true) {
  const store = {
    isLocalOnlyDrive: vi.fn((subject: string) => local && subject === drive),
    getAgent: vi.fn(() => ({ subject: agentSubject })),
    setServerUrl: vi.fn(),
    getResource: vi.fn(async () => ({})),
    waitForServerConnected: vi.fn(async () => true),
    promoteLocalDrive: vi.fn(async () => {}),
    getSyncStatus: vi.fn(() => ({ serverConnected: true })),
  };
  const setServer = vi.fn();

  return {
    store,
    setServer,
    args: {
      store: store as never,
      drive,
      agentSubject,
      setServer,
      hostingConsentAccepted: true,
    },
  };
}

describe('Cloud Server setup', () => {
  afterEach(() => vi.unstubAllGlobals());
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ ok: true })),
    );
    vi.mocked(createManagedSyncEnrollment).mockResolvedValue({
      drive,
      node: null,
      http_origin: 'https://cloud.example',
    });
  });

  it('does not enroll or transfer data without explicit agreement', async () => {
    const { args, store } = setup();
    await expect(
      enableCloudSyncForDrive({ ...args, hostingConsentAccepted: false }),
    ).rejects.toThrow(/Agree/);
    expect(createManagedSyncEnrollment).not.toHaveBeenCalled();
    expect(store.promoteLocalDrive).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('waits for the assigned server rather than the old React connection', async () => {
    const { args, store } = setup();
    let actualOrigin = 'https://old.example';
    store.setServerUrl.mockImplementation((url: string) => {
      actualOrigin = url;
    });
    store.waitForServerConnected.mockImplementation(async () => {
      expect(actualOrigin).toBe('https://cloud.example');

      return true;
    });
    await enableCloudSyncForDrive(args);
    expect(store.promoteLocalDrive).toHaveBeenCalledWith(drive);
  });

  it('leaves a local drive unpromoted when connection fails', async () => {
    const { args, store } = setup();
    store.waitForServerConnected.mockResolvedValue(false);
    await expect(enableCloudSyncForDrive(args)).rejects.toThrow(/Timed out/);
    expect(store.promoteLocalDrive).not.toHaveBeenCalled();
  });

  it('does not claim success or promote against an unrelated server without placement', async () => {
    vi.mocked(createManagedSyncEnrollment).mockResolvedValue({
      drive,
      node: null,
      http_origin: null,
    });
    const { args, store, setServer } = setup();
    await expect(enableCloudSyncForDrive(args)).rejects.toThrow(
      /server address/i,
    );
    expect(setServer).not.toHaveBeenCalled();
    expect(store.promoteLocalDrive).not.toHaveBeenCalled();
  });

  it('replicates an existing remote drive from its source without switching the app', async () => {
    const { args, store, setServer } = setup(false);
    await enableCloudSyncForDrive({
      ...args,
      sourceServer: 'https://source.example',
    });
    expect(fetch).toHaveBeenCalledWith(
      'https://source.example/replicate-drive',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ drive, target: 'https://cloud.example' }),
      }),
    );
    expect(setServer).not.toHaveBeenCalled();
    expect(store.promoteLocalDrive).not.toHaveBeenCalled();
  });

  it('surfaces a refused replication without switching away from the source', async () => {
    vi.mocked(fetch).mockResolvedValue({ ok: false, status: 403 } as Response);
    const { args, setServer } = setup(false);
    await expect(
      enableCloudSyncForDrive({
        ...args,
        sourceServer: 'https://source.example',
      }),
    ).rejects.toThrow(/replicat/i);
    expect(setServer).not.toHaveBeenCalled();
  });
});
