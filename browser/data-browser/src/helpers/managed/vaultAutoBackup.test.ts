import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  Agent,
  JSCryptoProvider,
  Store,
  Resource,
  core,
  dataBrowser,
} from '@tomic/lib';
import {
  isEmbeddedVaultDrive,
  ensureVaultBackup,
  forgetEnrolledVaults,
  onVaultChanged,
  restoreFromVault,
  watchForVaultBackups,
  type VaultAutoBackupDeps,
} from './vaultAutoBackup';
import type { VaultEnrollment, VaultKeyOps } from './vault';

/**
 * Cloud Vault is on for everyone, without a button. These cover the three
 * decisions that make that safe: it never blocks or throws, it never enrols a
 * drive its owner switched off, and it restores only when there is actually
 * something to restore.
 */

const DRIVE = 'did:ad:drive:test';
const PSEUDONYM = 'pseudonym-1';
const LANE = 'ab'.repeat(32);
const KEY = new Uint8Array(32).fill(9);

const keys: VaultKeyOps & { proofMessage: Uint8Array } = {
  proofMessage: new Uint8Array([1, 2, 3]),
  vaultGenerateKey: () => KEY,
  vaultWrapKey: () => 'envelope',
  vaultUnwrapKey: () => KEY,
};

const enrollment: VaultEnrollment = {
  id: '1',
  drive_subject: DRIVE,
  drive_pseudonym: PSEUDONYM,
  status: 'active',
  used_bytes: 0,
  quota_bytes: 100,
  last_backup_at: null,
};

async function signedInStore(): Promise<Store> {
  const store = new Store({ serverUrl: 'https://example.com', connect: false });
  const pair = await Agent.generateKeyPair();
  store.setAgent(
    new Agent(
      new JSCryptoProvider(pair.privateKey),
      `did:ad:agent:${pair.publicKey}`,
    ),
  );

  return store;
}

function fakeDeps(overrides: Partial<VaultAutoBackupDeps> = {}) {
  const deps: VaultAutoBackupDeps = {
    hasAccount: vi.fn(async () => true),
    loadKeys: vi.fn(async () => keys),
    laneId: vi.fn(async () => LANE),
    db: vi.fn(async () => ({}) as never),
    setUpVaultForDrive: vi.fn(async () => ({
      enrollment,
      driveKey: KEY,
      keyEpoch: 1,
    })),
    runVaultBackup: vi.fn(async () => ({
      status: 'backed-up' as const,
      kind: 'pack' as const,
      resources: 1,
      unchanged: 0,
      bytes: 10,
      objectKey: 'k',
    })),
    listVaultDrives: vi.fn(async () => [enrollment]),
    getVaultState: vi.fn(async () => ({
      enrollment,
      lanes: {},
      checkpoints: [],
      pending_uploads: 0,
      confirmed_objects: 1,
    })),
    recoverDriveKey: vi.fn(async () => ({ driveKey: KEY, keyEpoch: 1 })),
    restoreDrive: vi.fn(async () => ({
      packsRead: 1,
      objectsSkipped: 0,
      objectsUnreadable: 0,
      resourcesRestored: 3,
      tombstonesApplied: 0,
    })),
    optedOut: vi.fn(() => false),
    ...overrides,
  };

  return deps;
}

beforeEach(() => {
  forgetEnrolledVaults();
  vi.spyOn(console, 'warn').mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('ensureVaultBackup', () => {
  it('shares the drive name and emoji and refreshes them after edits', async () => {
    const store = await signedInStore();
    const drive = new Resource(DRIVE);
    await drive.set(core.properties.name, 'Design', false);
    await drive.set(dataBrowser.properties.emoji, '🎨', false);
    store.addResource(drive);
    const deps = fakeDeps();
    await ensureVaultBackup(store, DRIVE, deps);
    expect(deps.setUpVaultForDrive).toHaveBeenLastCalledWith(
      expect.objectContaining({
        metadata: { name: 'Design', emoji: '🎨' },
      }),
    );
    await drive.set(core.properties.name, 'Studio', false);
    await ensureVaultBackup(store, DRIVE, deps);
    expect(deps.setUpVaultForDrive).toHaveBeenLastCalledWith(
      expect.objectContaining({
        metadata: { name: 'Studio', emoji: '🎨' },
      }),
    );
  });

  it('enrols and backs up a signed-in drive', async () => {
    const store = await signedInStore();
    const deps = fakeDeps();

    const outcome = await ensureVaultBackup(store, DRIVE, deps);

    expect(outcome.status).toBe('backed-up');
    expect(deps.setUpVaultForDrive).toHaveBeenCalledWith(
      expect.objectContaining({
        driveSubject: DRIVE,
        agentSubject: store.getAgent()!.subject,
      }),
    );
    expect(deps.runVaultBackup).toHaveBeenCalledWith(
      expect.objectContaining({
        driveSubject: DRIVE,
        drivePseudonym: PSEUDONYM,
        devicePubkey: LANE,
        driveKey: KEY,
      }),
    );
  });

  /** The second pass must not enrol again: the key is already in hand. */
  it('does not enroll a drive while the local identity disagrees with the portal account', async () => {
    const store = await signedInStore();
    const deps = fakeDeps({ identityMatches: vi.fn(async () => false) });
    expect(await ensureVaultBackup(store, DRIVE, deps)).toEqual({
      status: 'skipped',
      reason: 'account identity needs reconciliation',
    });
    expect(deps.setUpVaultForDrive).not.toHaveBeenCalled();
    expect(deps.runVaultBackup).not.toHaveBeenCalled();
  });

  it('reuses the enrollment on later passes', async () => {
    const store = await signedInStore();
    const deps = fakeDeps();

    await ensureVaultBackup(store, DRIVE, deps);
    await ensureVaultBackup(store, DRIVE, deps);

    expect(deps.setUpVaultForDrive).toHaveBeenCalledTimes(1);
    expect(deps.hasAccount).toHaveBeenCalledTimes(2);
    expect(deps.runVaultBackup).toHaveBeenCalledTimes(2);
  });

  it('does not attempt to claim a drive backed up by another account', async () => {
    const store = await signedInStore();
    const deps = fakeDeps({ canEnroll: vi.fn(async () => false) });
    expect(await ensureVaultBackup(store, DRIVE, deps)).toMatchObject({
      status: 'skipped',
      reason: 'drive backup belongs to another account',
    });
    expect(deps.setUpVaultForDrive).not.toHaveBeenCalled();
    expect(deps.runVaultBackup).not.toHaveBeenCalled();
  });

  it('does not reuse an enrollment after the account session ends', async () => {
    const store = await signedInStore();
    const deps = fakeDeps();
    await ensureVaultBackup(store, DRIVE, deps);
    vi.mocked(deps.hasAccount).mockResolvedValue(false);
    expect(await ensureVaultBackup(store, DRIVE, deps)).toMatchObject({
      status: 'skipped',
    });
    expect(deps.runVaultBackup).toHaveBeenCalledTimes(1);
  });

  it('cancels an in-flight backup when the agent changes', async () => {
    const store = await signedInStore();
    const deps = fakeDeps({
      runVaultBackup: vi.fn(async args => {
        store.setAgent(undefined);
        expect(args.signal?.aborted).toBe(true);
        throw new Error('ClientDb worker destroyed');
      }),
    });
    expect(await ensureVaultBackup(store, DRIVE, deps)).toMatchObject({
      status: 'skipped',
    });
    expect(console.warn).not.toHaveBeenCalled();
  });

  it('shares one pass between concurrent callers', async () => {
    const store = await signedInStore();
    const deps = fakeDeps();

    await Promise.all([
      ensureVaultBackup(store, DRIVE, deps),
      ensureVaultBackup(store, DRIVE, deps),
    ]);

    expect(deps.setUpVaultForDrive).toHaveBeenCalledTimes(1);
    expect(deps.runVaultBackup).toHaveBeenCalledTimes(1);
  });

  it('does nothing without an account session', async () => {
    const store = await signedInStore();
    const deps = fakeDeps({ hasAccount: vi.fn(async () => false) });

    const outcome = await ensureVaultBackup(store, DRIVE, deps);

    expect(outcome).toEqual({
      status: 'skipped',
      reason: 'no account session',
    });
    expect(deps.setUpVaultForDrive).not.toHaveBeenCalled();
  });

  it('does nothing when signed out', async () => {
    const store = new Store({
      serverUrl: 'https://example.com',
      connect: false,
    });
    const deps = fakeDeps();

    const outcome = await ensureVaultBackup(store, DRIVE, deps);

    expect(outcome.status).toBe('skipped');
    expect(deps.hasAccount).not.toHaveBeenCalled();
  });

  /**
   * "On by default" must not mean "cannot be turned off": the Sync page's
   * "Turn off" would otherwise be undone by the next sign-in.
   */
  it('respects a drive its owner switched off', async () => {
    const store = await signedInStore();
    const deps = fakeDeps({ optedOut: vi.fn(() => true) });

    const outcome = await ensureVaultBackup(store, DRIVE, deps);

    expect(outcome.status).toBe('skipped');
    expect(deps.setUpVaultForDrive).not.toHaveBeenCalled();
  });

  it('reports failure instead of throwing, and retries enrollment next time', async () => {
    const store = await signedInStore();
    const deps = fakeDeps({
      runVaultBackup: vi
        .fn()
        .mockRejectedValueOnce(new Error('storage down'))
        .mockResolvedValueOnce({ status: 'nothing-to-do' }),
    });

    const first = await ensureVaultBackup(store, DRIVE, deps);
    expect(first.status).toBe('failed');

    const second = await ensureVaultBackup(store, DRIVE, deps);
    expect(second.status).toBe('nothing-to-do');
    expect(deps.setUpVaultForDrive).toHaveBeenCalledTimes(2);
  });

  it('waits for the local database rather than skipping', async () => {
    const store = await signedInStore();
    let attach!: () => void;
    const deps = fakeDeps({
      db: vi.fn(
        () =>
          new Promise<never>(resolve => {
            attach = () => resolve({} as never);
          }),
      ),
    });

    const pass = ensureVaultBackup(store, DRIVE, deps);
    await Promise.resolve();
    expect(deps.setUpVaultForDrive).not.toHaveBeenCalled();

    attach();
    expect((await pass).status).toBe('backed-up');
  });

  it('skips when this build has no local database', async () => {
    const store = await signedInStore();
    const deps = fakeDeps({ db: vi.fn(async () => null) });

    const outcome = await ensureVaultBackup(store, DRIVE, deps);

    expect(outcome).toEqual({
      status: 'skipped',
      reason: 'no local database or device id',
    });
    expect(deps.setUpVaultForDrive).not.toHaveBeenCalled();
  });

  it('tells vault-status listeners which drive changed', async () => {
    const store = await signedInStore();
    const deps = fakeDeps();
    const changed: string[] = [];
    const off = onVaultChanged(drive => changed.push(drive));

    await ensureVaultBackup(store, DRIVE, deps);
    expect(changed).toEqual([DRIVE]);

    off();
    forgetEnrolledVaults();
    await ensureVaultBackup(store, DRIVE, deps);
    expect(changed).toEqual([DRIVE]);
  });
});

describe('restoreFromVault', () => {
  it('restores a drive with a confirmed backup', async () => {
    const store = await signedInStore();
    const deps = fakeDeps();

    const outcome = await restoreFromVault(store, DRIVE, deps);

    expect(outcome.status).toBe('restored');
    expect(deps.recoverDriveKey).toHaveBeenCalledWith(
      expect.objectContaining({ drivePseudonym: PSEUDONYM }),
    );
    expect(deps.restoreDrive).toHaveBeenCalledWith(
      expect.objectContaining({ drivePseudonym: PSEUDONYM, driveKey: KEY }),
    );
  });

  /** The device now holds the key: later edits back up without re-enrolling. */
  it('remembers the key so the next backup skips enrollment', async () => {
    const store = await signedInStore();
    const deps = fakeDeps();

    await restoreFromVault(store, DRIVE, deps);
    await ensureVaultBackup(store, DRIVE, deps);

    expect(deps.setUpVaultForDrive).not.toHaveBeenCalled();
    expect(deps.runVaultBackup).toHaveBeenCalledTimes(1);
  });

  it('is no-backup without a session, so sign-in falls through quietly', async () => {
    const store = await signedInStore();
    const deps = fakeDeps({ hasAccount: vi.fn(async () => false) });

    expect((await restoreFromVault(store, DRIVE, deps)).status).toBe(
      'no-backup',
    );
    expect(deps.listVaultDrives).not.toHaveBeenCalled();
    // The database wait is the long one (up to 20s); a device with no session
    // must not sit through it to hear "no".
    expect(deps.db).not.toHaveBeenCalled();
  });

  it('is no-backup for a drive the account never enrolled', async () => {
    const store = await signedInStore();
    const deps = fakeDeps({ listVaultDrives: vi.fn(async () => []) });

    expect((await restoreFromVault(store, DRIVE, deps)).status).toBe(
      'no-backup',
    );
    expect(deps.restoreDrive).not.toHaveBeenCalled();
  });

  /** Zero resources restored looks exactly like a failed restore on screen. */
  it('is no-backup for an enrollment with nothing confirmed in it', async () => {
    const store = await signedInStore();
    const deps = fakeDeps({
      getVaultState: vi.fn(async () => ({
        enrollment,
        lanes: {},
        checkpoints: [],
        pending_uploads: 0,
        confirmed_objects: 0,
      })),
    });

    expect((await restoreFromVault(store, DRIVE, deps)).status).toBe(
      'no-backup',
    );
    expect(deps.restoreDrive).not.toHaveBeenCalled();
  });

  it('reports a failed download instead of throwing', async () => {
    const store = await signedInStore();
    const deps = fakeDeps({
      restoreDrive: vi.fn(async () => {
        throw new Error('403');
      }),
    });

    expect((await restoreFromVault(store, DRIVE, deps)).status).toBe('failed');
  });
});

describe('watchForVaultBackups', () => {
  function fakeWindow() {
    const listeners = new Map<string, () => void>();
    const doc = {
      visibilityState: 'visible',
      addEventListener: (name: string, fn: () => void) =>
        listeners.set(`document:${name}`, fn),
      removeEventListener: (name: string) =>
        listeners.delete(`document:${name}`),
    };
    const win = {
      document: doc,
      addEventListener: (name: string, fn: () => void) =>
        listeners.set(name, fn),
      removeEventListener: (name: string) => listeners.delete(name),
    };

    return { win: win as unknown as Window, doc, listeners };
  }

  it('backs up during continuous editing by the maximum delay', async () => {
    vi.useFakeTimers();
    const store = await signedInStore();
    store.setDrive(DRIVE);
    store.registerLocalOnlyDrive(DRIVE);
    const deps = fakeDeps();
    const stop = watchForVaultBackups(store, deps, {
      idleMs: 1000,
      maxWaitMs: 2000,
      window: null,
    });

    for (let i = 0; i < 5; i++) {
      store.notifyResourceSaved(store.getResourceLoading(`${DRIVE}/doc`));
      await vi.advanceTimersByTimeAsync(500);
    }

    expect(deps.runVaultBackup).toHaveBeenCalled();
    stop();
  });

  it('retains pending backups when switching drives', async () => {
    vi.useFakeTimers();
    const store = await signedInStore();
    const other = 'did:ad:drive:other';
    store.registerLocalOnlyDrive(DRIVE);
    store.registerLocalOnlyDrive(other);
    store.setDrive(DRIVE);
    const deps = fakeDeps();
    const stop = watchForVaultBackups(store, deps, {
      idleMs: 1000,
      window: null,
    });
    store.notifyResourceSaved(store.getResourceLoading(`${DRIVE}/doc`));
    store.setDrive(other);
    store.notifyResourceSaved(store.getResourceLoading(`${other}/doc`));
    await vi.advanceTimersByTimeAsync(1100);
    expect(
      vi
        .mocked(deps.runVaultBackup)
        .mock.calls.map(([args]) => args.driveSubject),
    ).toEqual(expect.arrayContaining([DRIVE, other]));
    stop();
  });

  it('retries when the account becomes available without another edit', async () => {
    vi.useFakeTimers();
    const store = await signedInStore();
    store.setDrive(DRIVE);
    store.registerLocalOnlyDrive(DRIVE);
    const deps = fakeDeps({ hasAccount: vi.fn(async () => false) });
    const stop = watchForVaultBackups(store, deps, {
      idleMs: 10,
      retryMs: 100,
      window: null,
    });
    await vi.advanceTimersByTimeAsync(20);
    expect(deps.runVaultBackup).not.toHaveBeenCalled();
    vi.mocked(deps.hasAccount).mockResolvedValue(true);
    await vi.advanceTimersByTimeAsync(110);
    expect(deps.runVaultBackup).toHaveBeenCalled();
    stop();
  });

  it('rediscovers an existing enrollment after reload without an edit', async () => {
    vi.useFakeTimers();
    const store = await signedInStore();
    store.setDrive(DRIVE);
    const deps = fakeDeps();
    const stop = watchForVaultBackups(store, deps, {
      idleMs: 10,
      window: null,
    });
    await vi.advanceTimersByTimeAsync(20);
    expect(deps.listVaultDrives).toHaveBeenCalled();
    expect(deps.runVaultBackup).toHaveBeenCalledTimes(1);
    stop();
  });

  it('recognizes Tauri embedded nodes but excludes external servers', async () => {
    const local = new Store({
      serverUrl: 'http://localhost:9883',
      connect: false,
    });
    const remote = new Store({
      serverUrl: 'https://example.com',
      connect: false,
    });
    vi.stubGlobal('window', {
      __TAURI_INTERNALS__: {},
      location: { protocol: 'tauri:', hostname: 'localhost' },
    });

    try {
      expect(isEmbeddedVaultDrive(local)).toBe(true);
      expect(isEmbeddedVaultDrive(remote)).toBe(false);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('retries pending work immediately when connectivity returns', async () => {
    vi.useFakeTimers();
    const store = await signedInStore();
    store.setDrive(DRIVE);
    store.registerLocalOnlyDrive(DRIVE);
    const deps = fakeDeps({ hasAccount: vi.fn(async () => false) });
    const { win, listeners } = fakeWindow();
    const stop = watchForVaultBackups(store, deps, { idleMs: 10, window: win });
    await vi.advanceTimersByTimeAsync(20);
    vi.mocked(deps.hasAccount).mockResolvedValue(true);
    listeners.get('online')!();
    await vi.advanceTimersByTimeAsync(0);
    expect(deps.runVaultBackup).toHaveBeenCalledTimes(1);
    stop();
  });

  it('backs the open local-only drive up once the edits stop', async () => {
    vi.useFakeTimers();
    const store = await signedInStore();
    store.setDrive(DRIVE);
    store.registerLocalOnlyDrive(DRIVE);
    const deps = fakeDeps();
    const { win } = fakeWindow();
    const stop = watchForVaultBackups(store, deps, {
      idleMs: 1000,
      window: win,
    });

    const resource = store.getResourceLoading(`${DRIVE}/doc`);
    store.notifyResourceSaved(resource);
    await vi.advanceTimersByTimeAsync(500);
    store.notifyResourceSaved(resource);
    await vi.advanceTimersByTimeAsync(500);

    // A burst of edits is one backup, not one per pause.
    expect(deps.runVaultBackup).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(600);

    expect(deps.runVaultBackup).toHaveBeenCalledTimes(1);
    stop();
  });

  /** A drive on a server is that server's to keep; only ours get a copy. */
  it('ignores edits in a drive that is neither local-only nor enrolled', async () => {
    vi.useFakeTimers();
    const store = await signedInStore();
    store.setDrive(DRIVE);
    const deps = fakeDeps({ listVaultDrives: vi.fn(async () => []) });
    const { win } = fakeWindow();
    const stop = watchForVaultBackups(store, deps, { idleMs: 10, window: win });

    store.notifyResourceSaved(store.getResourceLoading(`${DRIVE}/doc`));
    await vi.advanceTimersByTimeAsync(50);

    expect(deps.runVaultBackup).not.toHaveBeenCalled();
    stop();
  });

  it('backs up an enrolled drive that is not local-only', async () => {
    vi.useFakeTimers();
    const store = await signedInStore();
    store.setDrive(DRIVE);
    const deps = fakeDeps();
    await ensureVaultBackup(store, DRIVE, deps);
    const { win } = fakeWindow();
    const stop = watchForVaultBackups(store, deps, { idleMs: 10, window: win });

    store.notifyResourceSaved(store.getResourceLoading(`${DRIVE}/doc`));
    await vi.advanceTimersByTimeAsync(50);

    expect(deps.runVaultBackup).toHaveBeenCalledTimes(2);
    stop();
  });

  it('flushes a pending backup when the tab goes to the background', async () => {
    vi.useFakeTimers();
    const store = await signedInStore();
    store.setDrive(DRIVE);
    store.registerLocalOnlyDrive(DRIVE);
    const deps = fakeDeps();
    const { win, doc, listeners } = fakeWindow();
    const stop = watchForVaultBackups(store, deps, {
      idleMs: 60_000,
      window: win,
    });

    store.notifyResourceSaved(store.getResourceLoading(`${DRIVE}/doc`));
    doc.visibilityState = 'hidden';
    listeners.get('document:visibilitychange')!();
    await vi.advanceTimersByTimeAsync(0);

    expect(deps.runVaultBackup).toHaveBeenCalledTimes(1);
    stop();
  });

  it('stops listening once unsubscribed', async () => {
    vi.useFakeTimers();
    const store = await signedInStore();
    store.setDrive(DRIVE);
    store.registerLocalOnlyDrive(DRIVE);
    const deps = fakeDeps();
    const { win, listeners } = fakeWindow();
    const stop = watchForVaultBackups(store, deps, { idleMs: 10, window: win });

    store.notifyResourceSaved(store.getResourceLoading(`${DRIVE}/doc`));
    stop();
    await vi.advanceTimersByTimeAsync(50);

    expect(deps.runVaultBackup).not.toHaveBeenCalled();
    expect(listeners.size).toBe(0);
  });
});
