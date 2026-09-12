import { describe, it, expect, vi } from 'vitest';
import { prepareDriveSharing } from './prepareDriveSharing';

const drive = 'did:ad:drive';

function setup(local = false) {
  return {
    isLocalOnlyDrive: () => local,
    makeDriveLocal: vi.fn(async () => {}),
  };
}

describe('sharing an unenrolled drive with a saved server connection', () => {
  it('verifies and switches the complete local copy before creating a peer invite', async () => {
    const store = setup();
    expect(await prepareDriveSharing(store, drive, [])).toBe(true);
    expect(store.makeDriveLocal).toHaveBeenCalledWith(drive);
  });
  it('preserves a verification failure instead of issuing an invite', async () => {
    const store = setup();
    store.makeDriveLocal.mockRejectedValue(new Error('Missing attachment'));
    await expect(prepareDriveSharing(store, drive, [])).rejects.toThrow(
      'Missing attachment',
    );
  });
  it('does not use another drive enrollment to route this drive', async () => {
    const store = setup();
    expect(
      await prepareDriveSharing(store, drive, [
        { drive_subject: 'did:ad:other', status: 'Active' },
      ]),
    ).toBe(true);
    expect(store.makeDriveLocal).toHaveBeenCalledOnce();
  });
  it('preserves an enrolled drive connection', async () => {
    const store = setup();
    expect(
      await prepareDriveSharing(store, drive, [
        { drive_subject: drive, status: 'Active' },
      ]),
    ).toBe(false);
    expect(store.makeDriveLocal).not.toHaveBeenCalled();
  });
  it('does not migrate an already local drive', async () => {
    const store = setup(true);
    expect(await prepareDriveSharing(store, drive, [])).toBe(true);
    expect(store.makeDriveLocal).not.toHaveBeenCalled();
  });
});
