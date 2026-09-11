import { describe, expect, it, vi } from 'vitest';
import type { ClientDbWorker } from './client-db.js';
import { verifyLocalDriveCopy } from './local-drive-copy.js';
const drive = 'did:ad:drive';
const inventory = [{ subject: drive, vv: { a: 2 } }];

function fixture() {
  const db = {
    flush: vi.fn().mockResolvedValue(undefined),
    getVersionVectorsForDrive: vi.fn().mockResolvedValue({ [drive]: { a: 2 } }),
    getResourceWithSnapshot: vi
      .fn()
      .mockResolvedValue({ jsonAd: '{}', snapshot: new Uint8Array([1]) }),
    getBlob: vi.fn().mockResolvedValue(null),
    blake3Hash: vi.fn().mockResolvedValue(new Uint8Array(32)),
  };

  return {
    db,
    verify: (items = inventory) =>
      verifyLocalDriveCopy(db as unknown as ClientDbWorker, drive, items),
  };
}

describe('verified local drive copy', () => {
  it('accepts a complete local history', async () => {
    await expect(fixture().verify()).resolves.toBeUndefined();
  });
  it('rejects an empty or incomplete server inventory', async () => {
    await expect(fixture().verify([])).rejects.toThrow('inventory');
  });
  it('rejects missing history even with a cached resource', async () => {
    const f = fixture();
    f.db.getVersionVectorsForDrive.mockResolvedValue({ [drive]: { a: 1 } });
    await expect(f.verify()).rejects.toThrow('not fully stored');
  });
  it('rejects a missing attachment', async () => {
    const f = fixture();
    f.db.getResourceWithSnapshot.mockResolvedValue({
      jsonAd: JSON.stringify({
        'https://atomicdata.dev/properties/blob': `did:ad:blob:${'00'.repeat(32)}`,
      }),
      snapshot: new Uint8Array([1]),
    });
    await expect(f.verify()).rejects.toThrow('attachment is missing');
    f.db.getBlob.mockResolvedValue(new Uint8Array([2]));
    await expect(f.verify()).resolves.toBeUndefined();
    f.db.blake3Hash.mockResolvedValue(new Uint8Array(32).fill(1));
    await expect(f.verify()).rejects.toThrow('could not be verified');
  });
});
