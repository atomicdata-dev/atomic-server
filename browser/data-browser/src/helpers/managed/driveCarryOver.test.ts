// @wc-ignore-file
import { beforeEach, describe, expect, it, vi } from 'vitest';

/** In-memory stand-in for IndexedDB, so the staged record can be inspected. */
const idb = new Map<string, unknown>();

vi.mock('idb-keyval', () => ({
  get: async (key: string) => idb.get(key),
  set: async (key: string, value: unknown) => void idb.set(key, value),
  del: async (key: string) => void idb.delete(key),
}));

const {
  CARRY_OVER_TTL_MS,
  DRIVE_CARRY_OVER_KEY,
  MAX_CARRY_OVER_BYTES,
  importDriveCarryOver,
  readDriveCarryOver,
  stageDriveCarryOver,
} = await import('./driveCarryOver');

const guest = 'did:ad:agent:local';
const account = 'did:ad:agent:account';
const hashHex = 'ab'.repeat(32);
const BLOB = 'https://atomicdata.dev/properties/blob';

/**
 * A database holding one drive per entry of `drives`, each with one file
 * whose bytes are `file`. `vaultExport` seals the drive's subject, and
 * `vaultImport` records what it received, so a round trip is visible.
 */
function fakeDb(options: { sealedSize?: number; file?: Uint8Array } = {}) {
  const blobs = new Map<string, Uint8Array>();

  if (options.file) blobs.set(hashHex, options.file);

  const db = {
    imported: [] as { drive: string; key: Uint8Array; pseudonym: string }[],
    waitForReady: vi.fn(async () => true),
    vaultExport: vi.fn(
      async (
        drive: string,
        _key: { driveKey: Uint8Array; keyEpoch: number },
        pseudonym: string,
      ) => ({
        objectKey: `vault/${pseudonym}/checkpoints/ckpt-000001.loro`,
        sealed: options.sealedSize
          ? new Uint8Array(options.sealedSize)
          : new TextEncoder().encode(drive),
        kind: 'checkpoint' as const,
        resources: 2,
        unchanged: 0,
        tombstones: 0,
        coverage: {},
      }),
    ),
    vaultImport: vi.fn(
      async (
        key: { driveKey: Uint8Array; keyEpoch: number },
        pseudonym: string,
        _lane: string,
        objects: { objectKey: string; sealed: Uint8Array }[],
      ) => {
        db.imported.push({
          drive: new TextDecoder().decode(objects[0].sealed),
          key: key.driveKey,
          pseudonym,
        });

        return {
          packsRead: 1,
          resourcesRestored: 2,
          tombstonesApplied: 0,
          objectsSkipped: 0,
          objectsUnreadable: 0,
        };
      },
    ),
    getVersionVectorsForDrive: vi.fn(async (drive: string) => ({
      [drive]: {},
      [`${drive}/file`]: {},
    })),
    getResourcesWithSnapshots: vi.fn(async (subjects: string[]) =>
      subjects.map(subject => ({
        jsonAd: JSON.stringify(
          subject.endsWith('/file')
            ? { '@id': subject, [BLOB]: `did:ad:blob:${hashHex}` }
            : { '@id': subject },
        ),
      })),
    ),
    getBlob: vi.fn(
      async (hash: Uint8Array) =>
        blobs.get(
          Array.from(hash, b => b.toString(16).padStart(2, '0')).join(''),
        ) ?? null,
    ),
    putBlob: vi.fn(async (hash: Uint8Array, data: Uint8Array) => {
      blobs.set(
        Array.from(hash, b => b.toString(16).padStart(2, '0')).join(''),
        data,
      );
    }),
    blobs,
  };

  return db;
}

type FakeDb = ReturnType<typeof fakeDb>;

function fakeStore(agent: string, db: FakeDb | undefined) {
  const store = {
    agent,
    db,
    getAgent: () => ({ subject: store.agent }),
    waitForClientDb: vi.fn(async () => !!store.db),
    getClientDb: () => store.db,
    registerLocalOnlyDrive: vi.fn(),
  };

  return store;
}

beforeEach(() => idb.clear());

describe('staging local-only drives before the switch', () => {
  it('exports each drive and its attachment bytes for the account', async () => {
    const file = new Uint8Array([1, 2, 3]);
    const db = fakeDb({ file });

    const staged = await stageDriveCarryOver(fakeStore(guest, db), {
      from: guest,
      to: account,
      drives: ['did:ad:home', 'did:ad:kept'],
    });

    expect(staged).toEqual(['did:ad:home', 'did:ad:kept']);
    const record = await readDriveCarryOver();
    expect(record?.to).toBe(account);
    expect(record?.drives.map(entry => entry.drive)).toEqual(staged);

    // A fresh key and lane per drive: always a full checkpoint.
    const [first, second] = db.vaultExport.mock.calls;
    expect(first[1]).not.toEqual(second[1]);
    expect(first[2]).not.toBe(second[2]);
    expect(first.slice(4, 7)).toEqual([1, 1, false]);
    expect(record?.drives[0].blobs).toEqual([
      { hash: expect.any(Uint8Array), data: file },
    ]);
  });

  it('refuses without the old identity database attached', async () => {
    await expect(
      stageDriveCarryOver(fakeStore(guest, undefined), {
        from: guest,
        to: account,
        drives: ['did:ad:kept'],
      }),
    ).rejects.toThrow();

    // Attached, but another identity is active: not `from`'s database.
    await expect(
      stageDriveCarryOver(fakeStore(account, fakeDb()), {
        from: guest,
        to: account,
        drives: ['did:ad:kept'],
      }),
    ).rejects.toThrow();
    expect(idb.has(DRIVE_CARRY_OVER_KEY)).toBe(false);
  });

  it('refuses, staging nothing, past the size bound', async () => {
    const db = fakeDb({ sealedSize: MAX_CARRY_OVER_BYTES + 1 });

    await expect(
      stageDriveCarryOver(fakeStore(guest, db), {
        from: guest,
        to: account,
        drives: ['did:ad:kept'],
      }),
    ).rejects.toThrow('too large');
    expect(idb.has(DRIVE_CARRY_OVER_KEY)).toBe(false);
  });

  it('needs no database when there is nothing to carry', async () => {
    expect(
      await stageDriveCarryOver(fakeStore(guest, undefined), {
        from: guest,
        to: account,
        drives: [],
      }),
    ).toEqual([]);
  });
});

describe('importing into the account identity database', () => {
  async function stage(file?: Uint8Array) {
    await stageDriveCarryOver(fakeStore(guest, fakeDb({ file })), {
      from: guest,
      to: account,
      drives: ['did:ad:home', 'did:ad:kept'],
    });
  }

  it('imports every staged drive, registers it local-only, then clears', async () => {
    const file = new Uint8Array([9, 9]);
    await stage(file);
    const staged = await readDriveCarryOver();
    const db = fakeDb();
    const store = fakeStore(account, db);

    expect(await importDriveCarryOver(store, account)).toEqual([
      'did:ad:home',
      'did:ad:kept',
    ]);
    expect(db.imported).toEqual(
      staged!.drives.map(entry => ({
        drive: entry.drive,
        key: entry.key,
        pseudonym: entry.pseudonym,
      })),
    );
    expect(store.registerLocalOnlyDrive.mock.calls).toEqual([
      ['did:ad:home'],
      ['did:ad:kept'],
    ]);
    expect(db.blobs.get(hashHex)).toEqual(file);
    expect(idb.has(DRIVE_CARRY_OVER_KEY)).toBe(false);
  });

  it('imports for the account signed in under the other spelling', async () => {
    await stage();
    const signedIn = account.replace('did:ad:', 'atomic:');
    const db = fakeDb();

    expect(
      await importDriveCarryOver(fakeStore(signedIn, db), signedIn),
    ).toEqual(['did:ad:home', 'did:ad:kept']);
  });

  it('waits while another identity, or no database, is active', async () => {
    await stage();

    const other = fakeDb();
    expect(await importDriveCarryOver(fakeStore(guest, other), guest)).toEqual(
      [],
    );
    expect(
      await importDriveCarryOver(fakeStore(account, other), guest),
    ).toEqual([]);
    expect(
      await importDriveCarryOver(fakeStore(account, undefined), account),
    ).toEqual([]);
    expect(other.vaultImport).not.toHaveBeenCalled();
    expect(idb.has(DRIVE_CARRY_OVER_KEY)).toBe(true);
  });

  it('keeps the staging for a retry when an import fails', async () => {
    await stage();
    const db = fakeDb();
    db.vaultImport.mockResolvedValueOnce({
      packsRead: 0,
      resourcesRestored: 0,
      tombstonesApplied: 0,
      objectsSkipped: 0,
      objectsUnreadable: 1,
    });

    await expect(
      importDriveCarryOver(fakeStore(account, db), account),
    ).rejects.toThrow();
    expect(idb.has(DRIVE_CARRY_OVER_KEY)).toBe(true);

    expect(await importDriveCarryOver(fakeStore(account, db), account)).toEqual(
      ['did:ad:home', 'did:ad:kept'],
    );
  });

  it('drops a staging nobody claimed in time', async () => {
    await stage();
    const record = await readDriveCarryOver();
    idb.set(DRIVE_CARRY_OVER_KEY, {
      ...record,
      savedAt: Date.now() - CARRY_OVER_TTL_MS - 1,
    });
    const db = fakeDb();

    expect(await importDriveCarryOver(fakeStore(account, db), account)).toEqual(
      [],
    );
    expect(db.vaultImport).not.toHaveBeenCalled();
    expect(idb.has(DRIVE_CARRY_OVER_KEY)).toBe(false);
  });
});
