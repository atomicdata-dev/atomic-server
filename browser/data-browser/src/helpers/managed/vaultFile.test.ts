// @wc-ignore-file
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  buildVaultFile,
  checkpointNumberFromKey,
  parseVaultFile,
  restoreDriveFromFile,
  vaultFileBlob,
  VaultFileError,
  VAULT_FILE_VERSION,
} from './vaultFile';
import type { VaultCapableDb, VaultObject } from './vault';

const P = 'pseudo';
const LANE = 'lane-a';
const KEY = new Uint8Array(32);

const obj = (
  object_key: string,
  kind: string,
  extra: Partial<VaultObject> = {},
): VaultObject => ({
  object_id: object_key,
  object_key,
  kind,
  size_bytes: 0,
  key_epoch: 1,
  lane_device_pubkey: null,
  segment: null,
  ...extra,
});

const objects = [
  obj(`vault/${P}/checkpoints/ckpt-000002.loro`, 'checkpoint'),
  obj(`vault/${P}/lanes/${LANE}/seg-000001.pack`, 'pack', {
    lane_device_pubkey: LANE,
    segment: 1,
  }),
  obj(`vault/${P}/lanes/${LANE}/seg-000002.pack`, 'pack', {
    lane_device_pubkey: LANE,
    segment: 2,
  }),
];
const payloads = [
  new Uint8Array([1, 2, 3]),
  new Uint8Array([4, 5]),
  new Uint8Array([6]),
];

const build = () =>
  buildVaultFile({
    drivePseudonym: P,
    objects,
    bodies: payloads.map(p => new Blob([p as BlobPart])),
    now: 1700000000000,
  });

const asBytes = async (blob: Blob) => new Uint8Array(await blob.arrayBuffer());

afterEach(() => vi.restoreAllMocks());

describe('vault file format', () => {
  it('round-trips header and sealed bytes in order', async () => {
    const file = vaultFileBlob(await build());
    const parsed = await parseVaultFile(file);

    expect(parsed.header.version).toBe(VAULT_FILE_VERSION);
    expect(parsed.header.drivePseudonym).toBe(P);
    expect(parsed.header.keyEpoch).toBe(1);
    expect(parsed.header.objects.map(o => o.objectKey)).toEqual(
      objects.map(o => o.object_key),
    );
    expect(parsed.header.objects[0]).toMatchObject({
      kind: 'checkpoint',
      checkpointN: 2,
      lane: null,
      size: 3,
    });
    expect(parsed.header.objects[2]).toMatchObject({
      kind: 'pack',
      lane: LANE,
      segment: 2,
      checkpointN: null,
    });

    for (let i = 0; i < payloads.length; i++) {
      expect(await parsed.read(i)).toEqual(payloads[i]);
    }
  });

  it('reads checkpoint numbers from keys', () => {
    expect(
      checkpointNumberFromKey(`vault/x/checkpoints/ckpt-000012.loro`),
    ).toBe(12);
    expect(
      checkpointNumberFromKey(`vault/x/lanes/a/seg-000001.pack`),
    ).toBeNull();
  });

  it('rejects a file with the wrong magic', async () => {
    await expect(
      parseVaultFile(new Blob([new TextEncoder().encode('{"hello":"world"}')])),
    ).rejects.toThrow(/not an Atomic vault backup/);
    await expect(parseVaultFile(new Blob([]))).rejects.toThrow(VaultFileError);
  });

  it('rejects a truncated file, in header or in body', async () => {
    const bytes = await asBytes(vaultFileBlob(await build()));

    await expect(
      parseVaultFile(new Blob([bytes.slice(0, 20)])),
    ).rejects.toThrow(/incomplete/);
    await expect(
      parseVaultFile(new Blob([bytes.slice(0, bytes.length - 1)])),
    ).rejects.toThrow(/incomplete/);
  });

  it('rejects trailing data', async () => {
    const bytes = await asBytes(vaultFileBlob(await build()));

    await expect(
      parseVaultFile(new Blob([bytes, new Uint8Array([0])])),
    ).rejects.toThrow(/extra data/);
  });

  it('rejects a newer version with an update hint', async () => {
    const built = await build();
    const header = { ...built.header, version: VAULT_FILE_VERSION + 1 };
    const json = new TextEncoder().encode(JSON.stringify(header));
    const head = new Uint8Array(12 + json.length);
    head.set(built.head.slice(0, 8));
    new DataView(head.buffer).setUint32(8, json.length, false);
    head.set(json, 12);

    await expect(
      parseVaultFile(new Blob([head, ...built.bodies])),
    ).rejects.toThrow(/newer version/);
  });

  it('rejects a malformed header', async () => {
    const built = await build();
    const json = new TextEncoder().encode(
      JSON.stringify({
        version: 1,
        drivePseudonym: P,
        keyEpoch: 1,
        objects: [{}],
      }),
    );
    const head = new Uint8Array(12 + json.length);
    head.set(built.head.slice(0, 8));
    new DataView(head.buffer).setUint32(8, json.length, false);
    head.set(json, 12);

    await expect(parseVaultFile(new Blob([head]))).rejects.toThrow(/damaged/);
  });

  it('detects a flipped byte in an object', async () => {
    const bytes = await asBytes(vaultFileBlob(await build()));
    bytes[bytes.length - 1] ^= 0xff;
    const parsed = await parseVaultFile(new Blob([bytes]));

    await expect(parsed.read(2)).rejects.toThrow(/checksum/);
    expect(await parsed.read(0)).toEqual(payloads[0]);
  });
});

describe('restoreDriveFromFile', () => {
  const makeDb = () =>
    ({
      vaultExport: vi.fn(),
      vaultCommitSegment: vi.fn(),
      vaultImport: vi.fn(async () => ({
        packsRead: 2,
        resourcesRestored: 1,
        tombstonesApplied: 0,
        objectsSkipped: 0,
        objectsUnreadable: 0,
      })),
    }) satisfies VaultCapableDb;

  it('hands the objects to vaultImport in file order, without network', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const db = makeDb();
    const file = vaultFileBlob(await build());

    const outcome = await restoreDriveFromFile({
      file,
      db,
      drivePseudonym: P,
      devicePubkey: 'me',
      driveKey: KEY,
      keyEpoch: 1,
    });

    expect(outcome.resourcesRestored).toBe(1);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(db.vaultImport).toHaveBeenCalledTimes(1);
    const [key, epoch, pseudonym, device, imported] = db.vaultImport.mock
      .calls[0] as unknown as [
      Uint8Array,
      number,
      string,
      string,
      { objectKey: string; sealed: Uint8Array }[],
    ];
    expect([key, epoch, pseudonym, device]).toEqual([KEY, 1, P, 'me']);
    expect(imported.map(o => o.objectKey)).toEqual(
      objects.map(o => o.object_key),
    );
    expect(imported.map(o => o.sealed)).toEqual(payloads);
  });

  it('names a mismatch of workspace and imports nothing', async () => {
    const db = makeDb();

    await expect(
      restoreDriveFromFile({
        file: vaultFileBlob(await build()),
        db,
        drivePseudonym: 'other',
        devicePubkey: 'me',
        driveKey: KEY,
        keyEpoch: 1,
      }),
    ).rejects.toThrow(/different workspace/);
    expect(db.vaultImport).not.toHaveBeenCalled();
  });

  it('refuses a file sealed under another key epoch', async () => {
    const db = makeDb();

    await expect(
      restoreDriveFromFile({
        file: vaultFileBlob(await build()),
        db,
        drivePseudonym: P,
        devicePubkey: 'me',
        driveKey: KEY,
        keyEpoch: 2,
      }),
    ).rejects.toThrow(/different encryption key/);
    expect(db.vaultImport).not.toHaveBeenCalled();
  });

  it('imports nothing from a corrupt file', async () => {
    const db = makeDb();
    const bytes = await asBytes(vaultFileBlob(await build()));
    bytes[bytes.length - 1] ^= 1;

    await expect(
      restoreDriveFromFile({
        file: new Blob([bytes]),
        db,
        drivePseudonym: P,
        devicePubkey: 'me',
        driveKey: KEY,
        keyEpoch: 1,
      }),
    ).rejects.toThrow(/checksum/);
    expect(db.vaultImport).not.toHaveBeenCalled();
  });
});
