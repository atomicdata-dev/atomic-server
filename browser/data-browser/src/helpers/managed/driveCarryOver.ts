// @wc-ignore-file
// (Wuchale: storage keys and log strings only, nothing user-facing.)
import { del, get, set } from 'idb-keyval';
import { blobHashHex, isBlobSubject } from '@tomic/react';
import type { VaultCapableDb } from './vault';
import { sameAgent } from './recovery';
import { randomBytes } from '../bytes';

/**
 * Carrying local-only drives from a replaced identity into the account's.
 *
 * A local-only drive (a demo guest's kept template) lives in its
 * identity's own encrypted database, and the switch opens the account's
 * database instead. `initClientDb` refuses to seed one identity's database
 * from another's in-memory resources: on a shared device that would hand one
 * person's data to whoever signs in next. This is the deliberate exception
 * for one person switching to their own account: only drives the old
 * identity could write and has just granted the account write on (see
 * `driveHandover.ts`), exported while its database is open, imported once the
 * account's is.
 *
 * Export and import are Cloud Vault's own (`vaultExport` / `vaultImport`),
 * with a throwaway key and pseudonym instead of the account's vault: a full
 * checkpoint of the drive's Loro history and signed envelopes, merged into
 * the target the way a restore is. Attachments are not part of a vault pack,
 * so their bytes travel alongside.
 *
 * Nothing is deleted: the old database keeps its copy, and the old identity
 * stays archived on the device.
 */

export const DRIVE_CARRY_OVER_KEY = 'atomic.driveCarryOver';

/** Staging is held in IndexedDB between two page loads; keep it bounded. */
export const MAX_CARRY_OVER_BYTES = 100 * 1024 * 1024;

/** A carry-over nobody signed in to claim is dropped after this long. The
 *  drives are still in the old identity's database. */
export const CARRY_OVER_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** The vault lane the import records; a checkpoint records none. */
const LANE = 'handover';
const KEY_EPOCH = 1;
const BLOB_PROPERTY = 'https://atomicdata.dev/properties/blob';

export type CarryOverDb = Pick<
  VaultCapableDb,
  'vaultExport' | 'vaultImport'
> & {
  waitForReady(): Promise<boolean>;
  getVersionVectorsForDrive(
    drive: string,
  ): Promise<Record<string, Record<string, number>>>;
  getResourcesWithSnapshots(
    subjects: string[],
  ): Promise<Array<{ jsonAd: string | null }>>;
  getBlob(hash: Uint8Array): Promise<Uint8Array | null>;
  putBlob(hash: Uint8Array, data: Uint8Array): Promise<void>;
};

export type CarryOverStore = {
  getAgent(): { subject?: string } | undefined;
  waitForClientDb(timeoutMs?: number): Promise<boolean>;
  getClientDb(): CarryOverDb | undefined;
  registerLocalOnlyDrive(drive: string): void;
};

type StagedBlob = { hash: Uint8Array; data: Uint8Array };

type StagedDrive = {
  drive: string;
  key: Uint8Array;
  pseudonym: string;
  objectKey: string;
  sealed: Uint8Array;
  blobs: StagedBlob[];
};

/** Drives exported from one identity's database, for `to`'s. */
export type DriveCarryOver = {
  to: string;
  savedAt: number;
  drives: StagedDrive[];
};

export async function readDriveCarryOver(): Promise<
  DriveCarryOver | undefined
> {
  const value = (await get(DRIVE_CARRY_OVER_KEY)) as DriveCarryOver | undefined;

  return value &&
    typeof value.to === 'string' &&
    typeof value.savedAt === 'number' &&
    Array.isArray(value.drives)
    ? value
    : undefined;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

/** The drive's attachments that this database holds the bytes of. */
async function blobsOf(db: CarryOverDb, drive: string): Promise<StagedBlob[]> {
  const subjects = Object.keys(await db.getVersionVectorsForDrive(drive));
  const rows = await db.getResourcesWithSnapshots(subjects);
  const blobs = new Map<string, StagedBlob>();

  for (const { jsonAd } of rows) {
    if (!jsonAd) continue;

    const blob: unknown = JSON.parse(jsonAd)[BLOB_PROPERTY];
    const hashHex =
      typeof blob === 'string' && isBlobSubject(blob)
        ? blobHashHex(blob)
        : undefined;

    if (!hashHex || !/^[0-9a-f]{64}$/i.test(hashHex) || blobs.has(hashHex))
      continue;

    const hash = Uint8Array.from(hashHex.match(/../g)!, part =>
      parseInt(part, 16),
    );
    const data = await db.getBlob(hash);

    // Never downloaded here, so not this database's to carry: it is fetched
    // from wherever it came from, as it would have been before.
    if (data) blobs.set(hashHex, { hash, data });
  }

  return [...blobs.values()];
}

/**
 * Export `drives` from `from`'s database, which must be the one attached, and
 * keep them for `to`. Call after `to` was granted write on them and before
 * the switch. Throws when that cannot be done in full; nothing is kept then,
 * and nothing has switched yet.
 */
export async function stageDriveCarryOver(
  store: CarryOverStore,
  { from, to, drives }: { from: string; to: string; drives: string[] },
): Promise<string[]> {
  if (drives.length === 0) return [];

  await store.waitForClientDb();
  const db = store.getClientDb();

  // An attached database while `from` is active is `from`'s: the store
  // detaches it synchronously on every identity change.
  if (!db || !isActive(store, from) || !(await db.waitForReady()))
    throw new Error(`the local database of ${from} is not open`);

  const staged: StagedDrive[] = [];
  let bytes = 0;

  for (const drive of drives) {
    const key = randomBytes(32);
    const pseudonym = `handover-${hex(randomBytes(16))}`;
    // A new lane with no checkpoint: always a full checkpoint of the drive.
    const exported = await db.vaultExport(
      drive,
      key,
      KEY_EPOCH,
      pseudonym,
      LANE,
      1,
      1,
      false,
      {},
    );

    if (!exported) continue;

    const blobs = await blobsOf(db, drive);
    bytes += exported.sealed.byteLength;

    for (const blob of blobs) bytes += blob.data.byteLength;

    if (bytes > MAX_CARRY_OVER_BYTES)
      throw new Error(
        `local drives are too large to carry over (${bytes} bytes)`,
      );

    staged.push({
      drive,
      key,
      pseudonym,
      objectKey: exported.objectKey,
      sealed: exported.sealed,
      blobs,
    });
  }

  if (!isActive(store, from))
    throw new Error('the identity changed while its drives were exported');

  const previous = await readDriveCarryOver();
  const carried = new Set(staged.map(entry => entry.drive));
  await set(DRIVE_CARRY_OVER_KEY, {
    to,
    savedAt: Date.now(),
    drives: [
      ...(previous && sameAgent(previous.to, to)
        ? previous.drives.filter(entry => !carried.has(entry.drive))
        : []),
      ...staged,
    ],
  } satisfies DriveCarryOver);

  return [...carried];
}

/** Whether `agent` is the store's active identity, in either spelling. */
function isActive(store: CarryOverStore, agent: string): boolean {
  const active = store.getAgent()?.subject;

  return active !== undefined && sameAgent(active, agent);
}

const importing = new Map<string, Promise<string[]>>();

/**
 * Import what was staged for `agent` into its database, once that is the one
 * attached, and register the drives as local-only. Resolves to the drives
 * imported, or none when there is nothing to import yet. Throws when an
 * import failed; the staging stays, and a later call tries again (a Loro
 * merge makes a repeat harmless).
 */
export function importDriveCarryOver(
  store: CarryOverStore,
  agent: string,
): Promise<string[]> {
  const running = importing.get(agent);

  if (running) return running;

  const run = runImport(store, agent);

  const release = () => {
    importing.delete(agent);
  };

  run.then(release, release);
  importing.set(agent, run);

  return run;
}

async function runImport(
  store: CarryOverStore,
  agent: string,
): Promise<string[]> {
  const carryOver = await readDriveCarryOver();

  // The account's backup may spell its agent the legacy `did:ad:` way while
  // the signed-in agent uses `atomic:`, or the other way around.
  if (!carryOver || !sameAgent(carryOver.to, agent)) return [];

  if (Date.now() - carryOver.savedAt > CARRY_OVER_TTL_MS) {
    await del(DRIVE_CARRY_OVER_KEY);

    return [];
  }

  await store.waitForClientDb();
  const db = store.getClientDb();

  if (!db || !isActive(store, agent) || !(await db.waitForReady())) return [];

  // Same test as staging: attached while `agent` is active means `agent`'s.
  if (!isActive(store, agent) || store.getClientDb() !== db) return [];

  for (const entry of carryOver.drives) {
    // Before the import, so nothing about the drive is routed to a server.
    store.registerLocalOnlyDrive(entry.drive);

    const result = await db.vaultImport(
      entry.key,
      KEY_EPOCH,
      entry.pseudonym,
      LANE,
      [{ objectKey: entry.objectKey, sealed: entry.sealed }],
    );

    if (result.packsRead === 0)
      throw new Error(`could not import the carried-over drive ${entry.drive}`);

    for (const blob of entry.blobs) await db.putBlob(blob.hash, blob.data);
  }

  await del(DRIVE_CARRY_OVER_KEY);

  return carryOver.drives.map(entry => entry.drive);
}
