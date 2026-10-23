// @wc-ignore-file
// (Wuchale: storage keys and log strings only, nothing user-facing.)
import { core, server } from '@tomic/react';
import { sameAgent } from './recovery';

/**
 * Handing a local identity's drives to the account identity that replaces it.
 *
 * One email has one identity. When the account already has one and this
 * browser made a demo guest, the account's wins — but the guest may already
 * own drives (a kept template preview). Before the switch, while the guest
 * can still sign, it adds the account agent to each of those drives'
 * `write`, and copies the local-only ones out of its own database
 * (`driveCarryOver.ts`). After the switch, the account imports those copies
 * and lists every handed-over drive in its own home, the way
 * `addToSavedDrives` does for the demo.
 *
 * The guest's own home is read for the drives it lists, never handed over
 * itself: it holds nothing but that list, and the account has a home of its
 * own. Handing it over put a second "My drive" in the account's switcher.
 */

export const PENDING_DRIVE_HANDOVER_KEY = 'atomic.pendingDriveHandover';

/** The drives handed to `agent`, waiting to be listed in its home. */
export type PendingDriveHandover = { agent: string; drives: string[] };

/** The part of a Resource the handover touches. Narrow so tests can mock it. */
export type HandoverResource = {
  error?: unknown;
  get(property: string): unknown;
  push(property: string, values: string[], unique?: boolean): void;
  canWrite(agent?: string): Promise<[boolean, string | undefined]>;
  save(): Promise<unknown>;
  /** Only read on the personal drive, to see whether it holds anything. */
  getChildrenCollection?(pageSize?: number): Promise<{ totalMembers: number }>;
};

export type HandoverStore = {
  getResource(subject: string): Promise<HandoverResource>;
  isLocalOnlyDrive(subject: string): boolean;
};

export type DriveHandoverOptions = {
  /** The browser's identity, still active. */
  from: string;
  /** The account's identity. */
  to: string;
  /**
   * The personal drive the agent recorded at sign-in. Used only when the
   * agent resource cannot be read, which must not hide the drives on it.
   */
  personalDrive?: string;
  /** Drives that are not the user's to hand over: demo and preview drives. */
  skip: (string | undefined)[];
  /** Keep `from`'s key on this device; see `archiveStoredAgent`. */
  archiveIdentity: (
    subject: string,
    localOnlyDrives: string[],
  ) => Promise<void>;
  /**
   * Copy local-only drives out of `from`'s database for `to`'s; see
   * `driveCarryOver.ts`. Without it they stay with the archived identity.
   */
  carryOver?: (drives: string[]) => Promise<unknown>;
};

export function readPendingDriveHandover(): PendingDriveHandover | undefined {
  try {
    const value = JSON.parse(
      localStorage.getItem(PENDING_DRIVE_HANDOVER_KEY) ?? 'null',
    );

    if (
      value &&
      typeof value.agent === 'string' &&
      Array.isArray(value.drives) &&
      value.drives.every((drive: unknown) => typeof drive === 'string')
    )
      return value;
  } catch {
    /* Storage is unavailable or a previous version wrote invalid data. */
  }

  return undefined;
}

function personalDriveOf(resource: HandoverResource): string | undefined {
  const value = resource.get(core.properties.personalDrive);

  return typeof value === 'string' ? value : undefined;
}

function drivesListedIn(resource: HandoverResource): string[] {
  const value = resource.get(server.properties.drives);

  return Array.isArray(value)
    ? value.filter((drive): drive is string => typeof drive === 'string')
    : [];
}

/**
 * The drives `from`'s personal drive lists, without that personal drive
 * itself (it lists itself, for its own switcher).
 */
async function drivesOf(
  store: HandoverStore,
  from: string,
  recordedPersonalDrive: string | undefined,
): Promise<string[]> {
  let personalDrive: string | undefined;
  // Known to exist: its read failing is a reason to stop, not to skip it.
  let known = false;

  try {
    const agent = await store.getResource(from);

    if (!agent.error) {
      personalDrive = personalDriveOf(agent);
      known = personalDrive !== undefined;
    } else {
      personalDrive = recordedPersonalDrive;
    }
  } catch {
    personalDrive = recordedPersonalDrive;
  }

  if (!personalDrive) return [];

  const home = await store.getResource(personalDrive);

  if (home.error) {
    if (known)
      throw new Error(`could not read personal drive ${personalDrive}`);

    // Only the subject derived at sign-in, never created: nothing to hand over.
    return [];
  }

  const listed = drivesListedIn(home).filter(drive => drive !== personalDrive);

  // A home that holds documents of its own is work too; an empty one is only
  // the list, and handing that over gave the account a second empty "My drive".
  return (await holdsContent(home)) ? [...listed, personalDrive] : listed;
}

async function holdsContent(home: HandoverResource): Promise<boolean> {
  if (!home.getChildrenCollection) return false;

  return (await home.getChildrenCollection(1)).totalMembers > 0;
}

/**
 * The drives `from` could hand over, before any grant: what a sign-in as
 * someone else would bring along. Throws when they cannot be read.
 */
export async function listHandoverDrives(
  store: HandoverStore,
  from: string,
  personalDrive?: string,
): Promise<string[]> {
  return [...new Set(await drivesOf(store, from, personalDrive))];
}

const inFlight = new Map<string, Promise<PendingDriveHandover>>();

/**
 * Grant `to` write on every drive `from` can write, keep `from`'s key, and
 * record what `to` should list once it is the active identity. Throws when
 * any of that fails; nothing has switched yet, so the caller can still ask.
 *
 * Idempotent: a drive `to` can already write is not saved again, and a
 * second call while one runs shares it.
 */
export function handOverDrives(
  store: HandoverStore,
  options: DriveHandoverOptions,
): Promise<PendingDriveHandover> {
  const key = `${options.from} ${options.to}`;
  const running = inFlight.get(key);

  if (running) return running;

  const run = runHandover(store, options);

  const release = () => {
    inFlight.delete(key);
  };

  run.then(release, release);
  inFlight.set(key, run);

  return run;
}

async function runHandover(
  store: HandoverStore,
  {
    from,
    to,
    personalDrive,
    skip,
    archiveIdentity,
    carryOver,
  }: DriveHandoverOptions,
): Promise<PendingDriveHandover> {
  const drives = [
    ...new Set(await drivesOf(store, from, personalDrive)),
  ].filter(drive => !sameAgent(drive, to) && !skip.includes(drive));
  const synced: string[] = [];
  const localOnly: string[] = [];

  for (const subject of drives) {
    const drive = await store.getResource(subject);

    // A listed drive that no longer loads, or one only shared with `from`
    // for reading, is not `from`'s to give.
    if (drive.error || !(await drive.canWrite(from))[0]) continue;

    if (!grantsWrite(drive, to)) {
      drive.push(core.properties.write, [to], true);
      await drive.save();
    }

    (store.isLocalOnlyDrive(subject) ? localOnly : synced).push(subject);
  }

  // A local-only drive is stored in `from`'s own encrypted database, which
  // `to` does not open. Export it now, after the grant above so the copy
  // carries it, while that database is still the one attached. It is listed
  // in `to`'s home only once imported (`applyPendingDriveHandover`): listed
  // any earlier it would show a drive that fails to load.
  if (carryOver && localOnly.length > 0) await carryOver(localOnly);

  // Kept as well: the carried-over copy is a copy, the original stays here.
  await archiveIdentity(from, localOnly);

  return recordPending(to, synced);
}

/**
 * Whether `drive`'s own `write` already names `agent`. Rights on a drive are
 * its `write` list; an agent in either spelling (`did:ad:` or `atomic:`) is
 * the same agent, and granting it again would only add a duplicate commit.
 */
export function grantsWrite(
  drive: Pick<HandoverResource, 'get'>,
  agent: string,
): boolean {
  const writers = drive.get(core.properties.write);

  return (
    Array.isArray(writers) &&
    writers.some(
      writer => typeof writer === 'string' && sameAgent(writer, agent),
    )
  );
}

/** Add `drives` to what `agent`'s home should list. */
function recordPending(agent: string, drives: string[]): PendingDriveHandover {
  const previous = readPendingDriveHandover();
  const pending: PendingDriveHandover = {
    agent,
    drives: [
      ...new Set([
        ...(previous && sameAgent(previous.agent, agent)
          ? previous.drives
          : []),
        ...drives,
      ]),
    ],
  };
  localStorage.setItem(PENDING_DRIVE_HANDOVER_KEY, JSON.stringify(pending));

  return pending;
}

/**
 * Once `agent` is the active identity, import the local-only drives carried
 * over to it (`importCarriedDrives`, see `driveCarryOver.ts`), then list the
 * drives handed to it in its home, and forget them. Best-effort and safe to
 * repeat: until it succeeds the record stays, and the next check tries again.
 */
export async function applyPendingDriveHandover(
  store: Pick<HandoverStore, 'getResource'>,
  agent: string,
  importCarriedDrives: (agent: string) => Promise<string[]> = async () => [],
): Promise<boolean> {
  try {
    const imported = await importCarriedDrives(agent);

    if (imported.length > 0) recordPending(agent, imported);
  } catch (error) {
    // Listing what did hand over still goes ahead; the import retries.
    console.warn('importing carried-over drives failed, will retry:', error);
  }

  const pending = readPendingDriveHandover();

  if (!pending || !sameAgent(pending.agent, agent)) return false;

  try {
    const agentResource = await store.getResource(agent);
    const personalDrive = agentResource.error
      ? undefined
      : personalDriveOf(agentResource);

    if (!personalDrive) return false;

    const home = await store.getResource(personalDrive);

    if (home.error) return false;

    const listed = drivesListedIn(home);
    const missing = pending.drives.filter(
      drive => drive !== personalDrive && !listed.includes(drive),
    );

    if (missing.length > 0) {
      home.push(server.properties.drives, missing, true);
      await home.save();
    }

    localStorage.removeItem(PENDING_DRIVE_HANDOVER_KEY);

    return true;
  } catch (error) {
    console.warn('listing handed-over drives failed, will retry:', error);

    return false;
  }
}
