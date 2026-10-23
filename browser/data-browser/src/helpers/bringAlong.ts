// @wc-ignore-file
// (Wuchale: log strings only, nothing user-facing.)
import * as Sentry from '@sentry/react';
import type { Store } from '@tomic/react';
import { archiveStoredAgent } from './agentStorage';
import { isClientDbEnabled } from './clientDbMode';
import { localAgentWorkspace, sameAgent } from './managed';
import {
  importDriveCarryOver,
  stageDriveCarryOver,
} from './managed/driveCarryOver';
import {
  applyPendingDriveHandover,
  handOverDrives,
  listHandoverDrives,
} from './managed/driveHandover';
import {
  readInteractiveDemo,
  readTemplateDemo,
} from '../chunks/Templates/demoSession';

/**
 * Bringing work along when a sign-in replaces the identity this browser holds
 * (see planning/identity-bring-along.md). The browser holds A, the person
 * signs in as B: A's key is kept on the device, and A's drives come along to
 * B when A has any and the person says so.
 */

/** What the sign-in did with the identity that was here. */
export type SwitchOutcome =
  /** Nothing was here, or it was the same one: a plain sign-in. */
  | 'plain'
  /** Kept on the device, nothing handed over (nothing to bring, or declined). */
  | 'left'
  /** Kept on the device and its drives were handed to the new one. */
  | 'brought';

/** The drives that are not the person's to bring: demo and preview drives. */
function skippedDrives(): (string | undefined)[] {
  return [readInteractiveDemo()?.drive, readTemplateDemo()?.drive];
}

/**
 * Hand `from`'s drives to `to` and keep `from`'s key (`driveHandover.ts`).
 * Throws when that fails, before anything has switched.
 */
export async function handOverFrom(
  store: Store,
  from: string,
  to: string,
): Promise<void> {
  await handOverDrives(store, {
    from,
    to,
    personalDrive: store.getAgent()?.privateDrive,
    skip: skippedDrives(),
    archiveIdentity: archiveStoredAgent,
    // Without a local database there is no identity database to leave the
    // drives behind in.
    carryOver: isClientDbEnabled()
      ? drives => stageDriveCarryOver(store, { from, to, drives })
      : undefined,
  });
}

/**
 * Whether `from` has anything worth asking about: a workspace holding at
 * least one drive besides its own home. Unreadable counts as yes, like the
 * reconcile gate: an identity that is merely offline must not be left behind
 * unasked.
 */
export async function hasWorkToBring(
  store: Store,
  from: string,
): Promise<boolean> {
  const workspace = await localAgentWorkspace(store, from);

  if (workspace === 'none') return false;
  if (workspace === 'unknown') return true;

  try {
    const skip = skippedDrives();
    const drives = await listHandoverDrives(
      store,
      from,
      store.getAgent()?.privateDrive,
    );

    return drives.some(drive => !skip.includes(drive));
  } catch {
    return true;
  }
}

/**
 * Run before a sign-in replaces the stored identity. Always keeps the old
 * key. When the old identity has work, `ask` shows the question and resolves
 * with the answer; yes hands the drives to `to`. Throws when bringing them
 * along fails, so the caller can stop before switching.
 */
export async function prepareIdentitySwitch(
  store: Store,
  to: string | undefined,
  ask: () => Promise<boolean>,
): Promise<SwitchOutcome> {
  const from = store.getAgent()?.subject;

  if (!from || !to || sameAgent(from, to)) return 'plain';

  try {
    await archiveStoredAgent(from);
  } catch (error) {
    // No stored key (an unsaved session): there is nothing to lose by going on.
    Sentry.captureException(
      new Error('keeping the previous identity failed', { cause: error }),
      { tags: { flow: 'identity-switch' } },
    );
  }

  if (!(await hasWorkToBring(store, from))) return 'left';

  if (!(await ask())) return 'left';

  await handOverFrom(store, from, to);

  return 'brought';
}

/**
 * After the switch, once `home` (the new identity's own drive) is on this
 * device: import carried-over drives and list the handed-over ones there.
 * Until it succeeds the record stays and the reconcile gate tries again.
 */
export function applyBroughtAlong(
  store: Store,
  agent: string,
  home?: string,
): Promise<boolean> {
  return applyPendingDriveHandover(
    store,
    agent,
    subject => importDriveCarryOver(store, subject),
    home,
  );
}
