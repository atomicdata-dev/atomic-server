// React Compiler: plain helpers, not components (see DemoDirector.ts).
'use no memo';
import {
  StoreEvents,
  core,
  enableLoro,
  type Agent,
  type Store,
} from '@tomic/react';
import {
  createDemoWorkspace,
  saveDemoManifest,
  type DemoManifest,
} from './demoWorkspace';
import { DemoDirector } from './DemoDirector';
import { ensureAgentForDemo } from './guestAgent';
import { checkOnboardingStorage } from '../../helpers/onboardingStorage';
import { whenRevealed } from '../../helpers/bootSplash';
import { holdDemoLock, releaseDemoLock } from '../../helpers/demoTabLock';

let activeDirector: DemoDirector | undefined;
let unwatchAgent: (() => void) | undefined;

/**
 * Whether the demo may keep playing for `next` after starting for `started`.
 * It is a scene for a guest: once another identity signs in, or this one gets
 * a personal drive (it became an account), the personas must stop writing, or
 * their lines land in a real account's chats, notifier and Inbox.
 */
export function demoOutlivesAgentChange(
  started: string,
  next: Pick<Agent, 'subject' | 'privateDrive'> | undefined,
): boolean {
  return !!next && next.subject === started && !next.privateDrive;
}

/** Pause between the workspace appearing and the first persona moving. */
const DIRECTOR_DELAY_MS = 1_200;

const sleep = (ms: number) =>
  new Promise<void>(resolve => setTimeout(resolve, ms));

/** localStorage key holding every demo drive subject ever created, so a
 *  re-run can hard-clean ALL of them — not just the last manifest's. */
const DEMO_DRIVES_KEY = 'atomic.demoDrives';

function loadDemoDrives(): string[] {
  try {
    const raw = localStorage.getItem(DEMO_DRIVES_KEY);

    return raw ? (JSON.parse(raw) as string[]) : [];
  } catch {
    return [];
  }
}

function saveDemoDrives(drives: string[]): void {
  localStorage.setItem(DEMO_DRIVES_KEY, JSON.stringify(drives));
}

/** Where demo setup is, so a report of a stalled setup can say where. */
export type DemoSetupStep = 'storage' | 'identity' | 'cleanup' | 'workspace';

/**
 * Start the demo: mint a guest agent if nobody is signed in, tear down
 * EVERY previous demo drive, build a FRESH workspace, start the
 * scripted scenario, and return the manifest for navigation.
 *
 * Re-running the demo must always feel new — never append onto an
 * already-played story — so cleanup is aggressive: it removes every
 * demo drive this browser ever created (tracked in localStorage), not
 * just the last one, covering runs whose manifest was lost.
 */
export async function startDemoWorkspace(
  store: Store,
  onStep: (step: DemoSetupStep) => void = () => {},
): Promise<DemoManifest> {
  onStep('identity');
  const [isGuest] = await Promise.all([
    ensureAgentForDemo(store),
    enableLoro(),
  ]);

  // The identity comes first because its database is the one that opens
  // (App.tsx defers the anonymous one on this route). This used to be a
  // separate "Checking local storage…" screen before the demo's own.
  onStep('storage');
  await checkOnboardingStorage(store);

  stopDemoDirector();

  onStep('cleanup');
  await cleanupAllDemoDrives(store);

  onStep('workspace');
  const manifest = await createDemoWorkspace(store, { guest: isGuest });

  saveDemoDrives([manifest.drive]);
  store.setDrive(manifest.drive);

  activeDirector = new DemoDirector(store, manifest);
  // The scenario waits until the workspace is on screen and has had a moment
  // to be looked at; starting while the splash was still up meant arriving
  // mid-sentence.
  activeDirector.start(whenRevealed().then(() => sleep(DIRECTOR_DELAY_MS)));
  // Other tabs join this demo rather than replacing it (demoTabLock.ts).
  holdDemoLock();

  const startedAs = store.getAgent()?.subject;

  if (startedAs) {
    unwatchAgent = store.on(StoreEvents.AgentChanged, next => {
      if (!demoOutlivesAgentChange(startedAs, next)) stopDemoDirector();
    });
  }

  return manifest;
}

/** Stop the scripted scenario (personas leave immediately). */
export function stopDemoDirector(): void {
  unwatchAgent?.();
  unwatchAgent = undefined;
  activeDirector?.stop();
  activeDirector = undefined;
  releaseDemoLock();
}

/** Tear down every demo drive this browser created. */
async function cleanupAllDemoDrives(store: Store): Promise<void> {
  const drives = loadDemoDrives();

  // The local DB must be ready or the parent-walk finds no children and
  // live-created resources (meeting, extra cards, messages) survive.
  const clientDb = store.getClientDb();

  if (clientDb && !clientDb.isReady) {
    await clientDb.waitForReady().catch(() => undefined);
  }

  for (const drive of drives) {
    await cleanupDemoDrive(store, drive);
  }

  saveDemoDrives([]);
  saveDemoManifest(undefined);
}

/**
 * Remove a demo drive and everything under it from the store and OPFS
 * (`removeResource` tombstones clientDb), and unregister it so the
 * persisted local-only set stays bounded. Descendants are found by
 * breadth-first parent-queries — deep enough to reach messages
 * (drive→chatroom→message) and board cards (drive→table→row).
 */
export async function cleanupDemoDrive(
  store: Store,
  drive: string,
): Promise<void> {
  try {
    const doomed = new Set<string>([drive]);
    let frontier = [drive];

    for (let depth = 0; depth < 8 && frontier.length > 0; depth++) {
      const next: string[] = [];

      for (const parent of frontier) {
        const result = await store.queryLocalDb({
          property: core.properties.parent,
          value: parent,
        });

        for (const subject of result?.subjects ?? []) {
          if (!doomed.has(subject)) {
            doomed.add(subject);
            next.push(subject);
          }
        }
      }

      frontier = next;
    }

    // A guest's profile row is the guest's own agent resource (see
    // `createGuestProfile`), so it is parented under this drive's team
    // table. The identity outlives the demo: removing it would tombstone the
    // agent for the rest of the session, and a later save on it (keeping a
    // template links the guest's home on it) would have nothing to save to.
    // Removing it left every later write ("Create drive" included) failing
    // with "Resource has no store". The next demo run rewrites the row in place.
    const agent = store.getAgent()?.subject;
    if (agent) doomed.delete(agent);

    for (const subject of doomed) {
      store.removeResource(subject, false);
    }

    store.unregisterLocalOnlyDrive(drive);
    await removeFromSavedDrives(store, drive);
  } catch (e) {
    console.warn('[Demo] cleanup of previous demo drive failed:', e);
  }
}

/** Drop the demo drive from the agent's drive switcher, so old runs
 *  don't pile up there. */
async function removeFromSavedDrives(
  store: Store,
  drive: string,
): Promise<void> {
  try {
    const agentSubject = store.getAgent()?.subject;
    if (!agentSubject) return;

    const agentResource = await store.getResource(agentSubject);
    const privateDrive = agentResource.get(core.properties.personalDrive) as
      | string
      | undefined;
    if (!privateDrive) return;

    const privateDriveResource = await store.getResource(privateDrive);
    const SERVER_DRIVES = 'https://atomicdata.dev/properties/drives';
    const current = (privateDriveResource.get(SERVER_DRIVES) ?? []) as string[];

    if (!current.includes(drive)) return;

    await privateDriveResource.set(
      SERVER_DRIVES,
      current.filter(d => d !== drive),
    );
    await privateDriveResource.save();
  } catch {
    // Best-effort; a stale switcher entry is harmless.
  }
}
