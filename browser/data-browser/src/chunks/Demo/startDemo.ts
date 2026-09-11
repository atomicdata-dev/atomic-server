// React Compiler: plain helpers, not components (see DemoDirector.ts).
'use no memo';
import { core, enableLoro, type Store } from '@tomic/react';
import {
  createDemoWorkspace,
  saveDemoManifest,
  type DemoManifest,
} from './demoWorkspace';
import { DemoDirector } from './DemoDirector';
import { ensureAgentForDemo } from './guestAgent';

let activeDirector: DemoDirector | undefined;

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
export async function startDemoWorkspace(store: Store): Promise<DemoManifest> {
  await enableLoro();

  const isGuest = await ensureAgentForDemo(store);

  activeDirector?.stop();
  activeDirector = undefined;

  await cleanupAllDemoDrives(store);

  const manifest = await createDemoWorkspace(store, { guest: isGuest });

  saveDemoDrives([manifest.drive]);
  store.setDrive(manifest.drive);

  activeDirector = new DemoDirector(store, manifest);
  activeDirector.start();

  return manifest;
}

/** Stop the scripted scenario (personas leave immediately). */
export function stopDemoDirector(): void {
  activeDirector?.stop();
  activeDirector = undefined;
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
