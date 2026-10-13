// @wc-ignore-file
import {
  StoreEvents,
  core,
  dataBrowser,
  type Resource,
  type Store,
} from '@tomic/react';
import {
  mergeActivity,
  parseActivityLog,
  type ActivityEntry,
  type ActivityKind,
} from './activityLog';

/** Wait this long after the last save before writing the drive. */
export const FLUSH_DEBOUNCE_MS = 15_000;
/** ...but never hold a continuous editing session back longer than this. */
export const FLUSH_MAX_WAIT_MS = 120_000;
/** Newer than this at save time counts as a creation. */
const FRESH_MS = 30_000;
/** Hard cap on queued subjects between flushes. */
const MAX_PENDING = 100;
const MAX_DEPTH = 12;
/** Failed drive writes before the queued entries are dropped. */
const MAX_FAILURES = 3;

/**
 * Classes that are high-frequency or schema plumbing (a table creates a class
 * and touches the ontology; that is not something a person did).
 */
const SKIPPED_CLASSES = new Set<string>([
  dataBrowser.classes.message,
  core.classes.class,
  core.classes.property,
  core.classes.ontology,
]);

interface Pending {
  kind: ActivityKind;
  at: number;
  resource: Resource;
}

/**
 * Records what the current agent does on `drive` into the drive's own bounded
 * activity log. The ResourceSaved handler is O(1) and synchronous: it only
 * touches a Map and a timer. Everything that needs awaits (ancestry, rights,
 * the drive write) happens in a debounced flush, one drive commit per burst.
 *
 * Returns a disposer that flushes what is queued, then detaches.
 */
export function startDriveActivityRecorder(
  store: Store,
  drive: string,
): () => void {
  const pending = new Map<string, Pending>();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let burstStart = 0;
  let flushing: Promise<void> | undefined;
  /** Entries that are resolved but not yet written (a failed save retries them). */
  let unsent: ActivityEntry[] = [];
  let failures = 0;
  let disposed = false;

  const onSaved = (resource: Resource) => {
    try {
      const subject = resource.subject;
      const existing = pending.get(subject);

      if (existing) {
        // Repeated saves of one resource: just move the timestamp.
        existing.at = Date.now();
        schedule();

        return;
      }

      if (
        subject === drive ||
        pending.size >= MAX_PENDING ||
        !store.getAgent()?.subject ||
        !resource.get(core.properties.parent) ||
        resource.getClasses().some(c => SKIPPED_CLASSES.has(c))
      ) {
        return;
      }

      const createdAt = resource.getCreatedAt();
      const kind: ActivityKind =
        createdAt !== undefined && Date.now() - createdAt < FRESH_MS
          ? 'created'
          : 'edited';

      pending.set(subject, { kind, at: Date.now(), resource });
      schedule();
    } catch {
      // Activity is a nicety: never let it reach the UI.
    }
  };

  function schedule() {
    if (disposed) return;

    const now = Date.now();

    if (timer === undefined) burstStart = now;
    else clearTimeout(timer);

    const wait = Math.max(
      0,
      Math.min(FLUSH_DEBOUNCE_MS, burstStart + FLUSH_MAX_WAIT_MS - now),
    );

    timer = setTimeout(() => void flush(), wait);
  }

  async function isInDrive(resource: Resource): Promise<boolean> {
    let parent = resource.get(core.properties.parent) as string | undefined;

    for (let depth = 0; parent && depth < MAX_DEPTH; depth++) {
      if (parent === drive) return true;

      const parentResource = await store.getResource(parent);

      if (depth === 0 && parentResource.hasClasses(dataBrowser.classes.table)) {
        // Rows are edited in bursts all day; the table itself is the activity.
        return false;
      }

      parent = parentResource.get(core.properties.parent) as string | undefined;
    }

    return false;
  }

  async function write(): Promise<void> {
    const agent = store.getAgent()?.subject;

    if (!agent) {
      pending.clear();
      unsent = [];

      return;
    }

    const batch = Array.from(pending.values());
    pending.clear();

    const entries: ActivityEntry[] = [];

    for (const item of batch) {
      if (await isInDrive(item.resource)) {
        entries.push({
          subject: item.resource.subject,
          agent,
          at: item.at,
          kind: item.kind,
        });
      }
    }

    unsent = mergeActivity(unsent, entries);

    if (unsent.length === 0) return;

    try {
      // Read the drive fresh: another writer may have changed the log since
      // we last saw it, and we must never overwrite from a stale local copy.
      await store.reloadResource(drive).catch(() => undefined);

      const driveResource = await store.getResource(drive);

      // No write right means no attempt. Unlike `useCanWrite` there is no
      // DID fallback: a DID drive owned by someone else would only reject us.
      const [allowed] = await driveResource.canWrite(agent);

      if (!allowed) {
        unsent = [];

        return;
      }

      // The datatype tag (`json`) is only written for properties in the store.
      await store.getResource(dataBrowser.properties.activityLog);

      const current = parseActivityLog(
        driveResource.get(dataBrowser.properties.activityLog),
      );
      const merged = mergeActivity(current, unsent);

      // After a failed save the local drive already holds the value; resend it.
      if (merged !== current || failures > 0) {
        await driveResource.set(
          dataBrowser.properties.activityLog,
          merged as unknown as never,
        );
        await driveResource.save();
      }

      unsent = [];
      failures = 0;
    } catch {
      // Keep the entries for the next flush, but give up after a few tries.
      if (++failures >= MAX_FAILURES) {
        unsent = [];
        failures = 0;
      } else {
        schedule();
      }
    }
  }

  function flush(): Promise<void> {
    if (timer !== undefined) clearTimeout(timer);

    timer = undefined;

    if (flushing) {
      // A write is in flight: queue behind it instead of racing the drive.
      return flushing.then(() => (pending.size ? flush() : undefined));
    }

    flushing = write()
      .catch(() => undefined)
      .then(() => {
        flushing = undefined;
      });

    return flushing;
  }

  const onHide = () => void flush();

  const onVisibility = () => {
    if (document.visibilityState === 'hidden') void flush();
  };

  const off = store.on(StoreEvents.ResourceSaved, onSaved);
  const hasWindow = typeof window !== 'undefined';

  if (hasWindow) {
    window.addEventListener('pagehide', onHide);
    document.addEventListener('visibilitychange', onVisibility);
  }

  return () => {
    off();

    if (hasWindow) {
      window.removeEventListener('pagehide', onHide);
      document.removeEventListener('visibilitychange', onVisibility);
    }

    disposed = true;
    void flush();
  };
}
