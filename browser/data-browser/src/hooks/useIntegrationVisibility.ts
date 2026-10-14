import {
  core,
  ensureSchema,
  findSchema,
  server,
  useCurrentAgent,
  useResource,
  useStore,
  type Store,
} from '@tomic/react';
import { useEffect, useRef, useState } from 'react';
import { usePrivateDrive } from './usePrivateDrive';
import {
  integrationVisibility,
  integrationVisibilitySchema,
  readPendingVisibility,
  readPreviewUnlocked,
  readVisibilityCache,
  writePendingVisibility,
  writePreviewUnlocked,
  writeVisibilityCache,
  type IntegrationVisibilityKey,
  type IntegrationVisibilityValues,
} from '@helpers/integrationVisibility';
import { retryDelayMs } from '@helpers/retryBackoff';

/**
 * One pass at the private drive's visibility schema.
 *
 * Kept out of the hook, and exported, so the retry above is testable without
 * rendering the settings page.
 *
 * `fromServer` is what makes asking again worth anything. A read that timed out
 * leaves an errored resource in the store's cache, and `getResource` hands that
 * same error back for as long as the tab is open, so a retry that asked the
 * cache would get the same answer forever. Going back to the server also heals
 * the drive resource that this panel's `ready` gate reads directly.
 */
export async function resolveVisibilitySchema(
  store: Store,
  privateDrive: string,
  fromServer: boolean,
): Promise<
  | { ok: true; properties: Record<string, string> }
  | { ok: false; error: string }
> {
  try {
    const drive = fromServer
      ? await store.fetchResourceFromServer(privateDrive)
      : await store.getResource(privateDrive);

    // An errored drive resource is not an answer. `findSchema` would read no
    // `default-ontology` off it and report an empty schema, which is exactly
    // what a drive that genuinely has none looks like, and the `ready` gate
    // below reads this same resource: a pass that accepted that would leave the
    // panel unready with nothing asking again.
    if (drive.error) return { ok: false, error: String(drive.error) };

    const schema = await findSchema(
      store,
      privateDrive,
      integrationVisibilitySchema(),
    );

    return { ok: true, properties: schema.properties ?? {} };
  } catch (reason) {
    return { ok: false, error: String(reason) };
  }
}

/**
 * These preferences only decide what discovery shows, so the toggle is applied
 * locally right away and written to the private drive in the background. That
 * keeps the checkboxes usable while the server is still starting up.
 */
export function useIntegrationVisibility({
  unlockToggle = false,
}: {
  /** Unlock the experimental toggle for this agent on this device. */
  unlockToggle?: boolean;
} = {}) {
  const store = useStore();
  const [agent] = useCurrentAgent();
  const actor = agent?.subject;
  const { privateDrive, loading } = usePrivateDrive();
  const resource = useResource(loading ? undefined : privateDrive);
  const ontologySubject = resource.get(server.properties.defaultOntology);
  const ontology = useResource(
    typeof ontologySubject === 'string' ? ontologySubject : undefined,
  );
  const ontologyProperties = JSON.stringify(
    ontology.get(core.properties.properties),
  );
  const [resolved, setResolved] = useState<{
    actor: string;
    drive: string;
    properties: Record<string, string>;
  }>();
  const [saving, setSaving] = useState(false);
  /** Last known values for this agent, shown until the drive is readable. */
  const [local, setLocal] = useState<IntegrationVisibilityValues>(() =>
    readVisibilityCache(actor),
  );
  /** Toggles that are queued, in flight, or failed: the local value wins.
   * Restored from storage, so a reload right after a toggle resumes its
   * write rather than reverting to the drive's older value. */
  const [unconfirmed, setUnconfirmed] = useState<IntegrationVisibilityKey[]>(
    () => pendingKeys(readPendingVisibility(actor)),
  );
  const [queue, setQueue] = useState<IntegrationVisibilityValues>(() =>
    readPendingVisibility(actor),
  );
  /** A facilitator unlocked the experimental toggle on this device. */
  const [unlocked, setUnlocked] = useState(() => readPreviewUnlocked(actor));
  const flushing = useRef(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    const pending = readPendingVisibility(actor);
    setUnlocked(readPreviewUnlocked(actor));
    setLocal(readVisibilityCache(actor));
    setUnconfirmed(pendingKeys(pending));
    setQueue(pending);
    setError(undefined);
  }, [actor]);

  // Resolving the schema is what makes this panel ready, so a read that failed
  // has to be asked again. It used to be a single attempt: one timed-out read of
  // the private drive rejected `findSchema`, the panel stayed `data-ready=false`
  // with an error beside its checkboxes, and nothing asked again, so the
  // preferences could not be changed until the page was reloaded. Measured on a
  // loaded box: "Async Request for subject atomic:… timed out after 10000ms",
  // then 30 seconds of a panel that never became ready.
  useEffect(() => {
    let active = true;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let failures = 0;
    setResolved(undefined);
    setError(undefined);
    if (!privateDrive || loading || !actor) return;

    const resolve = async () => {
      const result = await resolveVisibilitySchema(
        store,
        privateDrive,
        // The store cannot answer differently than it did a moment ago, so
        // every pass after the first goes back to the server.
        failures > 0,
      );

      if (!active) return;

      if (!result.ok) {
        failures += 1;
        setError(result.error);
        retry = setTimeout(() => void resolve(), retryDelayMs(failures));

        return;
      }

      failures = 0;
      setError(undefined);
      setResolved({
        actor,
        drive: privateDrive,
        properties: result.properties,
      });
    };

    void resolve();

    return () => {
      active = false;
      clearTimeout(retry);
    };
  }, [
    store,
    actor,
    privateDrive,
    loading,
    ontologySubject,
    ontologyProperties,
  ]);

  const ready =
    !loading &&
    !!privateDrive &&
    resolved?.drive === privateDrive &&
    resolved?.actor === actor &&
    !resource.loading &&
    !resource.error;
  const stored = integrationVisibility(
    resource,
    ready ? resolved.properties : {},
  );

  // Writes are queued rather than awaited, so a slow or unreachable server
  // never blocks the toggle that triggered them.
  useEffect(() => {
    const entries = Object.entries(queue) as [
      IntegrationVisibilityKey,
      boolean,
    ][];

    if (!ready || !actor || !privateDrive || flushing.current) return;

    if (entries.length === 0) return;

    flushing.current = true;
    setSaving(true);

    void saveVisibility(store, privateDrive, actor, entries).then(result => {
      flushing.current = false;
      setSaving(false);

      // Signing out or switching agents mid-write hands state to the effect
      // above, which reloads the preferences for whoever is signed in now.
      if (store.getAgent()?.subject !== actor) return;

      if (result.properties)
        setResolved({
          actor,
          drive: privateDrive,
          properties: result.properties,
        });

      if (!result.error) {
        const remaining = dropSaved(readPendingVisibility(actor), entries);
        writePendingVisibility(actor, remaining);
        setUnconfirmed(current =>
          stillUnconfirmed(current, entries, remaining),
        );
      }

      // A failed write leaves the choice applied locally; only saving failed.
      setError(result.error);
      setQueue(current => dropSaved(current, entries));
    });
  }, [ready, queue, actor, privateDrive, store]);

  // Once the drive is readable and in sync, it is the source of truth again.
  useEffect(() => {
    if (!ready) return;
    const confirmed: IntegrationVisibilityValues = {};

    if (!unconfirmed.includes('show-api-plugins'))
      confirmed['show-api-plugins'] = stored.showApiPlugins;

    if (!unconfirmed.includes('show-experimental-plugins'))
      confirmed['show-experimental-plugins'] = stored.showExperimentalPlugins;

    if (Object.keys(confirmed).length === 0) return;
    setLocal(writeVisibilityCache(actor, confirmed));
  }, [
    ready,
    actor,
    unconfirmed,
    stored.showApiPlugins,
    stored.showExperimentalPlugins,
  ]);

  const value = (key: IntegrationVisibilityKey, remote: boolean) =>
    ready && !unconfirmed.includes(key) ? remote : (local[key] ?? remote);

  useEffect(() => {
    if (!unlockToggle) return;
    writePreviewUnlocked(actor);
    setUnlocked(true);
  }, [unlockToggle, actor]);

  const setVisibility = (key: IntegrationVisibilityKey, next: boolean) => {
    // Whoever flips the switch keeps it, so it can't vanish under their cursor.
    if (key === 'show-experimental-plugins') {
      writePreviewUnlocked(actor);
      setUnlocked(true);
    }

    setLocal(writeVisibilityCache(actor, { [key]: next }));
    writePendingVisibility(actor, {
      ...readPendingVisibility(actor),
      [key]: next,
    });
    setUnconfirmed(current =>
      current.includes(key) ? current : [...current, key],
    );
    setQueue(current => ({ ...current, [key]: next }));
    setError(undefined);
  };

  const showExperimentalPlugins = value(
    'show-experimental-plugins',
    stored.showExperimentalPlugins,
  );

  return {
    showApiPlugins: value('show-api-plugins', stored.showApiPlugins),
    showExperimentalPlugins,
    /** Plugins are handed out in user-testing sessions, so ordinary users get
     * no toggle. It stays for anyone who already opted in, and shows for
     * anyone who unlocked it on this device. */
    experimentalToggleVisible: showExperimentalPlugins || unlocked,
    ready,
    saving,
    pending: saving || Object.keys(queue).length > 0,
    error,
    setVisibility,
  };
}

function pendingKeys(
  pending: IntegrationVisibilityValues,
): IntegrationVisibilityKey[] {
  return Object.keys(pending) as IntegrationVisibilityKey[];
}

/** Keeps entries that were changed again while the write was in flight. */
export function dropSaved(
  queued: IntegrationVisibilityValues,
  saved: [IntegrationVisibilityKey, boolean][],
): IntegrationVisibilityValues {
  const next = { ...queued };

  for (const [key, value] of saved) {
    if (next[key] === value) delete next[key];
  }

  return next;
}

/** A saved key is confirmed unless it was toggled again mid-flight, which
 * leaves it in the remaining pending values. */
export function stillUnconfirmed(
  current: IntegrationVisibilityKey[],
  saved: [IntegrationVisibilityKey, boolean][],
  remaining: IntegrationVisibilityValues,
): IntegrationVisibilityKey[] {
  return current.filter(
    key => key in remaining || !saved.some(([savedKey]) => savedKey === key),
  );
}

async function saveVisibility(
  store: Store,
  privateDrive: string,
  actor: string,
  entries: [IntegrationVisibilityKey, boolean][],
): Promise<{ properties?: Record<string, string>; error?: string }> {
  try {
    const schema = await ensureSchema(
      store,
      privateDrive,
      integrationVisibilitySchema(),
    );
    const drive = await store.getResource(privateDrive);

    // The agent may have changed while we waited for the server.
    if (store.getAgent()?.subject !== actor) return {};

    for (const [key, value] of entries) {
      await drive.set(schema.properties[key], value);
    }

    await drive.save();

    return { properties: schema.properties };
  } catch (reason) {
    return { error: String(reason) };
  }
}
