import { useEffect, useState } from 'react';
import { LOG_AFTER_PASSES, retryDelayMs } from '@helpers/retryBackoff';
import {
  findSchema,
  pluginSchema,
  server,
  useStore,
  type Store,
} from '@tomic/react';

/**
 * The plugin class of a drive, if it already has one.
 *
 * Read-only: rendering a context menu must not bring a schema into existence.
 * Resolved into React state, because a module cache read during render never
 * re-renders when it later fills.
 *
 * Re-resolves when the drive's ontology changes, so a drive that gains plugin
 * classes — from a plugin created in this tab, or synced from elsewhere — shows
 * the action without a reload.
 */
export function usePluginClass(drive: string | undefined): string | undefined {
  return useDriveClass(drive, 'plugin-script');
}

/** The drive's App class, once resolved. Absent while looking up. */
export function useAppClass(drive: string | undefined): string | undefined {
  return useDriveClass(drive, 'app');
}

/**
 * One of the drive's plugin classes, by shortname.
 *
 * Resolved in state rather than read during render: filling a module cache
 * re-renders nothing, so a page that asked during render would decide the
 * class does not exist and never look again.
 */
/**
 * One pass at the drive's schema, looking for the class called `shortname`.
 *
 * A read that FAILED and a class that is genuinely absent are different
 * answers, and keeping them apart is the whole job here: `{ ok: false }` means
 * nobody knows yet, `{ ok: true, value: undefined }` means the drive was read
 * and has no such class. Most drives are the second case, so it must not
 * retry, and the page that asked must not keep asking.
 *
 * The drive resource is read FIRST, on its own, because `findSchema` cannot
 * tell those two apart: it reads `default-ontology` off the drive and returns
 * `{}` when there is none, which is exactly what an errored or unloaded drive
 * resource also looks like. That empty answer used to arrive as a successful
 * "this drive has no app class", the hook wrote `undefined` into state, and
 * nothing ever asked again, because the ontology subscription it sets up needs
 * the very ontology it failed to read. One unlucky read then rendered an app as
 * a bare list of its properties for as long as the tab stayed open. The website
 * class collapsed the same way until `874c5bd`.
 *
 * `fromServer` is what makes asking again worth anything. `getResource` answers
 * from the store's cache and returns a resource that once failed as-is:
 * `if (found.isReady() || found.error) return found`. So a second `getResource`
 * hands back the very same error for as long as the tab is open. A retry has to
 * go back to the source.
 *
 * Outside the hook so the React compiler does not have to reason about a
 * try/catch inside a component.
 */
async function resolveDriveClass(
  store: Store,
  drive: string,
  shortname: 'plugin-script' | 'app',
  isCancelled: () => boolean,
  fromServer: boolean,
): Promise<
  | { ok: true; value: string | undefined; ontology: string | undefined }
  | { ok: false; error: unknown }
> {
  try {
    const driveResource = fromServer
      ? await store.fetchResourceFromServer(drive)
      : await store.getResource(drive);

    if (isCancelled()) return { ok: false, error: undefined };

    if (driveResource.error) {
      return { ok: false, error: driveResource.error };
    }

    const ontology = driveResource.get(server.properties.defaultOntology);

    if (typeof ontology !== 'string' || ontology.length === 0) {
      // A drive that names no ontology has no plugin classes, and most drives
      // are that case, so this must settle rather than poll. But a cached drive
      // resource that is merely INCOMPLETE looks identical from here, and
      // answering `undefined` for that renders an app as a bare list of its
      // properties with nothing ever asking again. Measured: that is what the
      // failing `apps.spec:180` snapshot shows, page chrome and a property list
      // where the app frame belongs, on a page that is demonstrably an app.
      //
      // So only the server gets to say "no ontology". One read settles it, and
      // it is a read this hook would not otherwise do.
      if (!fromServer) {
        return { ok: false, error: undefined };
      }

      return { ok: true, value: undefined, ontology: undefined };
    }

    const schema = await findSchema(store, drive, pluginSchema());

    if (isCancelled()) return { ok: false, error: undefined };

    return { ok: true, value: schema.classes?.[shortname], ontology };
  } catch (error) {
    return { ok: false, error };
  }
}

function useDriveClass(
  drive: string | undefined,
  shortname: 'plugin-script' | 'app',
): string | undefined {
  const store = useStore();
  const [pluginClass, setPluginClass] = useState<string>();

  useEffect(() => {
    if (!drive) {
      setPluginClass(undefined);

      return;
    }

    let cancelled = false;
    let unsubscribeOntology: (() => void) | undefined;
    let unsubscribeDrive: (() => void) | undefined;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let failures = 0;

    const resolve = async () => {
      const result = await resolveDriveClass(
        store,
        drive,
        shortname,
        () => cancelled,
        // The cache cannot answer differently than it did a moment ago, so
        // every pass after the first goes to the server.
        failures > 0,
      );

      if (cancelled) return;

      if (!result.ok) {
        failures += 1;

        if (failures === LOG_AFTER_PASSES && result.error !== undefined) {
          // Deliberately loud. A page that renders the wrong thing perfectly is
          // the worst failure to diagnose, and this one has cost CI runs. It
          // does not stop the retrying below.
          console.debug(
            `[plugins] still cannot resolve "${shortname}" for drive ${drive}; showing it as an ordinary resource meanwhile`,
            result.error,
          );
        }

        retry = setTimeout(
          () => void resolve().catch(() => undefined),
          retryDelayMs(failures),
        );

        return;
      }

      failures = 0;

      // A failed lookup leaves whatever was already resolved in place. It is
      // not evidence that the class is gone, and dropping it turns a working
      // page into a generic one.
      setPluginClass(result.value);

      // Re-resolve when the drive's ontology changes, so a drive that gains
      // plugin classes shows the action without a reload. Subscribed to the
      // ontology the pass above read, rather than reading the drive a second
      // time for it.
      if (result.ontology && !unsubscribeOntology) {
        unsubscribeOntology = store.subscribe(result.ontology, () => {
          void resolve().catch(() => undefined);
        });
      }

      // And to the drive itself, which is what changes when a drive gains its
      // first ontology. Without this, the settled "no plugin classes" above
      // would hold until the page is reloaded.
      if (!result.ontology && !unsubscribeDrive) {
        unsubscribeDrive = store.subscribe(drive, () => {
          void resolve().catch(() => undefined);
        });
      }
    };

    void resolve().catch(() => undefined);

    return () => {
      cancelled = true;
      clearTimeout(retry);
      unsubscribeOntology?.();
      unsubscribeDrive?.();
    };
  }, [store, drive, shortname]);

  return pluginClass;
}
