import { useEffect, useState } from 'react';
import { LOG_AFTER_PASSES, retryDelayMs } from '@helpers/retryBackoff';
import { core, useStore, type Store } from '@tomic/react';

/**
 * One pass over the resource's own declared classes, looking for `shortname`.
 *
 * A read that FAILED and a class that is genuinely absent are different
 * answers, and this is where they are kept apart: `{ ok: false }` means nobody
 * knows yet, `{ ok: true, value: undefined }` means every class was read and
 * none of them is the one. `store.getResource` rejects on a cancelled request
 * and after its own 10s settle timeout, which a loaded machine reaches.
 *
 * `fromServer` is what makes asking again worth anything. `getResource`
 * answers from the store's cache, and it returns a resource that once failed
 * as-is: `if (found.isReady() || found.error) return found`. So a second
 * `getResource` after a failed read hands back the very same error, for as
 * long as the tab is open, and a resource left stuck on `loading` costs
 * another 10s settle timeout each time. A retry has to go back to the source.
 *
 * Outside the hook so the React compiler does not have to reason about a
 * try/catch inside a component.
 */
async function readWebsiteClass(
  store: Store,
  classes: string[],
  shortname: string,
  isCancelled: () => boolean,
  fromServer: boolean,
): Promise<
  { ok: true; value: string | undefined } | { ok: false; error: unknown }
> {
  let failed: unknown;

  for (const id of classes) {
    try {
      const resource = fromServer
        ? await store.fetchResourceFromServer(id)
        : await store.getResource(id);

      if (isCancelled()) return { ok: false, error: undefined };

      if (resource.error) {
        failed = resource.error;
        continue;
      }

      if (resource.get(core.properties.shortname) === shortname) {
        return { ok: true, value: id };
      }
    } catch (error) {
      if (isCancelled()) return { ok: false, error };

      failed = error;
    }
  }

  // Every class was read and none of them is the one being looked for. That is
  // a real answer; most resources are not websites.
  if (failed === undefined) return { ok: true, value: undefined };

  return { ok: false, error: failed };
}

/** Inspect the resource's declared classes, not every term in the drive ontology. */
export function useWebsiteClass(
  classKey: string,
  shortname = 'website-project',
) {
  const store = useStore();
  const [resolved, setResolved] = useState<{ key: string; subject?: string }>();
  useEffect(() => {
    let active = true;
    let failures = 0;
    let retry: ReturnType<typeof setTimeout> | undefined;
    const classes = classKey.split('|').filter(Boolean);

    const resolve = async () => {
      clearTimeout(retry);
      retry = undefined;

      const result = await readWebsiteClass(
        store,
        classes,
        shortname,
        () => !active,
        failures > 0,
      );

      if (!active) return;

      // A failed lookup leaves whatever was already resolved in place. It is
      // not evidence that the class is gone, and dropping it turns a working
      // page into a generic one.
      if (!result.ok) {
        failures += 1;

        if (failures === LOG_AFTER_PASSES) {
          // `debug` rather than `error`: a page that renders the wrong thing
          // perfectly is the worst failure to diagnose, so this has to leave a
          // trace, but the e2e diagnostics collector polices every warning and
          // error with no allowlist, and the identical `console.error` in
          // `useDriveClass` is an open red there.
          console.debug(
            `[website] still cannot resolve "${shortname}" among ${classes.join(
              ', ',
            )}; showing the resource as an ordinary one meanwhile`,
            result.error,
          );
        }

        // Keep asking, for as long as this stays mounted. A fixed few attempts
        // is not enough: each read can take its own 10s timeout, so three of
        // them are spent inside half a minute of load, and after that nothing
        // else ever asks, because the class resource does not change and so
        // the subscription below never fires. The page then renders a website
        // as a bare list of its properties until someone reloads it: that is
        // what `website.spec:10` catches, with the class itself rendered as a
        // raw subject because nothing in the app could read it either.
        retry = setTimeout(
          () => void resolve().catch(() => undefined),
          retryDelayMs(failures),
        );

        return;
      }

      failures = 0;

      setResolved(previous => {
        // A class's shortname does not change. So a later read of the same
        // classes that no longer sees it read something momentarily
        // incomplete, and is not news. Dropping the answer would render a
        // different component at `WebsitePage`'s position, which unmounts it
        // and loses its state, inline editing included; `ResourcePage`
        // already guards its loading branch for that reason.
        if (previous?.key === classKey && previous.subject && !result.value) {
          return previous;
        }

        return { key: classKey, subject: result.value };
      });
    };

    const unsubscribes = classes.map(id =>
      store.subscribe(id, () => {
        void resolve().catch(() => undefined);
      }),
    );
    void resolve().catch(() => undefined);

    return () => {
      active = false;
      clearTimeout(retry);
      unsubscribes.forEach(unsubscribe => unsubscribe());
    };
  }, [store, classKey, shortname]);

  return resolved?.key === classKey ? resolved.subject : undefined;
}
