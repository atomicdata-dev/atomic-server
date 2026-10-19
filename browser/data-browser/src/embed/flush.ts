import { StoreEvents, type Store } from '@tomic/react';

/** How long a flush waits for the last edits to be handed to the host. */
export const FLUSH_CAP_MS = 3000;

interface FlushOptions {
  /** The page is going away: end any edit in progress first (blur). */
  leaving?: boolean;
}

/**
 * Makes every edit in the page reach the host before the page goes away.
 *
 * Edits leave the page on their own a little later: a field's value waits in
 * a debounce timer (`useValue`), a document's typing in the outbox's drain.
 * Closing the page (back, swipe back, the app going to the background) kills
 * those timers, and the edit with them. A flush runs them now and resolves
 * once the store has nothing left to hand over (`pendingDirtyCount === 0`),
 * or after {@link FLUSH_CAP_MS}, so leaving can never hang on it.
 */
export function createFlush(
  store: Store,
  db: { flush(): Promise<void> },
): (options?: FlushOptions) => Promise<void> {
  const settled = () => store.getSyncStatus().pendingDirtyCount === 0;

  const untilSettled = () =>
    new Promise<void>(resolve => {
      if (settled()) return resolve();

      const off = store.on(StoreEvents.SyncStatusChanged, () => {
        if (!settled()) return;

        off();
        resolve();
      });
    });

  const run = async ({ leaving = false }: FlushOptions) => {
    if (leaving) {
      // An input that saves on blur (a title being renamed) saves now.
      const active = document.activeElement;

      if (active instanceof HTMLElement && active !== document.body) {
        active.blur();
      }

      // Blur handlers schedule their saves; let them.
      await new Promise(resolve => setTimeout(resolve, 0));
    }

    await store.flushScheduledSaves();
    await store.syncDirtyResources();
    await untilSettled();
    await db.flush();
  };

  return options =>
    new Promise<void>(resolve => {
      const cap = setTimeout(() => {
        console.warn(
          '[embed] flush capped: edits still pending',
          store.getSyncStatus().pendingDirtyCount,
        );
        resolve();
      }, FLUSH_CAP_MS);

      run(options ?? {})
        .catch(e => console.warn('[embed] flush failed', e))
        .finally(() => {
          clearTimeout(cap);
          resolve();
        });
    });
}
