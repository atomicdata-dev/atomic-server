import { flushSync } from 'react-dom';

/**
 * Serializes concurrent view transitions. Without this, back-to-back navigate
 * calls fire `document.startViewTransition()` while the previous transition
 * is still animating — Chrome cancels the older one and logs
 * "Skipped ViewTransition due to another transition starting" to the console.
 * We wait for the prior transition's `finished` promise before starting the
 * next one; failures still unblock the queue so a botched transition can't
 * wedge the UI.
 */
let activeTransition: Promise<void> = Promise.resolve();

const QUEUE_TIMEOUT_MS = 1000;

/** Headless drivers don't paint, so `finished` can hang forever. */
function isAutomated(): boolean {
  if (typeof navigator === 'undefined' || navigator.webdriver !== true) {
    return false;
  }

  try {
    // Escape hatch for debugging transitions under automation:
    // localStorage.setItem('forceViewTransitions', '1')
    return localStorage.getItem('forceViewTransitions') !== '1';
  } catch {
    return true;
  }
}

function swallow(promise: Promise<unknown> | undefined) {
  promise?.then(
    () => undefined,
    () => undefined,
  );
}

function skipQuietly(transition: ViewTransition) {
  try {
    transition.skipTransition();
  } catch {
    // Already skipped, finished, or the UA does not implement skip.
  }
}

/**
 * Wrap an async navigation so it runs inside `document.startViewTransition`
 * when the API exists and the user has not disabled animations.
 *
 * Firefox 144+ implements the API but is stricter than Chromium: duplicate
 * `view-transition-name`s (including false duplicates from inline/block
 * splits) reject `ready` / `updateCallbackDone`, and a hung `finished`
 * promise leaves the `::view-transition` overlay on top of the page. We
 * always run the navigation, skip a stuck overlay, and never leave those
 * promises unhandled.
 */
export function wrapWithViewTransition<Args extends unknown[]>(
  disabled: boolean,
  cb: (...args: Args) => Promise<void>,
): (...args: Args) => Promise<void> {
  if (
    disabled ||
    typeof document === 'undefined' ||
    !document.startViewTransition ||
    isAutomated()
  ) {
    return cb;
  }

  const wrapped = async (...args: Args) => {
    const previous = activeTransition;
    const gate = Promise.race([
      previous.then(
        () => undefined,
        () => undefined,
      ),
      new Promise<void>(resolve => setTimeout(resolve, QUEUE_TIMEOUT_MS)),
    ]);

    const next = gate.then(async () => {
      let updateStarted = false;

      try {
        const transition = document.startViewTransition!(
          () =>
            new Promise<void>((innerResolve, innerReject) => {
              updateStarted = true;
              flushSync(() => {
                cb(...args).then(innerResolve, innerReject);
              });
            }),
        );

        // Firefox creates these promises during error handling (duplicate
        // names, IB splits) even before we read them — attach catches
        // immediately so they are not unhandled rejections.
        // See https://bugzilla.mozilla.org/show_bug.cgi?id=1999336
        swallow(transition.updateCallbackDone);
        transition.ready.then(undefined, () => skipQuietly(transition));
        swallow(transition.finished);

        await Promise.race([
          transition.finished.then(
            () => undefined,
            () => undefined,
          ),
          new Promise<void>(resolve => {
            setTimeout(() => {
              skipQuietly(transition);
              resolve();
            }, QUEUE_TIMEOUT_MS);
          }),
        ]);
      } catch {
        // Synchronous throw from startViewTransition (Firefox reports some
        // capture errors this way). Still navigate if the update callback
        // never ran.
        if (!updateStarted) {
          await cb(...args);
        }
      }
    });

    activeTransition = next.then(
      () => undefined,
      () => undefined,
    );

    return next;
  };

  return wrapped;
}

/** Test-only: drop in-flight queue state between cases. */
export function resetViewTransitionQueue() {
  activeTransition = Promise.resolve();
}
