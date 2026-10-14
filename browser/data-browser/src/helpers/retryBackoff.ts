/**
 * The backoff shared by every "a failed read must be asked again" loop
 * (`useDriveClass`, `useWebsiteClass`, `useIntegrationVisibility`,
 * `WebsitePage`). A page that gave up on one read stays wrong until someone
 * reloads it, so these keep asking for as long as they are mounted.
 *
 * Only the delay lives here: each loop differs in what a failure means (an
 * error state, a cleared timer, a first pass from the cache), so each keeps its
 * own counter and timer.
 */

/** A failed read backs off to at most this while recovery is still likely. */
const RETRY_CEILING_MS = 5_000;
/**
 * And to this once it is not, so a resource that cannot be read at all does
 * not have every open page polling the server every five seconds.
 */
const SLOW_CEILING_MS = 60_000;
/** After this many failed passes, recovery is no longer the likely case. */
const SLOW_AFTER_PASSES = 10;

/** How many failed passes before the give-up trace, which does not stop it. */
export const LOG_AFTER_PASSES = 3;

/** Delay before retry number `failures` (1 for the first failed pass). */
export function retryDelayMs(failures: number): number {
  return Math.min(
    150 * 2 ** (failures - 1),
    failures > SLOW_AFTER_PASSES ? SLOW_CEILING_MS : RETRY_CEILING_MS,
  );
}
