const RELOADED_KEY = 'atomic.staleChunkReloaded';

/**
 * Whether this tab already reloaded for a stale chunk. sessionStorage is a
 * per-viewer convenience: when it is unavailable we answer "yes", so a broken
 * storage can never turn a missing chunk into a reload loop.
 */
function claimReload(storage: () => Storage = () => sessionStorage): boolean {
  try {
    const s = storage();

    if (s.getItem(RELOADED_KEY)) return false;
    s.setItem(RELOADED_KEY, '1');

    return true;
  } catch {
    return false;
  }
}

/**
 * A tab that stays open across a deploy asks for a chunk the new build no
 * longer ships, and Vite raises `vite:preloadError`. Reload once per session
 * to pick up the new build. A second failure falls through, so a real outage
 * still shows up.
 */
export function handleStaleChunk(
  event: Pick<Event, 'preventDefault'>,
  reload: () => void = () => window.location.reload(),
  storage?: () => Storage,
): void {
  if (!claimReload(storage)) return;

  event.preventDefault();
  reload();
}

export function reloadOnStaleChunk(): void {
  window.addEventListener('vite:preloadError', event =>
    handleStaleChunk(event),
  );
}
