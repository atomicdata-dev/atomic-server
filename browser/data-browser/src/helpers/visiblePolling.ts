/** One refresh at a time, only while visible. Resume promptly after focus/online. */
export function startVisiblePolling(
  poll: () => Promise<unknown>,
  intervalMs: number,
): () => void {
  let stopped = false;
  let running = false;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const clear = () => {
    clearTimeout(timer);
    timer = undefined;
  };

  const isVisible = () => document.visibilityState !== 'hidden';

  const refresh = async () => {
    if (stopped || running || !isVisible()) return;
    clear();
    running = true;

    try {
      await poll();
    } catch {
      // A failed refresh must not disable retries. The caller owns error UI.
    } finally {
      running = false;
      if (!stopped && isVisible()) timer = setTimeout(refresh, intervalMs);
    }
  };

  const visibility = () => {
    clear();
    void refresh();
  };

  document.addEventListener('visibilitychange', visibility);
  window.addEventListener('focus', refresh);
  window.addEventListener('online', refresh);
  void refresh();

  return () => {
    stopped = true;
    clear();
    document.removeEventListener('visibilitychange', visibility);
    window.removeEventListener('focus', refresh);
    window.removeEventListener('online', refresh);
  };
}
