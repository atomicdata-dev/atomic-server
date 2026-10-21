// @wc-ignore-file
/**
 * Full-screen overlays of the embed (the meeting chat) register here while they
 * are open, so the host's Back button (`atomicEmbed.back()`) dismisses the
 * topmost one before the page itself goes back.
 */
const closers: Array<() => void> = [];

/** Registers an open overlay; returns the function that unregisters it. */
export function registerOverlay(close: () => void): () => void {
  closers.push(close);

  return () => {
    const index = closers.lastIndexOf(close);

    if (index >= 0) closers.splice(index, 1);
  };
}

/** Closes the topmost overlay. False when none is open. */
export function closeTopOverlay(): boolean {
  const close = closers.pop();

  if (!close) return false;

  close();

  return true;
}
