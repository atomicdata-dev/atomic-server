import { useEffect } from 'react';

/**
 * How the page wants the app's swipe-back gesture handled.
 * 'default': the app's edge strip is active. 'horizontal': the page uses
 * horizontal drags itself (canvas, wide tables), so the strip is only a thin
 * sliver at the screen edge.
 */
export type EmbedGestures = 'default' | 'horizontal';

const claims: EmbedGestures[] = [];
/** A touch is on something that needs horizontal drags (until it ends). */
let touching = false;
let sent: EmbedGestures = 'default';

type Channel = { postMessage(message: string): void };

function channel(): Channel | undefined {
  return typeof window === 'undefined' ? undefined : window.AtomicFlutter;
}

function current(): EmbedGestures {
  return touching || claims.includes('horizontal') ? 'horizontal' : 'default';
}

function publish() {
  const mode = current();

  if (mode === sent) return;

  sent = mode;
  channel()?.postMessage(JSON.stringify({ method: 'gestures', mode }));
}

/** Declares the gesture needs of the view that is shown; returns the release. */
export function claimGestures(mode: EmbedGestures): () => void {
  claims.push(mode);
  publish();

  return () => {
    const index = claims.lastIndexOf(mode);

    if (index >= 0) claims.splice(index, 1);

    publish();
  };
}

/** `window.atomicEmbed.setGestures`: the page (or the host) sets the mode. */
export function setGestures(mode: EmbedGestures) {
  claims.length = 0;
  touching = false;

  if (mode === 'horizontal') claims.push(mode);

  publish();
}

/**
 * Declare that this view needs horizontal drags while mounted. A no-op outside
 * the app's web view.
 */
export function useEmbedGestures(mode: EmbedGestures) {
  useEffect(() => {
    if (!channel()) return;

    return claimGestures(mode);
  }, [mode]);
}

const GESTURE_SELECTOR = [
  'canvas',
  '[data-gesture-surface]',
  '[data-no-swipe-back]',
  'input[type="range"]',
  '.cm-editor',
  '.maplibregl-map',
  '.leaflet-container',
  '.excalidraw',
  '.tldraw',
  '[contenteditable]:not([contenteditable="false"])',
  'table',
].join(',');

/** Whether a touch that starts on [target] belongs to the page. */
export function needsHorizontalDrag(target: EventTarget | null): boolean {
  if (!(target instanceof Element)) return false;

  if (target.closest(GESTURE_SELECTOR)) return true;

  for (let el: Element | null = target; el; el = el.parentElement) {
    if (el.scrollWidth <= el.clientWidth) continue;

    const overflow = getComputedStyle(el).overflowX;

    if (overflow === 'auto' || overflow === 'scroll') return true;
  }

  return false;
}

/**
 * Tells the app, at touchstart, when the touch is on something that needs
 * horizontal drags, so it leaves the swipe back alone for that touch (the
 * message is there before the finger has moved). 'default' again at the end.
 * Only in the app's web view.
 */
export function installTouchGestures(): void {
  if (!channel()) return;

  const end = () => {
    touching = false;
    publish();
  };

  document.addEventListener(
    'touchstart',
    e => {
      touching = e.touches.length > 1 || needsHorizontalDrag(e.target);
      publish();
    },
    { capture: true, passive: true },
  );
  document.addEventListener('touchend', end, { capture: true, passive: true });
  document.addEventListener('touchcancel', end, {
    capture: true,
    passive: true,
  });
}

/** @internal for tests */
export function resetGesturesForTest() {
  claims.length = 0;
  touching = false;
  sent = 'default';
}
