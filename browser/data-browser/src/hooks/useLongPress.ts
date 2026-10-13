import { useCallback, useRef } from 'react';

const LONG_PRESS_MS = 500;
const MOVE_TOLERANCE = 8;
const CLICK_SETTLE_MS = 50;

/**
 * Fires `onLongPress` with the press point when a touch or pen is held still
 * and then released.
 * Mouse right-click is left to `onContextMenu`. Spread the returned handlers on
 * the element. `consumeClick()` is true once after a long press so the click
 * that follows the release can be ignored.
 */
export function useLongPress(
  onLongPress: (point: { x: number; y: number }) => void,
) {
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const start = useRef({ x: 0, y: 0 });
  const fired = useRef(false);

  const cancel = useCallback(() => clearTimeout(timer.current), []);

  const onPointerDown = useCallback(
    (e: React.PointerEvent) => {
      if (e.pointerType === 'mouse') return;
      fired.current = false;
      start.current = { x: e.clientX, y: e.clientY };
      cancel();
      timer.current = setTimeout(() => {
        fired.current = true;
        navigator.vibrate?.(10);
      }, LONG_PRESS_MS);
    },
    [cancel],
  );

  // Opens on release, after the click that follows it: an open menu would
  // otherwise count that click as one outside itself and close again.
  const onPointerUp = useCallback(() => {
    cancel();

    if (fired.current) {
      const point = start.current;
      setTimeout(() => onLongPress(point), CLICK_SETTLE_MS);
    }
  }, [cancel, onLongPress]);

  const onPointerMove = useCallback(
    (e: React.PointerEvent) => {
      if (
        Math.hypot(e.clientX - start.current.x, e.clientY - start.current.y) >
        MOVE_TOLERANCE
      ) {
        cancel();
      }
    },
    [cancel],
  );

  const consumeClick = useCallback(() => {
    const was = fired.current;
    fired.current = false;

    return was;
  }, []);

  return {
    handlers: {
      onPointerDown,
      onPointerMove,
      onPointerUp,
      onPointerCancel: cancel,
    },
    consumeClick,
  };
}
