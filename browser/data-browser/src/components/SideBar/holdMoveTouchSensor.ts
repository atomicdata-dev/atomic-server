import type {
  Activators,
  SensorInstance,
  SensorOptions,
  SensorProps,
} from '@dnd-kit/core';

interface Coordinates {
  x: number;
  y: number;
}

export interface HoldMoveTouchSensorOptions extends SensorOptions {
  /** How long the finger has to rest before the hold counts (ms). */
  holdDelay: number;
  /** Movement allowed before the hold, in px. More means a scroll: give up. */
  scrollTolerance: number;
  /** Movement after the hold that turns it into a drag, in px. */
  dragThreshold: number;
  /** The finger was held without moving and lifted: show the context menu. */
  onHold: (id: string, point: Coordinates) => void;
}

export type HoldMovePhase = 'pending' | 'armed' | 'dragging' | 'done';

const distance = (a: Coordinates, b: Coordinates) =>
  Math.hypot(a.x - b.x, a.y - b.y);

/**
 * What a finger movement means at a given phase of the gesture.
 *
 * - `pending` (finger down, hold not reached): small jitter is ignored, a real
 *   move is a scroll, so the gesture is abandoned and the browser scrolls.
 * - `armed` (held still long enough): small jitter is ignored, a real move
 *   starts the drag.
 */
export const classifyMove = (
  phase: HoldMovePhase,
  moved: number,
  { scrollTolerance, dragThreshold }: HoldMoveTouchSensorOptions,
): 'ignore' | 'cancel' | 'drag' => {
  if (phase === 'pending') {
    return moved > scrollTolerance ? 'cancel' : 'ignore';
  }

  if (phase === 'armed') {
    return moved > dragThreshold ? 'drag' : 'ignore';
  }

  return 'ignore';
};

const pointFromTouchEvent = (event: Event): Coordinates | undefined => {
  const { touches, changedTouches } = event as TouchEvent;
  const touch = touches?.[0] ?? changedTouches?.[0];

  return touch ? { x: touch.clientX, y: touch.clientY } : undefined;
};

/**
 * Touch sensor for the sidebar rows. A finger that rests on a row for
 * `holdDelay` arms it; then:
 *
 * - lifting without having moved calls `onHold` (the context menu), and the
 *   row is not navigated,
 * - moving past `dragThreshold` starts the drag.
 *
 * Moving before the hold ends the gesture without a drag, so a swipe still
 * scrolls the tree, and a quick tap is left alone so the link navigates.
 * dnd-kit's own TouchSensor can't do this: its delay constraint starts the
 * drag as soon as the delay elapses.
 */
export class HoldMoveTouchSensor implements SensorInstance {
  autoScrollEnabled = true;

  static activators: Activators<HoldMoveTouchSensorOptions> = [
    {
      eventName: 'onTouchStart',
      handler: ({ nativeEvent }: { nativeEvent: TouchEvent }) =>
        nativeEvent.touches.length <= 1,
    },
  ];

  phase: HoldMovePhase = 'pending';

  private readonly start: Coordinates;
  private readonly target: EventTarget;
  private readonly doc: Document;
  private readonly win: Window;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private readonly cleanups: Array<() => void> = [];

  constructor(private readonly props: SensorProps<HoldMoveTouchSensorOptions>) {
    const { event } = props;

    this.target = event.target ?? document;
    this.doc = (this.target as Node).ownerDocument ?? document;
    this.win = this.doc.defaultView ?? window;
    this.start = pointFromTouchEvent(event) ?? { x: 0, y: 0 };

    // Listen on the touched element itself: unlike the document it keeps
    // receiving touch events when the element is unmounted mid-gesture.
    this.listen(this.target, 'touchmove', this.handleMove, { passive: false });
    this.listen(this.target, 'touchend', this.handleEnd);
    this.listen(this.target, 'touchcancel', this.handleCancel);
    this.listen(this.win, 'resize', this.handleCancel);
    this.listen(this.win, 'visibilitychange', this.handleCancel);
    this.listen(this.doc, 'keydown', this.handleKeydown);
    // Android fires `contextmenu` on a long press and would open the menu
    // (and the native one) mid-hold. We open it ourselves on release.
    this.listen(this.win, 'contextmenu', this.suppress, { capture: true });
    this.listen(this.win, 'dragstart', this.suppress);

    this.timer = setTimeout(this.handleHold, props.options.holdDelay);
  }

  private listen(
    target: EventTarget,
    name: string,
    handler: (event: Event) => void,
    options?: AddEventListenerOptions,
  ) {
    target.addEventListener(name, handler, options);
    this.cleanups.push(() =>
      target.removeEventListener(name, handler, options),
    );
  }

  private detach() {
    clearTimeout(this.timer);
    this.timer = undefined;

    for (const cleanup of this.cleanups.splice(0)) {
      cleanup();
    }

    // Swallow the click a finished gesture may still synthesize.
    if (this.phase === 'armed' || this.phase === 'dragging') {
      // Only the browser's own tap: the menu opens through a scripted click.
      const stop = (e: Event) => {
        if (e.isTrusted) e.stopPropagation();
      };

      this.doc.addEventListener('click', stop, { capture: true });
      setTimeout(
        () => this.doc.removeEventListener('click', stop, { capture: true }),
        50,
      );
    }

    this.phase = 'done';
  }

  private suppress = (event: Event) => {
    if (event.cancelable) {
      event.preventDefault();
    }

    if (event.type === 'contextmenu') {
      event.stopImmediatePropagation();
    }
  };

  private handleHold = () => {
    if (this.phase !== 'pending') {
      return;
    }

    this.phase = 'armed';
    // A short buzz where supported, so the hold is felt before lifting.
    navigator.vibrate?.(10);
    this.doc.getSelection()?.removeAllRanges();
  };

  private handleMove = (event: Event) => {
    const point = pointFromTouchEvent(event);

    if (!point || this.phase === 'done') {
      return;
    }

    if (this.phase === 'dragging') {
      if (event.cancelable) event.preventDefault();

      this.props.onMove(point);

      return;
    }

    const verdict = classifyMove(
      this.phase,
      distance(this.start, point),
      this.props.options,
    );

    if (verdict === 'cancel') {
      this.handleCancel();

      return;
    }

    // Held still: the browser has not started scrolling, keep it that way.
    if (this.phase === 'armed' && event.cancelable) {
      event.preventDefault();
    }

    if (verdict === 'drag') {
      this.phase = 'dragging';
      this.doc.getSelection()?.removeAllRanges();
      this.props.onStart(this.start);
      this.props.onMove(point);
    }
  };

  private handleEnd = (event: Event) => {
    const wasArmed = this.phase === 'armed';
    const wasDragging = this.phase === 'dragging';

    // Cancelling touchend stops the browser from firing a click on the row.
    if ((wasArmed || wasDragging) && event.cancelable) {
      event.preventDefault();
    }

    this.detach();

    if (!wasDragging) {
      this.props.onAbort(this.props.active);
    }

    this.props.onEnd();

    if (wasArmed) {
      const point = pointFromTouchEvent(event) ?? this.start;

      this.props.options.onHold(String(this.props.active), point);
    }
  };

  private handleCancel = () => {
    const wasDragging = this.phase === 'dragging';

    this.detach();

    if (!wasDragging) {
      this.props.onAbort(this.props.active);
    }

    this.props.onCancel();
  };

  private handleKeydown = (event: Event) => {
    if ((event as KeyboardEvent).code === 'Escape') {
      this.handleCancel();
    }
  };
}
