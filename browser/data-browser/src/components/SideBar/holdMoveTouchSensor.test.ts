// @vitest-environment jsdom
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type Mock,
} from 'vitest';
import type { SensorProps } from '@dnd-kit/core';
import {
  HoldMoveTouchSensor,
  classifyMove,
  type HoldMoveTouchSensorOptions,
} from './holdMoveTouchSensor';

const opts = (onHold = vi.fn()): HoldMoveTouchSensorOptions => ({
  holdDelay: 400,
  scrollTolerance: 8,
  dragThreshold: 8,
  onHold,
});

describe('classifyMove', () => {
  it('treats a move before the hold as a scroll', () => {
    expect(classifyMove('pending', 3, opts())).toBe('ignore');
    expect(classifyMove('pending', 12, opts())).toBe('cancel');
  });

  it('starts the drag when moving after the hold', () => {
    expect(classifyMove('armed', 3, opts())).toBe('ignore');
    expect(classifyMove('armed', 12, opts())).toBe('drag');
  });
});

const touch = (type: string, x: number, y: number, target: EventTarget) => {
  const event = new Event(type, { bubbles: true, cancelable: true });
  const t = { clientX: x, clientY: y };

  Object.assign(event, {
    touches: type === 'touchend' ? [] : [t],
    changedTouches: [t],
  });
  target.dispatchEvent(event);

  return event;
};

describe('HoldMoveTouchSensor', () => {
  let el: HTMLElement;
  let onHold: Mock<HoldMoveTouchSensorOptions['onHold']>;
  let props: SensorProps<HoldMoveTouchSensorOptions>;

  beforeEach(() => {
    vi.useFakeTimers();
    el = document.createElement('a');
    document.body.append(el);
    onHold = vi.fn();
    const start = new Event('touchstart');

    Object.assign(start, { touches: [{ clientX: 10, clientY: 10 }] });
    Object.defineProperty(start, 'target', { value: el });
    props = {
      active: 'did:ad:x',
      event: start,
      options: opts(onHold),
      onStart: vi.fn(),
      onMove: vi.fn(),
      onEnd: vi.fn(),
      onCancel: vi.fn(),
      onAbort: vi.fn(),
      onPending: vi.fn(),
    } as unknown as SensorProps<HoldMoveTouchSensorOptions>;
  });

  afterEach(() => {
    vi.useRealTimers();
    el.remove();
  });

  it('leaves a quick tap alone', () => {
    new HoldMoveTouchSensor(props);
    vi.advanceTimersByTime(100);
    const end = touch('touchend', 10, 10, el);

    expect(end.defaultPrevented).toBe(false);
    expect(onHold).not.toHaveBeenCalled();
    expect(props.onStart).not.toHaveBeenCalled();
    expect(props.onAbort).toHaveBeenCalled();
  });

  it('gives up on a swipe before the hold, so the tree scrolls', () => {
    new HoldMoveTouchSensor(props);
    vi.advanceTimersByTime(100);
    const move = touch('touchmove', 10, 40, el);

    expect(move.defaultPrevented).toBe(false);
    expect(props.onCancel).toHaveBeenCalled();
    vi.advanceTimersByTime(1000);
    touch('touchend', 10, 40, el);
    expect(props.onStart).not.toHaveBeenCalled();
    expect(onHold).not.toHaveBeenCalled();
  });

  it('opens the menu when held still and lifted, without a click', () => {
    new HoldMoveTouchSensor(props);
    vi.advanceTimersByTime(450);
    touch('touchmove', 12, 11, el);
    const end = touch('touchend', 12, 11, el);

    expect(end.defaultPrevented).toBe(true);
    expect(onHold).toHaveBeenCalledWith('did:ad:x', { x: 12, y: 11 });
    expect(props.onStart).not.toHaveBeenCalled();
  });

  it('starts a drag when moving after the hold, and no menu', () => {
    new HoldMoveTouchSensor(props);
    vi.advanceTimersByTime(450);
    touch('touchmove', 10, 40, el);

    expect(props.onStart).toHaveBeenCalledWith({ x: 10, y: 10 });
    expect(props.onMove).toHaveBeenCalledWith({ x: 10, y: 40 });
    touch('touchend', 10, 40, el);
    expect(onHold).not.toHaveBeenCalled();
    expect(props.onEnd).toHaveBeenCalled();
  });

  it('swallows the native long-press contextmenu', () => {
    new HoldMoveTouchSensor(props);
    vi.advanceTimersByTime(450);
    const menu = touch('contextmenu', 10, 10, el);

    expect(menu.defaultPrevented).toBe(true);
  });
});
