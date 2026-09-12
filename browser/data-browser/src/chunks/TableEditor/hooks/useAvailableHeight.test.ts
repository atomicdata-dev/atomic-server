import { afterEach, expect, it, vi } from 'vitest';
import { useAvailableHeight } from './useAvailableHeight';

const lifecycle = vi.hoisted(() => ({
  cleanup: undefined as (() => void) | undefined,
}));
vi.mock('react', () => ({
  useLayoutEffect: (effect: () => () => void) => {
    lifecycle.cleanup = effect();
  },
}));

afterEach(() => {
  lifecycle.cleanup?.();
  vi.unstubAllGlobals();
});

it('defers and coalesces observed layout writes, then cancels them on unmount', () => {
  let notifyResize!: () => void;
  let frame: FrameRequestCallback | undefined;
  vi.stubGlobal(
    'ResizeObserver',
    class {
      constructor(callback: () => void) {
        notifyResize = callback;
      }
      observe() {}
      disconnect() {}
    },
  );
  vi.stubGlobal(
    'MutationObserver',
    class {
      observe() {}
      disconnect() {}
    },
  );
  const requestFrame = vi.fn((callback: FrameRequestCallback) => {
    frame = callback;

    return 1;
  });
  const cancelFrame = vi.fn();
  vi.stubGlobal('requestAnimationFrame', requestFrame);
  vi.stubGlobal('cancelAnimationFrame', cancelFrame);
  vi.stubGlobal('getComputedStyle', () => ({
    overflowY: 'auto',
    borderTopWidth: '0',
    borderBottomWidth: '0',
  }));
  let height = '';
  const setProperty = vi.fn((_name: string, value: string) => {
    height = value;
  });
  const parent = {
    scrollHeight: 800,
    clientHeight: 800,
    scrollTop: 0,
    children: [],
    getBoundingClientRect: () => ({ top: 0 }),
  };
  const table = {
    parentElement: parent,
    getBoundingClientRect: () => ({ top: 100 }),
    style: { getPropertyValue: () => height, setProperty },
  } as unknown as HTMLDivElement;
  useAvailableHeight({ current: table }, { current: null });
  expect(height).toBe('684px');
  setProperty.mockClear();

  parent.clientHeight = 600;
  notifyResize();
  notifyResize();
  // ResizeObserver delivers before paint. Writing an observed ancestor here
  // triggers Chromium's "undelivered notifications" loop diagnostic.
  expect(setProperty).not.toHaveBeenCalled();
  expect(requestFrame).toHaveBeenCalledTimes(1);
  frame!(0);
  expect(height).toBe('484px');

  notifyResize();
  lifecycle.cleanup?.();
  lifecycle.cleanup = undefined;
  expect(cancelFrame).toHaveBeenCalledWith(1);
});
