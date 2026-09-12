import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  resetViewTransitionQueue,
  wrapWithViewTransition,
} from './viewTransition';
import {
  getTransitionName,
  getTransitionStyle,
  PAGE_TITLE_TRANSITION_TAG,
  RESOURCE_PAGE_TRANSITION_TAG,
  transitionName,
} from './transitionName';

vi.mock('react-dom', () => ({
  flushSync: (fn: () => void) => fn(),
}));

describe('transitionName helpers', () => {
  it('emits a hashed name plus a view-transition-class for the tag', () => {
    const subject = 'did:ad:example';
    const name = getTransitionName(RESOURCE_PAGE_TRANSITION_TAG, subject);

    expect(transitionName(RESOURCE_PAGE_TRANSITION_TAG, subject)).toBe(
      `view-transition-name: ${name}; view-transition-class: ${RESOURCE_PAGE_TRANSITION_TAG}`,
    );
    expect(getTransitionStyle(PAGE_TITLE_TRANSITION_TAG, subject)).toEqual({
      viewTransitionName: getTransitionName(PAGE_TITLE_TRANSITION_TAG, subject),
      viewTransitionClass: PAGE_TITLE_TRANSITION_TAG,
    });
  });

  it('falls back when there is no subject', () => {
    expect(transitionName(RESOURCE_PAGE_TRANSITION_TAG, undefined)).toBe(
      'view-transition-name: none',
    );
    expect(getTransitionStyle(RESOURCE_PAGE_TRANSITION_TAG, undefined)).toEqual(
      {},
    );
  });
});

describe('wrapWithViewTransition', () => {
  beforeEach(() => {
    resetViewTransitionQueue();
    vi.useFakeTimers();
    vi.stubGlobal('navigator', { webdriver: false });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    resetViewTransitionQueue();
  });

  it('runs the callback directly when the API is missing', async () => {
    vi.stubGlobal('document', {});
    const cb = vi.fn(async () => undefined);
    const wrapped = wrapWithViewTransition(false, cb);

    await wrapped();

    expect(cb).toHaveBeenCalledOnce();
  });

  it('runs the callback directly when transitions are disabled', async () => {
    const startViewTransition = vi.fn();
    vi.stubGlobal('document', { startViewTransition });
    const cb = vi.fn(async () => undefined);
    const wrapped = wrapWithViewTransition(true, cb);

    await wrapped();

    expect(cb).toHaveBeenCalledOnce();
    expect(startViewTransition).not.toHaveBeenCalled();
  });

  it('still navigates when startViewTransition throws before the update', async () => {
    const startViewTransition = vi.fn(() => {
      throw new TypeError('Duplicate view-transition-name value');
    });
    vi.stubGlobal('document', { startViewTransition });
    const cb = vi.fn(async () => undefined);
    const wrapped = wrapWithViewTransition(false, cb);

    await wrapped();

    expect(cb).toHaveBeenCalledOnce();
  });

  it('does not navigate twice when the throw happens after the update started', async () => {
    const startViewTransition = vi.fn((update: () => void | Promise<void>) => {
      void update();
      throw new TypeError('Duplicate view-transition-name value');
    });
    vi.stubGlobal('document', { startViewTransition });
    const cb = vi.fn(async () => undefined);
    const wrapped = wrapWithViewTransition(false, cb);

    await wrapped();

    expect(cb).toHaveBeenCalledOnce();
  });

  it('skips a hung transition so the overlay cannot cover the page', async () => {
    const skipTransition = vi.fn();
    const startViewTransition = vi.fn((update: () => void | Promise<void>) => {
      void update();

      return {
        skipTransition,
        ready: Promise.resolve(),
        finished: new Promise(() => undefined),
        updateCallbackDone: Promise.resolve(),
      };
    });
    vi.stubGlobal('document', { startViewTransition });
    const cb = vi.fn(async () => undefined);
    const wrapped = wrapWithViewTransition(false, cb);

    const done = wrapped();
    await vi.advanceTimersByTimeAsync(1000);
    await done;

    expect(cb).toHaveBeenCalledOnce();
    expect(skipTransition).toHaveBeenCalledOnce();
  });

  it('skips when ready rejects (Firefox duplicate-name / IB-split)', async () => {
    const skipTransition = vi.fn();
    let rejectReady: (reason?: unknown) => void = () => undefined;
    let resolveFinished: () => void = () => undefined;
    const startViewTransition = vi.fn((update: () => void | Promise<void>) => {
      void update();

      return {
        skipTransition: () => {
          skipTransition();
          resolveFinished();
        },
        ready: new Promise<void>((_, reject) => {
          rejectReady = reject;
        }),
        finished: new Promise<void>(resolve => {
          resolveFinished = resolve;
        }),
        updateCallbackDone: Promise.resolve(),
      };
    });
    vi.stubGlobal('document', { startViewTransition });
    const cb = vi.fn(async () => undefined);
    const wrapped = wrapWithViewTransition(false, cb);

    const done = wrapped();
    await vi.waitFor(() => expect(startViewTransition).toHaveBeenCalledOnce());
    rejectReady(new Error('duplicate name'));
    await done;

    expect(cb).toHaveBeenCalledOnce();
    expect(skipTransition).toHaveBeenCalledOnce();
  });
});
