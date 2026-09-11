import { afterEach, describe, expect, it, vi } from 'vitest';
import { ScheduledSave } from './scheduled-save.js';

describe('scheduled save ownership', () => {
  afterEach(() => vi.useRealTimers());

  it('coalesces timers, balances cancellation once, and flushes on owner disposal', async () => {
    vi.useFakeTimers();
    let pending = 0;
    const save = vi.fn(async () => undefined);
    const owner = new ScheduledSave(
      save,
      n => {
        pending += n;
      },
      () => undefined,
    );
    owner.schedule(100);
    owner.schedule(100);
    expect(pending).toBe(1);
    owner.cancel();
    owner.cancel();
    await vi.runAllTimersAsync();
    expect(pending).toBe(0);
    expect(save).not.toHaveBeenCalled();
    owner.schedule(100);
    await owner.flush();
    expect(save).toHaveBeenCalledTimes(1);
    expect(pending).toBe(0);
  });

  it('allows a synchronous subscriber to cancel newly scheduled work', async () => {
    vi.useFakeTimers();
    let pending = 0;
    const save = vi.fn(async () => undefined);
    const owner = new ScheduledSave(
      save,
      delta => {
        pending += delta;
        if (delta === 1) owner.cancel();
      },
      () => undefined,
    );
    owner.schedule(10);
    expect(pending).toBe(0);
    await vi.runAllTimersAsync();
    expect(save).not.toHaveBeenCalled();
  });

  it('keeps an in-flight save counted when a later edit is cancelled', async () => {
    vi.useFakeTimers();
    let finish!: () => void;
    let pending = 0;
    const owner = new ScheduledSave(
      () =>
        new Promise<void>(r => {
          finish = r;
        }),
      n => {
        pending += n;
      },
      () => undefined,
    );
    owner.schedule(10);
    await vi.advanceTimersByTimeAsync(10);
    owner.schedule(10);
    expect(pending).toBe(2);
    owner.cancel();
    expect(pending).toBe(1);
    const flushed = owner.flush();
    finish();
    await flushed;
    expect(pending).toBe(0);
  });

  it('releases accounting and reports failed saves', async () => {
    vi.useFakeTimers();
    let pending = 0;
    const onError = vi.fn();
    const owner = new ScheduledSave(
      async () => {
        throw new Error('offline persistence failed');
      },
      n => {
        pending += n;
      },
      onError,
    );
    owner.schedule(10);
    await owner.flush();
    expect(pending).toBe(0);
    expect(onError).toHaveBeenCalledOnce();
  });
});
