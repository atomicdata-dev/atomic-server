import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { startVisiblePolling } from './visiblePolling';
let doc: EventTarget & { visibilityState: string };
beforeEach(() => {
  vi.useFakeTimers();
  doc = Object.assign(new EventTarget(), { visibilityState: 'visible' });
  vi.stubGlobal('document', doc);
  vi.stubGlobal('window', new EventTarget());
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});
it('pauses hidden tabs and refreshes once when they become visible', async () => {
  const poll = vi.fn().mockResolvedValue(undefined);
  const stop = startVisiblePolling(poll, 5000);
  await vi.advanceTimersByTimeAsync(10000);
  expect(poll).toHaveBeenCalledTimes(3);
  doc.visibilityState = 'hidden';
  doc.dispatchEvent(new Event('visibilitychange'));
  window.dispatchEvent(new Event('focus'));
  await vi.advanceTimersByTimeAsync(60000);
  expect(poll).toHaveBeenCalledTimes(3);
  doc.visibilityState = 'visible';
  doc.dispatchEvent(new Event('visibilitychange'));
  await vi.advanceTimersByTimeAsync(0);
  expect(poll).toHaveBeenCalledTimes(4);
  stop();
  await vi.advanceTimersByTimeAsync(60000);
  window.dispatchEvent(new Event('online'));
  expect(poll).toHaveBeenCalledTimes(4);
});
it('does not overlap slow refreshes or restart after disposal', async () => {
  const pending = Promise.withResolvers<void>();
  const poll = vi.fn(() => pending.promise);
  const stop = startVisiblePolling(poll, 5000);
  await vi.advanceTimersByTimeAsync(20000);
  window.dispatchEvent(new Event('online'));
  expect(poll).toHaveBeenCalledTimes(1);
  stop();
  pending.resolve();
  await vi.advanceTimersByTimeAsync(20000);
  expect(poll).toHaveBeenCalledTimes(1);
});
it('retries a failed refresh', async () => {
  const poll = vi
    .fn()
    .mockRejectedValueOnce(new Error('offline'))
    .mockResolvedValue(undefined);
  const stop = startVisiblePolling(poll, 5000);
  await vi.advanceTimersByTimeAsync(5000);
  expect(poll).toHaveBeenCalledTimes(2);
  stop();
});
