import { afterEach, expect, it, vi } from 'vitest';
import { openNative, setActionsHost } from './hostActions';

afterEach(() => setActionsHost(undefined));

it('is false without an app', async () => {
  expect(await openNative('chatroom', 'did:ad:room')).toBe(false);
});

it('asks the app and reports its answer', async () => {
  const call = vi.fn().mockResolvedValue(true);

  setActionsHost({ call });
  expect(await openNative('chatroom', 'did:ad:room', 'Standup')).toBe(true);
  expect(call).toHaveBeenCalledWith('openNative', [
    'chatroom',
    'did:ad:room',
    'Standup',
  ]);
});

it('is false when the app declines or does not know the call', async () => {
  setActionsHost({ call: vi.fn().mockResolvedValue(false) });
  expect(await openNative('chatroom', 'did:ad:room')).toBe(false);

  setActionsHost({ call: vi.fn().mockRejectedValue(new Error('unknown')) });
  expect(await openNative('chatroom', 'did:ad:room')).toBe(false);
});
