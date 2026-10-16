// @wc-ignore-file
// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';

const fetchMock = vi.hoisted(() => vi.fn());
const setTokenMock = vi.hoisted(() => vi.fn());
vi.mock('./api', () => ({
  managedFetch: fetchMock,
  setManagedDeviceToken: setTokenMock,
  hasManagedApi: () => true,
  getManagedApiBase: () => 'https://atomic.place/api',
  getManagedDeviceToken: () => null,
}));
vi.mock('./recovery', () => ({ forgetCachedRecoverySecret: vi.fn() }));
vi.mock('../agentStorage', () => ({ saveAgentToIDB: vi.fn() }));

import { saveAgentToIDB } from '../agentStorage';
import { getManagedAccount } from './session';
import { signOutEverywhere } from './signOut';

afterEach(() => {
  vi.useRealTimers();
});

it('signs out within the deadline when /logout hangs, and keeps ignoring stale answers until it settles', async () => {
  vi.useFakeTimers();
  const logout = Promise.withResolvers<Response>();
  fetchMock.mockImplementation((path: string) =>
    path === '/logout'
      ? logout.promise
      : Promise.resolve(Response.json({ email: 'a@example.com' })),
  );

  let done = false;
  const signOut = signOutEverywhere().then(() => {
    done = true;
  });

  await vi.advanceTimersByTimeAsync(2900);
  expect(done).toBe(false);
  await vi.advanceTimersByTimeAsync(200);
  await signOut;
  expect(done).toBe(true);
  expect(saveAgentToIDB).toHaveBeenCalledWith(undefined);
  expect(setTokenMock).toHaveBeenCalledWith(null);

  // The request is still pending, so account lookups stay blocked.
  expect(await getManagedAccount()).toBeNull();
  logout.resolve(new Response(null, { status: 200 }));
  await vi.advanceTimersByTimeAsync(0);
  expect(await getManagedAccount()).not.toBeNull();
});
