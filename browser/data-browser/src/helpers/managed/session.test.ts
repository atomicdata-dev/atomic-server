// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
const fetchMock = vi.hoisted(() => vi.fn());
// Logout also drops the device token (and the portal it was issued by).
const setTokenMock = vi.hoisted(() => vi.fn());
const configured = vi.hoisted(() => vi.fn(() => true));
vi.mock('./api', () => ({
  managedFetch: fetchMock,
  setManagedDeviceToken: setTokenMock,
  hasManagedApi: configured,
  getManagedDeviceToken: () => null,
}));
import {
  getManagedAccount,
  logoutManagedSession,
  noteManagedSessionChanged,
  onManagedSessionChanged,
  SESSION_CACHE_TTL_MS,
} from './session';

beforeEach(() => {
  noteManagedSessionChanged();
});

afterEach(() => {
  vi.useRealTimers();
});

it('does not probe a hosted account when no managed API is configured', async () => {
  configured.mockReturnValueOnce(false);
  fetchMock.mockClear();
  fetchMock.mockResolvedValue(Response.json({ email: 'test@example.com' }));
  expect(await getManagedAccount()).toBeNull();
  expect(fetchMock).not.toHaveBeenCalled();
});

it('discards a session response that arrives after logout', async () => {
  const response = Promise.withResolvers<Response>();
  fetchMock.mockImplementation((path: string) =>
    path === '/me'
      ? response.promise
      : Promise.resolve(new Response(null, { status: 200 })),
  );
  const pendingAccount = getManagedAccount();
  await logoutManagedSession();
  response.resolve(Response.json({ email: 'test@example.com' }));
  expect(await pendingAccount).toBeNull();
  expect(setTokenMock).toHaveBeenCalledWith(null);
});

it('does not call the SaaS logout endpoint on a FOSS server', async () => {
  configured.mockReturnValueOnce(false);
  fetchMock.mockClear();
  setTokenMock.mockClear();
  await logoutManagedSession();
  expect(fetchMock).not.toHaveBeenCalled();
  // The local token still goes, so a stale link cannot outlive the sign-out.
  expect(setTokenMock).toHaveBeenCalledWith(null);
});

it('does not probe for an account without a configured control plane', async () => {
  configured.mockReturnValueOnce(false);
  fetchMock.mockClear();
  expect(await getManagedAccount()).toBeNull();
  expect(fetchMock).not.toHaveBeenCalled();
});

it('asks the account server once for callers asking at the same time', async () => {
  fetchMock.mockClear();
  fetchMock.mockImplementation(async () => new Response(null, { status: 204 }));

  const answers = await Promise.all([
    getManagedAccount(),
    getManagedAccount(),
    getManagedAccount(),
  ]);

  expect(answers).toEqual([null, null, null]);
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

it('serves a settled answer without asking again within the TTL', async () => {
  vi.useFakeTimers();
  fetchMock.mockClear();
  fetchMock.mockImplementation(async () => new Response(null, { status: 204 }));

  expect(await getManagedAccount()).toBeNull();
  expect(await getManagedAccount()).toBeNull();
  expect(fetchMock).toHaveBeenCalledTimes(1);

  vi.advanceTimersByTime(SESSION_CACHE_TTL_MS + 1);
  await getManagedAccount();
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

it('forgets the settled answer when the user returns to the tab', async () => {
  fetchMock.mockClear();
  fetchMock.mockImplementation(async () => new Response(null, { status: 204 }));

  await getManagedAccount();
  window.dispatchEvent(new Event('focus'));
  await getManagedAccount();
  expect(fetchMock).toHaveBeenCalledTimes(2);

  document.dispatchEvent(new Event('visibilitychange'));
  await getManagedAccount();
  expect(fetchMock).toHaveBeenCalledTimes(3);

  window.dispatchEvent(new Event('pageshow'));
  await getManagedAccount();
  expect(fetchMock).toHaveBeenCalledTimes(4);
});

it('skips the settled answer when asked for a fresh one', async () => {
  fetchMock.mockClear();
  fetchMock.mockImplementation(async () => new Response(null, { status: 204 }));

  await getManagedAccount();
  await getManagedAccount({ fresh: true });
  expect(fetchMock).toHaveBeenCalledTimes(2);

  // The fresh answer becomes the settled one.
  fetchMock.mockImplementation(async () => Response.json({ email: 'acct_1' }));
  expect(await getManagedAccount({ fresh: true })).toEqual({ email: 'acct_1' });
  expect(await getManagedAccount()).toEqual({ email: 'acct_1' });
  expect(fetchMock).toHaveBeenCalledTimes(3);
});

it('asks again after a sign-in is announced, and tells listeners', async () => {
  fetchMock.mockClear();
  fetchMock.mockImplementation(async () => new Response(null, { status: 204 }));
  const listener = vi.fn();
  const off = onManagedSessionChanged(listener);

  expect(await getManagedAccount()).toBeNull();
  fetchMock.mockImplementation(async () => Response.json({ email: 'acct_1' }));
  noteManagedSessionChanged();
  expect(listener).toHaveBeenCalledTimes(1);
  expect(await getManagedAccount()).toEqual({ email: 'acct_1' });
  expect(fetchMock).toHaveBeenCalledTimes(2);
  off();
});

it('does not keep a settled answer across logout', async () => {
  fetchMock.mockClear();
  fetchMock.mockImplementation(async (path: string) =>
    path === '/me'
      ? Response.json({ email: 'acct_1' })
      : new Response(null, { status: 200 }),
  );

  await getManagedAccount();
  await logoutManagedSession();
  fetchMock.mockImplementation(async () => new Response(null, { status: 204 }));
  expect(await getManagedAccount()).toBeNull();
});

it('does not cache a rejected fetch', async () => {
  fetchMock.mockClear();
  fetchMock.mockRejectedValueOnce(new TypeError('network down'));
  await expect(getManagedAccount()).rejects.toThrow('network down');

  fetchMock.mockResolvedValueOnce(Response.json({ email: 'test@example.com' }));
  expect(await getManagedAccount()).toEqual({ email: 'test@example.com' });
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

it('does not cache a 5xx answer', async () => {
  fetchMock.mockClear();
  fetchMock.mockResolvedValueOnce(new Response(null, { status: 503 }));
  await expect(getManagedAccount()).rejects.toThrow();

  fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));
  expect(await getManagedAccount()).toBeNull();
  expect(fetchMock).toHaveBeenCalledTimes(2);
});
