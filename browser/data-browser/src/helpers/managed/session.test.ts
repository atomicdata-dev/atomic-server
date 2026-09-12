import { expect, it, vi } from 'vitest';
const fetchMock = vi.hoisted(() => vi.fn());
// Logout also drops the device token (and the portal it was issued by).
const setTokenMock = vi.hoisted(() => vi.fn());
const configured = vi.hoisted(() => vi.fn(() => true));
const portal = vi.hoisted(() => vi.fn(() => 'https://portal.example/api'));
const token = vi.hoisted(() => vi.fn(() => null as string | null));
vi.mock('./api', () => ({
  managedFetch: fetchMock,
  setManagedDeviceToken: setTokenMock,
  hasManagedApi: configured,
  getManagedApiBase: portal,
  getManagedDeviceToken: token,
}));
import { getManagedAccount, logoutManagedSession } from './session';
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

it('shares concurrent account reads but checks the next request freshly', async () => {
  fetchMock.mockClear();
  const pending = Promise.withResolvers<Response>();
  fetchMock.mockReturnValueOnce(pending.promise);
  const one = getManagedAccount();
  const two = getManagedAccount();
  expect(fetchMock).toHaveBeenCalledTimes(1);
  pending.resolve(Response.json({ email: 'first@example.com' }));
  expect(await one).toEqual(await two);
  fetchMock.mockResolvedValueOnce(
    Response.json({ email: 'second@example.com' }),
  );
  expect(await getManagedAccount()).toEqual({ email: 'second@example.com' });
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

it.each(['portal', 'token'])(
  'does not reuse an in-flight read after a %s change',
  async credential => {
    fetchMock.mockClear();
    const old = Promise.withResolvers<Response>();
    fetchMock.mockReturnValueOnce(old.promise);
    const first = getManagedAccount();
    if (credential === 'portal')
      portal.mockReturnValue('https://other.example/api');
    else token.mockReturnValue('new-device-session');
    fetchMock.mockResolvedValueOnce(
      Response.json({ email: 'new@example.com' }),
    );
    expect(await getManagedAccount()).toEqual({ email: 'new@example.com' });
    old.resolve(Response.json({ email: 'old@example.com' }));
    expect(await first).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    portal.mockReturnValue('https://portal.example/api');
    token.mockReturnValue(null);
  },
);
it('retries after a rejected account request', async () => {
  fetchMock.mockRejectedValueOnce(new Error('offline'));
  await expect(getManagedAccount()).rejects.toThrow('offline');
  fetchMock.mockResolvedValueOnce(
    Response.json({ email: 'online@example.com' }),
  );
  expect(await getManagedAccount()).toEqual({ email: 'online@example.com' });
});
