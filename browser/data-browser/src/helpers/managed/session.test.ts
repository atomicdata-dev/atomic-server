import { expect, it, vi } from 'vitest';
const fetchMock = vi.hoisted(() => vi.fn());
// Logout also drops the device token (and the portal it was issued by).
const setTokenMock = vi.hoisted(() => vi.fn());
vi.mock('./api', () => ({
  managedFetch: fetchMock,
  setManagedDeviceToken: setTokenMock,
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
