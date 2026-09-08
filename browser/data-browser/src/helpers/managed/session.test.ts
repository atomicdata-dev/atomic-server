import { expect, it, vi } from 'vitest';
const fetchMock = vi.hoisted(() => vi.fn());
const configured = vi.hoisted(() => vi.fn(() => true));
vi.mock('./api', () => ({
  managedFetch: fetchMock,
  hasManagedApi: configured,
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
});

it('does not call the SaaS logout endpoint on a FOSS server', async () => {
  configured.mockReturnValueOnce(false);
  fetchMock.mockClear();
  await logoutManagedSession();
  expect(fetchMock).not.toHaveBeenCalled();
});
