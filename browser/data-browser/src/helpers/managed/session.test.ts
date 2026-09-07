import { expect, it, vi } from 'vitest';
const fetchMock = vi.hoisted(() => vi.fn());
vi.mock('./api', () => ({ managedFetch: fetchMock }));
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
