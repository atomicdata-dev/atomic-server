// @vitest-environment jsdom
// @wc-ignore-file
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, renderHook } from '@testing-library/react';
import type { Resource } from '@tomic/react';
import { useCreateInviteLink } from './useCreateInviteLink';

const mocks = vi.hoisted(() => ({
  account: vi.fn(),
  fetch: vi.fn(),
  info: vi.fn(),
  prepare: vi.fn(),
  route: vi.fn(),
  token: vi.fn(),
}));
vi.mock('@tomic/react', () => ({
  server: { classes: { drive: 'Drive' } },
  useCurrentAgent: () => [{ subject: 'atomic:agent:test' }],
  useStore: () => ({
    isLocalOnlyDrive: () => false,
    getServerUrlForSubject: mocks.route,
  }),
}));
vi.mock('@tomic/lib', () => ({ generateInviteToken: mocks.token }));
vi.mock('../../helpers/managed/session', () => ({
  getManagedAccount: mocks.account,
}));
vi.mock('../../helpers/managed/api', () => ({ managedFetch: mocks.fetch }));
vi.mock('../../helpers/managedServer', () => ({
  fetchManagedInfo: mocks.info,
}));
vi.mock('../../helpers/managed/prepareDriveSharing', () => ({
  prepareDriveSharing: mocks.prepare,
}));
vi.mock('../../helpers/managed/cloudSync', () => ({
  getManagedPortalUrl: () => 'https://account.example',
}));
vi.mock('../../helpers/browserPeerSync', () => ({}));
vi.mock('../../helpers/originNode', () => ({
  isOriginWithoutNode: () => false,
}));

const target = {
  subject: 'atomic:drive',
  hasClasses: () => true,
} as unknown as Resource;
beforeEach(() => {
  mocks.route.mockReturnValue('https://tenant.example');
  mocks.token.mockResolvedValue('signed-invite');
});
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});

it('shares a self-hosted drive without asking the configured portal for an account', async () => {
  mocks.info.mockResolvedValue({ managed: false });
  const { result } = renderHook(() => useCreateInviteLink(target));
  const link = await result.current({ write: false });
  expect(mocks.route).toHaveBeenCalledWith(target.subject);
  expect(mocks.info).toHaveBeenCalledWith('https://tenant.example');
  expect(mocks.account).not.toHaveBeenCalled();
  expect(mocks.fetch).not.toHaveBeenCalled();
  expect(link).toContain('server=https%3A%2F%2Ftenant.example');
});

it('requires an account before querying managed drive enrollments', async () => {
  mocks.info.mockResolvedValue({ managed: true });
  mocks.account.mockResolvedValue(null);
  const { result } = renderHook(() => useCreateInviteLink(target));
  await expect(result.current({ write: true })).rejects.toThrow(
    'Sign in to your portal account',
  );
  expect(mocks.fetch).not.toHaveBeenCalled();
  expect(mocks.token).not.toHaveBeenCalled();
});

it('checks enrollment before signing an invite to the owning managed node', async () => {
  mocks.info.mockResolvedValue({ managed: true });
  mocks.account.mockResolvedValue({ email: 'test@example.com' });
  mocks.fetch.mockResolvedValue(Response.json([]));
  mocks.prepare.mockResolvedValue(false);
  const { result } = renderHook(() => useCreateInviteLink(target));
  await result.current({ write: true });
  expect(mocks.prepare).toHaveBeenCalledWith(
    expect.anything(),
    target.subject,
    [],
  );
  expect(mocks.token).toHaveBeenCalled();
});
