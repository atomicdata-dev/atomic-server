// @wc-ignore-file
import { beforeEach, expect, it, vi } from 'vitest';
import { cameFromPortal, portalReturnUrl, signOutEverywhere } from './signOut';
import { getManagedApiBase, hasManagedApi } from './api';
import { logoutManagedSession } from './session';
import { forgetCachedRecoverySecret } from './recovery';
import { saveAgentToIDB } from '../agentStorage';

vi.mock('./api', () => ({
  getManagedApiBase: vi.fn(),
  hasManagedApi: vi.fn(),
}));
vi.mock('./session', () => ({ logoutManagedSession: vi.fn() }));
vi.mock('./recovery', () => ({ forgetCachedRecoverySecret: vi.fn() }));
vi.mock('../agentStorage', () => ({ saveAgentToIDB: vi.fn() }));

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(hasManagedApi).mockReturnValue(true);
  vi.mocked(getManagedApiBase).mockReturnValue('https://atomic.place/api');
});

it('ends the account session before the key leaves the device', async () => {
  const order: string[] = [];
  vi.mocked(logoutManagedSession).mockImplementation(async () => {
    order.push('account');
  });
  vi.mocked(saveAgentToIDB).mockImplementation(async () => {
    order.push('key');
  });

  await signOutEverywhere({ agentSubject: 'did:ad:agent:a', forget: true });

  expect(order).toEqual(['account', 'key']);
  expect(forgetCachedRecoverySecret).toHaveBeenCalledWith('did:ad:agent:a');
});

it('keeps the cached backup unless asked to forget it', async () => {
  await signOutEverywhere({ agentSubject: 'did:ad:agent:a' });

  expect(forgetCachedRecoverySecret).not.toHaveBeenCalled();
});

it('returns only to the portal it came from', () => {
  expect(portalReturnUrl('https://atomic.place/signin')).toBe(
    'https://atomic.place/signin',
  );
  expect(portalReturnUrl('https://evil.example/signin')).toBeUndefined();
  expect(portalReturnUrl('javascript:alert(1)')).toBeUndefined();
  expect(portalReturnUrl(undefined)).toBeUndefined();

  vi.mocked(hasManagedApi).mockReturnValue(false);
  expect(portalReturnUrl('https://atomic.place/signin')).toBeUndefined();
});

it('signs out without asking only when the portal sent the person here', () => {
  expect(cameFromPortal('https://atomic.place/dashboard')).toBe(true);
  expect(cameFromPortal('https://evil.example/')).toBe(false);
  expect(cameFromPortal('')).toBe(false);
});
