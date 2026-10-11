// @wc-ignore-file
import { describe, expect, it, vi } from 'vitest';
import { hostDriveOnPortal, shouldOfferPortalHosting } from './hostOnPortal';

const base = {
  portalUrl: 'https://portal.example',
  serverExplicitlyChosen: false,
  serverManaged: false,
  enrolled: false,
};

describe('shouldOfferPortalHosting', () => {
  it('offers hosting for an unhosted drive when a portal is known', () => {
    expect(shouldOfferPortalHosting(base)).toBe(true);
  });

  it.each([
    ['no portal is known', { portalUrl: null }],
    ['the person chose their own server', { serverExplicitlyChosen: true }],
    ['the server in use is managed', { serverManaged: true }],
    ['the drive is already enrolled', { enrolled: true }],
  ])('stays away when %s', (_, change) => {
    expect(shouldOfferPortalHosting({ ...base, ...change })).toBe(false);
  });
});

describe('hostDriveOnPortal', () => {
  const args = {
    drive: 'did:ad:drive',
    agentSubject: 'did:ad:agent:a',
    hostingConsentAccepted: true,
  } as unknown as Parameters<typeof hostDriveOnPortal>[0];
  const hosted = { ok: true, httpOrigin: 'https://n1', replicated: false };
  const noAccount = {
    ok: false,
    reason: 'no-account',
    portalUrl: 'https://portal.example',
  };

  it('hosts straight away when signed in', async () => {
    const enable = vi.fn().mockResolvedValue(hosted);
    const ensureSession = vi.fn();

    expect(await hostDriveOnPortal(args, { enable, ensureSession })).toEqual({
      status: 'hosted',
      httpOrigin: 'https://n1',
      replicated: false,
    });
    expect(ensureSession).not.toHaveBeenCalled();
  });

  it('runs the portal sign-in, then retries', async () => {
    const enable = vi
      .fn()
      .mockResolvedValueOnce(noAccount)
      .mockResolvedValueOnce(hosted);
    const ensureSession = vi.fn().mockResolvedValue(true);
    const outcome = await hostDriveOnPortal(args, { enable, ensureSession });

    expect(ensureSession).toHaveBeenCalledWith('https://portal.example');
    expect(enable).toHaveBeenCalledTimes(2);
    expect(outcome.status).toBe('hosted');
  });

  it('reports a cancelled sign-in without retrying', async () => {
    const enable = vi.fn().mockResolvedValue(noAccount);
    const ensureSession = vi.fn().mockResolvedValue(false);

    expect(await hostDriveOnPortal(args, { enable, ensureSession })).toEqual({
      status: 'cancelled',
    });
    expect(enable).toHaveBeenCalledTimes(1);
  });

  it('says so when there is no portal to sign in to', async () => {
    const enable = vi.fn().mockResolvedValue({ ...noAccount, portalUrl: null });
    const ensureSession = vi.fn();

    expect(await hostDriveOnPortal(args, { enable, ensureSession })).toEqual({
      status: 'no-portal',
    });
    expect(ensureSession).not.toHaveBeenCalled();
  });
});
