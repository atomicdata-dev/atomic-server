import { expect, it } from 'vitest';
import { inviteSignupUrl, resumeInviteUrl } from './inviteSignup';
import type { ManagedInfo } from './managedServer';

it('sends managed invitees to email signup and preserves the opaque token', () => {
  const url = new URL(
    inviteSignupUrl(
      {
        managed: true,
        portalUrl: 'https://staging.atomicserver.eu',
      } as ManagedInfo,
      'a+b/=',
    )!,
  );
  expect(url.origin + url.pathname).toBe(
    'https://staging.atomicserver.eu/signin',
  );
  expect(url.searchParams.get('invite')).toBe('a+b/=');
});
it('keeps self-hosted invitations local', () => {
  expect(
    inviteSignupUrl(
      { managed: false, acceptsNewDrives: false } as ManagedInfo,
      'token',
    ),
  ).toBeUndefined();
});
it('resumes at the local invite route, never an arbitrary destination', () => {
  expect(resumeInviteUrl('https://evil.example')).toBe(
    '/app/invite?token=https%3A%2F%2Fevil.example&accept=true',
  );
});
