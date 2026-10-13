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

it('carries the invitation node through email and another-browser recovery', () => {
  const signup = new URL(
    inviteSignupUrl(
      { managed: true, portalUrl: 'https://portal.example' } as ManagedInfo,
      'a+b/=',
      'https://team.example',
    )!,
  );
  const invitation = signup.searchParams.get('invite')!;
  const resumed = new URL(resumeInviteUrl(invitation), 'https://app.example');
  expect(resumed.origin).toBe('https://app.example');
  expect(resumed.pathname).toBe('/app/invite');
  expect(resumed.searchParams.get('token')).toBe('a+b/=');
  expect(resumed.searchParams.get('server')).toBe('https://team.example');
  expect(resumed.searchParams.has('accept')).toBe(false);
});
it('reads only the invitation token and node, ignoring redirect fields', () => {
  const resumed = new URL(
    resumeInviteUrl(
      'https://team.example/app/invite?token=abc&next=https://evil.example',
    ),
    'https://app.example',
  );
  expect(resumed.origin).toBe('https://app.example');
  expect(resumed.searchParams.get('server')).toBe('https://team.example');
  expect(resumed.searchParams.get('token')).toBe('abc');
  expect(resumed.searchParams.has('next')).toBe(false);
});
