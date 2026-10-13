import { accountCreationTarget, type ManagedInfo } from './managedServer';

/** Carry the invitation node through the portal's opaque invitation field. */
export function inviteSignupUrl(
  info: ManagedInfo,
  token: string,
  serverOrigin?: string,
): string | undefined {
  const target = accountCreationTarget(info);
  if (target.kind !== 'portal') return;
  const url = new URL(target.url);
  // A token names the drive and grant, but not the node holding it. Keeping
  // both in the email link also works when it opens on another browser.
  const invitation = serverOrigin
    ? new URL(`/app/invite?${new URLSearchParams({ token })}`, serverOrigin)
        .href
    : token;
  url.searchParams.set('invite', invitation);

  return url.href;
}

export function resumeInviteUrl(invitation: string): string {
  const params = new URLSearchParams({ token: invitation, accept: 'true' });

  try {
    const url = new URL(invitation);
    const token = url.searchParams.get('token');

    if (
      (url.protocol === 'https:' || url.protocol === 'http:') &&
      url.pathname === '/app/invite' &&
      !url.username &&
      !url.password &&
      token
    ) {
      params.set('token', token);
      params.set('server', url.origin);
      // The destination is untrusted input. The invite route confirms an
      // unfamiliar server, then the user reviews and accepts the invitation.
      params.delete('accept');
    }
  } catch {
    // Older links contain only the opaque signed token.
  }

  // Always open our own invite screen; never navigate to a supplied URL.
  return `/app/invite?${params}`;
}
