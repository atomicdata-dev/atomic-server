import { accountCreationTarget, type ManagedInfo } from './managedServer';

/** Carry only an invitation, never a caller-controlled redirect destination. */
export function inviteSignupUrl(
  info: ManagedInfo,
  token: string,
): string | undefined {
  const target = accountCreationTarget(info);
  if (target.kind !== 'portal') return;
  const url = new URL(target.url);
  url.searchParams.set('invite', token);

  return url.href;
}

export function resumeInviteUrl(token: string): string {
  return `/app/invite?${new URLSearchParams({ token, accept: 'true' })}`;
}
