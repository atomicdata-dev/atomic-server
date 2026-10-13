/** What a drive is called when its resource has no name on this device. */
export const UNNAMED_DRIVE = 'Drive';

/**
 * A drive's name for display. A drive this device holds no copy of has no name
 * to read, and its subject (`atomic:W2Q3m…`, `did:ad:…`) is an identifier, not
 * something to put in a title bar or a switcher; a plain label reads better.
 * An ordinary http(s) subject is kept: that is a server's own address.
 */
export function driveDisplayName(
  name: string | undefined | null,
  subject: string,
): string {
  if (name) return name;

  return /^(atomic|did):/.test(subject) ? UNNAMED_DRIVE : subject;
}
