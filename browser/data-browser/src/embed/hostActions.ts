import type { NativeChannel } from '@tomic/lib';

let host: NativeChannel | undefined;

/** The channel to the app the page runs in (not set outside the app). */
export function setActionsHost(channel: NativeChannel | undefined) {
  host = channel;
}

/** What the app can show natively instead of the page. */
export type NativeKind = 'chatroom';

/**
 * Asks the app to open `subject` in its own native screen of that kind (the
 * chat of a meeting or chat room). Resolves true when the app did, false when
 * it has no such screen, does not know the call (an older app, the desktop
 * mock) or there is no app: then the page shows the resource itself.
 */
export async function openNative(
  kind: NativeKind,
  subject: string,
  title = '',
): Promise<boolean> {
  if (!host) return false;

  try {
    return (await host.call('openNative', [kind, subject, title])) === true;
  } catch {
    return false;
  }
}
