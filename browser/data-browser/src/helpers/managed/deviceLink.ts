import {
  getManagedApiBase,
  getManagedDeviceToken,
  getRememberedManagedPortalUrl,
  rememberManagedPortalUrl,
  safePortalUrl,
  setManagedDeviceToken,
} from './api';

/**
 * Linking this install to a hosted provider.
 *
 * A browser served from the provider's own site uses a cookie and never needs
 * any of this. Everything else does: a self-hoster's app on their own origin,
 * and the desktop and Android apps on `tauri://localhost`, are all a different
 * site and cannot hold one. They ask for a code, the user approves it somewhere
 * they are already signed in, and this collects a session to carry in a header.
 *
 * Nothing here names a provider. The URL comes from the caller, which is what
 * keeps a hosted product out of the open core — see
 * `FOSS_SELF_HOST_GUARDRAILS.md` in atomic-saas.
 */

export type LinkRequest = {
  device_code: string;
  user_code: string;
  expires_in: number;
  interval: number;
};

/** Where a link has got to, as far as this device can tell. */
export type LinkProgress =
  | { state: 'pending' }
  | { state: 'approved'; token: string }
  | { state: 'expired' };

/**
 * A name the approving user will recognise. Best-effort by design — it is a
 * label on a confirmation dialog, not an identifier, and a wrong guess costs
 * nothing beyond a vaguer prompt.
 */
export function describeThisDevice(): string {
  const ua = typeof navigator === 'undefined' ? '' : navigator.userAgent;

  const platform = /Android/i.test(ua)
    ? 'Android'
    : /iPhone|iPad|iPod/i.test(ua)
      ? 'iOS'
      : /Macintosh|Mac OS/i.test(ua)
        ? 'Mac'
        : /Windows/i.test(ua)
          ? 'Windows'
          : /Linux/i.test(ua)
            ? 'Linux'
            : 'This device';

  const browser = /Firefox\//.test(ua)
    ? 'Firefox'
    : /Edg\//.test(ua)
      ? 'Edge'
      : /Chrome\//.test(ua)
        ? 'Chrome'
        : /Safari\//.test(ua)
          ? 'Safari'
          : null;

  return browser ? `${platform} · ${browser}` : platform;
}

/** Ask a provider to start a link. Needs no credentials — that is the point. */
export async function requestDeviceLink(
  portalUrl: string,
  deviceName = describeThisDevice(),
): Promise<LinkRequest> {
  // The session this produces is only ever sent to `portalUrl`, so it has to
  // be an address a bearer token may travel to at all.
  if (!safePortalUrl(portalUrl)) {
    throw new Error('The provider address must start with https://');
  }

  const response = await fetch(`${apiBaseFor(portalUrl)}/device-link`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device_name: deviceName }),
  });

  if (!response.ok) {
    throw new Error(
      response.status === 429
        ? 'Too many attempts. Wait a minute and try again.'
        : 'Could not reach that provider. Check the address and try again.',
    );
  }

  return (await response.json()) as LinkRequest;
}

/**
 * Has it been approved yet?
 *
 * A 404 means expired, already collected, or never existed — the provider
 * refuses to distinguish those, so this reports the only thing a client can
 * act on: start again.
 */
export async function pollDeviceLink(
  portalUrl: string,
  deviceCode: string,
): Promise<LinkProgress> {
  const response = await fetch(
    `${apiBaseFor(portalUrl)}/device-link/${encodeURIComponent(deviceCode)}`,
  );

  if (response.status === 404) return { state: 'expired' };

  if (!response.ok) {
    throw new Error('Lost contact with that provider while waiting.');
  }

  const body = (await response.json()) as { state: string; token?: string };

  return body.state === 'approved' && body.token
    ? { state: 'approved', token: body.token }
    : { state: 'pending' };
}

/**
 * Wait for approval, then keep the session.
 *
 * Polls at the interval the provider asked for rather than one we picked, and
 * stops at the expiry it declared — a client that polls forever turns a code
 * the user abandoned into a permanent background request.
 */
export async function awaitDeviceLink(
  portalUrl: string,
  request: LinkRequest,
  { signal }: { signal?: AbortSignal } = {},
): Promise<'linked' | 'expired'> {
  const deadline = Date.now() + request.expires_in * 1000;
  const intervalMs = Math.max(1, request.interval) * 1000;

  while (Date.now() < deadline) {
    if (signal?.aborted) return 'expired';

    const progress = await pollDeviceLink(portalUrl, request.device_code);

    if (progress.state === 'approved') {
      // The token and the portal that issued it are recorded together: from
      // here on, this is the only origin the token goes to, whatever a later
      // connected node reports as its portal.
      setManagedDeviceToken(progress.token, portalUrl);
      rememberProvider(portalUrl);

      return 'linked';
    }

    if (progress.state === 'expired') return 'expired';

    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }

  return 'expired';
}

/** Forget the session. The provider still has it until it expires. */
export function unlinkDevice(): void {
  setManagedDeviceToken(null);
}

export function isDeviceLinked(): boolean {
  return getManagedDeviceToken() !== null;
}

/**
 * Can this client sign in to the provider the ordinary way — by holding its
 * session cookie?
 *
 * Only a page on the provider's own site can: the cookie is set for the
 * portal's registrable domain, which covers `app.` on the same domain and
 * nothing else. The desktop and Android apps live on `tauri://localhost`, a
 * self-hoster's app on their own origin; sending either to the portal's sign-in
 * page ends with a session in some browser and none in the app. Those link
 * instead — see {@link requestDeviceLink}.
 */
export function canHoldProviderCookie(portalUrl: string | null): boolean {
  if (!portalUrl) return false;

  if (typeof window === 'undefined') return false;

  if (!/^https?:$/.test(window.location.protocol)) return false;

  try {
    const portalHost = new URL(portalUrl).hostname;
    const here = window.location.hostname;

    return here === portalHost || here.endsWith(`.${portalHost}`);
  } catch {
    return false;
  }
}

/**
 * The provider this install linked to, so a later session knows where its token
 * is valid. Stored separately from the token: knowing the address is not the
 * same as being able to use it.
 *
 * Deliberately the *same* memory `getManagedApiBase()` reads. A provider we now
 * hold a session for is a control plane by any definition, and it is the only
 * one the desktop and Android apps ever learn — `tauri://localhost` has no
 * same-origin `/api`, and their embedded node is not managed and names no
 * portal. Keeping a second key here meant linking appeared to succeed while
 * every managed call afterwards resolved against `tauri.localhost/api` and
 * failed, which read as "no control plane" rather than as a bug.
 */
export function rememberProvider(portalUrl: string): void {
  rememberManagedPortalUrl(trimSlashes(portalUrl));
}

export function getRememberedProvider(): string | null {
  return getRememberedManagedPortalUrl();
}

/** Where the user approves. The provider owns this path; we only address it. */
export function approvalUrl(portalUrl: string, userCode: string): string {
  return `${trimSlashes(portalUrl)}/link?code=${encodeURIComponent(userCode)}`;
}

/**
 * A provider's API base.
 *
 * Uses `getManagedApiBase()` when the caller names the provider this build
 * already talks to, so the one place that knows about same-origin deployments
 * and the Tauri case stays in charge of it. Anything else is a URL the user
 * typed, and gets the documented `/api` suffix.
 */
function apiBaseFor(portalUrl: string): string {
  const base = getManagedApiBase();

  if (base.startsWith(trimSlashes(portalUrl))) return base;

  return `${trimSlashes(portalUrl)}/api`;
}

const trimSlashes = (url: string) => url.replace(/\/+$/, '');
