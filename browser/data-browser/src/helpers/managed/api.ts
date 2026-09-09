declare global {
  interface Window {
    __ATOMIC_MANAGED__?: { portalUrl?: string };
  }
}

export function getRuntimeManagedPortalUrl(): string | null {
  const value =
    typeof window === 'undefined'
      ? undefined
      : window.__ATOMIC_MANAGED__?.portalUrl;
  if (!value) return null;

  try {
    const url = new URL(value);

    return ['http:', 'https:'].includes(url.protocol) ? url.origin : null;
  } catch {
    return null;
  }
}

// [RECOVERY-RECONSTRUCTED] The original `helpers/managed/api.ts` was never captured
// in any Claude transcript (it predates the recovery window and isn't on the
// pushed `did` branch). Reconstructed from its call sites: every managed helper
// fetches `${getManagedApiBase()}/<endpoint>` against the control plane
// (routes are `/api/me`, `/api/logout`, `/api/sync-enrollments`,
// `/api/recovery-secret`). The dev portal URL mirrors `managedServer.ts`.
// VERIFY the production base against your real deployment.

import { isRunningInTauri } from '../tauri';

const PORTAL_URL_STORAGE_KEY = 'atomic-managed-portal-url';
/** The portal the device token was issued by. See {@link getLinkedPortalOrigin}. */
const LINKED_PORTAL_STORAGE_KEY = 'atomic-managed-portal-origin-linked';
const DEVICE_TOKEN_STORAGE_KEY = 'atomic-managed-device-token';

const trimTrailingSlashes = (url: string): string => url.replace(/\/+$/, '');

/**
 * A portal URL this app may open, navigate to, or send its bearer token to —
 * or undefined when it is not one.
 *
 * Only absolute `https:` URLs qualify, plus `http:` on `localhost` /
 * `127.0.0.1` for development. The value usually comes from a remote node's
 * `GET /server`, which is exactly the party that must not be able to point
 * "Sign in" at a phishing page or a `javascript:` URL. Trailing slashes are
 * trimmed so `${url}/api` composes cleanly.
 */
export function safePortalUrl(
  url: string | null | undefined,
): string | undefined {
  if (typeof url !== 'string') return undefined;

  const trimmed = url.trim();

  if (trimmed.length === 0) return undefined;

  let parsed: URL;

  try {
    parsed = new URL(trimmed);
  } catch {
    return undefined;
  }

  // Embedded credentials have no business in a portal address.
  if (parsed.username || parsed.password) return undefined;

  const isLocalhost =
    parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';

  if (
    parsed.protocol === 'https:' ||
    (parsed.protocol === 'http:' && isLocalhost)
  ) {
    return trimTrailingSlashes(trimmed);
  }

  return undefined;
}

function sameOrigin(a: string, b: string): boolean {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

let rememberedPortalUrl: string | null = null;

/**
 * Remember the control plane that a managed node pointed us at.
 *
 * The desktop app has no useful origin of its own — the webview serves it from
 * `tauri://localhost`, so neither a same-origin `/api` nor `window.location`
 * says anything about where the control plane lives. The only thing that does
 * is the `portalUrl` a managed node reports on `GET /server`; this stores it
 * for {@link getManagedApiBase}, persisted so a restart doesn't drop the
 * account before the first `/server` fetch comes back.
 *
 * A falsy URL is ignored rather than clearing the memory: the desktop shell
 * also asks its own embedded node, which is not managed and reports no portal.
 * That answer must not erase the real control plane.
 *
 * Two refusals, both logged: a URL that fails {@link safePortalUrl}, and — while
 * this device holds a token — any origin other than the one it was linked to.
 * Whatever node is connected right now does not get to redirect an existing
 * session; that portal stays until the device is unlinked.
 */
export function rememberManagedPortalUrl(url: string | null | undefined): void {
  if (!url) return;

  const safe = safePortalUrl(url);

  if (!safe) {
    console.warn('Ignoring portal URL that is not https:', url);

    return;
  }

  const linked = getLinkedPortalOrigin();

  if (linked && !sameOrigin(linked, safe)) {
    console.warn(
      `Ignoring portal ${safe}: this device is linked to ${linked}. Unlink it first to switch.`,
    );

    return;
  }

  rememberedPortalUrl = safe;

  try {
    localStorage.setItem(PORTAL_URL_STORAGE_KEY, rememberedPortalUrl);
  } catch {
    // Storage disabled (private mode) — the in-memory copy still serves this session.
  }
}

/**
 * The last control plane a managed node named, or null if none ever has.
 *
 * While a device token exists this is the portal that issued it, whatever any
 * node has said since — the same rule {@link getManagedApiBase} applies, so
 * the "Sign in" buttons and the bearer token always agree on where the account
 * lives.
 */
export function getRememberedManagedPortalUrl(): string | null {
  const linked = getLinkedPortalOrigin();

  if (linked) return linked;

  if (rememberedPortalUrl) return rememberedPortalUrl;

  try {
    const stored = localStorage.getItem(PORTAL_URL_STORAGE_KEY);

    // Written before `safePortalUrl` existed, so re-checked on the way out.
    if (stored) rememberedPortalUrl = safePortalUrl(stored) ?? null;
  } catch {
    // Storage disabled — nothing remembered.
  }

  return rememberedPortalUrl;
}

/**
 * The portal a build was compiled against, if any. Read here rather than via
 * `managedServer.ts`'s `managedPortalOverride()` because that module imports
 * this one.
 */
function portalFromEnv(): string | null {
  const fromEnv =
    typeof import.meta !== 'undefined'
      ? (import.meta.env?.VITE_MANAGED_PORTAL_URL as string | undefined)
      : undefined;

  return fromEnv ? trimTrailingSlashes(fromEnv) : null;
}

/**
 * Whether this install knows of a control plane at all. A FOSS or self-hosted
 * node has no SaaS session to end, and its origin answers `/api/logout` with a
 * 405 that the browser logs as an error. Ported from #1386.
 */
export function hasManagedApi(): boolean {
  return Boolean(
    getLinkedPortalOrigin() ||
    getRuntimeManagedPortalUrl() ||
    (typeof import.meta !== 'undefined' &&
      import.meta.env?.VITE_MANAGED_API_BASE) ||
    getRememberedManagedPortalUrl() ||
    portalFromEnv(),
  );
}

/** Base URL of the control-plane API (includes the `/api` prefix). */
export function getManagedApiBase(): string {
  // A linked device talks to the portal that issued its token and nothing
  // else. Checked before every other source, including the remembered portal:
  // that one is fed by whichever node happens to be connected, and a hostile
  // node must not be able to collect the bearer token by naming itself.
  const linked = getLinkedPortalOrigin();

  if (linked) return `${linked}/api`;

  const runtime = getRuntimeManagedPortalUrl();
  if (runtime) return `${runtime}/api`;

  const fromEnv =
    typeof import.meta !== 'undefined'
      ? (import.meta.env?.VITE_MANAGED_API_BASE as string | undefined)
      : undefined;

  if (fromEnv) return trimTrailingSlashes(fromEnv);

  // Checked BEFORE the localhost branch below, deliberately: the desktop
  // webview's origin is `tauri://localhost`, whose hostname is literally
  // `localhost`. Falling through would point every desktop build — shipped
  // ones included — at whatever happens to run on a dev machine's :3030.
  // There is no same-origin `/api` here either, so the real answers are the
  // control plane the connected managed node named, or the one the build was
  // compiled against (the store apps; see tauri-release.yml). Before either
  // (pure self-hosted, or nothing fetched yet) these fetches just fail, which
  // every caller already treats as "no control plane".
  if (isRunningInTauri()) {
    const portalUrl = getRememberedManagedPortalUrl() ?? portalFromEnv();

    return portalUrl ? `${portalUrl}/api` : '/api';
  }

  if (typeof window !== 'undefined') {
    const { hostname } = window.location;

    if (hostname === 'localhost' || hostname === '127.0.0.1') {
      // Local dev: the control-plane backend (`cargo run` binds
      // 0.0.0.0:3030 and serves /api/*; its CORS allows :6747/:49237/:6747).
      // The portal (:49237) is only the frontend and has no /api.
      return 'http://localhost:3030/api';
    }
  }

  // Same-origin deployment fallback.
  return '/api';
}

/**
 * The session a linked device holds, if this install has one.
 *
 * Browsers on our own origin never have this — they use the cookie, and the
 * control plane prefers it. This is for the clients that cannot: a self-hoster
 * on their own origin, and the desktop and Android apps on `tauri://localhost`.
 * See `planning/FOSS_LINK_TO_HOSTED.md` in atomic-saas.
 */
export function getManagedDeviceToken(): string | null {
  try {
    return localStorage.getItem(DEVICE_TOKEN_STORAGE_KEY);
  } catch {
    // Storage disabled (private mode). Nothing is linked, which is the honest
    // answer — a token we cannot persist would vanish on reload anyway.
    return null;
  }
}

/**
 * The portal the device token belongs to, or null when the device is not
 * linked. A token is only ever sent here — see {@link getManagedApiBase}.
 *
 * A token stored by a build that predates this record adopts the portal that
 * was remembered at the time, once: that is the portal it was linked against,
 * and adopting it before any node can overwrite the memory is what closes the
 * hole for existing installs.
 */
export function getLinkedPortalOrigin(): string | null {
  if (!getManagedDeviceToken()) return null;

  try {
    const stored = localStorage.getItem(LINKED_PORTAL_STORAGE_KEY);
    const safe = safePortalUrl(stored);

    if (safe) return safe;

    const legacy =
      safePortalUrl(rememberedPortalUrl) ??
      safePortalUrl(localStorage.getItem(PORTAL_URL_STORAGE_KEY));

    if (legacy) {
      localStorage.setItem(LINKED_PORTAL_STORAGE_KEY, legacy);
    }

    return legacy ?? null;
  } catch {
    return null;
  }
}

/**
 * Store (or clear, with `null`) the linked-device session.
 *
 * `linkedPortalUrl` is the portal that issued the token; it is recorded next
 * to the token and is the only place the token will ever be sent. Clearing
 * the token clears it too, so a later link to another provider starts clean.
 */
export function setManagedDeviceToken(
  token: string | null,
  linkedPortalUrl?: string,
): void {
  try {
    if (token) {
      localStorage.setItem(DEVICE_TOKEN_STORAGE_KEY, token);

      if (linkedPortalUrl !== undefined) {
        const safe = safePortalUrl(linkedPortalUrl);

        if (safe) {
          localStorage.setItem(LINKED_PORTAL_STORAGE_KEY, safe);
        } else {
          console.warn(
            'Not recording link origin: not https:',
            linkedPortalUrl,
          );
          localStorage.removeItem(LINKED_PORTAL_STORAGE_KEY);
        }
      }
    } else {
      localStorage.removeItem(DEVICE_TOKEN_STORAGE_KEY);
      localStorage.removeItem(LINKED_PORTAL_STORAGE_KEY);
    }
  } catch {
    // Same as above: unlinkable rather than broken.
  }
}

/**
 * Call the control plane.
 *
 * Every managed request goes through here so the linked-device token is
 * attached in exactly one place. Adding it at each call site instead would
 * work until someone adds an eleventh call site and forgets — and the symptom
 * would be one endpoint failing only on desktop and Android, which is close to
 * the worst bug to be handed.
 *
 * `credentials: 'include'` stays for the browser-on-our-origin case; the two
 * mechanisms coexist and the server prefers the cookie when both arrive.
 */
export async function managedFetch(
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const token = getManagedDeviceToken();
  const headers = new Headers(init.headers);

  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  return fetch(`${getManagedApiBase()}${path}`, {
    ...init,
    credentials: 'include',
    headers,
  });
}
