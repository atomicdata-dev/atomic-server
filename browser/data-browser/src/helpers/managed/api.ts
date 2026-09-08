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

const trimTrailingSlashes = (url: string): string => url.replace(/\/+$/, '');

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
 */
export function rememberManagedPortalUrl(url: string | null | undefined): void {
  if (!url) return;

  rememberedPortalUrl = trimTrailingSlashes(url);

  try {
    localStorage.setItem(PORTAL_URL_STORAGE_KEY, rememberedPortalUrl);
  } catch {
    // Storage disabled (private mode) — the in-memory copy still serves this session.
  }
}

/** The last control plane a managed node named, or null if none ever has. */
export function getRememberedManagedPortalUrl(): string | null {
  if (rememberedPortalUrl) return rememberedPortalUrl;

  try {
    const stored = localStorage.getItem(PORTAL_URL_STORAGE_KEY);

    if (stored) rememberedPortalUrl = trimTrailingSlashes(stored);
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

/** FOSS installations have no SaaS session to end. */
export function hasManagedApi(): boolean {
  return Boolean(
    getRuntimeManagedPortalUrl() ||
    getRememberedManagedPortalUrl() ||
    portalFromEnv() ||
    import.meta.env?.VITE_MANAGED_API_BASE,
  );
}

/** Base URL of the control-plane API (includes the `/api` prefix). */
export function getManagedApiBase(): string {
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

const DEVICE_TOKEN_STORAGE_KEY = 'atomic-managed-device-token';

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

export function setManagedDeviceToken(token: string | null): void {
  try {
    if (token) {
      localStorage.setItem(DEVICE_TOKEN_STORAGE_KEY, token);
    } else {
      localStorage.removeItem(DEVICE_TOKEN_STORAGE_KEY);
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
