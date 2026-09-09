import type { Agent } from './agent.js';
import type { HeadersObject } from './client.js';
import { getTimestampNow } from './commit.js';

/** Returns a JSON-AD resource of an Authentication */
export async function createAuthentication(subject: string, agent: Agent) {
  const timestamp = getTimestampNow();

  if (!agent.subject) {
    throw new Error('Agent has no subject, cannot authenticate');
  }

  const object = {
    'https://atomicdata.dev/properties/auth/agent': agent.subject,
    'https://atomicdata.dev/properties/auth/requestedSubject': subject,
    'https://atomicdata.dev/properties/auth/publicKey':
      await agent.getPublicKey(),
    'https://atomicdata.dev/properties/auth/timestamp': timestamp,
    'https://atomicdata.dev/properties/auth/signature':
      await agent.createSignature(subject, timestamp),
  };

  return object;
}

/** Localhost Agents are not allowed to sign requests to external domain */
function localTryingExternal(subject: string, agent: Agent) {
  return (
    !subject.startsWith('http://localhost') &&
    agent?.subject?.startsWith('http://localhost')
  );
}

/**
 * Creates authentication headers and signs the request. Does not add headers if
 * the Agents subject is missing.
 */
export async function signRequest(
  /** The resource meant to be fetched */
  subject: string,
  agent: Agent,
  headers: HeadersObject,
): Promise<HeadersObject> {
  const timestamp = getTimestampNow();
  const newHeaders = { ...headers };

  if (agent?.subject && !localTryingExternal(subject, agent)) {
    newHeaders['x-atomic-public-key'] = await agent.getPublicKey();
    newHeaders['x-atomic-signature'] = await agent.createSignature(
      subject,
      timestamp,
    );
    newHeaders['x-atomic-timestamp'] = timestamp.toString();

    if (agent.subject) {
      newHeaders['x-atomic-agent'] = agent.subject;
    }
  }

  return newHeaders;
}

const ONE_DAY = 24 * 60 * 60 * 1000;

/**
 * Every parent domain a host-only cookie could have wrongly been scoped to.
 *
 * `staging.example.com` → `['staging.example.com', 'example.com']`. The TLD
 * itself is never included: browsers reject `Domain=com`, and attempting it
 * would only produce a no-op write.
 */
export function parentDomainsOf(hostname: string): string[] {
  const labels = hostname.split('.');
  const out: string[] = [];

  for (let i = 0; i < labels.length - 1; i++) {
    out.push(labels.slice(i).join('.'));
  }

  return out;
}

/**
 * An auth cookie is only ever valid for the exact server that signed it — its
 * `requestedSubject` is that server's URL — so it must not be sent anywhere
 * else.
 *
 * This used to set `Domain=<hostname>` explicitly, which does the opposite of
 * what it looks like: naming a domain *widens* a cookie to every subdomain.
 * A session minted on `example.com` was therefore sent to
 * `staging.example.com`, where the server rightly rejected it —
 * "Wrong requested subject in auth token, expected https://staging.example.com/…
 * was https://example.com" — and the user was locked out of a sibling
 * deployment by merely having visited the main one.
 *
 * Omitting `Domain` entirely makes the cookie host-only, which is what was
 * meant all along.
 */
const setCookieExpires = (
  name: string,
  value: string,
  serverUrl: string,
  expires_in_ms = ONE_DAY,
) => {
  const expiry = new Date(Date.now() + expires_in_ms).toUTCString();
  const encodedValue = encodeURIComponent(value);

  // `Secure` whenever the page is served over TLS, so the session never rides
  // along on a plain-http request to the same host. Omitted on http (local
  // dev), where a Secure cookie would simply never be stored.
  const secure =
    typeof window !== 'undefined' && window.location?.protocol === 'https:'
      ? ';Secure'
      : '';

  // No `Domain=`: host-only. See the note above.
  const cookieString = `${name}=${encodedValue};Expires=${expiry};SameSite=Lax;path=/${secure}`;
  document.cookie = cookieString;
};

/**
 * Deletes any copy of `name` that an older build scoped to a parent domain.
 *
 * Shipping the host-only fix is not enough on its own: browsers already hold
 * the over-broad cookie, and it keeps being sent to sibling hosts until it
 * expires. A parent-domain cookie can only be cleared by naming that same
 * domain, so walk them explicitly.
 */
const clearParentDomainCookies = (name: string) => {
  if (typeof document === 'undefined' || typeof location === 'undefined') {
    return;
  }

  // Includes the current hostname deliberately. A cookie written with
  // `Domain=example.com` is a *different* entry from the host-only cookie for
  // `example.com`, and on the apex host it is the very one doing the leaking —
  // skipping it would leave production still poisoning its own subdomains.
  // Deleting by domain does not touch the host-only cookie set alongside it.
  for (const domain of parentDomainsOf(location.hostname)) {
    document.cookie = `${name}=;Max-Age=-99999999;Domain=${domain};path=/`;
  }
};

const COOKIE_NAME_AUTH = 'atomic_session';

/** Sets a cookie for the current Agent, signing the Authentication. It expires after some default time. */
export const setCookieAuthentication = async (
  serverURL: string,
  agent: Agent,
): Promise<void> => {
  // Returns a promise so callers (e.g. the HTTP request signing path
  // in client.fetchResourceHTTP) can await the cookie before issuing
  // the request. Without an await, the first request after `setAgent`
  // race-conditions a 401: the cookie isn't installed yet because the
  // signing is async. The catch is per-caller — failures here are
  // surfaced via the request 401 if the cookie ever did matter.
  try {
    // Drop any parent-domain copy left by an older build first, so the
    // browser isn't left holding two `atomic_session` cookies — the stale
    // wide one would otherwise keep being sent alongside this one.
    clearParentDomainCookies(COOKIE_NAME_AUTH);
    const auth = await createAuthentication(serverURL, agent);
    setCookieExpires(COOKIE_NAME_AUTH, btoa(JSON.stringify(auth)), serverURL);
  } catch (e) {
    console.warn('[Auth] cookie installation failed:', e);
  }
};

/** Returns false if the auth cookie is not set / expired */
export const checkAuthenticationCookie = (): boolean => {
  const matches = document.cookie.match(
    /^(.*;)?\s*atomic_session\s*=\s*[^;]+(.*)?$/,
  );

  if (!matches) {
    return false;
  }

  return matches.length > 0;
};

export const removeCookieAuthentication = () => {
  document.cookie = `${COOKIE_NAME_AUTH}=;Max-Age=-99999999;path=/`;
  // Signing out must also clear the over-broad cookies older builds wrote,
  // otherwise a "signed out" browser keeps presenting one to sibling hosts.
  clearParentDomainCookies(COOKIE_NAME_AUTH);
};
