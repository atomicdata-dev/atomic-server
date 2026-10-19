import type { Agent } from './agent.js';
import type { HeadersObject } from './client.js';
import { getTimestampNow } from './commit.js';
import { decodeB64, encodeB64 } from './base64.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from './value.js';
import { toLegacyScheme } from './subject.js';

/** The old identity is only used at the origin named by the imported secret. */
export function legacyAgentForRequest(
  url: string,
  agent: Agent,
): string | undefined {
  const legacy = agent.legacySubject;
  if (!legacy) return undefined;

  try {
    const target = new URL(url);
    const identity = new URL(legacy);

    return ['http:', 'https:'].includes(identity.protocol) &&
      target.origin === identity.origin
      ? legacy
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The agent subject as it goes into an auth proof: the `did:ad:agent:` spelling.
 *
 * A proof is sent before the server has said what it understands (the
 * capabilities arrive with `AUTH_OK`), and a node that predates the `atomic:`
 * scheme reads `atomic:agent:{key}` as an external URL and refuses it with
 * "hosted elsewhere". Servers accept both spellings forever and compare them
 * canonically; the signed message never includes the agent field.
 */
export function agentSubjectForAuth(agentSubject: string): string {
  return toLegacyScheme(agentSubject);
}

/**
 * Returns a JSON-AD resource of an Authentication.
 *
 * `options.agentSubject` overrides the spelling of the `auth/agent` field (the
 * default is {@link agentSubjectForAuth}). Browser peers pass the canonical
 * `agent.subject`: both ends are current, and the Rust peer session compares
 * the field to the pinned issuer and to ephemeral frames by string.
 */
export async function createAuthentication(
  subject: string,
  agent: Agent,
  options: { agentSubject?: string } = {},
) {
  const timestamp = getTimestampNow();

  if (!agent.subject) {
    throw new Error('Agent has no subject, cannot authenticate');
  }

  const object = {
    'https://atomicdata.dev/properties/auth/agent':
      options.agentSubject ?? agentSubjectForAuth(agent.subject),
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

/** The header that selects the request signature version. Absent is 1. */
export const SIGNATURE_VERSION_HEADER = 'x-atomic-signature-version';

/** A request body as `fetch` would send it, for hashing. */
export type SignableBody = string | Uint8Array | ArrayBuffer | undefined | null;

/** Lower-case hex SHA-256 of a request body; a string is hashed as UTF-8. */
export function sha256Hex(body: SignableBody): string {
  const bytes =
    body === undefined || body === null
      ? new Uint8Array()
      : typeof body === 'string'
        ? new TextEncoder().encode(body)
        : body instanceof Uint8Array
          ? body
          : new Uint8Array(body);

  return bytesToHex(sha256(bytes));
}

/**
 * The message a version 2 request signature signs (ontola/atomic-plugins#54):
 *
 * ```text
 * atomic-request-v2
 * {METHOD}
 * {full URL, including query}
 * {timestamp, Unix ms}
 * {sha-256 hex of the body}
 * ```
 *
 * Mirrors `request_signature_message_v2` in `lib/src/authentication.rs`;
 * `authentication_v2_vectors.json` pins the two together.
 */
export function requestSignatureMessageV2(
  method: string,
  url: string,
  timestamp: number,
  bodySha256Hex: string,
): string {
  return [
    'atomic-request-v2',
    method.toUpperCase(),
    url,
    timestamp.toString(),
    bodySha256Hex,
  ].join('\n');
}

/** Options that make {@link signRequest} produce a version 2 signature. */
export interface SignRequestOptions {
  /**
   * The HTTP method. Giving one selects version 2: the signature then also
   * covers the method and the SHA-256 of `body`, and
   * `x-atomic-signature-version: 2` is sent. Without it, version 1 as before.
   */
  method?: string;
  /** The exact body that will be sent. Omit for none. */
  body?: SignableBody;
  /**
   * `x-atomic-agent` to send instead of `agent.subject`, e.g. the
   * `atomic:agent:<pubkey>` form for a server that accepts no other.
   */
  agentSubject?: string;
  /** Original HTTP agent for a request to its own legacy server (v1 only). */
  legacySubject?: string;
  /** Signing time, Unix ms. Defaults to now. For tests. */
  timestamp?: number;
}

/**
 * Creates authentication headers and signs the request. Does not add headers if
 * the Agents subject is missing.
 *
 * Version 1 (the default) signs `"{url} {timestamp}"`, which is what cookies,
 * WebSocket `AUTH` and plain reads use. Passing `{ method, body }` signs
 * version 2 instead, which also covers the method and body so a captured
 * request cannot be replayed with a different body. For version 2, `subject`
 * must be the full URL the request goes to, query included; it is signed as
 * `new URL(subject).href`. Works with a non-extractable WebCrypto key: it only
 * ever asks the agent to sign.
 */
export async function signRequest(
  /** The resource meant to be fetched */
  subject: string,
  agent: Agent,
  headers: HeadersObject,
  /**
   * Original HTTP agent for a request to its own legacy server, or
   * {@link SignRequestOptions}.
   */
  legacySubjectOrOptions?: string | SignRequestOptions,
): Promise<HeadersObject> {
  const options: SignRequestOptions =
    typeof legacySubjectOrOptions === 'string'
      ? { legacySubject: legacySubjectOrOptions }
      : (legacySubjectOrOptions ?? {});
  const timestamp = options.timestamp ?? getTimestampNow();
  const newHeaders = { ...headers };
  const legacySubject = options.legacySubject;

  if (options.method !== undefined) {
    if (legacySubject) {
      throw new Error(
        'A version 2 request signature cannot use a legacy agent subject',
      );
    }

    const agentSubject = options.agentSubject ?? agent?.subject;

    if (!agentSubject) {
      throw new Error('Agent has no subject, cannot sign the request');
    }

    const url = new URL(subject).href;
    const message = requestSignatureMessageV2(
      options.method,
      url,
      timestamp,
      sha256Hex(options.body),
    );

    newHeaders['x-atomic-public-key'] = await agent.getPublicKey();
    newHeaders['x-atomic-signature'] = await agent.sign(message);
    newHeaders['x-atomic-timestamp'] = timestamp.toString();
    newHeaders['x-atomic-agent'] = agentSubject;
    newHeaders[SIGNATURE_VERSION_HEADER] = '2';

    return newHeaders;
  }

  if (agent?.subject && !localTryingExternal(subject, agent)) {
    newHeaders['x-atomic-public-key'] = await agent.getPublicKey();
    newHeaders['x-atomic-signature'] = await agent.createSignature(
      subject,
      timestamp,
    );
    newHeaders['x-atomic-timestamp'] = timestamp.toString();

    // Version 1 is what a node of any age understands; version 2 needs a
    // current server, which reads either spelling, so it keeps `atomic:`.
    newHeaders['x-atomic-agent'] =
      options.agentSubject ?? agentSubjectForAuth(agent.subject);

    if (legacySubject) {
      newHeaders['x-atomic-agent'] = legacySubject;
      // Old servers decode standard base64 and compare the public-key text
      // against the original Agent resource. DID-era base64url fails both.
      newHeaders['x-atomic-public-key'] = encodeB64(
        decodeB64(newHeaders['x-atomic-public-key']),
      );
      newHeaders['x-atomic-signature'] = encodeB64(
        decodeB64(newHeaders['x-atomic-signature']),
      );
    }
  }

  return newHeaders;
}

/**
 * How long a signed authentication proof stays valid, mirroring the server's
 * `AUTH_MAX_AGE_MS` in `lib/src/authentication.rs`. Before 0.41 a proof never
 * expired, so anything that stored one could keep presenting it; now anything
 * that stores one has to replace it before it ages out.
 */
export const AUTH_PROOF_MAX_AGE_MS = 5 * 60 * 1000;

/**
 * When a stored proof counts as due for replacement. Comfortably inside
 * {@link AUTH_PROOF_MAX_AGE_MS}, so a request that goes out just before the
 * refresh still reaches the server with minutes to spare.
 */
export const AUTH_PROOF_REFRESH_MS = 2 * 60 * 1000;

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
  expires_in_ms = AUTH_PROOF_MAX_AGE_MS,
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

const AUTH_TIMESTAMP_PROPERTY =
  'https://atomicdata.dev/properties/auth/timestamp';

/** The value of the auth cookie this browser holds, if it holds one. */
const readAuthCookie = (): string | undefined => {
  if (typeof document === 'undefined') {
    return undefined;
  }

  return document.cookie.match(
    new RegExp(`(?:^|;)\\s*${COOKIE_NAME_AUTH}\\s*=\\s*([^;]+)`),
  )?.[1];
};

/** When the proof inside a cookie value was signed, if it can be read. */
const proofSignedAt = (cookieValue: string): number | undefined => {
  try {
    const proof = JSON.parse(atob(decodeURIComponent(cookieValue)));
    const signedAt = proof?.[AUTH_TIMESTAMP_PROPERTY];

    return typeof signedAt === 'number' ? signedAt : undefined;
  } catch {
    // Not a cookie this library wrote, or not one it can still parse.
    return undefined;
  }
};

/**
 * Whether this browser holds an auth cookie the server will still accept.
 *
 * Presence alone is not enough, and treating it as enough is what produced
 * thousands of 401s a day on staging. The cookie carries a proof signed at the
 * moment it was installed, and since 0.41 the server refuses one older than
 * `AUTH_MAX_AGE_MS` (see {@link AUTH_PROOF_MAX_AGE_MS}). The cookie itself
 * outlived that by a wide margin, so a session went on presenting the same
 * dead proof for as long as the tab stayed open: one staging tab re-sent an
 * identical `signed at` timestamp every five seconds for hours, each time
 * answered with "Authentication timestamp rejected".
 *
 * Reporting an ageing proof as absent is what makes the request path
 * (`Client.fetchResourceHTTP`) sign and install a fresh one, well before the
 * server would refuse it.
 */
export const checkAuthenticationCookie = (): boolean => {
  const value = readAuthCookie();

  if (value === undefined) {
    return false;
  }

  const signedAt = proofSignedAt(value);

  // A proof whose age cannot be read is not one to keep presenting.
  if (signedAt === undefined) {
    return false;
  }

  // Both timestamps come from this device, so the difference is elapsed time
  // regardless of how wrong the device's clock is.
  return Date.now() - signedAt < AUTH_PROOF_REFRESH_MS;
};

export const removeCookieAuthentication = () => {
  document.cookie = `${COOKIE_NAME_AUTH}=;Max-Age=-99999999;path=/`;
  // Signing out must also clear the over-broad cookies older builds wrote,
  // otherwise a "signed out" browser keeps presenting one to sibling hosts.
  clearParentDomainCookies(COOKIE_NAME_AUTH);
};
