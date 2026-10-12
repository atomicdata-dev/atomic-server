import {
  errorMessageFromResponse,
  signRequest,
  type Store,
} from '@tomic/react';

/**
 * The person's side of approving an MCP client at a node's OAuth
 * authorization endpoint (`/oauth/authorize`, see planning/mcp-endpoint.md).
 * Both calls are signed as the person, like any write. The node never signs
 * as them: it only mints an identity for the client, and what that identity
 * may reach is what the person grants it here.
 */

/** The origin of a URL, or undefined when it is not an http(s) URL. */
function originOf(value: string): string | undefined {
  try {
    const url = new URL(value);

    return url.protocol === 'https:' || url.protocol === 'http:'
      ? url.origin
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Whether `server` is a node the person is already using: one of
 * `trustedOrigins` (the app's own origin, the node the app talks to, the
 * node their drive lives on). The consent link comes from outside, so
 * anything else is refused. Otherwise a crafted link would make the app sign
 * requests for, and give read access to, whatever host the link names.
 */
export function isTrustedServer(
  server: string,
  trustedOrigins: Array<string | undefined>,
): boolean {
  const origin = originOf(server);

  return (
    origin !== undefined &&
    trustedOrigins.some(trusted => trusted && originOf(trusted) === origin)
  );
}

/**
 * The URL to send the browser back to, only if it is the `redirect_uri` the
 * page was opened with, plus `code`, `state`, `iss`, `error` and
 * `error_description`. The node's answer is not trusted: a `javascript:` URL
 * or another host would run in, or leak from, the app.
 */
export function safeRedirect(redirectUrl: string, redirectUri: string): string {
  let target: URL;
  let expected: URL;

  try {
    target = new URL(redirectUrl);
    expected = new URL(redirectUri);
  } catch {
    throw new Error('The node sent back a redirect that is not a URL.');
  }

  const isLoopback =
    expected.hostname === 'localhost' ||
    expected.hostname === '127.0.0.1' ||
    expected.hostname === '[::1]';
  const blocked = ['javascript:', 'data:', 'vbscript:', 'file:', 'blob:'];
  // https, http only on this machine, or a native app's own scheme.
  const schemeOk =
    !blocked.includes(expected.protocol) &&
    (expected.protocol !== 'http:' || isLoopback);

  const sameBase =
    target.protocol === expected.protocol &&
    target.host === expected.host &&
    target.pathname === expected.pathname &&
    target.username === '' &&
    target.password === '';

  if (!schemeOk || !sameBase) {
    throw new Error(
      'The node sent back a redirect that does not match the app you are connecting. Nothing was shared beyond what you picked.',
    );
  }

  const allowed = new Set([
    'code',
    'state',
    'iss',
    'error',
    'error_description',
  ]);

  for (const [key] of expected.searchParams) {
    // Whatever the client registered stays as it was.
    allowed.add(key);
  }

  for (const key of new Set(target.searchParams.keys())) {
    if (!allowed.has(key)) {
      throw new Error('The node sent back a redirect with unexpected data.');
    }
  }

  return target.href;
}

async function signedPost<T>(
  store: Store,
  server: string,
  path: string,
  body: Record<string, unknown>,
): Promise<T> {
  const agent = store.getAgent();

  if (!agent) {
    throw new Error('Sign in to approve an app');
  }

  const url = new URL(path, server).href;
  const payload = JSON.stringify(body);
  const headers = await signRequest(
    url,
    agent,
    {},
    { method: 'POST', body: payload },
  );
  const response = await fetch(url, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: payload,
  });

  if (!response.ok) {
    throw new Error(
      errorMessageFromResponse(await response.text(), response.status),
    );
  }

  return (await response.json()) as T;
}

/** A fresh identity for this client, to give rights to before approving. */
export function requestIssuedAgent(
  store: Store,
  server: string,
  clientId: string,
): Promise<{ agent: string; nonce: string }> {
  return signedPost(store, server, '/oauth/agent', { client_id: clientId });
}

/** Where to send the browser back to the client, carrying its authorization code. */
export async function approveAuthorization(
  store: Store,
  server: string,
  request: {
    clientId: string;
    redirectUri: string;
    codeChallenge: string;
    nonce: string;
    /** The person let the client edit, not only read. */
    write: boolean;
    state?: string;
  },
): Promise<string> {
  const { redirect_url } = await signedPost<{ redirect_url: string }>(
    store,
    server,
    '/oauth/approve',
    {
      client_id: request.clientId,
      redirect_uri: request.redirectUri,
      code_challenge: request.codeChallenge,
      nonce: request.nonce,
      write: request.write,
      state: request.state,
    },
  );

  return safeRedirect(redirect_url, request.redirectUri);
}
