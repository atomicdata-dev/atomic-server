/**
 * Connecting this machine to a node: OAuth 2.1 with PKCE as a public client,
 * the same flow claude.ai uses against the node's `/mcp`. The person approves
 * in the app (which drives, and whether the client may edit); the result is a
 * token that is kept in a file, so the secret of the person is never involved.
 */
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { homedir } from 'node:os';
import path from 'node:path';

export interface StoredConnection {
  /** The node's origin, e.g. https://atomicdata.dev. */
  server: string;
  clientId: string;
  accessToken: string;
  refreshToken: string;
  /** Seconds since the epoch. */
  expiresAt: number;
  scope: string;
}

export interface ConnectOptions {
  server: string;
  clientName: string;
  /** Ask to edit, not only read. The person still decides on the consent page. */
  write: boolean;
  /**
   * Approve in the AtomicServer desktop app instead of the browser: the app
   * holds the person's identity, a browser on the same machine does not.
   */
  desktop?: boolean;
  /** Shows the person where to go. Defaults to printing the link and opening it. */
  openUrl?: (url: string) => void | Promise<void>;
  /** How long to wait for the person, in milliseconds. */
  timeoutMs?: number;
  fetch?: typeof fetch;
}

const b64url = (bytes: Buffer) => bytes.toString('base64url');

export function pkcePair() {
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash('sha256').update(verifier).digest());

  return { verifier, challenge };
}

/** `https://host/` and `https://host` are the same node. */
export function normalizeServer(server: string): string {
  const url = new URL(server);

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`ATOMIC_SERVER_URL must be an http(s) URL, got ${server}`);
  }

  return url.origin;
}

export function configPath(server: string): string {
  const base = process.env.XDG_CONFIG_HOME ?? path.join(homedir(), '.config');
  const host = new URL(server).host.replace(/[^\w.-]/g, '_');

  return path.join(base, 'atomic-mcp', `${host}.json`);
}

export async function loadConnection(
  server: string,
): Promise<StoredConnection | undefined> {
  try {
    const parsed = JSON.parse(await readFile(configPath(server), 'utf8'));

    // Files from before this used one local key: nothing to reuse.
    if (typeof parsed.refreshToken !== 'string') return undefined;

    return parsed as StoredConnection;
  } catch {
    return undefined;
  }
}

export async function saveConnection(connection: StoredConnection) {
  const file = configPath(connection.server);
  await mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  await writeFile(file, JSON.stringify(connection, null, 2), { mode: 0o600 });
}

interface TokenReply {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
}

const now = () => Math.floor(Date.now() / 1000);

async function tokenRequest(
  server: string,
  body: Record<string, string>,
  doFetch: typeof fetch,
): Promise<TokenReply> {
  const response = await doFetch(`${server}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ ...body, resource: `${server}/mcp` }),
  });
  const text = await response.text();

  if (!response.ok) {
    throw new Error(`The node refused the token request: ${text}`);
  }

  return JSON.parse(text) as TokenReply;
}

/** Trades the refresh token for a new access token, and keeps the result. */
export async function refresh(
  connection: StoredConnection,
  doFetch: typeof fetch = fetch,
): Promise<StoredConnection> {
  const reply = await tokenRequest(
    connection.server,
    {
      grant_type: 'refresh_token',
      refresh_token: connection.refreshToken,
      client_id: connection.clientId,
    },
    doFetch,
  );
  const next: StoredConnection = {
    ...connection,
    accessToken: reply.access_token,
    refreshToken: reply.refresh_token ?? connection.refreshToken,
    expiresAt: now() + (reply.expires_in ?? 3600),
    scope: reply.scope ?? connection.scope,
  };
  await saveConnection(next);

  return next;
}

/** Waits for the browser to come back to the loopback address with a code. */
function listenForCode(timeoutMs: number) {
  let resolveCallback: (params: URLSearchParams) => void;
  let rejectCallback: (error: Error) => void;
  const done = new Promise<URLSearchParams>((resolve, reject) => {
    resolveCallback = resolve;
    rejectCallback = reject;
  });
  // The timer can fire while connect() is still registering, before anything
  // awaits `done`. Without a handler that is an unhandled rejection.
  done.catch(() => undefined);
  const http = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');

    if (url.pathname !== '/callback') {
      res.writeHead(404).end();

      return;
    }

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(
      '<!doctype html><meta charset="utf-8"><title>Connected</title><p>You can close this tab and go back to your terminal.</p>',
    );
    resolveCallback(url.searchParams);
  });
  const timer = setTimeout(
    () => rejectCallback(new Error('Gave up waiting for you to allow it.')),
    timeoutMs,
  );

  return new Promise<{
    redirectUri: string;
    done: Promise<URLSearchParams>;
    close: () => void;
  }>((resolve, reject) => {
    http.once('error', error => {
      clearTimeout(timer);
      reject(error);
    });
    http.listen(0, '127.0.0.1', () => {
      const address = http.address();

      if (!address || typeof address === 'string') {
        clearTimeout(timer);
        http.close();
        reject(new Error('Could not listen on this machine.'));

        return;
      }

      resolve({
        redirectUri: `http://127.0.0.1:${address.port}/callback`,
        done,
        close: () => {
          clearTimeout(timer);
          http.close();
        },
      });
    });
  });
}

/** Runs the whole connect flow and stores the result. */
export async function connect({
  server,
  clientName,
  write,
  desktop = false,
  openUrl,
  timeoutMs = 10 * 60 * 1000,
  fetch: doFetch = fetch,
}: ConnectOptions): Promise<StoredConnection> {
  const origin = normalizeServer(server);
  const metaResponse = await doFetch(
    `${origin}/.well-known/oauth-authorization-server`,
  );

  if (!metaResponse.ok) {
    throw new Error(
      `${origin} does not offer MCP sign-in (answered ${metaResponse.status}). Is it an AtomicServer that is new enough?`,
    );
  }

  const meta = (await metaResponse.json()) as {
    authorization_endpoint: string;
    registration_endpoint: string;
  };
  const listener = await listenForCode(timeoutMs);

  try {
    const registered = await doFetch(meta.registration_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: clientName,
        redirect_uris: [listener.redirectUri],
      }),
    });

    if (!registered.ok) {
      throw new Error(`Registering failed: ${await registered.text()}`);
    }

    const { client_id: clientId } = (await registered.json()) as {
      client_id: string;
    };
    const { verifier, challenge } = pkcePair();
    const state = b64url(randomBytes(16));
    const scope = write ? 'read write' : 'read';
    const link = desktop
      ? `atomic://authorize-mcp?${new URLSearchParams({
          server: origin,
          client_id: clientId,
          client_name: clientName,
          redirect_uri: listener.redirectUri,
          code_challenge: challenge,
          scope,
          state,
        })}`
      : `${meta.authorization_endpoint}?${new URLSearchParams({
          response_type: 'code',
          client_id: clientId,
          redirect_uri: listener.redirectUri,
          code_challenge: challenge,
          code_challenge_method: 'S256',
          scope,
          state,
        })}`;

    await (openUrl ?? defaultOpenUrl)(link);

    const params = await listener.done;

    if (params.get('error')) {
      throw new Error(
        `Not connected: ${params.get('error_description') ?? params.get('error')}`,
      );
    }

    if (params.get('state') !== state) {
      throw new Error('The answer did not match this request. Try again.');
    }

    if (params.get('iss') && params.get('iss') !== origin) {
      throw new Error('The answer came from another server. Try again.');
    }

    const code = params.get('code');

    if (!code) {
      throw new Error('The node sent no code. Try again.');
    }

    const reply = await tokenRequest(
      origin,
      {
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        redirect_uri: listener.redirectUri,
        client_id: clientId,
      },
      doFetch,
    );

    if (!reply.refresh_token) {
      throw new Error('The node sent no refresh token.');
    }

    const connection: StoredConnection = {
      server: origin,
      clientId,
      accessToken: reply.access_token,
      refreshToken: reply.refresh_token,
      expiresAt: now() + (reply.expires_in ?? 3600),
      scope: reply.scope ?? (write ? 'read write' : 'read'),
    };
    await saveConnection(connection);

    return connection;
  } finally {
    listener.close();
  }
}

async function defaultOpenUrl(url: string) {
  const { spawn } = await import('node:child_process');

  process.stderr.write(
    `\nOpen this link to choose what this machine may reach:\n\n  ${url}\n\nWaiting for you to click Allow...\n`,
  );

  const opener =
    process.platform === 'darwin'
      ? 'open'
      : process.platform === 'win32'
        ? 'explorer'
        : 'xdg-open';

  try {
    spawn(opener, [url], { detached: true, stdio: 'ignore' })
      .on('error', () => undefined)
      .unref();
  } catch {
    // No browser to open: the printed link is enough.
  }
}
