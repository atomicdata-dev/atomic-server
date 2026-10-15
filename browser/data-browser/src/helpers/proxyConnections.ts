// @wc-ignore-file
/**
 * Integration-proxy connections, as the page manages them for apps
 * (ontola/atomic-plugins#54).
 *
 * The proxy account is the user's Atomic agent. A **connection** (platform +
 * sealed provider token) lives at the proxy and belongs to the agent that
 * redeemed it; a **delegation** says "app agent X may use connection C". The
 * page signs every call it makes to the proxy with the user key, using
 * version 2 request signatures (method and body covered).
 *
 * An app's view runs in a null-origin frame with no storage and never holds
 * the user key. It makes its own key in memory, and the page mints it a
 * short-lived **capability**, signed with the user key and bound to that
 * frame key, after checking that the connection is delegated to this app. The
 * frame then calls the proxy directly; see `view-client.js`.
 *
 * Replaces #1657's relay of LocalThought rotating connection codes (flag day,
 * decision 6 of #54): nothing credential-like is kept in this page's storage
 * any more, only a PKCE verifier for the ten minutes of a handoff.
 */

import { agentSubject, decodeB64, signRequest, type Agent } from '@tomic/react';

const PENDING = 'atomic-proxy-connect-v2:';
const MAX_BODY = 10 * 1024 * 1024;
const TIMEOUT = 30_000;

/**
 * How far ahead a capability's `exp` is set. The proxy allows 15 minutes
 * (900 s) by its own clock and ±5 min skew; 10 minutes keeps a capability
 * valid at a proxy whose clock is up to 5 minutes behind this device's.
 */
export const CAPABILITY_TTL_SECONDS = 600;
export const CAPABILITY_MESSAGE_PREFIX = 'integration-proxy-capability-v2\n';

/** Who a connection is being made for. */
export interface ConnectScope {
  drive: string;
  app: string;
  /** The app's own agent (`atomic:agent:…`), which gets the delegation. */
  appAgent: string;
}

interface PendingConnect extends ConnectScope {
  origin: string;
  platform: string;
  /** Where to go once the proxy sends the person back. */
  returnTo: string;
  expires: number;
  codeVerifier: string;
  label: string;
}

export interface ConnectionReference {
  connectionId: string;
  platform: string;
}

/** One row of `GET /connections`, as far as this page reads it. */
export interface ProxyConnection {
  connection_id: string;
  platform: string;
  owner?: string;
  created_at?: string | number;
  last_used_at?: string | number;
  delegations: { agent: string; label?: string }[];
}

/** What the frame gets: the capability, and where to use it. */
export interface MintedCapability {
  capability: string;
  /** The proxy origin, the capability's `aud`. */
  aud: string;
  /** Unix seconds. */
  exp: number;
  connectionId: string;
  platform: string;
}

/** What `hostStore` needs for one app's frame. */
export interface ProxyHost {
  capability(request: {
    platform: string;
    connectionId: string;
    publicKey: string;
  }): Promise<MintedCapability>;
  connections(platform: string): Promise<ConnectionReference[]>;
  /** The configured proxy's origin: the only place `proxyFetch` may go. */
  origin: string;
}

/** An error the proxy returned: `{error, message}` and the HTTP status. */
export class ProxyError extends Error {
  constructor(
    readonly status: number,
    readonly code: string | undefined,
    message: string,
  ) {
    super(message);
  }
}

export const isPlatformId = (value: unknown): value is string =>
  typeof value === 'string' && /^[a-z0-9-]{1,80}$/.test(value);

export const base64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');

/**
 * `atomic:agent:<base64url-no-pad key>` for an Ed25519 agent id in either
 * prefix (`atomic:agent:`, `did:ad:agent:`) and either base64 alphabet, the
 * form the proxy stores and compares. Throws for anything else.
 */
export function canonicalAgent(id: string): string {
  const match = /^(?:atomic:agent:|did:ad:agent:)([A-Za-z0-9+/_=-]+)$/.exec(
    id.trim(),
  );
  if (!match) throw new Error(`Not an agent id: ${id}`);
  const key = decodeB64(match[1]);
  if (key.length !== 32) throw new Error(`Not an Ed25519 agent id: ${id}`);

  return agentSubject(base64url(key));
}

async function limitedText(response: Response): Promise<string> {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let size = 0;
  let text = '';

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY) throw new Error('Proxy response exceeds 10 MB');
      text += decoder.decode(value, { stream: true });
    }

    return text + decoder.decode();
  } finally {
    await reader.cancel().catch(() => undefined);
  }
}

function parseBody(text: string): unknown {
  if (text === '') return null;

  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/**
 * The capability payload and the bytes the user key signs.
 *
 * Wire form (agreed with the proxy, #54): `Authorization: Capability
 * <payload>.<sig>`, where `payload` is base64url of the JSON claims and `sig`
 * is the user key's Ed25519 signature over
 * `integration-proxy-capability-v2\n` followed by those same JSON bytes.
 */
export function capabilityClaims(claims: {
  connection_id: string;
  platform: string;
  aud: string;
  app: string;
  cnf: string;
  exp: number;
}): { json: string; message: Uint8Array } {
  // Key order as in the proposal; the proxy verifies the bytes, not a
  // re-serialization, so it does not depend on it.
  const json = JSON.stringify({
    v: 2,
    connection_id: claims.connection_id,
    platform: claims.platform,
    aud: claims.aud,
    app: claims.app,
    cnf: claims.cnf,
    exp: claims.exp,
  });

  return {
    json,
    message: new TextEncoder().encode(CAPABILITY_MESSAGE_PREFIX + json),
  };
}

export class ProxyConnections {
  constructor(
    private storage: Storage,
    /** The proxy origin. */
    readonly origin: string,
    /** The signed-in user. Every call the page makes is signed with it. */
    private agent: () => Agent | undefined,
    private http: typeof fetch = (...args) => fetch(...args),
    private now: () => number = Date.now,
  ) {}

  private user(): { agent: Agent; subject: Promise<string> } {
    const agent = this.agent();
    if (!agent) throw new Error('Sign in to use integration connections.');

    return {
      agent,
      subject: agent.getPublicKey().then(key => agentSubject(key)),
    };
  }

  /** One call to the proxy, signed v2 with the user key. */
  private async call(
    method: 'GET' | 'POST' | 'DELETE',
    path: string,
    body?: unknown,
  ): Promise<unknown> {
    const { agent, subject } = this.user();
    const url = new URL(path, this.origin);
    const text = body === undefined ? undefined : JSON.stringify(body);
    const headers = await signRequest(
      url.href,
      agent,
      text === undefined ? {} : { 'Content-Type': 'application/json' },
      { method, body: text, agentSubject: await subject },
    );
    const response = await this.http(url.href, {
      method,
      body: text,
      headers,
      credentials: 'omit',
      redirect: 'error',
      signal: AbortSignal.timeout(TIMEOUT),
    });
    const parsed = parseBody(await limitedText(response));

    if (!response.ok) {
      const error = parsed as { error?: unknown; message?: unknown } | null;
      const code = typeof error?.error === 'string' ? error.error : undefined;
      const message =
        typeof error?.message === 'string'
          ? error.message
          : `HTTP ${response.status}`;
      throw new ProxyError(
        response.status,
        code,
        `The integration proxy refused ${method} ${url.pathname}: ${message}`,
      );
    }

    return parsed;
  }

  /**
   * Starts the PKCE handoff and returns the proxy URL to send the person to.
   * The proxy only returns to `/app/integrations`, so `returnTo` is where the
   * return handler goes afterwards. No proxy login: the redeem that follows
   * is signed with the user key, and that makes the user the owner.
   */
  async start(
    scope: ConnectScope,
    platform: string,
    returnTo: string,
    label: string,
    pageOrigin = location.origin,
  ): Promise<string> {
    if (!isPlatformId(platform)) throw new Error('Invalid platform');
    const back = new URL(returnTo, pageOrigin);
    if (back.origin !== pageOrigin) throw new Error('Invalid return URL');
    const appAgent = canonicalAgent(scope.appAgent);

    const state = base64url(crypto.getRandomValues(new Uint8Array(32)));
    const codeVerifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
    const codeChallenge = base64url(
      new Uint8Array(
        await crypto.subtle.digest(
          'SHA-256',
          new TextEncoder().encode(codeVerifier),
        ),
      ),
    );
    const callback = new URL('/app/integrations', pageOrigin);
    callback.searchParams.set('integration_state', state);
    callback.searchParams.set('platform', platform);
    const url = new URL('/connect', this.origin);

    for (const [k, v] of Object.entries({
      platform,
      redirect_uri: callback.href,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    }))
      url.searchParams.set(k, v);

    const pending: PendingConnect = {
      ...scope,
      appAgent,
      origin: this.origin,
      platform,
      returnTo: back.href,
      expires: this.now() + 600_000,
      codeVerifier,
      label,
    };
    this.storage.setItem(PENDING + state, JSON.stringify(pending));

    return url.href;
  }

  private pending(state: string): PendingConnect | undefined {
    const raw = this.storage.getItem(PENDING + state);
    if (!raw) return undefined;

    try {
      return JSON.parse(raw) as PendingConnect;
    } catch {
      return undefined;
    }
  }

  /** Whether `params` is a return from a handoff this browser started. */
  isReturn(params: URLSearchParams): boolean {
    const state = params.get('integration_state');

    return !!state && !!this.pending(state);
  }

  /**
   * Redeems the proxy's handoff code, signed with the user key (who becomes
   * the connection's owner), then delegates the new connection to the app,
   * also signed. Returns where to go next. A refusal at the proxy
   * (`error=access_denied`) drops the pending handoff and still returns
   * there, so the app can offer to connect again.
   */
  async finish(
    params: URLSearchParams,
  ): Promise<{ returnTo: string; connected: boolean; connectionId?: string }> {
    const state = params.get('integration_state') ?? '';
    const c = this.pending(state);
    // Consumed before anything else: the verifier is single-use either way.
    this.storage.removeItem(PENDING + state);

    if (!c || c.origin !== this.origin)
      throw new Error(
        'This connection return is not one this browser started.',
      );

    if (params.get('platform') !== c.platform || c.expires < this.now())
      throw new Error('The connection return expired. Connect again.');

    const code = params.get('connection_code');

    if (!code || code.length > 4096) {
      return { returnTo: c.returnTo, connected: false };
    }

    const result = (await this.call('POST', '/connect/redeem', {
      code,
      code_verifier: c.codeVerifier,
    })) as { connection_id?: unknown; platform?: unknown } | null;

    if (result?.platform !== c.platform)
      throw new Error('The proxy connected a different platform than asked.');

    if (
      typeof result.connection_id !== 'string' ||
      !result.connection_id ||
      result.connection_id.length > 512
    )
      throw new Error('The proxy returned an invalid connection id.');

    await this.delegate(result.connection_id, c.appAgent, c.label);

    return {
      returnTo: c.returnTo,
      connected: true,
      connectionId: result.connection_id,
    };
  }

  /** This user's connections at the proxy, with their delegations. */
  async list(platform?: string): Promise<ProxyConnection[]> {
    const result = (await this.call('GET', '/connections')) as
      | { connections?: unknown }
      | unknown[]
      | null;
    const rows = Array.isArray(result)
      ? result
      : Array.isArray(result?.connections)
        ? result.connections
        : [];

    return (rows as ProxyConnection[])
      .filter(
        row =>
          typeof row?.connection_id === 'string' &&
          typeof row.platform === 'string' &&
          (platform === undefined || row.platform === platform),
      )
      .map(row => ({
        ...row,
        delegations: Array.isArray(row.delegations) ? row.delegations : [],
      }));
  }

  /** Connections for `platform` delegated to `appAgent`. References only. */
  async delegated(
    appAgent: string,
    platform: string,
  ): Promise<ConnectionReference[]> {
    const app = canonicalAgent(appAgent);

    return (await this.list(platform))
      .filter(row => row.delegations.some(d => sameAgent(d.agent, app)))
      .map(row => ({ connectionId: row.connection_id, platform }));
  }

  /** "App agent X may use connection C." Signed by the owner. */
  async delegate(connectionId: string, agent: string, label?: string) {
    await this.call(
      'POST',
      `/connections/${encodeURIComponent(connectionId)}/agents`,
      { agent: canonicalAgent(agent), ...(label ? { label } : {}) },
    );
  }

  /** Takes a delegation away; the proxy refuses the app from then on. */
  async undelegate(connectionId: string, agent: string) {
    await this.call(
      'DELETE',
      `/connections/${encodeURIComponent(connectionId)}/agents/${encodeURIComponent(canonicalAgent(agent))}`,
    );
  }

  /** Deletes a connection at the proxy, and with it every delegation. */
  async revoke(connectionId: string) {
    await this.call(
      'DELETE',
      `/connections/${encodeURIComponent(connectionId)}`,
    );
  }

  /**
   * Mints a capability for a frame's key, after checking that the connection
   * is this user's, for `platform`, and delegated to `appAgent`. The proxy
   * checks all of that again on every request; checking here as well means a
   * frame cannot get a signed statement about a connection it has no business
   * with.
   */
  async mintCapability(request: {
    appAgent: string;
    platform: string;
    connectionId: string;
    publicKey: string;
  }): Promise<MintedCapability> {
    const { platform, connectionId } = request;
    if (!isPlatformId(platform)) throw new Error('Invalid platform');
    if (typeof connectionId !== 'string' || !connectionId)
      throw new Error('connectionId is required');
    if (typeof request.publicKey !== 'string')
      throw new Error('publicKey is required');
    const cnf = canonicalAgent(agentSubject(request.publicKey));
    const app = canonicalAgent(request.appAgent);
    const { agent } = this.user();

    const row = (await this.list(platform)).find(
      r => r.connection_id === connectionId,
    );

    if (!row || !row.delegations.some(d => sameAgent(d.agent, app)))
      throw new Error(
        `No ${platform} connection ${connectionId} is delegated to this app. Connect again.`,
      );

    const exp = Math.floor(this.now() / 1000) + CAPABILITY_TTL_SECONDS;
    const { json, message } = capabilityClaims({
      connection_id: connectionId,
      platform,
      aud: this.origin,
      app,
      cnf,
      exp,
    });
    const sig = await agent.signBytes(message);

    return {
      capability: `${base64url(new TextEncoder().encode(json))}.${sig}`,
      aud: this.origin,
      exp,
      connectionId,
      platform,
    };
  }

  /** What `hostStore` answers one app's frame with. */
  host(appAgent: () => Promise<string>): ProxyHost {
    return {
      origin: this.origin,
      capability: async request =>
        this.mintCapability({ ...request, appAgent: await appAgent() }),
      connections: async platform => this.delegated(await appAgent(), platform),
    };
  }
}

function sameAgent(a: unknown, canonical: string): boolean {
  if (typeof a !== 'string') return false;

  try {
    return canonicalAgent(a) === canonical;
  } catch {
    return false;
  }
}
