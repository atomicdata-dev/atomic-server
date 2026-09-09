/** Browser-owned credentials. Never store these in Atomic graph resources. */
export const DEFAULT_PROXY = 'https://localthought.io';
const key = 'localthought-browser-v1:';
export interface Connection {
  drive: string;
  actor: string;
  platform: string;
  origin: string;
  expires: number;
  code?: string;
  ready: boolean;
}
export interface Engine {
  describeIntegration(text: string): Promise<string>;
  fetchIntegration(
    text: string,
    platform: string,
    constants: string,
    range: string | undefined,
    fetch: (url: string) => Promise<string>,
  ): Promise<string>;
}
export function proxyOrigin(value = DEFAULT_PROXY): string {
  const u = new URL(value);
  if (
    u.origin !== value ||
    (u.protocol !== 'https:' &&
      !(
        u.protocol === 'http:' &&
        ['localhost', '127.0.0.1'].includes(u.hostname)
      ))
  )
    throw new Error('Proxy must be an HTTPS origin or localhost');
  return value;
}
const base64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
export async function sign(secret: string, text: string) {
  const encoder = new TextEncoder();
  const k = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return base64url(
    new Uint8Array(await crypto.subtle.sign('HMAC', k, encoder.encode(text))),
  );
}
async function limitedText(response: Response): Promise<string> {
  if (!response.body) throw new Error('Empty proxy response');
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let size = 0,
    text = '';
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 10 * 1024 * 1024)
        throw new Error('Proxy response exceeds 10 MB');
      text += decoder.decode(value, { stream: true });
    }
    return text + decoder.decode();
  } finally {
    await reader.cancel();
  }
}
export class BrowserIntegrations {
  constructor(
    private storage: Storage,
    private engine: () => Promise<Engine>,
    readonly origin = DEFAULT_PROXY,
    private http: typeof fetch = (...args) => fetch(...args),
  ) {
    proxyOrigin(origin);
  }
  private async get(path: string, signal?: AbortSignal) {
    const response = await this.http(`${this.origin}${path}`, {
      credentials: 'omit',
      redirect: 'error',
      signal: signal ?? AbortSignal.timeout(30000),
    });
    if (!response.ok)
      throw new Error(`LocalThought returned HTTP ${response.status}`);
    return limitedText(response);
  }
  async catalog(signal?: AbortSignal): Promise<string[]> {
    const names = JSON.parse(await this.get('/catalog', signal));
    if (
      !Array.isArray(names) ||
      names.length > 200 ||
      names.some(s => typeof s !== 'string' || !/^[a-z0-9-]{1,80}$/.test(s))
    )
      throw new Error('Invalid platform catalog');
    return names;
  }
  private async document(platform: string) {
    if (!/^[a-z0-9-]{1,80}$/.test(platform))
      throw new Error('Invalid platform');
    return this.get(`/catalog/${platform}.yaml`);
  }
  async describe(platform: string) {
    return JSON.parse(
      await (
        await this.engine()
      ).describeIntegration(await this.document(platform)),
    ) as {
      parameters: string[];
      collections: string[];
      upstream: string;
    };
  }
  async start(
    drive: string,
    actor: string,
    platform: string,
    returnUrl: string,
    secret: string,
  ) {
    if (!(await this.catalog()).includes(platform))
      throw new Error('Unknown platform');
    const encoded = secret.split('.')[0];
    let tenant: string;
    try {
      tenant = new TextDecoder('utf-8', { fatal: true }).decode(
        Uint8Array.from(
          atob(encoded.replaceAll('-', '+').replaceAll('_', '/')),
          c => c.charCodeAt(0),
        ),
      );
    } catch {
      throw new Error('Invalid tenant secret');
    }
    if (!tenant || !secret.includes('.'))
      throw new Error('Invalid tenant secret');
    const callback = new URL(returnUrl);
    if (
      callback.origin !== location.origin ||
      !['/app/integrations', '/app/devonian-demo'].includes(
        callback.pathname,
      ) ||
      callback.search ||
      callback.hash
    )
      throw new Error('Invalid integration return URL');
    const state = base64url(crypto.getRandomValues(new Uint8Array(32)));
    callback.searchParams.set('integration_state', state);
    callback.searchParams.set('platform', platform);
    const challenge = JSON.parse(await this.get('/session'));
    const url = new URL(`${this.origin}/connect`);
    for (const [k, v] of Object.entries({
      redirect_uri: callback.href,
      platform,
      ts: String(challenge.ts),
      nonce: challenge.nonce,
      challenge: challenge.challenge,
      tenant_id: tenant,
      user_id: actor,
      user_id_sig: await sign(secret, actor),
      response: await sign(secret, challenge.challenge),
    }))
      url.searchParams.set(k, v as string);
    // Only the short-lived handoff survives navigation, never the tenant secret.
    this.storage.setItem(
      key + state,
      JSON.stringify({
        drive,
        actor,
        platform,
        origin: this.origin,
        expires: Date.now() + 600000,
        ready: false,
      } satisfies Connection),
    );
    return { state, url: url.href };
  }
  private connection(id: string, drive: string, actor: string) {
    const raw = this.storage.getItem(key + id);
    if (!raw) throw new Error('Reconnect your account');
    const c: Connection = JSON.parse(raw);
    if (c.drive !== drive || c.actor !== actor || c.origin !== this.origin)
      throw new Error('Connection belongs to another drive, agent or proxy');
    return c;
  }
  finish(drive: string, actor: string, state: string, code: string) {
    const c = this.connection(state, drive, actor);
    if (c.ready || c.expires < Date.now() || !code || code.length > 4096)
      throw new Error('Invalid, expired or completed connection');
    this.storage.setItem(
      key + state,
      JSON.stringify({ ...c, ready: true, code }),
    );
    return { connection: state, platform: c.platform };
  }
  /** Shared rotating-code transport for browser-owned writes as well as reads. */
  async request(
    drive: string,
    actor: string,
    id: string,
    platform: string,
    path: string,
    init: { method?: string; body?: string } = {},
  ): Promise<{ status: number; body: string }> {
    if (!navigator.locks)
      throw new Error('This browser needs Web Locks for integrations');
    if (!path.startsWith('/') || path.startsWith('//') || /[\\\\#]/.test(path))
      throw new Error('Invalid proxy path');
    const destination = new URL(`/proxy/${platform}${path}`, this.origin);
    if (!destination.pathname.startsWith(`/proxy/${platform}/`))
      throw new Error('Invalid proxy path');
    return navigator.locks.request(key + id, async () => {
      const c = this.connection(id, drive, actor);
      if (c.platform !== platform)
        throw new Error('Connection belongs to another platform');
      const response = await this.send(
        id,
        drive,
        actor,
        path,
        init,
        AbortSignal.timeout(30000),
      );
      return { status: response.status, body: await limitedText(response) };
    });
  }
  private async send(
    id: string,
    drive: string,
    actor: string,
    path: string,
    init: { method?: string; body?: string },
    signal: AbortSignal,
  ) {
    const current = this.connection(id, drive, actor);
    if (!current.ready || !current.code)
      throw new Error('Reconnect before retrying an uncertain request');
    const code = current.code;
    delete current.code;
    this.storage.setItem(key + id, JSON.stringify(current));
    const response = await this.http(
      `${this.origin}/proxy/${current.platform}${path}`,
      {
        ...init,
        headers: {
          Authorization: `Bearer ${code}`,
          'Content-Type': 'application/json',
        },
        credentials: 'omit',
        redirect: 'error',
        signal,
      },
    );
    const next = response.headers.get('x-connection-code');
    if (!next)
      throw new Error(
        'Proxy did not expose a rotated code; reconnect and check CORS',
      );
    this.storage.setItem(key + id, JSON.stringify({ ...current, code: next }));
    return response;
  }
  async fetchRecords(
    drive: string,
    actor: string,
    id: string,
    constants: Record<string, string>,
    range?: { start: string; end: string },
  ) {
    // Web Locks serialize rotating credentials across tabs as well as UI actions.
    if (!navigator.locks)
      throw new Error('This browser needs Web Locks for integrations');
    return navigator.locks.request(key + id, async () => {
      const c = this.connection(id, drive, actor);
      if (!c.ready || !c.code) throw new Error('Reconnect your account');
      const text = await this.document(c.platform);
      const engine = await this.engine();
      const { upstream } = JSON.parse(await engine.describeIntegration(text));
      const base = new URL(upstream);
      let requests = 0;
      const signal = AbortSignal.timeout(120000);
      const transport = async (raw: string) => {
        signal.throwIfAborted();
        const target = new URL(raw);
        if (
          target.origin !== base.origin ||
          target.username ||
          target.password ||
          target.hash
        )
          throw new Error('Pagination left the catalog API origin');
        if (++requests > 200)
          throw new Error('Import exceeds 200 requests; narrow its scope');
        const response = await this.send(
          id,
          drive,
          actor,
          `${target.pathname}${target.search}`,
          {},
          signal,
        );
        const headers = Object.fromEntries(
          [...response.headers].filter(
            ([name]) => name !== 'x-connection-code',
          ),
        );
        return JSON.stringify({
          status: response.status,
          headers,
          body: await limitedText(response),
        });
      };
      const result = await engine.fetchIntegration(
        text,
        c.platform,
        JSON.stringify(constants),
        range ? JSON.stringify(range) : undefined,
        transport,
      );
      signal.throwIfAborted();
      return JSON.parse(result);
    });
  }
}
