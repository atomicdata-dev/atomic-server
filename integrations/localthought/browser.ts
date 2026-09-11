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
  codeVerifier?: string;
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
export interface ImportLimits {
  minRequestIntervalMs: number;
  maxRequests: number;
  timeoutMs: number;
}
interface QuerySelection {
  query_overrides: { path: string; values: Record<string, unknown> }[];
}
function querySelection(value: unknown): QuerySelection {
  if (value === undefined || value === null) return { query_overrides: [] };
  if (typeof value !== 'object' || Array.isArray(value))
    throw new Error('Invalid catalog selection');
  const raw = value as Record<string, unknown>;
  if (raw.query_overrides === undefined) return { query_overrides: [] };
  if (
    !Array.isArray(raw.query_overrides) ||
    raw.query_overrides.some(
      item =>
        typeof item !== 'object' ||
        item === null ||
        Array.isArray(item) ||
        typeof (item as Record<string, unknown>).path !== 'string' ||
        typeof (item as Record<string, unknown>).values !== 'object' ||
        (item as Record<string, unknown>).values === null ||
        Array.isArray((item as Record<string, unknown>).values),
    )
  )
    throw new Error('Invalid catalog selection');
  return raw as unknown as QuerySelection;
}
export function mergeQuerySelections(defaults: unknown, explicit?: unknown) {
  const merged = new Map<string, Record<string, unknown>>();
  for (const selection of [querySelection(defaults), querySelection(explicit)]) {
    for (const override of selection.query_overrides) {
      merged.set(override.path, {
        ...merged.get(override.path),
        ...override.values,
      });
    }
  }
  return merged.size
    ? { query_overrides: [...merged].map(([path, values]) => ({ path, values })) }
    : undefined;
}
const DEFAULT_IMPORT_LIMITS: ImportLimits = {
  minRequestIntervalMs: 0,
  maxRequests: 10000,
  timeoutMs: 1800000,
};
const MAX_IMPORT_LIMITS: ImportLimits = {
  minRequestIntervalMs: 300000,
  maxRequests: 10000,
  timeoutMs: 1800000,
};
function importLimits(value: unknown): ImportLimits {
  if (value === undefined || value === null) return DEFAULT_IMPORT_LIMITS;
  if (typeof value !== 'object' || Array.isArray(value))
    throw new Error('Invalid import limits');
  const raw = value as Record<string, unknown>;
  const result = { ...DEFAULT_IMPORT_LIMITS };
  for (const key of Object.keys(result) as (keyof ImportLimits)[]) {
    if (raw[key] !== undefined) {
      if (
        typeof raw[key] !== 'number' ||
        !Number.isInteger(raw[key]) ||
        raw[key] < 0 ||
        raw[key] > MAX_IMPORT_LIMITS[key]
      )
        throw new Error(`Invalid import limits ${key}`);
      result[key] = raw[key];
    }
  }
  if (result.maxRequests < 1 || result.timeoutMs < 1000)
    throw new Error('Invalid import limits');
  return result;
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
    private sleep: (milliseconds: number) => Promise<void> = milliseconds =>
      new Promise(resolve => setTimeout(resolve, milliseconds)),
    private limits: Partial<ImportLimits> = {},
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
  private async selection(platform: string) {
    if (!/^[a-z0-9-]{1,80}$/.test(platform))
      throw new Error('Invalid platform');
    return JSON.parse(await this.get(`/catalog/${platform}.selection.json`));
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
  ) {
    if (!(await this.catalog()).includes(platform))
      throw new Error('Unknown platform');
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
    const codeVerifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
    const codeChallenge = base64url(
      new Uint8Array(
        await crypto.subtle.digest(
          'SHA-256',
          new TextEncoder().encode(codeVerifier),
        ),
      ),
    );
    callback.searchParams.set('integration_state', state);
    callback.searchParams.set('platform', platform);
    const url = new URL(`${this.origin}/connect`);
    for (const [k, v] of Object.entries({
      platform,
      redirect_uri: callback.href,
      user_id: actor,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      credentials: 'connection',
    }))
      url.searchParams.set(k, v as string);
    // Only the short-lived PKCE handoff survives navigation.
    this.storage.setItem(
      key + state,
      JSON.stringify({
        drive,
        actor,
        platform,
        origin: this.origin,
        expires: Date.now() + 600000,
        codeVerifier,
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
  cancel(drive: string, actor: string, state: string) {
    this.connection(state, drive, actor);
    this.storage.removeItem(key + state);
  }
  async finish(drive: string, actor: string, state: string, code: string) {
    const c = this.connection(state, drive, actor);
    if (c.expires < Date.now()) {
      this.storage.removeItem(key + state);
      throw new Error('Reconnect your account');
    }
    if (c.ready || !c.codeVerifier || !code || code.length > 4096)
      throw new Error('Reconnect your account');
    const verifier = c.codeVerifier;
    delete c.codeVerifier;
    // Consume before dispatch: a lost response may have spent the handoff code.
    this.storage.setItem(key + state, JSON.stringify(c));
    const response = await this.http(`${this.origin}/connect/redeem`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, code_verifier: verifier }),
      credentials: 'omit',
      redirect: 'error',
      signal: AbortSignal.timeout(30000),
    });
    if (!response.ok)
      throw new Error(`LocalThought returned HTTP ${response.status}`);
    const result = JSON.parse(await limitedText(response)) as {
      connection_code?: unknown;
      platform?: unknown;
    };
    if (result.platform !== c.platform)
      throw new Error('Returned platform did not match the requested platform');
    if (
      typeof result.connection_code !== 'string' ||
      !result.connection_code ||
      result.connection_code.length > 4096
    )
      throw new Error('LocalThought returned an invalid connection code');
    this.storage.setItem(
      key + state,
      JSON.stringify({ ...c, ready: true, code: result.connection_code }),
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
    init: { method?: string; body?: string; ifMatch?: string } = {},
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
    init: { method?: string; body?: string; ifMatch?: string },
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
        method: init.method,
        body: init.body,
        headers: {
          Authorization: `Bearer ${code}`,
          'Content-Type': 'application/json',
          ...(init.ifMatch ? { 'If-Match': init.ifMatch } : {}),
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
  /** Check one catalog-selected API URL without importing or following pagination. */
  async validateConnection(
    drive: string,
    actor: string,
    id: string,
    constants: Record<string, string>,
    selection?: unknown,
  ): Promise<void> {
    await this.fetchRecords(drive, actor, id, constants, selection, true);
  }
  async fetchRecords(
    drive: string,
    actor: string,
    id: string,
    constants: Record<string, string>,
    selection?: unknown,
    validateOnly = false,
  ) {
    // Web Locks serialize rotating credentials across tabs as well as UI actions.
    if (!navigator.locks)
      throw new Error('This browser needs Web Locks for integrations');
    return navigator.locks.request(key + id, async () => {
      const c = this.connection(id, drive, actor);
      if (!c.ready || !c.code) throw new Error('Reconnect your account');
      const [text, defaults] = await Promise.all([
        this.document(c.platform),
        this.selection(c.platform),
      ]);
      const engine = await this.engine();
      const description = JSON.parse(await engine.describeIntegration(text));
      const { upstream } = description;
      // Resource budgets belong to this consumer, not the API description.
      const policy = importLimits(this.limits);
      const base = new URL(upstream);
      let requests = 0;
      const signal = AbortSignal.timeout(policy.timeoutMs);
      const deadline = Date.now() + policy.timeoutMs;
      let lastRequestAt: number | undefined;
      let probeAttempted = false;
      let probeError: unknown;
      const probeComplete = new Error('Access check complete');
      const transport = async (raw: string) => {
        if (validateOnly && probeAttempted) throw probeComplete;
        signal.throwIfAborted();
        const target = new URL(raw);
        if (
          target.origin !== base.origin ||
          target.username ||
          target.password ||
          target.hash
        )
          throw new Error('Pagination left the catalog API origin');
        if (validateOnly) {
          probeAttempted = true;
          try {
            const response = await this.send(
              id,
              drive,
              actor,
              `${target.pathname}${target.search}`,
              {},
              AbortSignal.any([signal, AbortSignal.timeout(30000)]),
            );
            if (!response.ok)
              throw new Error(`LocalThought returned HTTP ${response.status}`);
            const body = JSON.parse(await limitedText(response));
            if (!body || typeof body !== 'object')
              throw new Error('Expected a JSON collection response');
          } catch (error) {
            probeError = error;
          }
          // Syncables owns URL expansion. Stop its traversal at the first
          // request; the access-check response is deliberately never imported.
          throw probeComplete;
        }
        if (lastRequestAt !== undefined) {
          const wait = policy.minRequestIntervalMs - (Date.now() - lastRequestAt);
          if (wait > 0) await this.sleep(wait);
          signal.throwIfAborted();
        }
        lastRequestAt = Date.now();
        let response: Response;
        let retries = 0;
        for (;;) {
          if (++requests > policy.maxRequests)
            throw new Error(
              `Import exceeds ${policy.maxRequests} requests; narrow its scope`,
            );
          const requestSignal = AbortSignal.any([
            signal,
            AbortSignal.timeout(30000),
          ]);
          response = await this.send(
            id,
            drive,
            actor,
            `${target.pathname}${target.search}`,
            {},
            requestSignal,
          );
          if (response.status !== 429 || retries >= 3) break;
          const retryAfter = response.headers.get('retry-after');
          const seconds = retryAfter === null ? NaN : Number(retryAfter);
          const retryAt = Number.isFinite(seconds)
            ? Date.now() + Math.max(0, seconds) * 1000
            : retryAfter
              ? Date.parse(retryAfter)
              : NaN;
          if (!Number.isFinite(retryAt)) break;
          const delay = Math.max(0, retryAt - Date.now());
          if (delay > deadline - Date.now())
            throw new Error('API retry delay exceeds remaining import time');
          retries++;
          await this.sleep(delay);
          signal.throwIfAborted();
          lastRequestAt = Date.now();
        }
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
      let result: string;
      try {
        result = await engine.fetchIntegration(
          text,
          c.platform,
          JSON.stringify(constants),
          JSON.stringify(mergeQuerySelections(defaults, selection)),
          transport,
        );
      } catch (error) {
        if (!validateOnly || !probeAttempted) throw error;
      }
      if (validateOnly) {
        if (probeError) throw probeError;
        if (!probeAttempted) throw new Error('No collection available to check');
        return;
      }
      signal.throwIfAborted();
      return JSON.parse(result!);
    });
  }
}
