import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// The desktop and Android apps are the case that matters: on
// `tauri://localhost` the API base comes entirely from what was remembered,
// which is exactly what a hostile node tries to overwrite.
const inTauri = { value: false };
vi.mock('../tauri', () => ({ isRunningInTauri: () => inTauri.value }));

const PORTAL = 'https://portal.example';
const OTHER = 'https://attacker.example';

// The default vitest environment here is `node`, so there is no localStorage —
// the same stand-in `deviceLink.test.ts` uses.
function installLocalStorage(): Map<string, string> {
  const store = new Map<string, string>();

  globalThis.localStorage = {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => void store.set(key, value),
    removeItem: (key: string) => void store.delete(key),
    clear: () => store.clear(),
    key: (index: number) => [...store.keys()][index] ?? null,
    get length() {
      return store.size;
    },
  } as Storage;

  return store;
}

// The module keeps the remembered portal in memory as well as in storage, so
// every test gets a fresh copy of it.
async function freshApi() {
  vi.resetModules();

  return import('./api');
}

let storage: Map<string, string>;
let warn: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  storage = installLocalStorage();
  warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
  inTauri.value = true;
});

afterEach(() => {
  vi.restoreAllMocks();
  inTauri.value = false;
});

describe('safePortalUrl', () => {
  it('accepts absolute https URLs, trimming trailing slashes', async () => {
    const { safePortalUrl } = await freshApi();

    expect(safePortalUrl('https://portal.example')).toBe(PORTAL);
    expect(safePortalUrl('https://portal.example/')).toBe(PORTAL);
    expect(safePortalUrl('https://portal.example///')).toBe(PORTAL);
    expect(safePortalUrl('  https://portal.example/ ')).toBe(PORTAL);
    expect(safePortalUrl('https://portal.example/signin')).toBe(
      'https://portal.example/signin',
    );
  });

  it('accepts plain http only on localhost', async () => {
    const { safePortalUrl } = await freshApi();

    expect(safePortalUrl('http://localhost:49237')).toBe(
      'http://localhost:49237',
    );
    expect(safePortalUrl('http://127.0.0.1:49237/')).toBe(
      'http://127.0.0.1:49237',
    );
    expect(safePortalUrl('http://portal.example')).toBeUndefined();
    expect(safePortalUrl('http://localhost.example')).toBeUndefined();
  });

  it('refuses anything that is not a plain https address', async () => {
    const { safePortalUrl } = await freshApi();

    expect(safePortalUrl('javascript:alert(1)')).toBeUndefined();
    expect(safePortalUrl('data:text/html,hi')).toBeUndefined();
    expect(safePortalUrl('tauri://localhost')).toBeUndefined();
    expect(safePortalUrl('portal.example')).toBeUndefined();
    expect(safePortalUrl('/relative')).toBeUndefined();
    expect(safePortalUrl('https://user:pw@portal.example')).toBeUndefined();
    expect(safePortalUrl('')).toBeUndefined();
    expect(safePortalUrl('   ')).toBeUndefined();
    expect(safePortalUrl(null)).toBeUndefined();
    expect(safePortalUrl(undefined)).toBeUndefined();
  });
});

describe('rememberManagedPortalUrl', () => {
  it('remembers a safe portal and serves it as the API base', async () => {
    const api = await freshApi();

    api.rememberManagedPortalUrl(`${PORTAL}/`);

    expect(api.getRememberedManagedPortalUrl()).toBe(PORTAL);
    expect(api.getManagedApiBase()).toBe(`${PORTAL}/api`);
    expect(storage.get('atomic-managed-portal-url')).toBe(PORTAL);
  });

  it('ignores a portal that is not https', async () => {
    const api = await freshApi();

    api.rememberManagedPortalUrl(PORTAL);
    api.rememberManagedPortalUrl('http://attacker.example');
    api.rememberManagedPortalUrl('javascript:alert(1)');

    expect(api.getRememberedManagedPortalUrl()).toBe(PORTAL);
    expect(warn).toHaveBeenCalledTimes(2);
  });

  it('ignores a falsy value rather than forgetting the portal', async () => {
    const api = await freshApi();

    api.rememberManagedPortalUrl(PORTAL);
    api.rememberManagedPortalUrl(null);
    api.rememberManagedPortalUrl('');

    expect(api.getRememberedManagedPortalUrl()).toBe(PORTAL);
  });

  it('re-checks a portal stored by an older build', async () => {
    storage.set('atomic-managed-portal-url', 'http://attacker.example');
    const api = await freshApi();

    expect(api.getRememberedManagedPortalUrl()).toBeNull();
    expect(api.getManagedApiBase()).toBe('/api');
  });
});

describe('a linked device', () => {
  it('keeps the token bound when runtime configuration names another portal', async () => {
    const api = await freshApi();
    api.setManagedDeviceToken('sess', PORTAL);
    vi.stubGlobal('window', { __ATOMIC_MANAGED__: { portalUrl: OTHER } });
    expect(api.getManagedApiBase()).toBe(`${PORTAL}/api`);
  });

  /**
   * The bug this guards: a node's self-reported `portalUrl` used to become the
   * API base, and the bearer token went with it. Connecting the app to a
   * hostile server handed that server the control-plane session.
   */
  it('keeps sending its token to the portal it linked with, whatever a node says later', async () => {
    const api = await freshApi();

    api.setManagedDeviceToken('sess', PORTAL);
    expect(api.getLinkedPortalOrigin()).toBe(PORTAL);

    // What fetchManagedInfo does after connecting to a server that names
    // another portal.
    api.rememberManagedPortalUrl(OTHER);

    expect(api.getManagedApiBase()).toBe(`${PORTAL}/api`);
    expect(api.getRememberedManagedPortalUrl()).toBe(PORTAL);
    expect(storage.get('atomic-managed-portal-url')).not.toBe(OTHER);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining(OTHER));
  });

  it('sends managedFetch to the linked portal, with the token', async () => {
    const api = await freshApi();
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue({ ok: true } as Response);

    api.setManagedDeviceToken('sess', PORTAL);
    api.rememberManagedPortalUrl(OTHER);

    await api.managedFetch('/me', {});

    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe(`${PORTAL}/api/me`);
    expect((init!.headers as Headers).get('Authorization')).toBe('Bearer sess');
  });

  it('still accepts the same origin from a node, trailing slash or not', async () => {
    const api = await freshApi();

    api.setManagedDeviceToken('sess', PORTAL);
    api.rememberManagedPortalUrl(`${PORTAL}/`);

    expect(warn).not.toHaveBeenCalled();
    expect(api.getManagedApiBase()).toBe(`${PORTAL}/api`);
  });

  it('is free to follow a new portal once unlinked', async () => {
    const api = await freshApi();

    api.setManagedDeviceToken('sess', PORTAL);
    api.setManagedDeviceToken(null);

    expect(api.getLinkedPortalOrigin()).toBeNull();
    expect(storage.has('atomic-managed-portal-origin-linked')).toBe(false);

    api.rememberManagedPortalUrl(OTHER);

    expect(api.getManagedApiBase()).toBe(`${OTHER}/api`);
  });

  it('does not record a link origin that is not https', async () => {
    const api = await freshApi();

    api.setManagedDeviceToken('sess', 'http://attacker.example');

    expect(api.getLinkedPortalOrigin()).toBeNull();
    expect(warn).toHaveBeenCalled();
  });

  /**
   * Installs that linked before the origin was recorded: the portal remembered
   * at that time is the one the token was issued by. It is adopted before any
   * node gets a chance to overwrite the memory.
   */
  it('adopts the portal an older build remembered, and keeps it against a later node', async () => {
    storage.set('atomic-managed-device-token', 'sess');
    storage.set('atomic-managed-portal-url', PORTAL);
    const api = await freshApi();

    api.rememberManagedPortalUrl(OTHER);

    expect(api.getLinkedPortalOrigin()).toBe(PORTAL);
    expect(api.getManagedApiBase()).toBe(`${PORTAL}/api`);
    expect(storage.get('atomic-managed-portal-origin-linked')).toBe(PORTAL);
  });

  it('has no link origin without a token', async () => {
    storage.set('atomic-managed-portal-origin-linked', PORTAL);
    const api = await freshApi();

    expect(api.getLinkedPortalOrigin()).toBeNull();
  });
});
