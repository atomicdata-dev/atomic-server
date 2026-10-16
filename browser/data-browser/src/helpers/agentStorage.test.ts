import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { Agent } from '@tomic/react';

/** In-memory stand-in for IndexedDB, so we can inspect exactly what got stored. */
const store = new Map<string, unknown>();
/** Extra latency on every write, for tests that race a slow sign-in. */
let writeDelayMs = 0;

vi.mock('idb-keyval', () => ({
  get: async (key: string) => store.get(key),
  set: async (key: string, value: unknown) => {
    if (writeDelayMs) await new Promise(r => setTimeout(r, writeDelayMs));
    store.set(key, value);
  },
  del: async (key: string) => void store.delete(key),
  keys: async () => [...store.keys()],
}));

const {
  archiveStoredAgent,
  getAgentFromIDB,
  readPreviousIdentities,
  saveAgentToIDB,
} = await import('./agentStorage');
const { waitForSessionDbKey } = await import('./localDbKey');

const AGENT_IDB_KEY = 'atomic.agent';
const AGENT_FALLBACK_KEY = 'atomic.agent.fallback';
const SESSION_KEY_PREFIX = 'atomic.clientdb.session-key.';
const WRAPPED_KEY_PREFIX = 'atomic.clientdb.wrapped-key.';
const WRAPPED_KEY_V2_PREFIX = 'atomic.clientdb.wrapped-key-v2.';

async function makeSecret(): Promise<string> {
  const keys = await Agent.generateKeyPair();

  return Agent.buildSecret(keys.privateKey, 'http://localhost/agents/test');
}

/** Simulates an insecure context (plain-HTTP origin), where Web Crypto is absent. */
function withoutSubtleCrypto(run: () => Promise<void>): Promise<void> {
  const real = globalThis.crypto.subtle;
  Object.defineProperty(globalThis.crypto, 'subtle', {
    value: undefined,
    configurable: true,
  });

  return run().finally(() => {
    Object.defineProperty(globalThis.crypto, 'subtle', {
      value: real,
      configurable: true,
    });
  });
}

describe('agent key storage', () => {
  beforeEach(() => store.clear());
  afterEach(() => store.clear());

  it('announces a sign-in before its first await, so the database opener waits for it', async () => {
    const secret = await makeSecret();
    const order: string[] = [];
    // A sign-in slower than the opener's own patience, as one that loads the
    // wasm bundle on a cold page is.
    writeDelayMs = 300;
    // What callers do: set the agent (which starts the opener), then save.
    const saving = saveAgentToIDB(secret).then(() => order.push('saved'));
    const opening = waitForSessionDbKey('atomic:agent:test', 100).then(() =>
      order.push('opened'),
    );
    await Promise.all([saving, opening]).finally(() => (writeDelayMs = 0));

    expect(order).toEqual(['saved', 'opened']);
  });

  it('never stores a readable private key where Web Crypto is available', async () => {
    await saveAgentToIDB(await makeSecret());

    expect(store.has(AGENT_IDB_KEY)).toBe(true);
    // The whole point of the non-extractable keypair: a readable copy beside it
    // would hand back exactly what non-extractability withholds.
    expect(store.has(AGENT_FALLBACK_KEY)).toBe(false);
  });

  it('discards a readable key left behind by an earlier version', async () => {
    const secret = await makeSecret();
    await saveAgentToIDB(secret);
    // An install from before the fix: plaintext sitting next to the keypair.
    store.set(AGENT_FALLBACK_KEY, {
      privateKey: 'leaked',
      subject: 'http://localhost/agents/test',
    });

    const agent = await getAgentFromIDB();

    expect(agent).toBeDefined();
    expect(store.has(AGENT_FALLBACK_KEY)).toBe(false);
  });

  it('falls back to a readable key only in an insecure context', async () => {
    const secret = await makeSecret();

    await withoutSubtleCrypto(async () => {
      await saveAgentToIDB(secret);

      expect(store.has(AGENT_FALLBACK_KEY)).toBe(true);
      expect(store.has(AGENT_IDB_KEY)).toBe(false);

      // ...and it stays usable — dropping it would lock the user out.
      const agent = await getAgentFromIDB();
      expect(agent).toBeDefined();
      expect(store.has(AGENT_FALLBACK_KEY)).toBe(true);
    });
  });

  it('signs out by removing both key records, and the session db keys', async () => {
    await saveAgentToIDB(await makeSecret());
    store.set(AGENT_FALLBACK_KEY, { privateKey: 'x', subject: 'y' });
    store.set(`${SESSION_KEY_PREFIX}fingerprint`, 'session-copy');
    store.set(`${WRAPPED_KEY_PREFIX}fingerprint`, 'wrapped-copy');
    store.set(`${WRAPPED_KEY_V2_PREFIX}fingerprint`, 'wrapped-copy-v2');

    await saveAgentToIDB(undefined);

    expect(store.has(AGENT_IDB_KEY)).toBe(false);
    expect(store.has(AGENT_FALLBACK_KEY)).toBe(false);
    // The session copy of the local-database key goes, so this signed-out
    // session can no longer open the encrypted OPFS cache...
    expect(store.has(`${SESSION_KEY_PREFIX}fingerprint`)).toBe(false);
    // ...while the wrapped copy survives, so the owning agent's cache becomes
    // readable again on their next sign-in rather than being wiped.
    expect(store.has(`${WRAPPED_KEY_PREFIX}fingerprint`)).toBe(true);
    expect(store.has(`${WRAPPED_KEY_V2_PREFIX}fingerprint`)).toBe(true);
  });
});

it('persists folder identities through non-extractable key restoration and keypair updates', async () => {
  const secret = await makeSecret();
  const expected = await Agent.aiChatsFoldersFromSecret(secret);
  await saveAgentToIDB(secret);
  const restored = await getAgentFromIDB();
  expect(restored?.aiChatsFolders).toEqual(expected);
  const stored = store.get(AGENT_IDB_KEY) as {
    keyPair: CryptoKeyPair;
    subject: string;
  };
  await saveAgentToIDB(stored.keyPair, stored.subject);
  expect((await getAgentFromIDB())?.aiChatsFolders).toEqual(expected);
});

describe('keeping a replaced identity', () => {
  beforeEach(() => store.clear());

  it('keeps the stored key aside, once, even after another agent is saved', async () => {
    await saveAgentToIDB(await makeSecret(), { adoptOnDevice: false });
    const { subject, keyPair } = store.get(AGENT_IDB_KEY) as {
      subject: string;
      keyPair: CryptoKeyPair;
    };

    await archiveStoredAgent(subject, ['did:ad:kept']);
    await archiveStoredAgent(subject, ['did:ad:kept', 'did:ad:other']);
    await saveAgentToIDB(await makeSecret(), { adoptOnDevice: false });

    const [previous, ...rest] = await readPreviousIdentities();
    expect(rest).toEqual([]);
    expect(previous.subject).toBe(subject);
    expect((previous.record as { keyPair: CryptoKeyPair }).keyPair).toBe(
      keyPair,
    );
    expect(previous.localOnlyDrives).toEqual(['did:ad:kept', 'did:ad:other']);
  });

  it('finds the stored key when asked for the other spelling of the same agent', async () => {
    await saveAgentToIDB(await makeSecret(), { adoptOnDevice: false });
    const { subject } = store.get(AGENT_IDB_KEY) as { subject: string };
    const key = subject.replace(/^(atomic|did:ad):agent:/, '');
    const otherSpelling = subject.startsWith('atomic:agent:')
      ? `did:ad:agent:${key}`
      : `atomic:agent:${key}`;
    expect(otherSpelling).not.toBe(subject);

    await archiveStoredAgent(otherSpelling);

    const [previous, ...rest] = await readPreviousIdentities();
    expect(rest).toEqual([]);
    expect(previous.subject).toBe(subject);
  });

  it('refuses when the device holds no key for the identity', async () => {
    await expect(archiveStoredAgent('did:ad:agent:missing')).rejects.toThrow();
  });
});

describe('getAgentFromIDB with the read started by index.html', () => {
  const fakeWindow = {} as Window;

  beforeEach(() => {
    vi.stubGlobal('window', fakeWindow);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    store.clear();
  });

  it('uses the early read once, then reads the database again', async () => {
    const secret = await makeSecret();
    await saveAgentToIDB(secret, { adoptOnDevice: false });
    const record = store.get(AGENT_IDB_KEY);
    store.delete(AGENT_IDB_KEY);

    // The early read saw the agent; the database no longer has it.
    fakeWindow.__atomicAgentRead = Promise.resolve({ agent: record as never });
    expect(await getAgentFromIDB()).toBeDefined();
    expect(fakeWindow.__atomicAgentRead).toBeUndefined();
    expect(await getAgentFromIDB()).toBeUndefined();
  });

  it('reads as before when the early read failed', async () => {
    const secret = await makeSecret();
    await saveAgentToIDB(secret, { adoptOnDevice: false });

    fakeWindow.__atomicAgentRead = Promise.reject(new Error('blocked'));
    expect(await getAgentFromIDB()).toBeDefined();

    fakeWindow.__atomicAgentRead = Promise.resolve(undefined);
    expect(await getAgentFromIDB()).toBeDefined();
  });
});
