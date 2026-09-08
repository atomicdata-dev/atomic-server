import { beforeEach, describe, expect, it, vi } from 'vitest';
const records = vi.hoisted(() => new Map<string, unknown>());
vi.mock('idb-keyval', () => ({
  get: async (key: string) => records.get(key),
  set: async (key: string, value: unknown) => {
    records.set(key, value);
  },
  del: async (key: string) => {
    records.delete(key);
  },
  keys: async () => [...records.keys()],
  // IndexedDB update reads and writes in one readwrite transaction.
  update: async (key: string, updater: (value: unknown) => unknown) => {
    records.set(key, updater(records.get(key)));
  },
}));
import {
  getOrCreateSessionDbKey,
  getSessionDbKey,
  ensureDbKeyOnSignIn,
  clearSessionDbKeys,
} from './localDbKey';
const subject = 'did:ad:agent:concurrent-key-test';
const privateKey = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)));
beforeEach(() => records.clear());
describe('persistent local database keys', () => {
  it('concurrent database openers receive the same persisted key', async () => {
    const keys = await Promise.all(
      Array.from({ length: 8 }, () => getOrCreateSessionDbKey(subject)),
    );
    for (const key of keys) expect(key).toEqual(await getSessionDbKey(subject));
  });
  it('concurrent sign-in and database initialization preserve the key across sign-out', async () => {
    const [openedWith, signedInWith] = await Promise.all([
      getOrCreateSessionDbKey(subject),
      ensureDbKeyOnSignIn(subject, privateKey),
      ensureDbKeyOnSignIn(subject, privateKey),
    ]);
    expect(signedInWith).toEqual(openedWith);
    await clearSessionDbKeys();
    expect(await ensureDbKeyOnSignIn(subject, privateKey)).toEqual(openedWith);
  });
});
