import { describe, it, expect, beforeEach } from 'vitest';
import { readKnownPeers, upsertKnownPeer, writeKnownPeers } from './knownPeers';

// The default vitest environment here is `node`, so there is no localStorage.
// A tiny in-memory stand-in keeps this dependency-free and lets a test drive
// the quota-exceeded branch, which jsdom will not do on demand.
function installLocalStorage(
  onWrite?: (key: string, value: string) => void,
): Map<string, string> {
  const store = new Map<string, string>();

  globalThis.localStorage = {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => {
      onWrite?.(key, value);
      store.set(key, value);
    },
    removeItem: (key: string) => void store.delete(key),
    clear: () => store.clear(),
    key: (index: number) => [...store.keys()][index] ?? null,
    get length() {
      return store.size;
    },
  } as Storage;

  return store;
}

const NODE_A = `did:ad:node:${'a'.repeat(64)}`;
const NODE_B = `did:ad:node:${'b'.repeat(64)}`;

describe('knownPeers', () => {
  let store: Map<string, string>;

  beforeEach(() => {
    store = installLocalStorage();
  });

  it('records a peer with a truncated-DID placeholder label', () => {
    upsertKnownPeer(NODE_A);

    const peers = readKnownPeers();
    expect(peers).toHaveLength(1);
    expect(peers[0].nodeId).toBe(NODE_A);
    // Enough of the DID to tell two devices apart before either says HELLO.
    expect(peers[0].label).toContain('did:ad:node:aaaaaaaa');
  });

  it('keeps an atomic:node: peer that an upgraded server emitted', () => {
    const canonical = `atomic:node:${'b'.repeat(64)}`;
    upsertKnownPeer(canonical);

    const peers = readKnownPeers();
    expect(peers).toHaveLength(1);
    expect(peers[0].nodeId).toBe(canonical);
  });

  it('a later name replaces the placeholder rather than adding a peer', () => {
    upsertKnownPeer(NODE_A);
    upsertKnownPeer(NODE_A, "Joep's phone");

    expect(readKnownPeers()).toEqual([
      { nodeId: NODE_A, label: "Joep's phone" },
    ]);
  });

  it('re-pairing without a name keeps the name already learned', () => {
    upsertKnownPeer(NODE_A, "Joep's phone");
    upsertKnownPeer(NODE_A);

    expect(readKnownPeers()[0].label).toBe("Joep's phone");
  });

  it('matches an existing peer case-insensitively', () => {
    upsertKnownPeer(NODE_A);
    upsertKnownPeer(NODE_A.toUpperCase(), 'Tablet');

    const peers = readKnownPeers();
    expect(peers).toHaveLength(1);
    expect(peers[0].label).toBe('Tablet');
  });

  it('keeps distinct peers side by side', () => {
    upsertKnownPeer(NODE_A, 'Phone');
    upsertKnownPeer(NODE_B, 'Tablet');

    expect(readKnownPeers().map(p => p.label)).toEqual(['Phone', 'Tablet']);
  });

  it('writeKnownPeers stores the list under atomic-peers as plain JSON', () => {
    const peers = [{ nodeId: NODE_A, label: 'Phone', lastSync: 'x' }];

    writeKnownPeers(peers);

    expect(JSON.parse(store.get('atomic-peers')!)).toEqual(peers);
    expect(readKnownPeers()).toEqual(peers);
  });

  it('reads back nothing from corrupt storage instead of throwing', () => {
    store.set('atomic-peers', '{not json');

    expect(readKnownPeers()).toEqual([]);
  });

  it('drops entries whose node id is not 64 hex characters', () => {
    store.set(
      'atomic-peers',
      JSON.stringify([
        { nodeId: NODE_A, label: 'Real' },
        { nodeId: 'did:ad:node:xyz', label: 'Too short' },
        { nodeId: 'garbage', label: 'Not a DID' },
        { label: 'No id at all' },
      ]),
    );

    expect(readKnownPeers().map(p => p.label)).toEqual(['Real']);
  });

  it('survives a storage quota error — pairing again can re-record it', () => {
    installLocalStorage(() => {
      throw new Error('QuotaExceededError');
    });

    expect(() => upsertKnownPeer(NODE_A)).not.toThrow();
  });
});
