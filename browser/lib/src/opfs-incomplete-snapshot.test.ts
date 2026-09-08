import { beforeAll, describe, it } from 'vitest';
import { Store } from './store.js';
import { Agent } from './agent.js';
import { JSCryptoProvider } from './CryptoProvider.js';
import { LoroLoader } from './loro-loader.js';
import { core } from './index.js';

/**
 * Reproduces the user-reported "deeply broken resource" bug: a DID Folder that
 * renders as a bare subject (no class view, no title) yet has `error == null`
 * and `loading == false`.
 *
 * Root cause: the OPFS cold-load path (`fetchResourceWithLocalFallback`) imports
 * the stored Loro snapshot via `importLoroUpdate` but — unlike the WS path
 * (`applyIncoming`, which checks `complete`) — IGNORES its return value. When
 * the stored snapshot is an unapplyable delta (missing base ops, so Loro buffers
 * it as `pending` and materialises nothing) AND the stored JSON-AD is only the
 * server-managed skeleton (parent/drive/createdAt/lastCommit, no isA/name), the
 * resource ends up with those four preserved props but no `isA`. The OPFS guard
 * only refetches when `getEntries().length === 0`; four entries slip past it, so
 * the server GET is suppressed — no fetch, no error, a silently-faulty resource.
 */

const PARENT = 'https://atomicdata.dev/properties/parent';
const DRIVE = 'https://atomicdata.dev/properties/drive';
const CREATED_AT = 'https://atomicdata.dev/properties/createdAt';
const LAST_COMMIT = 'https://atomicdata.dev/properties/lastCommit';
const NAME = 'https://atomicdata.dev/properties/name';
const FOLDER = 'https://atomicdata.dev/classes/Folder';

beforeAll(async () => {
  await LoroLoader.initializeLoro();
});

/** Build an unapplyable delta: ops that depend on a base (V1) the importer
 *  never has, so Loro buffers them as pending and materialises nothing. */
function incompleteDelta(): Uint8Array {
  const { LoroDoc } = LoroLoader.Loro;
  const doc = new LoroDoc();
  const props = doc.getMap('properties');
  props.set(core.properties.isA, [FOLDER]);
  doc.commit();
  const v1 = doc.oplogVersion();
  props.set(NAME, 'Folder');
  doc.commit();

  return doc.export({ mode: 'update', from: v1 });
}

async function makeStore(): Promise<Store> {
  const store = new Store({ serverUrl: 'https://example.com' });
  const keys = await Agent.generateKeyPair();
  store.setAgent(
    new Agent(
      new JSCryptoProvider(keys.privateKey),
      `did:ad:agent:${keys.publicKey}`,
    ),
  );

  return store;
}

/** A clientDb stub that returns a fixed OPFS hit for one subject. */
function fakeClientDb(subject: string, jsonAd: string, snapshot: Uint8Array) {
  return {
    isReady: true,
    isInitialized: true,
    initError: undefined,
    waitForReady: async () => true,
    waitForInit: async () => undefined,
    exportAllResources: async () => '[]',
    flush: async () => undefined,
    putResourceWithSnapshot: async () => undefined,
    getResourceWithSnapshot: async (s: string) =>
      s === subject ? { jsonAd, snapshot } : { jsonAd: null, snapshot: null },
  };
}

describe('OPFS cold-load — incomplete snapshot must not yield a silent-faulty resource', () => {
  const subject =
    'did:ad:incompleteOpfsSnapshotReproAAAAAAAAAAAAAAAAAAAAAAAAAAAA==';

  // The exact bad OPFS state: server-managed skeleton JSON-AD (no isA/name) …
  const skeletonJsonAd = JSON.stringify({
    '@id': subject,
    [PARENT]: 'did:ad:somedrive',
    [DRIVE]: 'did:ad:somedrive',
    [CREATED_AT]: 1782114679532,
    [LAST_COMMIT]: 'did:ad:commit:stale',
  });

  it('a contentless OPFS hit is never left loaded-without-error (offline ⇒ errored)', async ({
    expect,
  }) => {
    const store = await makeStore();
    store.setClientDb(
      fakeClientDb(
        subject,
        skeletonJsonAd,
        incompleteDelta(),
      ) as unknown as Parameters<Store['setClientDb']>[0],
    );

    const r = store.getResourceLoading(subject);

    // Let fetchResourceWithLocalFallback run (OPFS hit + snapshot import).
    for (let i = 0; i < 50 && r.loading; i++) {
      await new Promise(res => setTimeout(res, 10));
    }

    // BEFORE the fix this resource was `loading=false`, `error=undefined`,
    // `isA=undefined` — a silently-broken resource (the user's "deeply broken
    // folder", rendered as a bare subject). The OPFS path now recognises the
    // incomplete import as a cache miss and keeps the resource LOADING while it
    // waits briefly for the WS (a reload reconnects within ~100ms; failing
    // instantly flashes an ErrorPage). Either way the invariant holds: it's
    // never settled `loading=false` with no class and no error.
    expect(r.loading).toBe(true);
    expect(r.get(core.properties.isA)).toBeUndefined();
  });

  it('a skeleton JSON-AD with NO snapshot is also never left loaded-without-error', async ({
    expect,
  }) => {
    // The second route to the same broken state: OPFS returns the
    // server-managed skeleton JSON-AD but no Loro snapshot at all. No import
    // runs, so a `complete`-only guard would wave it through — yet it has no
    // class and is unrenderable. Must still be a miss (offline ⇒ errored).
    const store = await makeStore();
    store.setClientDb(
      fakeClientDb(
        subject,
        skeletonJsonAd,
        new Uint8Array(),
      ) as unknown as Parameters<Store['setClientDb']>[0],
    );

    const r = store.getResourceLoading(subject);

    for (let i = 0; i < 50 && r.loading; i++) {
      await new Promise(res => setTimeout(res, 10));
    }

    // Same invariant: a class-less skeleton hit is a miss, so the resource
    // stays LOADING (waiting for the WS) — never settled-blank without error.
    expect(r.loading).toBe(true);
    expect(r.get(core.properties.isA)).toBeUndefined();
  });
});
