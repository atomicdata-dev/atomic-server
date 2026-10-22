import { afterEach, describe, expect, it, vi } from 'vitest';
import { Agent } from './agent.js';
import { decodeB64 } from './base64.js';
import {
  NativeClientDb,
  NativeCryptoProvider,
  type NativeChannel,
} from './client-db.native.js';
import type { ClientDbWorker } from './client-db.js';
import { commits } from './ontologies/commits.js';
import { core } from './ontologies/core.js';
import { server } from './ontologies/server.js';
import { JSCryptoProvider } from './CryptoProvider.js';
import { Store } from './store.js';

/**
 * The Flutter app's embedded renderer: a `connect: false` store whose host
 * (Rust) holds the real store and the agent's key. Before the commit
 * transport, a page like that never saved an edit anywhere the host kept:
 * typed text was gone once the page closed.
 */
async function embeddedStore({ transport = true } = {}) {
  const keys = await Agent.generateKeyPair();
  const agentDID = `did:ad:agent:${keys.publicKey}`;
  const key = new JSCryptoProvider(keys.privateKey);
  const calls: Array<[string, unknown[]]> = [];
  /** Commits the host applied, as it received them. */
  const applied: Array<Record<string, unknown>> = [];

  // The host's side of the channel: signs, applies, keeps no page database.
  const channel: NativeChannel = {
    async call(method, args) {
      calls.push([method, args]);

      switch (method) {
        case 'init':
          return true;
        case 'publicKey':
          return keys.publicKey;
        case 'sign':
          return key.sign(args[0] as string);
        case 'signBytes':
          return key.signBytes(decodeB64(args[0] as string));
        case 'applyCommit':
          applied.push(JSON.parse(args[0] as string));

          return null;
        case 'getResourcesWithSnapshots':
          return (args[0] as string[]).map(() => ({
            jsonAd: null,
            snapshot: null,
          }));
        case 'outboxEntries':
        case 'query':
          return method === 'query' ? { subjects: [], count: 0 } : [];
        default:
          return null;
      }
    },
  };
  const db = new NativeClientDb(channel);
  const store = new Store({
    serverUrl: 'https://embed.invalid',
    connect: false,
    agent: new Agent(new NativeCryptoProvider(channel), agentDID),
    commitTransport: transport ? db.commitTransport : undefined,
  });
  store.setClientDb(db as unknown as ClientDbWorker);
  await db.waitForInit();

  vi.spyOn(store, 'getProperty').mockRejectedValue(
    new Error('test: property validation skipped'),
  );
  const fetch = vi.fn(async () => {
    throw new Error('test: no network in the embed');
  });
  store.injectFetch(fetch);
  const postCommit = vi.fn();
  (store as unknown as { client: { postCommit: unknown } }).client.postCommit =
    postCommit;

  return { store, db, agentDID, calls, applied, fetch, postCommit };
}

const named = (store: Store, name: string) =>
  store.newResource({
    isA: server.classes.drive,
    noParent: true,
    propVals: { [core.properties.name]: name },
  });

afterEach(() => {
  vi.restoreAllMocks();
});

describe('a commit transport', () => {
  it('saves without a server: the signed genesis goes to the host', async () => {
    const { store, agentDID, calls, applied, postCommit } =
      await embeddedStore();
    const doc = await named(store, 'Typed on the phone');

    await expect(doc.save()).resolves.toBe('persisted');

    expect(applied).toHaveLength(1);
    const genesis = applied[0];
    expect(genesis[commits.properties.isGenesis]).toBe(true);
    expect(genesis[commits.properties.subject]).toBe(doc.subject);
    expect(genesis[commits.properties.signer]).toBe(agentDID);
    expect(typeof genesis[commits.properties.signature]).toBe('string');
    expect(typeof genesis[commits.properties.loroUpdate]).toBe('string');
    // The id is the host's to give, like a server's.
    expect(genesis['@id']).toBeUndefined();
    // Signed by the host: the page never held the key.
    const methods = calls.map(([m]) => m);
    expect(methods).toContain('signBytes');
    expect(methods.indexOf('sign')).toBeLessThan(
      methods.indexOf('applyCommit'),
    );
    expect(postCommit).not.toHaveBeenCalled();
    expect(store.getSyncStatus().pendingDirtyCount).toBe(0);
  });

  it('an edit to a saved resource is a Loro update on top of the last commit', async () => {
    const { store, applied } = await embeddedStore();
    const doc = await named(store, 'Draft');
    await doc.save();

    await doc.set(core.properties.name, 'Renamed');
    await expect(doc.save()).resolves.toBe('persisted');

    expect(applied).toHaveLength(2);
    const edit = applied[1];
    expect(edit[commits.properties.isGenesis]).toBeUndefined();
    expect(edit[commits.properties.subject]).toBe(doc.subject);
    expect(typeof edit[commits.properties.loroUpdate]).toBe('string');
    expect(store.getSyncStatus().pendingDirtyCount).toBe(0);
  });

  it('typing in a document drains on its own, with no save() call', async () => {
    const { store, applied } = await embeddedStore();
    const doc = await named(store, 'Draft');
    await doc.save();

    // What the rich-text editor (loro-prosemirror) does on a keystroke: a
    // local change committed straight to the resource's Loro document.
    const loro = doc.getLoroDoc()!;
    loro.getText('documentContent').insert(0, 'typed text');
    loro.commit();

    await vi.waitFor(() => expect(applied).toHaveLength(2));
    await vi.waitFor(() =>
      expect(store.getSyncStatus().pendingDirtyCount).toBe(0),
    );
    expect(applied[1][commits.properties.subject]).toBe(doc.subject);
  });

  it('a delete goes to the host', async () => {
    const { store, applied } = await embeddedStore();
    const doc = await named(store, 'Doomed');
    await doc.save();

    await expect(doc.destroy()).resolves.toBeUndefined();

    expect(applied).toHaveLength(2);
    expect(applied[1][commits.properties.destroy]).toBe(true);
    expect(applied[1][commits.properties.subject]).toBe(doc.subject);
    expect(store.outbox.hasPending(doc.subject)).toBe(false);
  });

  it('leaves reads offline: no server, no fetch', async () => {
    const { store, fetch } = await embeddedStore();
    const doc = await named(store, 'Draft');
    await doc.save();

    expect(store.serverConnected).toBe(false);
    expect(store.getSyncStatus().serverConnected).toBe(false);
    expect(store.canCommit).toBe(true);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('without one a save stays offline; setting one drains what is queued', async () => {
    const { store, db, applied } = await embeddedStore({ transport: false });
    const doc = await named(store, 'Before the transport');

    expect(store.canCommit).toBe(false);
    await expect(doc.save()).resolves.toBe('offline');
    expect(applied).toHaveLength(0);
    expect(store.getSyncStatus().pendingDirtyCount).toBeGreaterThan(0);

    store.setCommitTransport(db.commitTransport);

    await vi.waitFor(() => expect(applied).toHaveLength(1));
    await vi.waitFor(() =>
      expect(store.getSyncStatus().pendingDirtyCount).toBe(0),
    );
    expect(applied[0][commits.properties.subject]).toBe(doc.subject);
  });
});
