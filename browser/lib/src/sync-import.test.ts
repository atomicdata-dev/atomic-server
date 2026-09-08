import { describe, it, vi } from 'vitest';
import { Store } from './store.js';
import { Agent } from './agent.js';
import { JSCryptoProvider } from './CryptoProvider.js';
import { LoroLoader } from './loro-loader.js';
import { Resource } from './resource.js';
import { core } from './index.js';

/** Mirror the real WS ordering: the GET/SUB creates a loading
 *  placeholder in the store BEFORE the UPDATE/PUSH bytes arrive. Seed
 *  it directly so `applyIncoming` finds `existing` and doesn't kick a
 *  (test-environment-failing) server fetch. */
function seedLoadingPlaceholder(store: Store, subject: string): void {
  const r = new Resource(subject);
  r.setStore(store);
  r.loading = true;
  (store as unknown as { resources: Map<string, Resource> }).resources.set(
    subject,
    r,
  );
}

/**
 * Regression: an incomplete Loro import must surface an error, not a
 * silently-empty "loaded" resource.
 *
 * Live bug (2026-05-29): a second tab whose OPFS leadership failed
 * reported version vectors it couldn't honour, so the server's
 * `export_updates_since` (lib/src/sync/engine.rs) shipped a delta whose
 * base ops the tab never had. Loro imports those as *pending* ops and
 * applies nothing visible — the resource ended up with only `subject`
 * + `lastCommit`, rendered as a normal (empty) resource, with no error
 * anywhere. `importLoroUpdate` now reports `complete: false` for that
 * case and `applyIncoming` turns it into a real error.
 */
describe('applyIncoming — incomplete Loro import surfaces an error', () => {
  it('errors the resource when missing base state cannot be recovered', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    const keys = await Agent.generateKeyPair();
    store.setAgent(
      new Agent(
        new JSCryptoProvider(keys.privateKey),
        `did:ad:agent:${keys.publicKey}`,
      ),
    );

    // Build a doc with a base version V1, then more ops past it. Export
    // a delta `from: V1` — those bytes depend on the V1 base ops.
    const { LoroDoc } = LoroLoader.Loro;
    const doc = new LoroDoc();
    const props = doc.getMap('properties');
    props.set(core.properties.isA, ['https://atomicdata.dev/classes/Document']);
    doc.commit();
    const v1 = doc.oplogVersion();
    props.set('https://atomicdata.dev/properties/name', 'Real Name');
    doc.commit();

    // Delta from V1 — un-appliable on a fresh empty doc (the V1 base
    // ops are missing, so Loro buffers these as pending).
    const delta = doc.export({ mode: 'update', from: v1 });
    expect(delta.length).toBeGreaterThan(4);

    const subject =
      'did:ad:incompleteImportReproAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==';
    seedLoadingPlaceholder(store, subject);

    vi.spyOn(store, 'fetchResourceFromServer').mockRejectedValue(
      new Error('Could not recover missing base state'),
    );
    const result = store.applyIncoming({
      subject,
      loroBytes: delta,
      commitId: 'did:ad:commit:someStaleCommitId',
      source: 'ws-sync-push',
    });

    // The import was incomplete → applyIncoming reports it as invalid…
    expect(result).toBe('invalid');

    // …and the resource carries a real error instead of pretending to
    // be a loaded-but-empty resource.
    const r = store.resources.get(subject);
    expect(r).toBeDefined();
    expect(r!.loading).toBe(false);
    await vi.waitFor(() => expect(r!.error).toBeDefined());
    expect(r!.error?.message).toMatch(/incomplete update|missing base state/i);

    // Crucially: it did NOT silently materialize as an empty resource.
    expect(r!.get('https://atomicdata.dev/properties/name')).toBeUndefined();
    expect(r!.get(core.properties.isA)).toBeUndefined();
  });

  it('applies cleanly when the bytes are a full snapshot (no pending deps)', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    const keys = await Agent.generateKeyPair();
    store.setAgent(
      new Agent(
        new JSCryptoProvider(keys.privateKey),
        `did:ad:agent:${keys.publicKey}`,
      ),
    );

    const { LoroDoc } = LoroLoader.Loro;
    const doc = new LoroDoc();
    const props = doc.getMap('properties');
    props.set(core.properties.isA, ['https://atomicdata.dev/classes/Document']);
    props.set('https://atomicdata.dev/properties/name', 'Full Snapshot Name');
    doc.commit();

    // A full snapshot is self-contained — no missing base deps.
    const snapshot = doc.export({ mode: 'snapshot' });

    const subject =
      'did:ad:fullSnapshotReproBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==';
    seedLoadingPlaceholder(store, subject);

    const result = store.applyIncoming({
      subject,
      loroBytes: snapshot,
      source: 'ws-sync-push',
    });

    expect(result).toBe('applied');
    const r = store.resources.get(subject);
    expect(r?.loading).toBe(false);
    expect(r?.error).toBeUndefined();
    expect(r?.get('https://atomicdata.dev/properties/name')).toBe(
      'Full Snapshot Name',
    );
  });

  it('does NOT error a commit-detail resource whose delta is partial', async ({
    expect,
  }) => {
    // Regression: a commit's `loroUpdate` is a delta by design.
    // Importing it into a fresh `did:ad:commit:` resource leaves pending
    // ops — that's expected, NOT a sync error. Earlier this failed the
    // commit and chatroom <CommitDetail>s vanished on refresh.
    const store = new Store({ serverUrl: 'https://example.com' });
    const keys = await Agent.generateKeyPair();
    store.setAgent(
      new Agent(
        new JSCryptoProvider(keys.privateKey),
        `did:ad:agent:${keys.publicKey}`,
      ),
    );

    const { LoroDoc } = LoroLoader.Loro;
    const doc = new LoroDoc();
    const props = doc.getMap('properties');
    props.set(core.properties.isA, ['https://atomicdata.dev/classes/Document']);
    doc.commit();
    const v1 = doc.oplogVersion();
    props.set('https://atomicdata.dev/properties/name', 'Real Name');
    doc.commit();
    // A delta with unsatisfiable base deps — the same shape that errors
    // a normal resource, but a commit resource must tolerate it.
    const delta = doc.export({ mode: 'update', from: v1 });

    const subject =
      'did:ad:commit:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC==';
    seedLoadingPlaceholder(store, subject);

    const result = store.applyIncoming({
      subject,
      loroBytes: delta,
      source: 'ws-pending-get',
    });

    // Applied (not 'invalid'), no error — the commit renders.
    expect(result).toBe('applied');
    const r = store.resources.get(subject);
    expect(r?.loading).toBe(false);
    expect(r?.error).toBeUndefined();
  });
});
