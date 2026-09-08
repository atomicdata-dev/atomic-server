import { beforeAll, describe, it } from 'vitest';
import { Store } from './store.js';
import { Agent } from './agent.js';
import { JSCryptoProvider } from './CryptoProvider.js';
import { LoroLoader } from './loro-loader.js';
import { Resource } from './resource.js';
import { commits, core } from './index.js';

/**
 * The live channel is deltas, and nothing in it can say "you are missing
 * something". A receiver that misses one update parks it as pending and every
 * later update parks behind it — no error, no indicator, the document just
 * quietly stops being live until someone reloads.
 *
 * Measured in the field: two paired nodes, same document open, one side typed
 * `awdawdawad oawdinawiodawoi dn` and the other kept showing `awd`, with the
 * sender's cursor still blinking in it the whole time. A reload pulled the full
 * text immediately, so the server had it throughout.
 *
 * What made it silent rather than loud: an unappliable delta on a resource that
 * already had content fell through to "applied", stamping `lastCommit` for a
 * commit that was never applied.
 */

const NAME = 'https://atomicdata.dev/properties/name';

beforeAll(async () => {
  await LoroLoader.initializeLoro();
});

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

/** Build the exact shape of the field failure: a seed the receiver has, a
 *  commit it never receives, and then a delta that depends on that missing
 *  commit. Exporting a fresh doc as `update` does NOT reproduce this — with no
 *  prior version it carries every op from the start and applies cleanly. The
 *  gap only exists if the delta is exported `from` a version the receiver
 *  never reached. */
function withheldCommit(): { seed: Uint8Array; orphaned: Uint8Array[] } {
  const { LoroDoc } = LoroLoader.Loro;
  const doc = new LoroDoc();
  const map = doc.getMap('properties');

  map.set(core.properties.isA, [core.classes.class]);
  map.set(NAME, 'awd');
  doc.commit();
  const seed = doc.export({ mode: 'snapshot' });

  // The update that goes missing on the wire.
  map.set(NAME, 'the delta that never arrived');
  doc.commit();
  const missed = doc.version();

  // Everything after it depends on it, so none of it can apply.
  const orphaned: Uint8Array[] = [];

  for (const text of [
    'awdawdawad oawdinawiodawoi dn',
    'aw',
    'd',
    'more',
    'and more',
  ]) {
    map.set(NAME, text);
    doc.commit();
    orphaned.push(
      doc.export({ mode: 'update', from: missed } as never) as Uint8Array,
    );
  }

  return { seed, orphaned };
}

describe('a delta that cannot apply triggers a catch-up fetch', () => {
  const subject = 'did:ad:gapRecoveryReproAAAAAAAAAAAAAAAAAAAAAAAAAAAA==';

  /** Seed a resource with real, usable content — the case the old code let
   *  through silently, because a resource with an `isA` was assumed healthy. */
  async function seeded(store: Store): Promise<{ orphaned: Uint8Array[] }> {
    const { seed, orphaned } = withheldCommit();
    const r = new Resource(subject);
    r.setStore(store);
    r.loading = true;
    store.applyIncoming({
      subject,
      loroBytes: seed,
      source: 'ws-pending-get',
      replaceLoroDocsFromRemote: true,
    });

    return { orphaned };
  }

  it('fetches the missing base for a resource first seen as a live delta', async ({
    expect,
  }) => {
    const store = await makeStore();
    const { orphaned } = withheldCommit();
    const asked: string[] = [];

    store.fetchResourceFromServer = async s => {
      asked.push(s);

      return store.resources.get(s)!;
    };

    const outcome = store.applyIncoming({
      subject,
      loroBytes: orphaned[0],
      source: 'ws-sub-push',
      commitId: 'did:ad:commit:pending-base',
    });
    expect(outcome).not.toBe('applied');
    expect(asked).toEqual([subject]);
    expect(
      store.resources.get(subject)?.get(commits.properties.lastCommit),
    ).not.toBe('did:ad:commit:pending-base');
  });

  it('asks the server for full state instead of reporting success', async ({
    expect,
  }) => {
    const store = await makeStore();
    const { orphaned } = await seeded(store);

    const asked: string[] = [];

    (
      store as unknown as {
        fetchResourceFromServer: (s: string, o?: unknown) => Promise<Resource>;
      }
    ).fetchResourceFromServer = async (s: string) => {
      asked.push(s);

      return store.resources.get(s)!;
    };

    const outcome = store.applyIncoming({
      subject,
      loroBytes: orphaned[0],
      commitId: 'did:ad:commit:neverApplied',
      source: 'ws-sub-push',
    });

    expect(outcome).not.toBe('applied');
    expect(asked).toEqual([subject]);
  });

  it('does not claim a commit it never applied', async ({ expect }) => {
    const store = await makeStore();
    const { orphaned } = await seeded(store);

    (
      store as unknown as { fetchResourceFromServer: () => Promise<unknown> }
    ).fetchResourceFromServer = async () => undefined;

    store.applyIncoming({
      subject,
      loroBytes: orphaned[0],
      commitId: 'did:ad:commit:neverApplied',
      source: 'ws-sub-push',
    });

    // Stamping it would make the echo-dedup at the top of `applyIncoming`
    // drop the very fetch issued to repair the gap — the fix would then be
    // a no-op that still looks like it works.
    const resource = store.resources.get(subject)!;
    expect(resource.get(commits.properties.lastCommit)).not.toBe(
      'did:ad:commit:neverApplied',
    );
  });

  it('keeps the content it already had rather than blanking the document', async ({
    expect,
  }) => {
    const store = await makeStore();
    const { orphaned } = await seeded(store);

    (
      store as unknown as { fetchResourceFromServer: () => Promise<unknown> }
    ).fetchResourceFromServer = async () => undefined;

    store.applyIncoming({
      subject,
      loroBytes: orphaned[0],
      commitId: 'did:ad:commit:neverApplied',
      source: 'ws-sub-push',
    });

    // Failing the resource outright would be the other way to be loud about
    // this, and it would throw away a document the user can still read.
    const resource = store.resources.get(subject)!;
    expect(resource.get(NAME)).toBe('awd');
    expect(resource.error).toBeUndefined();
  });

  it('fires one catch-up fetch for a burst of unappliable deltas', async ({
    expect,
  }) => {
    const store = await makeStore();
    const { orphaned } = await seeded(store);

    let pending: (() => void) | undefined;
    let calls = 0;

    (
      store as unknown as { fetchResourceFromServer: () => Promise<unknown> }
    ).fetchResourceFromServer = () => {
      calls++;

      return new Promise(resolve => {
        pending = () => resolve(undefined);
      });
    };

    // Every later delta parks behind the first missing one, so they arrive as
    // a burst. One repair fetch is enough for all of them.
    orphaned.forEach((bytes, i) => {
      store.applyIncoming({
        subject,
        loroBytes: bytes,
        commitId: `did:ad:commit:burst${i}`,
        source: 'ws-sub-push',
      });
    });

    expect(calls).toBe(1);

    pending?.();
  });
});

describe("the echo of a client's own commit", () => {
  const subject = 'did:ad:ownCommitEchoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==';

  /** What the server does with a commit: import it, then stamp `lastCommit`
   *  under its own peer. The echo it fans out is both. A peer that boots
   *  from the stored snapshot builds its next edit on top of the stamp. */
  function serverSide(
    authorSnapshot: Uint8Array,
    commitId: string,
  ): {
    echo: Uint8Array;
    peerEdit: Uint8Array;
  } {
    const { LoroDoc } = LoroLoader.Loro;
    const server = new LoroDoc();
    const before = server.version();
    server.import(authorSnapshot);
    server.getMap('properties').set(commits.properties.lastCommit, commitId);
    server.commit();
    const echo = server.export({ mode: 'update', from: before } as never);

    const peer = new LoroDoc();
    peer.import(server.export({ mode: 'snapshot' }));
    const peerBefore = peer.version();
    peer.getMap('properties').set(NAME, 'typed by the peer');
    peer.commit();
    const peerEdit = peer.export({
      mode: 'update',
      from: peerBefore,
    } as never);

    return { echo, peerEdit };
  }

  it('is imported, not dropped, so a peer edit built on the stored snapshot applies', async ({
    expect,
  }) => {
    const store = await makeStore();
    const commitId = 'did:ad:commit:mine';

    const { LoroDoc } = LoroLoader.Loro;
    const authored = new LoroDoc();
    authored
      .getMap('properties')
      .set(core.properties.isA, [core.classes.class]);
    authored.getMap('properties').set(NAME, 'mine');
    authored.commit();

    // The author's resource, already stamped with its own commit id — the
    // state right after COMMIT_OK.
    const r = new Resource(subject);
    r.setStore(store);
    r.loading = true;
    store.applyIncoming({
      subject,
      loroBytes: authored.export({ mode: 'snapshot' }),
      source: 'ws-pending-get',
      replaceLoroDocsFromRemote: true,
    });
    store.resources.get(subject)!.setLastCommitValue(commitId);

    const { echo, peerEdit } = serverSide(
      authored.export({ mode: 'snapshot' }),
      commitId,
    );

    let fetched = 0;

    (
      store as unknown as { fetchResourceFromServer: () => Promise<unknown> }
    ).fetchResourceFromServer = async () => {
      fetched += 1;

      return undefined;
    };

    expect(
      store.applyIncoming({
        subject,
        loroBytes: echo,
        commitId,
        source: 'ws-sub-push',
      }),
    ).toBe('deduped');

    expect(
      store.applyIncoming({
        subject,
        loroBytes: peerEdit,
        commitId: 'did:ad:commit:theirs',
        source: 'ws-sub-push',
      }),
    ).toBe('applied');
    expect(store.resources.get(subject)!.get(NAME)).toBe('typed by the peer');
    expect(fetched).toBe(0);
  });

  it('does not leave the author looking unsaved, which would re-commit forever', async ({
    expect,
  }) => {
    const store = await makeStore();
    const commitId = 'did:ad:commit:mine';

    const { LoroDoc } = LoroLoader.Loro;
    const authored = new LoroDoc();
    authored
      .getMap('properties')
      .set(core.properties.isA, [core.classes.class]);
    authored.getMap('properties').set(NAME, 'mine');
    authored.commit();

    const r = new Resource(subject);
    r.setStore(store);
    r.loading = true;
    store.applyIncoming({
      subject,
      loroBytes: authored.export({ mode: 'snapshot' }),
      source: 'ws-pending-get',
      replaceLoroDocsFromRemote: true,
    });
    const resource = store.resources.get(subject)!;
    resource.setLastCommitValue(commitId);
    // Hydrated clean: the cursor sits at everything the server has.
    expect(resource.hasOpsPastSaveCursor()).toBe(false);

    const { echo, peerEdit } = serverSide(
      authored.export({ mode: 'snapshot' }),
      commitId,
    );

    store.applyIncoming({
      subject,
      loroBytes: echo,
      commitId,
      source: 'ws-sub-push',
    });
    expect(
      resource.hasOpsPastSaveCursor(),
      "the server's stamp is not local work to sign",
    ).toBe(false);

    store.applyIncoming({
      subject,
      loroBytes: peerEdit,
      commitId: 'did:ad:commit:theirs',
      source: 'ws-sub-push',
    });
    expect(
      resource.hasOpsPastSaveCursor(),
      "a collaborator's edit is not local work to sign either",
    ).toBe(false);
    expect(resource.hasUnsavedChanges()).toBe(false);

    // A real local edit still counts.
    await resource.set(NAME, 'edited here');
    expect(resource.hasUnsavedChanges()).toBe(true);
  });

  it('stays absorbed when the echo lands before the ack advances the cursor', async ({
    expect,
  }) => {
    // The drain captures the version at export time and moves the cursor
    // there once the server acks. Under load the echo of that very commit
    // arrives first; the ack must not throw its absorbed ops away.
    const store = await makeStore();
    const commitId = 'did:ad:commit:mine';

    const { LoroDoc } = LoroLoader.Loro;
    const authored = new LoroDoc();
    authored
      .getMap('properties')
      .set(core.properties.isA, [core.classes.class]);
    authored.getMap('properties').set(NAME, 'mine');
    authored.commit();

    const r = new Resource(subject);
    r.setStore(store);
    r.loading = true;
    store.applyIncoming({
      subject,
      loroBytes: authored.export({ mode: 'snapshot' }),
      source: 'ws-pending-get',
      replaceLoroDocsFromRemote: true,
    });
    const resource = store.resources.get(subject)!;
    resource.setLastCommitValue(commitId);
    const versionAtExport = resource.getLoroDoc()!.oplogVersion();

    const { echo } = serverSide(
      authored.export({ mode: 'snapshot' }),
      commitId,
    );
    store.applyIncoming({
      subject,
      loroBytes: echo,
      commitId,
      source: 'ws-sub-push',
    });
    expect(resource.hasOpsPastSaveCursor()).toBe(false);

    // The ack, arriving second.
    resource.markLoroSavedAt(versionAtExport);
    expect(
      resource.hasOpsPastSaveCursor(),
      'the ack must keep the absorbed server ops',
    ).toBe(false);
  });

  it('does not strip the history token off an edit that was pending when it landed', async ({
    expect,
  }) => {
    // A Loro import commits pending local ops, without a message. The echo
    // now lands while the user is still typing, so without care the title
    // edit is sealed untagged, falls into the base bucket of the history,
    // and the version that should show "First Title" shows the later state.
    const store = await makeStore();
    const commitId = 'did:ad:commit:mine';

    const { LoroDoc } = LoroLoader.Loro;
    const authored = new LoroDoc();
    authored
      .getMap('properties')
      .set(core.properties.isA, [core.classes.class]);
    authored.commit();

    const r = new Resource(subject);
    r.setStore(store);
    r.loading = true;
    store.applyIncoming({
      subject,
      loroBytes: authored.export({ mode: 'snapshot' }),
      source: 'ws-pending-get',
      replaceLoroDocsFromRemote: true,
    });
    const resource = store.resources.get(subject)!;
    resource.setLastCommitValue(commitId);

    // Pending, not yet drained.
    await resource.set(NAME, 'First Title');

    const { echo } = serverSide(
      authored.export({ mode: 'snapshot' }),
      commitId,
    );
    store.applyIncoming({
      subject,
      loroBytes: echo,
      commitId,
      source: 'ws-sub-push',
    });

    // The drain comes round.
    const exported = resource.exportLoroDeltaForDrain(false, 'c-drain');
    expect(exported).toBeDefined();

    const first = resource
      .getLoroHistory()
      .find(v => v.propvals.get(NAME) === 'First Title');
    expect(first, 'a version must show the first title').toBeDefined();
    expect(first!.token ?? '').toMatch(/^c-/);
  });

  it('keeps the token when a server response is written into the doc mid-edit', async ({
    expect,
  }) => {
    // `applyHydratedValues` runs on every acked save. It used to close the
    // pending edit with a bare commit — the exact shape the history e2e
    // caught once the author started receiving its own echoes.
    const store = await makeStore();
    const { LoroDoc } = LoroLoader.Loro;
    const authored = new LoroDoc();
    authored
      .getMap('properties')
      .set(core.properties.isA, [core.classes.class]);
    authored.commit();

    const r = new Resource(subject);
    r.setStore(store);
    r.loading = true;
    store.applyIncoming({
      subject,
      loroBytes: authored.export({ mode: 'snapshot' }),
      source: 'ws-pending-get',
      replaceLoroDocsFromRemote: true,
    });
    const resource = store.resources.get(subject)!;

    await resource.set(NAME, 'First Title');
    resource.applyHydratedValues([
      [commits.properties.lastCommit, 'did:ad:commit:acked'],
    ]);
    expect(resource.exportLoroDeltaForDrain(false, 'c-drain')).toBeDefined();

    const first = resource
      .getLoroHistory()
      .find(v => v.propvals.get(NAME) === 'First Title');
    expect(first?.token ?? '').toMatch(/^c-/);
  });
  it('keeps the token when third-party code commits the doc mid-edit', async ({
    expect,
  }) => {
    // loro-prosemirror commits the shared doc from its own plugin, with no
    // message. That is what sealed the title ops untagged in the history
    // e2e once the echo started re-rendering the page between keystrokes.
    const store = await makeStore();
    const { LoroDoc } = LoroLoader.Loro;
    const authored = new LoroDoc();
    authored
      .getMap('properties')
      .set(core.properties.isA, [core.classes.class]);
    authored.commit();

    const r = new Resource(subject);
    r.setStore(store);
    r.loading = true;
    store.applyIncoming({
      subject,
      loroBytes: authored.export({ mode: 'snapshot' }),
      source: 'ws-pending-get',
      replaceLoroDocsFromRemote: true,
    });
    const resource = store.resources.get(subject)!;

    await resource.set(NAME, 'First Title');
    // Someone else's bare commit.
    resource.getLoroDoc()!.commit();
    expect(resource.exportLoroDeltaForDrain(false, 'c-drain')).toBeDefined();

    const first = resource
      .getLoroHistory()
      .find(v => v.propvals.get(NAME) === 'First Title');
    expect(first?.token ?? '').toMatch(/^c-/);
  });
  it('is recognised by signature when it lands before the ack', async ({
    expect,
  }) => {
    // Under load the echo of an own commit arrives before COMMIT_OK, so
    // `lastCommit` is not stamped yet. The signature was registered at sign
    // time; the echo must import silently, not notify.
    const store = await makeStore();
    const { LoroDoc } = LoroLoader.Loro;
    const authored = new LoroDoc();
    authored
      .getMap('properties')
      .set(core.properties.isA, [core.classes.class]);
    authored.commit();

    const r = new Resource(subject);
    r.setStore(store);
    r.loading = true;
    store.applyIncoming({
      subject,
      loroBytes: authored.export({ mode: 'snapshot' }),
      source: 'ws-pending-get',
      replaceLoroDocsFromRemote: true,
    });
    const resource = store.resources.get(subject)!;
    resource.appliedCommitSignatures.add('sigAAA');

    let notified = 0;
    const off = store.subscribe(subject, () => {
      notified += 1;
    });

    const { echo } = serverSide(
      authored.export({ mode: 'snapshot' }),
      'did:ad:commit:sigAAA',
    );
    const outcome = store.applyIncoming({
      subject,
      loroBytes: echo,
      commitId: 'did:ad:commit:sigAAA',
      source: 'ws-sub-push',
    });
    off();

    expect(outcome).toBe('deduped');
    expect(notified).toBe(0);
    expect(resource.hasOpsPastSaveCursor()).toBe(false);
  });
});
