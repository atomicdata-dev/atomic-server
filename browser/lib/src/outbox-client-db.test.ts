import { afterEach, describe, expect, it, vi } from 'vitest';
import { Agent } from './agent.js';
import type { ClientDbOutboxWrite, ClientDbWorker } from './client-db.js';
import type { Commit } from './commit.js';
import { JSCryptoProvider } from './CryptoProvider.js';
import { core } from './ontologies/core.js';
import { server } from './ontologies/server.js';
import { Store } from './store.js';
import { LoroLoader } from './loro-loader.js';

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
  localStorage.setItem('ws-disconnected', '1');
});

/**
 * The client database a tab talks to, reduced to what saving, reloading and
 * draining touch: resource rows with their snapshots, and the outbox rows.
 * Shared between two `Store`s to stand in for a reload.
 */
class FakeClientDb {
  isReady = true;
  /** False while the database is still opening: writes reject until
   *  {@link finishOpening}, as the real one does once it is parked. */
  isOpen = true;
  private openWaiters: Array<(open: boolean) => void> = [];
  isInitialized = true;
  initError = undefined;
  unsupportedEnvironment = false;
  rows = new Map<string, { jsonAd: string; snapshot: Uint8Array | null }>();
  outbox = new Map<string, Map<string, string>>();
  /** Every outbox write, and whether it was made durable before resolving. */
  outboxWrites: Array<{ write: ClientDbOutboxWrite; durable: boolean }> = [];
  putCalls: Array<{ subject: string; outbox?: ClientDbOutboxWrite }> = [];

  async waitForReady() {
    return true;
  }

  whenOpen(_timeoutMs: number): Promise<boolean> {
    if (this.isOpen) return Promise.resolve(true);

    return new Promise(resolve => this.openWaiters.push(resolve));
  }

  finishOpening() {
    this.isOpen = true;
    this.openWaiters.splice(0).forEach(resolve => resolve(true));
  }

  async waitForInit() {
    return true;
  }

  async flush() {}

  async putResourceWithSnapshot(
    subject: string,
    jsonAd: string,
    snapshot?: Uint8Array,
    outbox?: ClientDbOutboxWrite,
  ) {
    if (!this.isOpen) throw new Error('ClientDb unavailable: still opening');
    this.putCalls.push({ subject, outbox });
    this.rows.set(subject, { jsonAd, snapshot: snapshot ?? null });
    if (outbox) this.applyOutbox(outbox, true);
  }

  async getResourceWithSnapshot(subject: string) {
    return this.rows.get(subject) ?? { jsonAd: null, snapshot: null };
  }

  async getResourcesWithSnapshots(subjects: string[]) {
    return Promise.all(subjects.map(s => this.getResourceWithSnapshot(s)));
  }

  async removeResource(subject: string) {
    this.rows.delete(subject);
  }

  async outboxEntries(agent: string) {
    return [...(this.outbox.get(agent)?.values() ?? [])];
  }

  async outboxWrite(write: ClientDbOutboxWrite, durable: boolean) {
    this.applyOutbox(write, durable);
  }

  private applyOutbox(write: ClientDbOutboxWrite, durable: boolean) {
    this.outboxWrites.push({ write, durable });
    const rows = this.outbox.get(write.agent) ?? new Map<string, string>();
    for (const subject of write.deletes) rows.delete(subject);
    for (const { subject, value } of write.puts) rows.set(subject, value);
    this.outbox.set(write.agent, rows);
  }

  queued(agent: string): Array<Record<string, unknown>> {
    return [...(this.outbox.get(agent)?.values() ?? [])].map(v =>
      JSON.parse(v),
    );
  }
}

/** A tab: a Store signed in as `agent`, its commits posted to a spy. */
async function tab(agent: Agent, db: FakeClientDb, connected: boolean) {
  const store = new Store({ serverUrl: 'https://example.com' });
  store.setServerConnected(connected);
  store.setAgent(agent);

  const posted: Commit[] = [];
  const postCommitSpy = vi.fn(async (commit: Commit) => {
    const created = {
      ...commit,
      id: `https://example.com/commits/${commit.signature}`,
    } as Commit;
    posted.push(created);

    return created;
  });
  (
    store as unknown as { client: { postCommit: typeof postCommitSpy } }
  ).client.postCommit = postCommitSpy;
  vi.spyOn(store, 'getProperty').mockRejectedValue(
    new Error('property validation skipped'),
  );
  store.injectFetch(async () => {
    throw new Error('network disabled');
  });

  store.setClientDb(db as unknown as ClientDbWorker);
  await store.outbox.whenHydrated();

  return { store, posted, postCommitSpy };
}

async function newAgent(): Promise<Agent> {
  const keys = await Agent.generateKeyPair();

  return new Agent(
    new JSCryptoProvider(keys.privateKey),
    `did:ad:agent:${keys.publicKey}`,
  );
}

describe('the outbox in the client database', () => {
  it.each(['genesis', 'edit', 'destroy', 'legacy-edit'] as const)(
    'replays a cold %s to its original drive server after the default changes',
    async operation => {
      const agent = await newAgent();
      const db = new FakeClientDb();
      const first = await tab(agent, db, true);
      const destination = 'https://tenant.example.com:8443';
      const drive = await first.store.newResource({
        isA: server.classes.drive,
        noParent: true,
      });
      first.store.setDriveServer(drive.subject, destination);
      first.store.reportServerConnection(destination, true);
      await drive.save();
      const resource = await first.store.newResource({ parent: drive.subject });
      if (operation !== 'genesis') await resource.save();
      first.store.reportServerConnection(destination, false);

      if (operation === 'destroy') await resource.destroy();
      else {
        await resource.set(core.properties.name, 'Queued on the tenant', false);
        await resource.save();
      }

      await first.store.outbox.flush();
      expect(db.queued(agent.subject!)).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            subject: resource.subject,
            route: { drive: drive.subject, server: destination },
          }),
        ]),
      );
      first.store.setServerConnected(false);

      if (operation === 'legacy-edit') {
        for (const [subject, value] of db.outbox.get(agent.subject!)!) {
          const entry = JSON.parse(value);
          delete entry.route;
          db.outbox.get(agent.subject!)!.set(subject, JSON.stringify(entry));
        }

        localStorage.removeItem(`atomic.outbox.${agent.subject}`);
      }

      const reload = await tab(agent, db, false);
      reload.store.setServerUrl('https://another.example.com');
      reload.store.reportServerConnection(destination, true);
      await reload.store.syncDirtyResources();
      expect(reload.postCommitSpy).toHaveBeenCalled();
      expect(
        reload.postCommitSpy.mock.calls.every(
          ([, endpoint]) => endpoint === `${destination}/commit`,
        ),
      ).toBe(true);
      expect(reload.store.outbox.hasPending(resource.subject)).toBe(false);
      reload.store.reportServerConnection(destination, false);
    },
  );

  it('keeps the existing home title when creating another drive after reload', async () => {
    const agent = await newAgent();
    const db = new FakeClientDb();
    const first = await tab(agent, db, false);
    const home = await first.store.createDrive('My named home', {
      localOnly: true,
    });
    const second = await tab(agent, db, false);

    await second.store.createDrive('Project', {
      personal: false,
      localOnly: true,
    });

    const restored = await second.store.getResource(home.subject);
    expect(restored.get(core.properties.name)).toBe('My named home');
  });

  it('creates a server-backed home when local storage is unsupported', async () => {
    const db = new FakeClientDb();
    db.unsupportedEnvironment = true;
    db.isReady = false;
    const { store } = await tab(await newAgent(), db, true);
    vi.spyOn(db, 'getResourceWithSnapshot').mockRejectedValue(
      new Error('ClientDb unavailable: unsupported environment'),
    );
    const home = await store.createDrive('Server home');
    expect(home.get(core.properties.name)).toBe('Server home');
    expect(store.outbox.hasPending(home.subject)).toBe(false);
    store.setServerConnected(false);
  });

  it('does not overwrite a home when its local database read fails', async () => {
    const agent = await newAgent();
    const db = new FakeClientDb();
    const first = await tab(agent, db, false);
    await first.store.createDrive('My named home', { localOnly: true });
    const second = await tab(agent, db, false);
    const writes = db.putCalls.length;
    vi.spyOn(db, 'getResourceWithSnapshot').mockRejectedValue(
      new Error('database read failed'),
    );

    await expect(
      second.store.createDrive('Project', { personal: false, localOnly: true }),
    ).rejects.toThrow('database read failed');
    expect(db.putCalls).toHaveLength(writes);
  });

  it('keeps edits made after a cached genesis while saving online', async () => {
    const db = new FakeClientDb();
    const { store, posted } = await tab(await newAgent(), db, true);
    const doc = await store.newResource({
      noParent: true,
      propVals: { [core.properties.name]: 'Before' },
    });
    await doc.persistToClientDb();
    await doc.set(core.properties.name, 'After the cached snapshot', false);
    await doc.save();
    const received = new LoroLoader.Loro.LoroDoc();

    for (const commit of posted) {
      if (commit.subject === doc.subject && commit.loroUpdate)
        received.import(commit.loroUpdate);
    }

    expect(received.getMap('properties').get(core.properties.name)).toBe(
      'After the cached snapshot',
    );
    expect(doc.get(core.properties.name)).toBe('After the cached snapshot');
    store.setServerConnected(false);
  });

  it('merges an offline snapshot without discarding newer in-memory edits', async () => {
    const db = new FakeClientDb();
    const { store, posted } = await tab(await newAgent(), db, true);
    const doc = await store.newResource({
      noParent: true,
      propVals: { [core.properties.name]: 'Before' },
    });
    await doc.save();
    store.setServerConnected(false);
    await doc.set(core.properties.description, 'Saved while offline', false);
    await doc.save();
    await doc.set(core.properties.name, 'Newer unsaved title', false);

    store.setServerConnected(true);
    await store.syncDirtyResources();
    const received = new LoroLoader.Loro.LoroDoc();

    for (const commit of posted) {
      if (commit.subject === doc.subject && commit.loroUpdate)
        received.import(commit.loroUpdate);
    }

    expect(received.getMap('properties').get(core.properties.name)).toBe(
      'Newer unsaved title',
    );
    expect(received.getMap('properties').get(core.properties.description)).toBe(
      'Saved while offline',
    );
    expect(store.outbox.hasPending(doc.subject)).toBe(false);
    store.setServerConnected(false);
  });

  it.each([
    { opened: false, legacy: false, reloadBeforeEdit: false },
    { opened: true, legacy: false, reloadBeforeEdit: false },
    { opened: false, legacy: true, reloadBeforeEdit: false },
    { opened: true, legacy: true, reloadBeforeEdit: false },
    { opened: false, legacy: false, reloadBeforeEdit: true },
  ])(
    'sends body edits after offline genesis across reload ($opened, legacy: $legacy, reloaded before edit: $reloadBeforeEdit)',
    async ({ opened, legacy, reloadBeforeEdit }) => {
      const agent = await newAgent();
      const db = new FakeClientDb();
      const first = await tab(agent, db, false);
      let doc = await first.store.newResource({
        noParent: true,
        isA: 'https://atomicdata.dev/classes/DocumentV2',
        propVals: { [core.properties.name]: 'Offline document' },
      });
      await doc.save();

      if (reloadBeforeEdit) {
        const editor = await tab(agent, db, false);
        doc = await editor.store.getResource(doc.subject);
      }

      doc.getLoroDoc()!.getText('body').insert(0, 'alpha after genesis');
      doc.getLoroDoc()!.commit();
      doc.markDirty();
      await doc.save();

      if (legacy) {
        // Queues written before this fix have the full local snapshot but
        // no baseline for any edit while genesis was still unposted.
        for (const rows of db.outbox.values()) {
          const row = JSON.parse(rows.get(doc.subject)!);
          delete row.baseVersion;
          rows.set(doc.subject, JSON.stringify(row));
        }
      }

      const second = await tab(agent, db, false);
      if (opened) await second.store.getResource(doc.subject);
      second.store.setServerConnected(true);
      await second.store.syncDirtyResources();

      const received = new LoroLoader.Loro.LoroDoc();

      for (const commit of second.posted) {
        if (commit.subject === doc.subject && commit.loroUpdate) {
          received.import(commit.loroUpdate);
        }
      }

      expect(received.getText('body').toString()).toBe('alpha after genesis');
      expect(second.store.outbox.hasPending(doc.subject)).toBe(false);
      second.store.setServerConnected(false);
    },
  );

  it('an offline edit survives a reload and drains on reconnect', async () => {
    const agent = await newAgent();
    const db = new FakeClientDb();
    const first = await tab(agent, db, true);
    expect(first.store.outbox.isStoredIn(db)).toBe(true);

    const doc = await first.store.newResource({
      isA: server.classes.drive,
      noParent: true,
      propVals: { [core.properties.name]: 'Before' },
    });
    await expect(doc.save()).resolves.toBe('persisted');
    expect(first.posted).toHaveLength(1);
    await Promise.resolve();
    expect(db.queued(agent.subject!)).toEqual([]);

    first.store.setServerConnected(false);
    await doc.set(core.properties.name, 'Edited offline');
    await expect(doc.save()).resolves.toBe('offline');

    // The snapshot and its outbox row went in the same write.
    const offlinePut = db.putCalls.at(-1)!;
    expect(offlinePut.subject).toBe(doc.subject);
    expect(offlinePut.outbox?.puts.map(p => p.subject)).toEqual([doc.subject]);
    const [row] = db.queued(agent.subject!);
    expect(row.subject).toBe(doc.subject);
    expect(typeof row.baseVersion).toBe('string');
    expect(first.store.getSyncStatus().pendingDirtyCount).toBe(1);
    expect(localStorage.getItem(`atomic.outbox.${agent.subject}`)).toBeNull();

    // Reload: a new tab starts with nothing in memory and reads the queue
    // from the database.
    const second = await tab(agent, db, false);
    expect(second.store.outbox.getEntry(doc.subject)?.baseVersion).toBe(
      row.baseVersion,
    );
    // The Sync page lists the restored entry as pending.
    expect(
      second.store
        .getCommitLog()
        .some(e => e.subject === doc.subject && e.status === 'pending'),
    ).toBe(true);

    second.store.setServerConnected(true);
    await second.store.syncDirtyResources();

    expect(second.posted).toHaveLength(1);
    const commit = second.posted[0];
    expect(commit.subject).toBe(doc.subject);
    expect(commit.isGenesis).toBeFalsy();
    expect(commit.loroUpdate).toBeTruthy();
    expect(second.store.outbox.hasPending(doc.subject)).toBe(false);
    await Promise.resolve();
    expect(db.queued(agent.subject!)).toEqual([]);
    second.store.setServerConnected(false);
  });

  it('an offline save waits for a database that is still opening', async () => {
    const agent = await newAgent();
    const db = new FakeClientDb();
    db.isOpen = false;
    const { store } = await tab(agent, db, false);

    const doc = await store.newResource({
      isA: server.classes.drive,
      noParent: true,
      propVals: { [core.properties.name]: 'Made while opening' },
    });
    let outcome: string | undefined;
    const saving = doc.save().then(
      result => (outcome = result),
      e => (outcome = `threw: ${e.message}`),
    );

    // The write has nowhere else to go, so it must not fail while the open
    // is merely slow.
    await new Promise(resolve => setTimeout(resolve, 20));
    expect(outcome).toBeUndefined();
    expect(db.putCalls).toHaveLength(0);

    db.finishOpening();
    await saving;
    expect(outcome).toBe('offline');
    expect(db.putCalls.at(-1)?.subject).toBe(doc.subject);
    expect(db.queued(agent.subject!).map(r => r.subject)).toEqual([
      doc.subject,
    ]);
  });

  it('an offline create keeps its signed genesis across a reload', async () => {
    const agent = await newAgent();
    const db = new FakeClientDb();
    const first = await tab(agent, db, false);

    const doc = await first.store.newResource({
      isA: server.classes.drive,
      noParent: true,
      propVals: { [core.properties.name]: 'Made offline' },
    });
    await expect(doc.save()).resolves.toBe('offline');

    const [row] = db.queued(agent.subject!);
    expect(row.subject).toBe(doc.subject);
    expect(row.signedGenesis).toBeTruthy();
    // Written durably: a genesis cannot be signed again after a crash.
    expect(db.outboxWrites.every(w => w.durable)).toBe(true);

    const second = await tab(agent, db, true);
    expect(
      second.store.outbox.getEntry(doc.subject)?.signedGenesis,
    ).toBeTruthy();
    await second.store.syncDirtyResources();

    expect(second.posted[0]?.subject).toBe(doc.subject);
    expect(second.posted[0]?.isGenesis).toBe(true);
    expect(second.store.outbox.hasPending(doc.subject)).toBe(false);
    second.store.setServerConnected(false);
  });

  it('an offline delete is on disk before destroy() resolves', async () => {
    const agent = await newAgent();
    const db = new FakeClientDb();
    const first = await tab(agent, db, true);
    const doc = await first.store.newResource({
      isA: server.classes.drive,
      noParent: true,
      propVals: { [core.properties.name]: 'Doomed' },
    });
    await doc.save();
    first.store.setServerConnected(false);

    await doc.destroy();

    const rows = db.queued(agent.subject!);
    expect(rows.map(r => r.subject)).toEqual([doc.subject]);
    expect(rows[0].signedDestroy).toBeTruthy();
    expect(db.outboxWrites.at(-1)?.durable).toBe(true);

    const second = await tab(agent, db, true);
    expect(second.store.hasPendingDestroy(doc.subject)).toBe(true);
    await second.store.syncDirtyResources();
    expect(second.posted.map(c => c.destroy)).toEqual([true]);
    expect(second.store.outbox.hasPending(doc.subject)).toBe(false);
    second.store.setServerConnected(false);
  });

  it('moves a queue an older build kept in localStorage into the database', async () => {
    const agent = await newAgent();
    localStorage.setItem(
      `atomic.outbox.${agent.subject}`,
      JSON.stringify([
        { subject: 'did:ad:pending-edit', enqueuedAt: 3, baseVersion: 'AAEC' },
      ]),
    );
    const db = new FakeClientDb();
    const { store } = await tab(agent, db, false);

    expect(store.outbox.getEntry('did:ad:pending-edit')?.baseVersion).toBe(
      'AAEC',
    );
    expect(db.queued(agent.subject!)).toEqual([
      { subject: 'did:ad:pending-edit', enqueuedAt: 3, baseVersion: 'AAEC' },
    ]);
    expect(localStorage.getItem(`atomic.outbox.${agent.subject}`)).toBeNull();
  });

  it('keeps using localStorage with a database that has no outbox', async () => {
    const agent = await newAgent();
    const store = new Store({ serverUrl: 'https://example.com' });
    store.setAgent(agent);
    store.setClientDb({
      isReady: true,
      putResourceWithSnapshot: async () => undefined,
    } as unknown as ClientDbWorker);
    await store.outbox.whenHydrated();

    store.outbox.markDirty('did:ad:x');
    await store.outbox.flush();

    expect(localStorage.getItem(`atomic.outbox.${agent.subject}`)).toContain(
      'did:ad:x',
    );
  });
});
