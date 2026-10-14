import { beforeAll, describe, it, vi } from 'vitest';
import { Store } from './store.js';
import { LoroLoader } from './loro-loader.js';
import { commits, core } from './index.js';

/**
 * #1905. A local query hands back JSON-AD, not snapshots, so the resources it
 * hydrates get a Loro doc rebuilt from values: new ops, by a new peer, with
 * none of the history. Two things went wrong from there.
 *
 * - That doc was written back to the local database, replacing the real
 *   history the query had just read the values from.
 * - The drive sync that follows a reload sends deltas from the version
 *   vectors the local database reported. None of them can apply to a doc
 *   without that history, so each one parked as "incomplete" and waited on a
 *   full snapshot from the server. In the atomic-plugins money e2e the app a
 *   table offers sat under that repair for the ten seconds the test waited
 *   for it in "+ Add view" (#1846).
 */

const SUBJECT = 'atomic:syncDeltaLocalBaseAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const RENDERS = 'atomic:resource:prop-renders';
const OWN = 'atomic:resource:class-own';
const TXN = 'atomic:resource:class-txn';

beforeAll(async () => {
  await LoroLoader.initializeLoro();
});

/** A resource's history as the local database and the server hold it: the
 *  local copy stops where this client last synced, the server has one edit
 *  more, and sends the difference as a delta. */
function history() {
  const { LoroDoc } = LoroLoader.Loro;
  const doc = new LoroDoc();
  doc.setPeerId(1n);
  const props = doc.getMap('properties');
  props.set(core.properties.isA, [core.classes.class]);
  props.set(core.properties.name, 'New app');
  props.set(RENDERS, [OWN]);
  props.set(commits.properties.lastCommit, 'atomic:commit:one');
  doc.commit();
  const local = doc.export({ mode: 'snapshot' }) as Uint8Array;
  const synced = doc.version();

  props.set(RENDERS, [OWN, TXN]);
  props.set(commits.properties.lastCommit, 'atomic:commit:two');
  doc.commit();

  return {
    local,
    delta: doc.export({ mode: 'update', from: synced } as never) as Uint8Array,
    json: JSON.stringify({
      '@id': SUBJECT,
      [core.properties.isA]: [core.classes.class],
      [core.properties.name]: 'New app',
      [RENDERS]: [OWN],
      [commits.properties.lastCommit]: 'atomic:commit:one',
    }),
  };
}

/** A store whose local database holds `local`, and whose server never
 *  answers: every repair here has to come from the local database. */
function storeWith(json: string, local: Uint8Array) {
  const store = new Store({ serverUrl: 'https://example.com' });
  const writes: Uint8Array[] = [];
  const asked: string[] = [];

  store.setClientDb({
    isReady: true,
    waitForReady: async () => true,
    waitForInit: async () => true,
    flush: async () => undefined,
    getResourceWithSnapshot: async () => ({ jsonAd: json, snapshot: local }),
    putResourceWithSnapshot: async (
      _subject: string,
      _json: string,
      snapshot?: Uint8Array,
    ) => {
      if (snapshot) writes.push(snapshot);
    },
    removeResource: async () => undefined,
  } as never);

  store.fetchResourceFromServer = (async (subject: string) => {
    asked.push(subject);

    return new Promise(() => undefined);
  }) as never;

  return { store, writes, asked };
}

const settle = () => new Promise(resolve => setTimeout(resolve, 20));

describe('a sync delta for a resource with no local Loro history', () => {
  it('does not write a doc rebuilt from JSON-AD back to the local database', async ({
    expect,
  }) => {
    const { json, local } = history();
    const { store, writes } = storeWith(json, local);

    store.hydrateResourceFromJsonAd(SUBJECT, json);
    await settle();

    expect(writes).toEqual([]);
  });

  it('applies on the local history, without waiting for the server', async ({
    expect,
  }) => {
    const { json, local, delta } = history();
    const { store, asked } = storeWith(json, local);

    // What the table page's app query does after a reload.
    store.hydrateResourceFromJsonAd(SUBJECT, json);

    // Then the drive sync.
    store.applyIncoming({
      subject: SUBJECT,
      loroBytes: delta,
      source: 'ws-sync-push',
    });
    await settle();

    const resource = store.resources.get(SUBJECT)!;
    expect(resource.get(RENDERS)).toEqual([OWN, TXN]);
    expect(resource.isReady()).toBe(true);
    expect(asked).toEqual([]);
  });

  it('applies on the local history when the delta is the first word of it', async ({
    expect,
  }) => {
    const { json, local, delta } = history();
    const { store, asked } = storeWith(json, local);

    store.applyIncoming({
      subject: SUBJECT,
      loroBytes: delta,
      source: 'ws-sync-push',
    });
    await settle();

    const resource = store.resources.get(SUBJECT)!;
    expect(resource.get(RENDERS)).toEqual([OWN, TXN]);
    expect(resource.get(core.properties.name)).toBe('New app');
    expect(resource.isReady()).toBe(true);
    expect(asked).toEqual([]);
  });

  it('writes the repaired doc, history and all, to the local database', async ({
    expect,
  }) => {
    const { json, local, delta } = history();
    const { store, writes } = storeWith(json, local);

    store.hydrateResourceFromJsonAd(SUBJECT, json);
    store.applyIncoming({
      subject: SUBJECT,
      loroBytes: delta,
      source: 'ws-sync-push',
    });
    await settle();

    expect(writes.length).toBe(1);
    const { LoroDoc } = LoroLoader.Loro;
    const written = new LoroDoc();
    written.import(writes[0]);
    // Only the peer that wrote the history: no stand-in ops from a rebuild.
    expect([
      ...(written.oplogVersion().toJSON() as Map<string, number>).keys(),
    ]).toEqual(['1']);
  });

  it('does not warn about, or bring back, a resource deleted during the repair', async ({
    expect,
  }) => {
    // The delete e2e: a sync delta for a child parks as incomplete, the local
    // database has no base for it, and while the repair waits the parent's
    // delete cascades to the child. The server's "not found" is then right.
    const { json, delta } = history();
    const { store } = storeWith(json, new Uint8Array());
    let answer!: (error: Error) => void;
    store.fetchResourceFromServer = (() =>
      new Promise((_, reject) => {
        answer = reject;
      })) as never;
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    store.hydrateResourceFromJsonAd(SUBJECT, json);
    store.applyIncoming({
      subject: SUBJECT,
      loroBytes: delta,
      source: 'ws-sync-push',
    });
    await settle();
    store.removeResource(SUBJECT);
    answer(new Error(`DID Resource ${SUBJECT} not found locally`));
    await settle();

    expect(warn).not.toHaveBeenCalled();
    expect(store.resources.get(SUBJECT)).toBeUndefined();
    warn.mockRestore();
  });

  it('does not ask the server about a resource already deleted', async ({
    expect,
  }) => {
    const { json, delta } = history();
    const { store, asked } = storeWith(json, new Uint8Array());

    store.hydrateResourceFromJsonAd(SUBJECT, json);
    store.removeResource(SUBJECT);
    store.applyIncoming({
      subject: SUBJECT,
      loroBytes: delta,
      source: 'ws-sync-push',
    });
    await settle();

    expect(asked).toEqual([]);
  });

  it('still asks the server when the local database has no base either', async ({
    expect,
  }) => {
    const { json, delta } = history();
    const { store, asked } = storeWith(json, new Uint8Array());

    store.hydrateResourceFromJsonAd(SUBJECT, json);
    store.applyIncoming({
      subject: SUBJECT,
      loroBytes: delta,
      source: 'ws-sync-push',
    });
    await settle();

    expect(asked).toEqual([SUBJECT]);
  });
});
