import { describe, it, vi } from 'vitest';
import { encodeB64Url } from './base64.js';
import { encodeGenesisCert, genesisSignerDid } from './genesis.js';
import {
  localizeInternalSubject,
  normalizeLoroChangeTimestampMs,
  Resource,
} from './resource.js';
import type { JSONValue } from './value.js';
import { testStore } from './test-store.js';
import { core } from './index.js';

describe('resource.ts', () => {
  it('push propvals', ({ expect }) => {
    const resource = new Resource('test');
    const testsubject = 'https://example.com/testsubject';
    resource.push(
      'https://atomicdata.dev/properties/subresources',
      [testsubject],
      true,
    );
    resource.push(
      'https://atomicdata.dev/properties/subresources',
      [testsubject],
      true,
    );

    expect(
      resource.get('https://atomicdata.dev/properties/subresources'),
    ).toStrictEqual([testsubject]);

    const testsubject2 = 'https://example.com/testsubject2';

    resource.push(
      'https://atomicdata.dev/properties/subresources',
      [testsubject2, testsubject2],
      true,
    );

    expect(
      resource.get('https://atomicdata.dev/properties/subresources'),
    ).toStrictEqual([testsubject, testsubject2]);

    resource.push('https://atomicdata.dev/properties/subresources', [
      testsubject,
      testsubject,
    ]);

    expect(
      resource.get('https://atomicdata.dev/properties/subresources'),
    ).toStrictEqual([testsubject, testsubject2, testsubject, testsubject]);
  });

  it('getCreatedAt / getCreatedBy read the genesis change, surviving a snapshot round-trip', async ({
    expect,
  }) => {
    const subject = 'https://example.com/created-test';
    const description = 'https://atomicdata.dev/properties/description';
    // `signChanges` writes the signing agent's subject into the genesis Loro
    // change message; mirror that here with an explicit commit message.
    const agentSubject = 'did:ad:agent:testpubkey';
    // Millisecond-precise genesis timestamp (what the runtime stamps via
    // `Date.now()`), so `createdAt` is sub-second precise — not rounded to a
    // whole second by Loro's default auto-record.
    const createdAtMs = 1_700_000_123_456;

    const original = new Resource(subject);
    await original.set(description, 'hello', false);
    original
      .getLoroDoc()!
      .commit({ message: agentSubject, timestamp: createdAtMs });

    expect(original.getCreatedBy()).toBe(agentSubject);
    expect(original.getCreatedAt()).toBe(createdAtMs);

    // Simulate a refresh: hydrate a fresh Resource from the exported snapshot.
    // Creator + timestamp must come back from the oplog alone — no commit fetch.
    const snapshot = original.getLoroDoc()!.export({ mode: 'snapshot' });
    const reloaded = new Resource(subject);
    reloaded.importLoroUpdate(snapshot);

    expect(reloaded.getCreatedBy()).toBe(agentSubject);
    expect(reloaded.getCreatedAt()).toBe(createdAtMs);
  });

  it('getCreatedBy is undefined when the genesis change carries no message', async ({
    expect,
  }) => {
    const resource = new Resource('https://example.com/no-creator');
    await resource.set(
      'https://atomicdata.dev/properties/description',
      'x',
      false,
    );
    resource.getLoroDoc()!.commit();

    expect(resource.getCreatedBy()).toBeUndefined();
  });

  it('getCreatedAt / getCreatedBy prefer the genesis certificate over projections', async ({
    expect,
  }) => {
    const resource = new Resource('https://example.com/propval-wins');
    const cert = {
      signerPubkey: new Uint8Array(32).fill(7),
      createdAt: 1_700_001_234_567,
      nonce: new Uint8Array(16).fill(9),
      parent: '',
      drive: '',
    };
    await resource.set(
      'https://atomicdata.dev/properties/description',
      'hi',
      false,
    );
    // Oplog genesis carries one creator/time...
    resource
      .getLoroDoc()!
      .commit({ message: 'did:ad:agent:oplog', timestamp: 1_700_000_000_000 });
    // ...but the server/WASM-materialized propvals (as served in JSON-AD) are
    // authoritative and must win.
    await resource.set(
      'https://atomicdata.dev/properties/createdAt',
      1_700_000_999_999,
      false,
    );
    await resource.set(
      'https://atomicdata.dev/properties/createdBy',
      'did:ad:agent:materialized',
      false,
    );
    await resource.set(
      'https://atomicdata.dev/properties/genesis',
      encodeB64Url(encodeGenesisCert(cert)),
      false,
    );

    expect(resource.getCreatedAt()).toBe(cert.createdAt);
    expect(resource.getCreatedBy()).toBe(genesisSignerDid(cert));

    const snapshot = resource.getLoroDoc()!.export({ mode: 'snapshot' });
    const reloaded = new Resource('did:ad:cert-resource');
    reloaded.importLoroUpdate(snapshot);

    expect(reloaded.getCreatedAt()).toBe(cert.createdAt);
    expect(reloaded.getCreatedBy()).toBe(genesisSignerDid(cert));
  });

  it('merges remote state without dropping local unsaved loro edits', async ({
    expect,
  }) => {
    const subject = 'https://example.com/merge-test';
    const name = 'https://atomicdata.dev/properties/name';
    const description = 'https://atomicdata.dev/properties/description';

    const base = new Resource(subject);
    await base.set(name, 'Base', false);
    const baseSnapshot = base.getLoroDoc()!.export({
      mode: 'snapshot',
    });

    const local = new Resource(subject);
    local.importLoroUpdate(baseSnapshot);
    await local.set(description, 'Local unsaved edit', false);

    const remoteSource = new Resource(subject);
    remoteSource.importLoroUpdate(baseSnapshot);
    await remoteSource.set(name, 'Remote update', false);
    const remoteSnapshot = remoteSource.getLoroDoc()!.export({
      mode: 'snapshot',
    });

    const remote = new Resource(subject);
    remote.importLoroUpdate(remoteSnapshot);

    local.merge(remote);

    expect(local.get(name)).toBe('Remote update');
    expect(local.get(description)).toBe('Local unsaved edit');
    expect(local.hasUnsavedChanges()).toBe(true);
  });

  /**
   * Regression: when JSON-AD arrives carrying a `loroUpdate` property after a
   * resource has a live Loro doc (e.g. after an unsaved local edit, or after
   * the user's own commit returns and a subsequent re-fetch happens), the
   * raw-value apply path used to tear the doc down. The next getLoroDoc()
   * would allocate a FRESH random peer whose ops were concurrent with
   * stored ops — Loro LWW silently dropped them. Now it must keep the
   * existing doc and merge the snapshot in.
   */
  it('normalizes Loro oplog timestamps in seconds or milliseconds', ({
    expect,
  }) => {
    expect(normalizeLoroChangeTimestampMs(1_700_000_000)).toBe(
      1_700_000_000_000,
    );
    expect(normalizeLoroChangeTimestampMs(1_700_000_000_000)).toBe(
      1_700_000_000_000,
    );
    expect(normalizeLoroChangeTimestampMs(0)).toBe(0);
  });

  it('records Loro oplog timestamps in seconds', async ({ expect }) => {
    const resource = new Resource('https://example.com/loro-timestamp');
    await resource.set('https://atomicdata.dev/properties/name', 'test', false);
    const doc = resource.getLoroDoc();
    expect(doc).toBeDefined();
    doc!.commit();

    const timestamps: number[] = [];

    for (const changes of doc!.getAllChanges().values()) {
      for (const change of changes) {
        if (change.timestamp > 0) {
          timestamps.push(change.timestamp);
        }
      }
    }

    expect(timestamps.length).toBeGreaterThan(0);

    for (const ts of timestamps) {
      expect(ts).toBeLessThan(1_000_000_000_000);
    }
  });

  it('keeps the same Loro peer across a loroUpdate hydration', async ({
    expect,
  }) => {
    const subject = 'https://example.com/peer-stability';
    const name = 'https://atomicdata.dev/properties/name';
    const loroUpdate = 'https://atomicdata.dev/properties/loroUpdate';

    const resource = new Resource(subject);
    await resource.set(name, '1', false);
    const doc = resource.getLoroDoc()!;
    const peerBefore = doc.peerIdStr;
    const serverSnapshot = doc.export({ mode: 'snapshot' });

    resource.applyHydratedValues([[loroUpdate, serverSnapshot]]);

    const peerAfter = resource.getLoroDoc()!.peerIdStr;
    expect(peerAfter).toBe(peerBefore);
  });

  /**
   * `replaceListItems` underpins the canvas history-scrub commit: dragging
   * the undo button releases at a historical Version, and we need to swap
   * the live stroke list to that Version's strokes in **one** undo
   * checkpoint, with the same LoroList container identity preserved so
   * concurrent remote writes against the old list still merge correctly.
   */
  it('replaceListItems swaps a list atomically and keeps container identity', async ({
    expect,
  }) => {
    const subject = 'https://example.com/replace-list';
    const prop = 'https://atomicdata.dev/ontology/canvas/strokeData';

    const resource = new Resource(subject);
    resource.pushListItem(prop, { color: 1, width: 2, path: [[0, 0]] });
    resource.pushListItem(prop, { color: 3, width: 4, path: [[1, 1]] });

    const doc = resource.getLoroDoc()!;
    const map = doc.getMap('properties');
    const originalListId = (map.get(prop) as unknown as { id?: string })?.id;

    resource.replaceListItems(prop, [{ color: 9, width: 9, path: [[2, 2]] }]);

    const items = resource.get(prop) as Record<string, unknown>[] | undefined;
    expect(items ?? []).toHaveLength(1);
    expect(items?.[0]?.color).toBe(9);

    // Same LoroList container — identity preserved so any concurrent
    // remote writes against the old container ID still target this one.
    const newListId = (
      doc.getMap('properties').get(prop) as unknown as { id?: string }
    )?.id;
    expect(newListId).toBe(originalListId);
  });

  /**
   * Opening a filled table (and the sidebar tree) flashed as if row/column
   * order changed. OPFS cold-load hydrates JSON-AD first — which seeds a
   * *new* LoroList per array property — then merges the stored snapshot,
   * whose lists have different container IDs. Concurrent LoroLists concatenate
   * or LWW-swap, so `requires`/`recommends` (table columns) and `isA` shuffle
   * for a frame. Merging an authoritative snapshot must keep the original
   * array order, not interleave the seed.
   */
  it('importing a snapshot over a cache-seeded doc keeps resource-array order', async ({
    expect,
  }) => {
    const recommends = 'https://atomicdata.dev/properties/recommends';
    const order = [
      'https://example.com/col/name',
      'https://example.com/col/date',
      'https://example.com/col/number',
      'https://example.com/col/checkbox',
      'https://example.com/col/select',
    ];

    const original = new Resource('https://example.com/table-class');
    await original.set(recommends, order, false);
    const snapshot = original.getLoroDoc()!.export({ mode: 'snapshot' });

    // OPFS JSON-AD is stored without the binary snapshot (`includeBinary:
    // false`), so hydration seeds Loro from the flattened array.
    const jsonAd = original.toObject({ includeBinary: false })!;
    const loaded = new Resource('https://example.com/table-class');
    loaded.applyHydratedValues(
      Object.entries(jsonAd).filter(([key]) => key !== '@id') as [
        string,
        JSONValue,
      ][],
    );
    loaded.getLoroDoc();
    expect(loaded.get(recommends)).toEqual(order);

    loaded.importLoroUpdate(snapshot);

    expect(loaded.get(recommends)).toEqual(order);
  });

  it('replace-import of an OPFS snapshot does not drop isA or duplicate arrays', async ({
    expect,
  }) => {
    const recommends = 'https://atomicdata.dev/properties/recommends';
    const name = 'https://atomicdata.dev/properties/name';
    const isA = core.properties.isA;
    const tableClass = 'https://atomicdata.dev/classes/Table';
    const order = [
      'https://example.com/col/name',
      'https://example.com/col/date',
      'https://example.com/col/number',
    ];

    const original = new Resource('https://example.com/table-replace');
    await original.set(isA, [tableClass], false);
    await original.set(name, 'TypedRefresh', false);
    await original.set(recommends, order, false);
    const snapshot = original.getLoroDoc()!.export({ mode: 'snapshot' });

    const jsonAd = original.toObject({ includeBinary: false })!;
    const loaded = new Resource('https://example.com/table-replace');
    loaded.applyHydratedValues(
      Object.entries(jsonAd).filter(([key]) => key !== '@id') as [
        string,
        JSONValue,
      ][],
    );
    loaded.getLoroDoc();
    loaded.loading = true;

    const { complete } = loaded.importLoroUpdate(snapshot, true);

    expect(complete).toBe(true);
    expect(loaded.loading).toBe(false);
    expect(loaded.get(isA)).toEqual([tableClass]);
    expect(loaded.get(name)).toBe('TypedRefresh');
    expect(loaded.get(recommends)).toEqual(order);
  });

  /**
   * Regression: drawing onto a canvas whose strokes were seeded in bulk via
   * `set()` (template/demo content) threw "pushContainer is not a function"
   * and the new stroke was dropped. `set()` must store an array of objects as
   * a LoroList of container elements — same shape `pushListItem` expects — so
   * the first freehand stroke appends cleanly onto the baked ones.
   */
  it('pushListItem appends onto strokes seeded in bulk via set()', async ({
    expect,
  }) => {
    const prop = 'https://atomicdata.dev/ontology/canvas/strokeData';
    const resource = new Resource('https://example.com/seeded-strokes');

    // Bulk seed, exactly how demo/template canvases are created.
    await resource.set(
      prop,
      [
        { color: 1, width: 2, path: [[0, 0]] },
        { color: 2, width: 2, path: [[1, 1]] },
      ],
      false,
    );

    // The first live stroke — previously threw.
    expect(() =>
      resource.pushListItem(prop, { color: 3, width: 4, path: [[2, 2]] }),
    ).not.toThrow();

    const items = resource.get(prop) as Array<{ color: number }>;
    expect(items).toHaveLength(3);
    expect(items.map(s => s.color)).toEqual([1, 2, 3]);
  });

  /**
   * Regression: tapping undo on the canvas showed "Saving…" but the strokes
   * didn't visually update. Cause: `Resource.undo()` modified the Loro doc
   * and cache but never fired `LocalChange`, so React consumers stayed on
   * the pre-undo cache. `undo()` / `redo()` must emit a wildcard
   * `LocalChange` so listeners reload from the cache.
   */
  /**
   * Regression: tap-undo "didn't undo" because each save() wrote bookkeeping
   * commits to the Loro doc (datatype-tag mirroring, `lastCommit` pointer)
   * that the UndoManager faithfully recorded as undo steps. So the user's
   * first undo press silently reverted the *housekeeping* commit instead
   * of their last visible edit — the symptom is "Saving… shows, but the
   * stroke doesn't disappear". The fix tags those system commits with
   * `SYSTEM_COMMIT_ORIGIN` and excludes that prefix from the UndoManager.
   * One user-visible push = one undo step.
   */
  it('one push + save consumes exactly one undo step', async ({ expect }) => {
    const { Resource: ResourceClass } = await import('./resource.js');
    const r = new ResourceClass('https://example.com/one-undo');
    r.getLoroDoc();
    r.ensureUndoManager();

    const prop = 'https://atomicdata.dev/ontology/canvas/strokeData';
    r.pushListItem(prop, { color: 1, width: 2, path: [[0, 0]] });
    r.getLoroDoc()?.commit();

    // Mimic the housekeeping write that real `save()` performs on the
    // server ack — this is the exact call that previously polluted the
    // undo history with a phantom step. `writeDatatypeTags` would also
    // qualify but needs a store to read property definitions; this
    // setLastCommitValue path is enough to exercise the bug and the fix.
    r.setLastCommitValue('did:ad:commit:fake-server-ack');

    expect((r.get(prop) as unknown[]).length).toBe(1);
    expect(r.canUndo()).toBe(true);

    // Single undo press → stroke removed, no further undo available.
    expect(r.undo()).toBe(true);
    expect((r.get(prop) as unknown[] | undefined) ?? []).toHaveLength(0);
    expect(r.canUndo()).toBe(false);
  });

  it('undo and redo emit a LocalChange event so UI re-reads', async ({
    expect,
  }) => {
    const { Resource: ResourceClass, ResourceEvents } =
      await import('./resource.js');
    const r = new ResourceClass('https://example.com/undo-event');
    // Materialise the Loro doc, then create the UndoManager so it observes
    // subsequent ops as undoable checkpoints (mirrors how CanvasPage wires
    // it up: `ensureUndoManager()` runs once the resource is loaded, then
    // user input produces undoable ops).
    r.getLoroDoc();
    r.ensureUndoManager();
    await r.set('https://atomicdata.dev/properties/name', 'two', false);
    // Force the doc to commit the pending op so the UndoManager records a
    // checkpoint. In real use this happens via pushListItem/save.
    r.getLoroDoc()?.commit();

    const undoEvents: unknown[] = [];
    const off = r.on(ResourceEvents.LocalChange, (prop, value) =>
      undoEvents.push({ prop, value }),
    );

    expect(r.undo()).toBe(true);
    expect(undoEvents.length).toBeGreaterThan(0);

    off();

    const redoEvents: unknown[] = [];
    const off2 = r.on(ResourceEvents.LocalChange, (prop, value) =>
      redoEvents.push({ prop, value }),
    );
    expect(r.redo()).toBe(true);
    expect(redoEvents.length).toBeGreaterThan(0);
    off2();
  });

  /**
   * Regression: the resource history page used to read only `getMap('properties')`,
   * so a Document's body content (which loro-prosemirror writes into a separate
   * top-level `doc` container) never showed up — only title/metadata edits did.
   * `getLoroHistory()` must surface every top-level container besides
   * `properties` in `Version.containers`.
   */
  it('captures body container content in version history', async ({
    expect,
  }) => {
    const subject = 'https://example.com/loro-history-doc';
    const name = 'https://atomicdata.dev/properties/name';

    const resource = new Resource(subject);
    await resource.set(name, 'Initial title', false);
    const doc = resource.getLoroDoc()!;
    doc.commit();

    // Simulate what loro-prosemirror does for Document bodies: write to a
    // top-level `doc` map, not the `properties` map.
    const docMap = doc.getMap('doc');
    docMap.set('content', 'Hello world body');
    doc.commit();

    await resource.set(name, 'Updated title', false);
    doc.commit();

    const history = resource.getLoroHistory();
    expect(history.length).toBeGreaterThan(0);

    // Every Version exposes `containers`, and at least one must carry the
    // body content we wrote into `doc`.
    for (const v of history) {
      expect(v.containers).toBeInstanceOf(Map);
    }

    const docContents = history
      .map(v => v.containers.get('doc'))
      .filter((c): c is Record<string, JSONValue> => c !== undefined);

    expect(docContents.length).toBeGreaterThan(0);
    expect(
      docContents.some(
        c => (c as Record<string, unknown>).content === 'Hello world body',
      ),
    ).toBe(true);

    // Sanity: the `properties` root must NOT leak into containers — it's
    // already exposed as propvals and would double-render in the UI.
    for (const v of history) {
      expect(v.containers.has('properties')).toBe(false);
    }
  });

  /**
   * Regression: rapid typing across two tabs lost everything past the
   * first character. Root cause: import / merge paths called the old
   * `markLoroSaved`, which captured the doc's CURRENT oplog version.
   * When the sender's own WS echo arrived mid-typing, that snapshot
   * already included the in-progress local edits — so the cursor leapt
   * past unsigned ops, and the next `exportLoroDelta` emitted a 22-byte
   * empty-header frame. Imports must not advance the export cursor.
   */
  it('importLoroUpdate does not advance the export cursor past local edits', async ({
    expect,
  }) => {
    const name = 'https://atomicdata.dev/properties/name';
    const r = new Resource('https://example.com/sync-cursor');
    await r.set(name, 'a', false);
    const doc = r.getLoroDoc()!;
    doc.commit();

    // Mimic the cursor state after a successful sign of "a".
    const lvasAtSign = doc.oplogVersion();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (r as any)._loroVersionAtLastSave = lvasAtSign;

    // User types another char before the echo lands.
    await r.set(name, 'ab', false);
    doc.commit();

    // Server echoes the first commit back. Bytes contain ops the doc
    // already has — Loro merges idempotently and the state is unchanged.
    const echoBytes = doc.export({ mode: 'update', from: lvasAtSign });
    void echoBytes; // not the echo body itself; we exercise the path:
    r.importLoroUpdate(doc.export({ mode: 'snapshot' }));

    // Cursor must still point at the post-sign-of-"a" version, NOT at
    // the doc's current version (which includes the unsigned "b" op).
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const lvasAfterEcho = (r as any)._loroVersionAtLastSave;
    expect(lvasAfterEcho.encode()).toEqual(lvasAtSign.encode());

    // The next export from that cursor must carry the "b" op, not a
    // header-only no-op.
    const delta = doc.export({ mode: 'update', from: lvasAfterEcho });
    expect(delta.length).toBeGreaterThan(40);
  });

  /**
   * Regression: `cloneLoroStateFrom` used to stamp the CLONE's current
   * oplog version as its save cursor whenever the source had any cursor.
   * A clone (or `merge(…, { replaceLoroDocs: true })`) of a resource
   * holding not-yet-drained local ops thereby marked those ops "already
   * saved" — the next export started past them and the edit silently
   * never reached the server. The clone must carry the source's cursor
   * VALUE.
   */
  it('clone preserves the save cursor value, keeping un-drained ops exportable', async ({
    expect,
  }) => {
    const name = 'https://atomicdata.dev/properties/name';
    const r = new Resource('https://example.com/clone-cursor');
    await r.set(name, 'a', false);
    const doc = r.getLoroDoc()!;
    doc.commit();

    // Cursor state after a successful sign of "a".
    const lvasAtSign = doc.oplogVersion();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (r as any)._loroVersionAtLastSave = lvasAtSign;

    // A local edit that has NOT been drained yet.
    await r.set(name, 'ab', false);
    doc.commit();
    expect(r.hasOpsPastSaveCursor()).toBe(true);

    const cloned = r.clone();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const clonedCursor = (cloned as any)._loroVersionAtLastSave;
    expect(clonedCursor.encode()).toEqual(lvasAtSign.encode());
    expect(cloned.hasOpsPastSaveCursor()).toBe(true);

    // The next export from the clone still carries the un-drained op.
    const delta = cloned
      .getLoroDoc()!
      .export({ mode: 'update', from: clonedCursor });
    expect(delta.length).toBeGreaterThan(40);
  });
});

describe('Resource.merge Loro options', () => {
  it('replaceLoroDocs makes local state match remote state (drops local-only CRDT ops)', async ({
    expect,
  }) => {
    const subject = 'https://example.com/merge-loro-replace';
    const name = 'https://atomicdata.dev/properties/name';

    const local = new Resource(subject);
    await local.set(name, 'local-only', false);

    const remote = new Resource(subject);
    await remote.set(name, 'server', false);

    local.merge(remote, { replaceLoroDocs: true });

    expect(local.get(name)).toBe('server');
  });

  it('omitKeysFromMerge keeps local state and does not adopt remote state', async ({
    expect,
  }) => {
    const subject = 'https://example.com/merge-loro-omit';
    const name = 'https://atomicdata.dev/properties/name';

    const local = new Resource(subject);
    await local.set(name, 'baseline', false);

    const remote = new Resource(subject);
    await remote.set(name, 'live-with-ai', false);

    local.merge(remote, { omitKeysFromMerge: [name] });

    expect(local.get(name)).toBe('baseline');
  });

  /**
   * Regression: bootstrapped stubs carry an `incomplete` marker so visiting
   * the subject triggers a real fetch. The marker lives in the stub's local
   * Loro ops, and a CRDT merge UNIONS docs — so merging the fetched full
   * copy left the marker in place, and `getResourceLoading` kept refetching
   * forever. Merging a full copy must resolve the staleness.
   */
  it('drops the incomplete marker when merging in a full copy', async ({
    expect,
  }) => {
    const subject = 'https://example.com/merge-incomplete';
    const name = 'https://atomicdata.dev/properties/name';

    const stub = new Resource(subject);
    stub.applyHydratedValues([
      [core.properties.parent, 'https://example.com'],
      [core.properties.incomplete, true],
    ]);
    // Seed the stub's Loro doc so the merge goes down the CRDT-union path.
    stub.getLoroDoc();

    const full = new Resource(subject);
    await full.set(name, 'The real resource', false);
    full.loading = false;

    stub.merge(full);

    expect(stub.get(core.properties.incomplete)).toBeUndefined();
    expect(stub.get(name)).toBe('The real resource');
    expect(stub.loading).toBe(false);
  });

  it('keeps the incomplete marker when the incoming copy is itself incomplete', async ({
    expect,
  }) => {
    const subject = 'https://example.com/merge-still-incomplete';

    const stub = new Resource(subject);
    stub.applyHydratedValues([[core.properties.incomplete, true]]);
    stub.getLoroDoc();

    const alsoPartial = new Resource(subject);
    alsoPartial.applyHydratedValues([[core.properties.incomplete, true]]);
    alsoPartial.getLoroDoc();

    stub.merge(alsoPartial);

    expect(stub.get(core.properties.incomplete)).toBe(true);
  });
});

describe('getLoroHistory', () => {
  const name = 'https://atomicdata.dev/properties/name';
  const strokeData = 'https://atomicdata.dev/ontology/canvas/strokeData';

  const strokeCountOf = (v: { propvals: Map<string, JSONValue> }): number => {
    const sd = v.propvals.get(strokeData);

    return Array.isArray(sd) ? sd.length : 0;
  };

  /**
   * Regression: list edits commit without a message, so every edit between
   * drains collapsed into the unmessaged base bucket — history (and the
   * canvas scrub gesture built on it) only ever saw the latest state.
   * `commitLoroEdit` now tags each list mutation with a unique `e-` token,
   * so each one forms its own version.
   */
  it('keeps one version per local list edit', async ({ expect }) => {
    const r = new Resource('https://example.com/history-per-edit');
    await r.set(name, 'Canvas', false);
    r.getLoroDoc()!.commit();

    r.pushListItem(strokeData, { color: 1, width: 2, path: [[0, 0]] });
    r.pushListItem(strokeData, { color: 2, width: 2, path: [[1, 1]] });
    r.pushListItem(strokeData, { color: 3, width: 2, path: [[2, 2]] });
    r.replaceListItems(strokeData, [{ color: 9, width: 9, path: [[9, 9]] }]);

    const history = r.getLoroHistory();

    // Base state (no strokes), one version per push, then the replacement —
    // oldest first, ending at the current state.
    expect(history.map(strokeCountOf)).toEqual([0, 1, 2, 3, 1]);
    expect(history[history.length - 1].propvals.get(strokeData)).toEqual(
      r.get(strokeData),
    );
  });

  /**
   * The undo control needs to know whether anything older than "now" exists,
   * and that question was answered by materializing the entire history —
   * seconds of work on canvas open for a boolean nobody may ever act on.
   * The probe reads only change metadata.
   */
  describe('hasPriorLoroVersions', () => {
    it('is false for a resource whose only state is its current one', async ({
      expect,
    }) => {
      const r = new Resource('https://example.com/prior-none');
      await r.set(name, 'Canvas', false);
      r.getLoroDoc()!.commit();

      expect(r.hasPriorLoroVersions()).toBe(false);
    });

    it('is true once an edit leaves an older state behind', async ({
      expect,
    }) => {
      const r = new Resource('https://example.com/prior-some');
      await r.set(name, 'Canvas', false);
      r.getLoroDoc()!.commit();
      r.pushListItem(strokeData, { color: 1, width: 2, path: [[0, 0]] });

      expect(r.hasPriorLoroVersions()).toBe(true);
    });

    it('agrees with getLoroHistory without materializing anything', async ({
      expect,
    }) => {
      const r = new Resource('https://example.com/prior-agrees');
      await r.set(name, 'Canvas', false);
      r.getLoroDoc()!.commit();
      r.pushListItem(strokeData, { color: 1, width: 2, path: [[0, 0]] });
      r.pushListItem(strokeData, { color: 2, width: 2, path: [[1, 1]] });

      const doc = r.getLoroDoc()!;
      const fork = doc.fork.bind(doc);
      let forked = 0;
      vi.spyOn(doc, 'fork').mockImplementation(() => {
        forked++;

        return fork();
      });

      expect(r.hasPriorLoroVersions()).toBe(r.getLoroHistory().length > 1);
      // getLoroHistory forks to time-travel; the probe must not.
      expect(forked).toBe(1);
    });

    it('is false before the Loro WASM has produced a doc', ({ expect }) => {
      const r = new Resource('https://example.com/prior-no-doc');
      vi.spyOn(r, 'getLoroDoc').mockReturnValue(undefined);

      expect(r.hasPriorLoroVersions()).toBe(false);
    });
  });

  /**
   * Regression: history materialized *every* op counter — a checkout plus a
   * whole-document `toJSON()` each — then kept only the last one per bucket.
   * A canvas stores one op per stroke point, so opening a drawing with a few
   * thousand points spent seconds rebuilding states nothing ever read. Only
   * the last step of a bucket is observable, so only those get materialized.
   */
  it('materializes one state per version, not one per op', async ({
    expect,
  }) => {
    const r = new Resource('https://example.com/history-op-count');
    await r.set(name, 'Canvas', false);
    r.getLoroDoc()!.commit();

    // One edit carrying many ops — a single stroke with a long path is one
    // logical version but hundreds of Loro ops.
    const longPath = Array.from(
      { length: 400 },
      (_, i) => [i, i] as [number, number],
    );
    r.pushListItem(strokeData, { color: 1, width: 2, path: longPath });
    r.pushListItem(strokeData, { color: 2, width: 2, path: longPath });

    let opCount = 0;

    for (const changes of r.getLoroDoc()!.getAllChanges().values()) {
      for (const change of changes) {
        opCount += change.length;
      }
    }

    const doc = r.getLoroDoc()!;
    const fork = doc.fork.bind(doc);
    let checkouts = 0;
    vi.spyOn(doc, 'fork').mockImplementation(() => {
      const forked = fork();
      const checkout = forked.checkout.bind(forked);
      vi.spyOn(forked, 'checkout').mockImplementation(frontiers => {
        checkouts++;

        return checkout(frontiers);
      });

      return forked;
    });

    const history = r.getLoroHistory();

    expect(opCount).toBeGreaterThan(500);
    expect(history.map(strokeCountOf)).toEqual([0, 1, 2]);
    // One checkout per message bucket, independent of how many ops each
    // bucket spans. The bucket count is what may grow, never the op count.
    expect(checkouts).toBeLessThanOrEqual(history.length + 2);
  });

  /**
   * Regression: versions were deduped on `JSON.stringify` of raw `toJSON()`
   * output, whose map-key order depends on the path taken to reach the
   * version — jumping straight to one yields `{color, path, width}` where
   * replaying every op yields `{width, path, color}`. Identical states then
   * compared unequal, so whether a duplicate version collapsed depended on
   * how history happened to walk the doc. Key order is emitted by Loro, so
   * reproduce it here by shuffling the keys `toJSON()` hands back.
   */
  it('dedupes identical states regardless of map key order', async ({
    expect,
  }) => {
    const r = new Resource('https://example.com/history-key-order');
    await r.set(name, 'Canvas', false);
    r.getLoroDoc()!.commit();
    r.pushListItem(strokeData, { color: 1, width: 2, path: [[0, 0]] });
    r.replaceListItems(strokeData, [{ color: 1, width: 2, path: [[0, 0]] }]);

    const doc = r.getLoroDoc()!;
    const fork = doc.fork.bind(doc);
    let call = 0;
    vi.spyOn(doc, 'fork').mockImplementation(() => {
      const forked = fork();
      const toJSON = forked.toJSON.bind(forked);
      vi.spyOn(forked, 'toJSON').mockImplementation(() => {
        // Alternate key order per materialization without touching values.
        const reorder = (value: unknown): unknown => {
          if (!value || typeof value !== 'object') return value;

          if (Array.isArray(value)) return value.map(reorder);

          const keys = Object.keys(value as Record<string, unknown>);
          const ordered = call % 2 === 0 ? keys : [...keys].reverse();

          return Object.fromEntries(
            ordered.map(k => [k, reorder((value as never)[k])]),
          );
        };

        call++;

        return reorder(toJSON()) as ReturnType<typeof toJSON>;
      });

      return forked;
    });

    // The push and the replace leave the canvas in the same observable
    // state, so history must collapse them into one version — regardless of
    // the key order each materialization happened to come back in.
    expect(r.getLoroHistory().map(strokeCountOf)).toEqual([0, 1]);
  });

  /**
   * Regression: versions were sorted by (wall-clock timestamp, counter).
   * Second-resolution stamps tie for every edit in the same second and
   * counters are per-peer, so cross-peer order was arbitrary — a canvas
   * synced to a second device could show the genesis state *after* the
   * newest one, making scrub previews match the current screen. Lamport
   * order respects happened-before regardless of clocks.
   */
  it('orders versions causally even when timestamps tie across peers', async ({
    expect,
  }) => {
    vi.useFakeTimers();
    vi.setSystemTime(1_700_000_000_000);

    try {
      const subject = 'https://example.com/history-cross-peer';
      const first = new Resource(subject);
      await first.set(name, 'Original', false);
      first.getLoroDoc()!.commit({ timestamp: 1_700_000_000_000 });
      const snapshot = first.getLoroDoc()!.export({ mode: 'snapshot' });

      // A second device: fresh doc (different Loro peer id), same content.
      const second = new Resource(subject);
      second.importLoroUpdate(snapshot);
      second.pushListItem(strokeData, { color: 1, width: 2, path: [[0, 0]] });

      const history = second.getLoroHistory();
      expect(history.length).toBeGreaterThanOrEqual(2);

      // The base version comes first, the pushed-stroke state last — the
      // newest version must always be the current state.
      expect(strokeCountOf(history[0])).toBe(0);
      expect(history[0].propvals.get(name)).toBe('Original');
      expect(strokeCountOf(history[history.length - 1])).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('getCreatedBy ignores internal edit tokens on message-less docs', async ({
    expect,
  }) => {
    const r = new Resource('https://example.com/created-by-token-guard');
    // First-ever change is a tagged list edit (no signed genesis) — the
    // `e-` token must not leak out as the creator.
    r.pushListItem(strokeData, { color: 1, width: 2, path: [[0, 0]] });

    expect(r.getCreatedBy()).toBeUndefined();
  });
});

describe('subscribeLocalUpdates does not mark a `_new:` placeholder dirty', () => {
  // Regression: the interactive New-Resource form (`useNewForm.ts`) mints a
  // client-only `_new:` placeholder subject via `store.createSubject()` and
  // relies on `Resource.new` to stay true until an explicit `.save()` derives
  // the resource's real subject (see `_saveInner`'s genesis handling). If
  // something resets `.new` to false first (e.g. reconciling a fetch
  // response), the plain incremental dirty-tracking path used to enqueue an
  // outbox entry for the literal `_new:...` subject — a commit the server can
  // never accept — which then gets terminally dropped, refetched, and
  // re-armed on the next edit: an infinite "Dropped stuck commit" loop.
  it('does not enqueue an outbox entry for a `_new:` subject even if `new` is falsely false', async ({
    expect,
  }) => {
    const { store } = await testStore();

    const subject = `_new:${Math.random().toString(36).slice(2)}`;
    const resource = new Resource(subject, true);
    resource.setStore(store);

    // Simulate the reconciliation bug: something reset `new` before the
    // resource ever completed its genesis save.
    resource.new = false;

    await resource.set(core.properties.name, 'Incomplete Meeting', false);
    // `subscribeLocalUpdates` fires on the LoroDoc's commit boundary, not on
    // the buffered `.set()` itself — force it, mirroring what the real
    // debounced-save / drain path eventually does.
    resource.getLoroDoc()?.commit();

    expect(store.outbox.hasPending(subject)).toBe(false);
  });

  it('does enqueue a dirty entry for a real (non-`_new:`) subject once `new` is false', async ({
    expect,
  }) => {
    const { store, agentDID } = await testStore();

    const subject = `${agentDID}/some-resource`;
    const resource = new Resource(subject, true);
    resource.setStore(store);
    resource.new = false;

    await resource.set(core.properties.name, 'Real resource', false);
    resource.getLoroDoc()?.commit();

    expect(store.outbox.hasPending(subject)).toBe(true);
  });
});

describe('localizeInternalSubject', () => {
  const origin = 'https://atomicdata.dev';

  it('resolves internal subjects the way the server resolves them', ({
    expect,
  }) => {
    // The root drive keeps its trailing slash — this is the exact subject the
    // server serves for `internal:/`, so both spellings converge on one key.
    expect(localizeInternalSubject('internal:/', origin)).toBe(
      'https://atomicdata.dev/',
    );
    expect(
      localizeInternalSubject('internal:/01k4sg74k81tf8rr7d1m86vbkx', origin),
    ).toBe('https://atomicdata.dev/01k4sg74k81tf8rr7d1m86vbkx');
    expect(
      localizeInternalSubject('internal:/commits/FWAKdxeEs+w/Q==', origin),
    ).toBe('https://atomicdata.dev/commits/FWAKdxeEs+w/Q==');
    // A trailing slash on the origin must not double up.
    expect(localizeInternalSubject('internal:/abc', 'https://x.com/')).toBe(
      'https://x.com/abc',
    );
  });

  it('routes a tenant subject to its subdomain', ({ expect }) => {
    expect(localizeInternalSubject('internal:acme:/docs', origin)).toBe(
      'https://acme.atomicdata.dev/docs',
    );
  });

  it('leaves everything that is not an internal subject alone', ({
    expect,
  }) => {
    for (const value of [
      'https://atomicdata.dev/properties/parent',
      'did:ad:agent:abc',
      '_new:draft',
      '_local:thing',
      'Joep Meindertsma',
      '',
      // Prose that merely starts with the word — the guard requires a real
      // subject shape and no whitespace, so this is untouched.
      'internal: use the staging box for this',
      'internal:notasubject',
    ]) {
      expect(localizeInternalSubject(value, origin)).toBe(value);
    }
  });

  it('is idempotent', ({ expect }) => {
    const once = localizeInternalSubject('internal:/abc', origin);
    expect(localizeInternalSubject(once, origin)).toBe(once);
  });
});
