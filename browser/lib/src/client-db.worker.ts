/**
 * Web Worker that hosts the WASM ClientDb.
 * Communicates with the main thread via typed postMessage.
 *
 * The WASM module URL is passed as the first message after creation.
 */

import { openClientDb, isStorageBlockedDbError } from './client-db-open.js';
import { wasmBinaryUrl } from './wasm-url.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type WasmModule = any;

let db: WasmModule | null = null;
let initPromise: Promise<ClientDbInitTimings> | null = null;

/** Message types sent from main thread to worker */
export type WorkerRequest =
  | { id: number; type: 'canSendPeerFrame'; session: number; subject: string }
  | {
      id: number;
      type: 'createPeerSession';
      drive: string;
      expectedPeer?: string;
      challenge: string;
    }
  | { id: number; type: 'handlePeerFrame'; session: number; frame: Uint8Array }
  | { id: number; type: 'closePeerSession'; session: number }
  | {
      id: number;
      type: 'init';
      wasmUrl: string;
      /** The binary behind `wasmUrl`, compiled by the page ahead of time. */
      wasmModule?: WebAssembly.Module;
      baseUrl?: string;
      /** OPFS file name of the database; the WASM side defaults to the
       *  legacy shared `atomic_data.redb` when omitted. */
      dbName?: string;
      /** Encryption key for the database file. */
      dbKey?: Uint8Array;
      /** Migrate the legacy shared DB into `dbName` before opening. */
      migrateLegacy?: boolean;
      /** Allow discarding an undecryptable `dbName`; see `client-db-open.ts`. */
      discardUndecryptable?: boolean;
      /**
       * Drives that exist only in this browser (`Store.registerLocalOnlyDrive`).
       * Chat messages are moved into chat log pages for these alone; a drive a
       * server hosts gets its pages from the server.
       */
      localOnlyDrives?: string[];
    }
  | { id: number; type: 'getResource'; subject: string }
  | { id: number; type: 'getResourceWithSnapshot'; subject: string }
  | { id: number; type: 'getResourcesWithSnapshots'; subjects: string[] }
  | { id: number; type: 'putResource'; jsonAd: string }
  | { id: number; type: 'putResources'; jsonAds: string[] }
  | {
      id: number;
      type: 'putResourceWithSnapshot';
      subject: string;
      jsonAd: string;
      snapshot?: Uint8Array;
      /** Outbox rows written with the resource and made durable by the same
       *  flush, so a crash keeps both or neither. */
      outbox?: OutboxWrite;
    }
  | {
      id: number;
      type: 'putResourcesWithSnapshots';
      /** Written in one transaction and made durable by one flush. */
      items: {
        jsonAd: string;
        snapshot?: Uint8Array;
        outbox?: OutboxWrite;
      }[];
    }
  | { id: number; type: 'outboxEntries'; agent: string }
  | ({ id: number; type: 'outboxWrite'; durable: boolean } & OutboxWrite)
  | { id: number; type: 'applyCommit'; commitJsonAd: string }
  | { id: number; type: 'applyPeerCommit'; commitJsonAd: string }
  | { id: number; type: 'removeResource'; subject: string }
  | {
      id: number;
      type: 'query';
      property?: string;
      value?: string;
      filters?: Array<{ property?: string; value?: string; operator?: string }>;
      sortBy?: string;
      sortDesc?: boolean;
      limit?: number;
      offset?: number;
      includeResources?: boolean;
      drive?: string;
      /** Statistics over every matching resource — computed in WASM by the same
       *  Rust code the server runs. */
      aggregation?: unknown;
      /** Constraints on values computed per resource, evaluated in the same WASM
       *  pass. */
      expressionFilters?: unknown;
    }
  | {
      id: number;
      type: 'search';
      query: string;
      limit?: number;
      parents?: string | string[];
      filters?: Record<string, string | number | string[]>;
    }
  | { id: number; type: 'allSubjects' }
  | { id: number; type: 'populate' }
  | { id: number; type: 'flush' }
  | { id: number; type: 'exportAllResources' }
  | { id: number; type: 'importAllResources'; jsonArray: string }
  | { id: number; type: 'getLoroSnapshot'; subject: string }
  | { id: number; type: 'historyAttribution'; subject: string }
  | { id: number; type: 'envelopesFor'; subjects: string[] }
  | { id: number; type: 'importEnvelopes'; envelopes: string }
  | { id: number; type: 'putBlob'; hash: Uint8Array; data: Uint8Array }
  | { id: number; type: 'getBlob'; hash: Uint8Array }
  | { id: number; type: 'blake3Hash'; data: Uint8Array }
  | { id: number; type: 'getAllVersionVectors' }
  | { id: number; type: 'getVersionVectorsForDrive'; drive: string }
  | { id: number; type: 'getDriveSubjects'; drive: string }
  | {
      id: number;
      type: 'applyStateUpdates';
      subjects: string[];
      states: Uint8Array[];
    }
  | { id: number; type: 'getVersionVectorsForSubjects'; subjects: string[] }
  | { id: number; type: 'indexPendingSearch'; limit: number }
  // Cloud Vault. These live in the worker because it holds the only Db handle;
  // the network half stays on the main thread, where the control-plane session
  // and CORS setup already work. What crosses this boundary is ciphertext.
  | {
      id: number;
      type: 'vaultExport';
      driveSubject: string;
      key: Uint8Array;
      keyEpoch: number;
      drivePseudonym: string;
      devicePubkey: string;
      segment: number;
      checkpointN: number;
      driveHasCheckpoint: boolean;
      observedLanes: Record<string, number>;
      currentStateOnly?: boolean;
    }
  | {
      id: number;
      type: 'vaultImport';
      key: Uint8Array;
      keyEpoch: number;
      drivePseudonym: string;
      devicePubkey: string;
      objects: { objectKey: string; sealed: Uint8Array }[];
    }
  | {
      id: number;
      type: 'vaultCommitSegment';
      drivePseudonym: string;
      devicePubkey: string;
      segment: number;
    };

/** Outbox rows for one agent; mirrors `ClientDbOutboxWrite` in client-db.ts
 *  (duplicated, not imported: see the note on shared modules there). */
interface OutboxWrite {
  agent: string;
  puts: Array<{ subject: string; value: string }>;
  deletes: string[];
}

function writeOutbox(write: OutboxWrite): void {
  db!.outboxWrite(
    write.agent,
    JSON.stringify(write.puts),
    JSON.stringify(write.deletes),
  );
}

/** Message types sent from worker back to main thread */
export type WorkerResponse =
  | { id: number; type: 'ok'; data?: unknown }
  | { id: number; type: 'error'; message: string };

async function handleMessage(msg: WorkerRequest): Promise<unknown> {
  switch (msg.type) {
    case 'canSendPeerFrame':
      await ensureInit();

      return db!.canSendPeerFrame(msg.session, msg.subject);
    case 'createPeerSession':
      await ensureInit();

      return db!.createPeerSession(msg.drive, msg.expectedPeer, msg.challenge);
    case 'handlePeerFrame':
      await ensureInit();

      return db!.handlePeerFrame(msg.session, msg.frame);
    case 'closePeerSession':
      await ensureInit();

      return db!.closePeerSession(msg.session);

    case 'init': {
      // Return the per-phase init timings so the main thread can fold the
      // worker-side WASM/OPFS boot into its perf trace.
      if (initPromise) {
        return await initPromise;
      }

      initPromise = doInit(
        msg.wasmUrl,
        msg.wasmModule,
        msg.baseUrl,
        msg.dbName,
        msg.dbKey,
        msg.migrateLegacy,
        msg.discardUndecryptable,
        msg.localOnlyDrives,
      );

      return await initPromise;
    }

    case 'getResource': {
      await ensureInit();

      return db!.getResource(msg.subject);
    }

    case 'getResourcesWithSnapshots': {
      // One round trip for a whole list: opening a chat asks for every
      // message and part at once, and a postMessage per subject queued
      // behind boot-time sync traffic made that the slow part of the open.
      await ensureInit();
      const rows: Array<{
        jsonAd: string | null;
        snapshot: Uint8Array | null;
      }> = [];

      for (const subject of msg.subjects) {
        rows.push(await db!.getResourceWithSnapshot(subject));
      }

      return rows;
    }

    case 'getResourceWithSnapshot': {
      // One wasm call reads the stored row and its snapshot, without
      // decoding the CRDT history on the way (the tab imports the
      // snapshot into its own doc). One round trip instead of two for
      // every `fetchResourceWithLocalFallback`.
      await ensureInit();

      return db!.getResourceWithSnapshot(msg.subject);
    }

    case 'putResource': {
      await ensureInit();
      await db!.putResource(msg.jsonAd);

      return;
    }

    case 'putResources': {
      // Batch put: each individual `putResource` call costs one
      // postMessage round-trip. The startup seed loop in the data-
      // browser writes ~200 resources right after the WASM init —
      // batching them into one message saves ~200 postMessages of
      // overhead. The worker still processes them in order, so any
      // ordering-sensitive caller (properties seeded before others)
      // can keep its current sequencing.
      await ensureInit();

      for (const jsonAd of msg.jsonAds) {
        await db!.putResource(jsonAd);
      }

      return;
    }

    case 'putResourceWithSnapshot': {
      // One transaction: row, index entries and the Loro snapshot as the
      // tab holds it. Snapshot omitted for resources without a Loro doc
      // (e.g. Commit resources).
      await ensureInit();

      if (msg.snapshot) {
        await db!.putResourceWithSnapshot(msg.jsonAd, msg.snapshot);
      } else {
        await db!.putResource(msg.jsonAd);
      }

      // The outbox entry that says this snapshot still has to reach the
      // server. Both writes commit without fsync, so the one flush below
      // persists them together: redb rolls back every commit after the last
      // durable one, so a crash before it keeps neither, never just one.
      if (msg.outbox) writeOutbox(msg.outbox);

      // Per-write redb commits use `Durability::None` — see the periodic
      // `flush()` tick below. Everywhere else that's fine (the periodic
      // tick catches up within `FLUSH_INTERVAL_MS`), but this op is the
      // one `resource.ts` `persistToClientDb` uses specifically because
      // its caller (`saveOffline`) needs the write durable the moment its
      // promise resolves — an offline edit has no server copy to fall
      // back on. Without an immediate flush here, a reload landing before
      // the next tick reads the pre-edit (or entirely absent) state and
      // silently drops the offline edit.
      // Leave a periodic retry armed on failure, and reject the RPC so a
      // caller never mistakes an in-memory write for a durable snapshot.
      dirty = true;
      db!.flush();
      dirty = false;

      return;
    }

    case 'putResourcesWithSnapshots': {
      // What a burst of `putResourceWithSnapshot` calls costs one at a time:
      // a transaction each, so a page every resource touches (the parent's
      // member list, the name index) is written again per resource. Together
      // they share one commit and one flush.
      await ensureInit();
      await db!.putResourcesWithSnapshots(
        msg.items.map(item => item.jsonAd),
        msg.items.map(item => item.snapshot ?? null),
      );

      for (const item of msg.items) {
        if (item.outbox) writeOutbox(item.outbox);
      }

      dirty = true;
      db!.flush();
      dirty = false;

      return;
    }

    case 'outboxEntries': {
      await ensureInit();

      return db!.outboxEntries(msg.agent) as string[];
    }

    case 'outboxWrite': {
      await ensureInit();
      writeOutbox(msg);

      // Envelopes (a signed genesis or destroy) and offline cursors are
      // written durably; a plain dirty bit waits for the periodic tick.
      if (msg.durable) {
        dirty = true;
        db!.flush();
        dirty = false;
      } else {
        dirty = true;
      }

      return;
    }

    case 'applyPeerCommit':
      await ensureInit();

      return db!.applyPeerCommit(msg.commitJsonAd);

    case 'applyCommit': {
      await ensureInit();
      await db!.applyCommit(msg.commitJsonAd);

      return;
    }

    case 'removeResource': {
      await ensureInit();
      await db!.removeResource(msg.subject);

      return;
    }

    case 'query': {
      await ensureInit();

      return db!.query(
        msg.property ?? null,
        msg.value ?? null,
        msg.sortBy ?? null,
        msg.sortDesc ?? null,
        msg.limit ?? null,
        msg.offset ?? null,
        msg.includeResources ?? null,
        msg.drive ?? null,
        msg.filters ?? null,
        msg.aggregation ?? null,
        msg.expressionFilters ?? null,
      );
    }

    case 'search': {
      await ensureInit();

      return db!.search(
        msg.query,
        msg.limit ?? null,
        msg.parents ?? null,
        msg.filters ?? null,
      );
    }

    case 'allSubjects': {
      await ensureInit();

      return db!.allSubjects();
    }

    case 'populate': {
      await ensureInit();
      await db!.populate();

      return;
    }

    case 'flush': {
      await ensureInit();
      // Durability on demand. Writes commit with `Durability::None` and are
      // only persisted by a later Immediate commit, which otherwise happens
      // on the periodic tick below — so until it lands, a reload rolls the
      // writes back. Callers that are about to do something a rollback would
      // ruin (reload, navigate away, go offline) need to be able to ask for
      // it rather than wait and hope.
      db!.flush();
      dirty = false;

      return;
    }

    case 'exportAllResources': {
      await ensureInit();

      return db!.exportAllResources();
    }

    case 'importAllResources': {
      await ensureInit();

      return db!.importAllResources(msg.jsonArray);
    }

    case 'getLoroSnapshot': {
      await ensureInit();

      return db!.getLoroSnapshot(msg.subject);
    }

    case 'historyAttribution': {
      await ensureInit();

      return (await db!.historyAttribution(msg.subject)) as string;
    }

    case 'envelopesFor': {
      await ensureInit();

      return db!.envelopesFor(JSON.stringify(msg.subjects)) as string;
    }

    case 'importEnvelopes': {
      await ensureInit();

      return (await db!.importEnvelopes(msg.envelopes)) as number;
    }

    case 'putBlob': {
      await ensureInit();
      db!.putBlob(msg.hash, msg.data);

      return;
    }

    case 'getBlob': {
      await ensureInit();

      return db!.getBlob(msg.hash);
    }

    case 'blake3Hash': {
      await ensureInit();

      return db!.blake3Hash(msg.data);
    }

    case 'getAllVersionVectors': {
      await ensureInit();

      return db!.getAllVersionVectors();
    }

    case 'vaultExport': {
      await ensureInit();

      return db!.vaultExport(
        msg.driveSubject,
        msg.key,
        msg.keyEpoch,
        msg.drivePseudonym,
        msg.devicePubkey,
        msg.segment,
        // `checkpoint_n` is a u64 on the Rust side; wasm-bindgen wants a
        // BigInt for it and throws "Cannot convert 1 to a BigInt" for a
        // Number, which failed every automatic backup in the browser.
        BigInt(msg.checkpointN),
        msg.driveHasCheckpoint,
        msg.observedLanes,
        msg.currentStateOnly ?? false,
      );
    }

    case 'vaultImport': {
      await ensureInit();
      const summary = await db!.vaultImport(
        msg.key,
        msg.keyEpoch,
        msg.drivePseudonym,
        msg.devicePubkey,
        msg.objects,
      );
      // A restore writes a whole drive behind `Durability::None`, so without
      // persisting it here those writes wait for the next flush tick.
      //
      // Marking dirty is not enough: the tick is 1s away and the caller
      // reloads the page the moment this resolves (`onRestored` in
      // `VaultPanel`), so the reload regularly wins that race and the drive
      // comes back empty — a restore that reported success and silently did
      // nothing, which is the precise failure this is meant to prevent.
      //
      // A restore is one bulk write, so the amortisation the tick exists for
      // does not apply. Flush now; we are already inside the work queue, so
      // this cannot race an in-flight mutation.

      try {
        db!.flush();
      } catch (e) {
        // Fall back to the tick rather than failing a restore that did land.
        dirty = true;
        console.error('[ClientDb] flush after vault import failed:', e);
      }

      return summary;
    }

    case 'vaultCommitSegment': {
      await ensureInit();
      db!.vaultCommitSegment(msg.drivePseudonym, msg.devicePubkey, msg.segment);
      // Backup completion must survive an immediate reload. Waiting for the
      // periodic tick loses the cursor and uploads the same data again.
      // Keep the retry armed if flush fails, but propagate that failure so
      // the caller cannot report a durably completed backup.
      dirty = true;
      db!.flush();
      dirty = false;

      return undefined;
    }

    case 'getVersionVectorsForDrive': {
      await ensureInit();

      return db!.getVersionVectorsForDrive(msg.drive);
    }

    case 'applyStateUpdates': {
      await ensureInit();
      // Search entries are about three quarters of a pulled resource's index
      // writes; they are added afterwards by `indexPendingSearch`.
      const applied = await db!.applyStateUpdates(
        msg.subjects,
        msg.states,
        true,
      );

      dirty = true;

      return applied;
    }

    case 'indexPendingSearch': {
      await ensureInit();
      const done = await db!.indexPendingSearch(msg.limit);

      if (done > 0) dirty = true;

      return done;
    }

    case 'getDriveSubjects': {
      await ensureInit();

      return db!.getDriveSubjects(msg.drive);
    }

    case 'getVersionVectorsForSubjects': {
      await ensureInit();

      return db!.getVersionVectorsForSubjects(msg.subjects);
    }

    default:
      throw new Error(`Unknown message type: ${(msg as WorkerRequest).type}`);
  }
}

/**
 * Per-phase init timings (ms), measured on the worker's own clock and returned
 * to the main thread in the `init` ack so the OPFS/WASM boot — which is
 * otherwise invisible to the main-thread perf trace — shows up in
 * `__atomicPerf`. Durations are clock-independent, so no epoch reconciliation
 * is needed.
 */
export interface ClientDbInitTimings {
  wasmImportMs: number;
  wasmInstantiateMs: number;
  dbOpenMs: number;
  totalMs: number;
}

const round2 = (n: number) => Math.round(n * 100) / 100;

async function doInit(
  wasmUrl: string,
  wasmModule: WebAssembly.Module | undefined,
  baseUrl?: string,
  dbName?: string,
  dbKey?: Uint8Array,
  migrateLegacy?: boolean,
  discardUndecryptable?: boolean,
  localOnlyDrives?: string[],
): Promise<ClientDbInitTimings> {
  // Dynamic import of the WASM glue code.
  // The URL should point to the directory containing atomic_wasm.js and atomic_wasm_bg.wasm
  const t0 = performance.now();
  const wasm = await import(/* webpackIgnore: true */ wasmUrl);
  const t1 = performance.now();
  // Compile + instantiate the WASM module. The binary is named explicitly
  // instead of left to wasm-bindgen's `import.meta.url` default, which would
  // drop any version query on `wasmUrl` and pair this glue with a binary from
  // a different build — see `wasmBinaryUrl`.
  await wasm.default({ module_or_path: wasmModule ?? wasmBinaryUrl(wasmUrl) });
  const t2 = performance.now();

  // One-time migration of the legacy shared DB file into the per-agent
  // `dbName`. Must run BEFORE `ClientDb.open` takes the OPFS handle. A failed
  // migration must not block opening the new DB — the legacy file is left in
  // place for a later attempt.
  if (migrateLegacy && dbName && dbName !== 'atomic_data.redb') {
    try {
      await wasm.migrateLegacyClientDb(dbName, dbKey ?? undefined);
    } catch (e) {
      // When the browser is withholding storage there is no legacy file to
      // migrate and never will be, so this failure is expected and says
      // nothing the open below won't say better. Staying quiet here avoids
      // reporting the same condition twice, with a stack trace, per load.
      if (!isStorageBlockedDbError(e)) {
        console.warn('[ClientDb] legacy DB migration failed:', e);
      }
    }
  }

  // `ClientDb.open` opens the OPFS-backed database (acquire OPFS handle, open
  // redb, run migrations). `openClientDb` adds one recovery step: an existing
  // file this agent's key can no longer decrypt is deleted and recreated — but
  // only when the caller passed `discardUndecryptable`, having established that
  // the key is unrecoverable rather than just missing here. Every other open
  // failure still propagates.
  const opened = await openClientDb(wasm, {
    baseUrl: baseUrl ?? undefined,
    dbName: dbName ?? undefined,
    dbKey: dbKey ?? undefined,
    discardUndecryptable: discardUndecryptable ?? false,
  });
  db = opened.db;
  await migrateIndexKeys(db);
  await migrateMessages(db, localOnlyDrives ?? []);
  const t3 = performance.now();

  return {
    wasmImportMs: round2(t1 - t0),
    wasmInstantiateMs: round2(t2 - t1),
    dbOpenMs: round2(t3 - t2),
    totalMs: round2(t3 - t0),
  };
}

/** Resources the index rebuild handles per slice: small enough to report
 *  often, large enough that the round trips cost nothing. */
const INDEX_MIGRATION_SLICE = 100;

/**
 * Rebuilds the atom indexes of a database written with an older key layout,
 * before anything is served from it (a query would miss rows). Progress goes to
 * the page as `migration-progress` messages. Runs inside `init`, so the page
 * only sees the database as ready once this is done.
 */
async function migrateIndexKeys(opened: WasmModule): Promise<void> {
  if (!opened.indexMigrationPending?.()) return;

  const report = (done: number, total: number, finished: boolean) =>
    self.postMessage({ type: 'migration-progress', done, total, finished });

  report(0, 0, false);

  for (;;) {
    const step = JSON.parse(opened.migrateIndexKeysStep(INDEX_MIGRATION_SLICE));
    report(step.done, step.total, step.finished);

    if (step.finished) return;

    // Let the worker answer other messages (they queue behind `init`).
    await new Promise(resolve => setTimeout(resolve, 0));
  }
}

/** Messages the chat migration handles per slice (whole chats at a time). */
const MESSAGE_MIGRATION_SLICE = 500;

/**
 * Moves old chat messages into chat log pages (`planning/chat-log.md`): the
 * `Message` resources of group chats and comments, then the `ai-message`
 * resources of AI chats. Pages are written for the drives that exist only in
 * this browser; for a drive a server hosts the server makes them and this only
 * drops cached messages that already have their entry. Progress goes to the page
 * as `migration-progress` messages, like the index rebuild. Runs inside
 * `init`.
 */
async function migrateMessages(
  opened: WasmModule,
  localOnlyDrives: string[],
): Promise<void> {
  const drives = JSON.stringify(localOnlyDrives);

  await runChatMigration(opened.messageMigrationPending?.(), () =>
    opened.migrateMessagesStep(MESSAGE_MIGRATION_SLICE, drives),
  );
  await runChatMigration(opened.aiChatMigrationPending?.(), () =>
    opened.migrateAiChatsStep(MESSAGE_MIGRATION_SLICE, drives),
  );
}

async function runChatMigration(
  pending: boolean | undefined,
  step: () => Promise<string>,
): Promise<void> {
  if (!pending) return;

  const report = (done: number, total: number, finished: boolean) =>
    self.postMessage({
      type: 'migration-progress',
      phase: 'messages',
      done,
      total,
      finished,
    });

  report(0, 0, false);

  for (;;) {
    const result = JSON.parse(await step());
    report(result.done, result.total, result.finished);

    if (result.finished) return;

    await new Promise(resolve => setTimeout(resolve, 0));
  }
}

async function ensureInit(): Promise<void> {
  if (initPromise) {
    await initPromise;
  }

  if (!db) {
    throw new Error('ClientDb not initialized. Send an "init" message first.');
  }
}

// Serialize all message handling. Without this, an `async self.onmessage`
// dispatcher invokes a fresh handler per incoming message, all running
// concurrently — a `query` posted right after a burst of `putResource`
// messages would race the puts and return empty results because the index
// writes hadn't landed yet. Symptom: on initial drive-sync, every
// `useCollection`/`useChildren` would do a redundant `/query` GET to the
// server because the local DB query came back with 0 hits.
let workQueue: Promise<void> = Promise.resolve();

// Message types that mutate the DB. After any of these we owe the OPFS a
// durable `flush()` (see below).
const WRITE_OPS: ReadonlySet<WorkerRequest['type']> = new Set([
  'putResource',
  'putResources',
  'applyCommit',
  'removeResource',
  'putBlob',
  'importAllResources',
  'populate',
]);

// Per-write redb commits use `Durability::None` (no fsync) for throughput;
// they're only persisted to OPFS once a *subsequent* Immediate commit
// (`db.flush()`) lands. Without that, every write is rolled back on the next
// open (a page reload) — invisible online (the server re-fetches) but data
// loss when offline. So we flush on a short periodic tick whenever there have
// been writes since the last flush, mirroring the native server's flush tick
// (server/src/serve.rs). One fsync amortises a whole sync burst instead of
// paying one per write; an idle tab (no writes) does nothing.
const FLUSH_INTERVAL_MS = 1000;
let dirty = false;

setInterval(() => {
  if (!dirty || !db) return;

  dirty = false;
  // Route the flush through the same queue as writes so it never races an
  // in-flight mutation against the single redb instance.
  workQueue = workQueue.then(async () => {
    try {
      db!.flush();
    } catch (e) {
      // Re-arm so the next tick retries; a transient flush failure shouldn't
      // permanently strand un-persisted writes.
      dirty = true;
      console.error('[ClientDb] OPFS flush failed:', e);
    }
  });
}, FLUSH_INTERVAL_MS);

type ApplyStatesRequest = Extract<WorkerRequest, { type: 'applyStateUpdates' }>;

/** The most resources one coalesced write carries. */
const MAX_COALESCED_STATES = 2000;

/** Pulled states that arrived while the worker was busy, with no other message
 *  between them. They are applied as one transaction, so a page that several
 *  of them touch (a parent's member list, the search index) is written once.
 *  A first pull queues dozens of batches of 100 faster than they are stored. */
let statesBuffer: { msgs: ApplyStatesRequest[]; count: number } | null = null;

function respond(id: number, outcome: { data: unknown } | { error: unknown }) {
  const response: WorkerResponse =
    'error' in outcome
      ? {
          id,
          type: 'error',
          message:
            outcome.error instanceof Error
              ? outcome.error.message
              : String(outcome.error),
        }
      : { id, type: 'ok', data: outcome.data };

  self.postMessage(response);
}

function queueApplyStates(msg: ApplyStatesRequest): void {
  if (statesBuffer && statesBuffer.count < MAX_COALESCED_STATES) {
    statesBuffer.msgs.push(msg);
    statesBuffer.count += msg.subjects.length;

    return;
  }

  const buffer = { msgs: [msg], count: msg.subjects.length };

  statesBuffer = buffer;
  workQueue = workQueue.then(async () => {
    // Messages that piled up while the worker was busy are dispatched before
    // this timer fires, so they join the buffer instead of queueing behind it.
    await new Promise(resolve => setTimeout(resolve, 30));

    if (statesBuffer === buffer) statesBuffer = null;

    try {
      await handleMessage({
        id: msg.id,
        type: 'applyStateUpdates',
        subjects: buffer.msgs.flatMap(m => m.subjects),
        states: buffer.msgs.flatMap(m => m.states),
      });
      dirty = true;
      buffer.msgs.forEach(m => respond(m.id, { data: m.subjects.length }));
    } catch (error) {
      buffer.msgs.forEach(m => respond(m.id, { error }));
    }
  });
}

self.onmessage = (event: MessageEvent<WorkerRequest>) => {
  const msg = event.data;

  if (msg.type === 'applyStateUpdates') {
    queueApplyStates(msg);

    return;
  }

  // Anything else closes the buffer, so a later message cannot overtake it.
  // Envelopes ride along with every chunk of a pull and depend on nothing
  // in it, so they do not.
  if (msg.type !== 'importEnvelopes') statesBuffer = null;
  workQueue = workQueue.then(async () => {
    try {
      const data = await handleMessage(msg);

      if (WRITE_OPS.has(msg.type)) dirty = true;

      const response: WorkerResponse = { id: msg.id, type: 'ok', data };
      self.postMessage(response);
    } catch (e) {
      const response: WorkerResponse = {
        id: msg.id,
        type: 'error',
        message: e instanceof Error ? e.message : String(e),
      };
      self.postMessage(response);
    }
  });
};
