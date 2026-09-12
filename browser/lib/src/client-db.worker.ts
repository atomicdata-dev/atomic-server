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
      baseUrl?: string;
      /** OPFS file name of the database; the WASM side defaults to the
       *  legacy shared `atomic_data.redb` when omitted. */
      dbName?: string;
      /** Encryption key for the database file. */
      dbKey?: Uint8Array;
      /** Migrate the legacy shared DB into `dbName` before opening. */
      migrateLegacy?: boolean;
    }
  | { id: number; type: 'getResource'; subject: string }
  | { id: number; type: 'getResourceWithSnapshot'; subject: string }
  | { id: number; type: 'putResource'; jsonAd: string }
  | { id: number; type: 'putResources'; jsonAds: string[] }
  | {
      id: number;
      type: 'putResourceWithSnapshot';
      subject: string;
      jsonAd: string;
      snapshot?: Uint8Array;
    }
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
  | { id: number; type: 'putBlob'; hash: Uint8Array; data: Uint8Array }
  | { id: number; type: 'getBlob'; hash: Uint8Array }
  | { id: number; type: 'blake3Hash'; data: Uint8Array }
  | { id: number; type: 'getAllVersionVectors' }
  | { id: number; type: 'getVersionVectorsForDrive'; drive: string }
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
        msg.baseUrl,
        msg.dbName,
        msg.dbKey,
        msg.migrateLegacy,
      );

      return await initPromise;
    }

    case 'getResource': {
      await ensureInit();

      return db!.getResource(msg.subject);
    }

    case 'getResourceWithSnapshot': {
      // Combined getter for the cold-load fast path: every
      // `fetchResourceWithLocalFallback` used to do two sequential
      // worker round-trips (one for the JSON-AD, one for the Loro
      // snapshot). On a page that mounts 30 useResource hooks that's
      // 60× postMessage cost serially. Returning both in a single
      // response halves the worker traffic — and the caller already
      // ignores the snapshot when JSON-AD is null, so the combined
      // shape doesn't change semantics.
      //
      // Both calls MUST be awaited before being placed in the response
      // object. wasm-bindgen renders `getResource` / `getLoroSnapshot`
      // as Promise-returning JS functions; embedding a Promise in the
      // response makes `postMessage` throw "could not be cloned" and
      // every cold-load OPFS lookup fails — fell back to a much-slower
      // WS GET path, which is what surfaced as widespread e2e timeouts.
      await ensureInit();
      const jsonAd = await db!.getResource(msg.subject);
      const snapshot = jsonAd ? await db!.getLoroSnapshot(msg.subject) : null;

      return { jsonAd: jsonAd ?? null, snapshot: snapshot ?? null };
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
      // Atomic write: JSON-AD index entry + (optional) Loro snapshot
      // in one postMessage. Snapshot omitted for resources without
      // a Loro doc (e.g. Commit resources).
      await ensureInit();
      await db!.putResource(msg.jsonAd);
      if (msg.snapshot) db!.putLoroSnapshot(msg.subject, msg.snapshot);

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
  baseUrl?: string,
  dbName?: string,
  dbKey?: Uint8Array,
  migrateLegacy?: boolean,
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
  await wasm.default({ module_or_path: wasmBinaryUrl(wasmUrl) });
  const t2 = performance.now();

  // One-time migration of the legacy shared DB file into the per-agent
  // `dbName`. Must run BEFORE `new ClientDb` takes the OPFS handle. A failed
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

  // `new ClientDb` opens the OPFS-backed database (acquire OPFS handle, open
  // redb, run migrations). `openClientDb` adds one recovery step: an existing
  // file this agent's key can no longer decrypt is deleted and recreated,
  // because it is a cache whose contents are unreadable either way. Every
  // other open failure still propagates.
  const opened = await openClientDb(wasm, {
    baseUrl: baseUrl ?? undefined,
    dbName: dbName ?? undefined,
    dbKey: dbKey ?? undefined,
  });
  db = opened.db;
  const t3 = performance.now();

  return {
    wasmImportMs: round2(t1 - t0),
    wasmInstantiateMs: round2(t2 - t1),
    dbOpenMs: round2(t3 - t2),
    totalMs: round2(t3 - t0),
  };
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

self.onmessage = (event: MessageEvent<WorkerRequest>) => {
  const msg = event.data;
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
