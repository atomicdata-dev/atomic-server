/**
 * ClientDbWorker: typed async wrapper around the WASM ClientDb.
 *
 * Multi-tab strategy: **leader-owns-DB + BroadcastChannel fanout**.
 *
 * - Every tab constructs a `ClientDbWorker`. Each tab `navigator.locks.request`s
 *   the `atomic-db-leader:<dbName>` lock.
 * - One tab gets the lock — it becomes the **leader**. The leader spawns a
 *   dedicated worker, opens the OPFS handle, and answers DB calls locally.
 * - Other tabs are **followers**. They forward every DB call over a
 *   `BroadcastChannel` to the leader and await a response tagged by their
 *   tab id + request id.
 * - When the leader tab closes, its lock releases; a waiting follower's lock
 *   callback fires and it promotes itself to leader.
 *
 * Why not SharedWorker: Firefox/Safari don't expose `createSyncAccessHandle`
 * in SharedWorker, and Playwright's headless Chromium doesn't expose
 * `Worker` inside SharedWorker scope. Plain DedicatedWorker + navigator.locks
 * works in every evergreen browser and every automation runner.
 *
 * Usage:
 * ```ts
 * const clientDb = new ClientDbWorker('/wasm/atomic_wasm.js', '/wasm/client-db-worker.js');
 * await clientDb.init('https://myserver.com');
 * ```
 */

import {
  parseHistoryAttribution,
  type HistoryAttribution,
} from './history-attribution.js';
import type {
  Aggregation,
  AggregateOutcome,
  ExpressionFilter,
} from './collection.js';
import type {
  WorkerRequest,
  WorkerResponse,
  ClientDbInitTimings,
} from './client-db.worker.js';
import { perfMark, perfSpan } from './perf-trace.js';

/**
 * Duplicated from `client-db-open.ts` on purpose — do NOT import it here.
 *
 * That module is imported by `client-db.worker.ts`. Importing it from this
 * file too makes it a module shared across the worker boundary, and Vite then
 * hoists it into a common chunk that its worker build references but never
 * emits. The worker's `import` then resolves to the SPA's HTML fallback,
 * fails to parse, and dies with an empty `onerror` — taking the whole local
 * database with it.
 *
 * `client-db-open.test.ts` asserts this literal still matches the exported
 * constant, so the two cannot drift apart silently.
 */
const STORAGE_BLOCKED_MARKER = 'ATOMIC_DB_STORAGE_BLOCKED';

function isStorageBlockedDbError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);

  return message.includes(STORAGE_BLOCKED_MARKER);
}

/**
 * Normalizes a leader-init failure into the error we keep on `_initError`.
 *
 * A browser withholding storage from this origin (private browsing, tracking
 * prevention, blocked site data) is a known, permanent-for-this-session state,
 * not a fault to debug — so it gets the same treatment as the other explained
 * degraded modes here: one actionable sentence. Left raw, it surfaced a wasm
 * stack trace on every single page load. Every other failure passes through
 * untouched, because those we DO want to see in full.
 */
function asInitError(e: unknown): Error {
  if (isStorageBlockedDbError(e)) {
    return new Error(
      'Local caching and offline support are disabled: this browser is not ' +
        'giving this site access to local storage right now. That is usually ' +
        'private browsing, or a setting that blocks site data or cross-site ' +
        'tracking — but it can also be another tab of this site still ' +
        'holding the local database, in which case a reload clears it. The ' +
        'app still works, reading directly from the server; nothing is kept ' +
        'locally between reloads.',
    );
  }

  return e instanceof Error ? e : new Error(String(e));
}

export interface ClientDbQueryResult {
  subjects: string[];
  resources: string[];
  count: number;
  /** Statistics over every matching resource, when the query asked for them. */
  aggregates?: AggregateOutcome[];
}

export interface ClientDbQueryOpts {
  property?: string;
  value?: string;
  /** Extra `(property, value, operator?)` constraints, ANDed with the primary
   * `property`/`value`. `operator` defaults to `eq`. */
  filters?: Array<{ property?: string; value?: string; operator?: string }>;
  sortBy?: string;
  sortDesc?: boolean;
  limit?: number;
  offset?: number;
  includeResources?: boolean;
  /** Drive scope — required for sorted queries. */
  drive?: string;
  /** Statistics to compute over every matching resource, not just this page. */
  aggregation?: Aggregation;
  /** Constraints on values computed per resource, evaluated by the store over the
   *  set the index narrows to. */
  expressionFilters?: ExpressionFilter[];
}

/** Options for opening a specific (per-agent) local database. */
export interface ClientDbOptions {
  /** OPFS file name of the database. Defaults to the legacy shared name
   *  (`atomic_data.redb`) so existing callers keep their current DB. */
  dbName?: string;
  /** Encryption key for the database file, passed through to the WASM layer. */
  dbKey?: Uint8Array;
  /** When true (and `dbName` differs from the legacy name), the worker asks
   *  WASM to migrate the legacy shared DB file into `dbName` before opening. */
  migrateLegacy?: boolean;
}

type PendingRequest = {
  resolve: (value: unknown) => void;
  reject: (reason: Error) => void;
};

/** Legacy shared database file name, used when no `dbName` is given. */
const DEFAULT_DB_NAME = 'atomic_data.redb';

// Lock/channel name prefixes. The instance-level names are suffixed with the
// database name so two different-agent DBs never share a leader — a leader
// only owns *its* OPFS file, and cross-tab RPC must stay within one DB.
const LEADER_LOCK_PREFIX = 'atomic-db-leader';
const RPC_CHANNEL_PREFIX = 'atomic-db-rpc';

/**
 * `'failed'` means leader election timed out: the lock is held by a stale tab
 * that isn't answering `leader-ping`, so we have no leader and aren't the
 * leader either. We park here, fail RPCs fast, and recover automatically if
 * the lock becomes acquirable later (`becomeLeader` flips us back to
 * `'leader'`) or another tab's `leader-announce` reaches us (handler flips us
 * to `'follower'`).
 */
type Role = 'initializing' | 'leader' | 'follower' | 'failed';

// How long we wait for either our own `navigator.locks.request` callback
// to fire OR a `leader-announce` to arrive from another tab. If neither
// happens within this window we assume the lock is held by a ghost
// leader — a prior tab whose `navigator.locks` lease is still active
// but whose BroadcastChannel listener is dead (HMR-killed bundle, top-
// frame crash, background-tab throttling). We then re-request the lock
// with `{ steal: true }` (Chromium-only) to forcibly take over.
//
// Was 30s before the steal-recovery path existed — without recovery,
// the only way out of a ghost-leader stall was to outwait it, so we
// burned 30s of wall time on every cold load behind a stuck tab. 2s
// is comfortably above the observed `leader-ping → leader-announce`
// round-trip even under dagger CPU contention (~50–200ms locally,
// ~500ms–1s on slow CI), so a healthy leader is never misclassified
// as a ghost.
const LEADER_ELECTION_WAIT_MS = 2_000;

// How long a steal gets to complete leader init before we park in degraded
// mode. Distinct from (and larger than) the election wait: post-steal we're
// no longer waiting on a possibly-dead peer, we're waiting on our OWN
// worker's wasm import + OPFS open, which can take seconds on a cold dev
// server. Ends early on success or on a definite failure.
const STEAL_SETTLE_WAIT_MS = 15_000;

// Lock stealing (`navigator.locks.request({ steal: true })`) is attempted on
// every browser. Modern Firefox (and Zen) honors `steal` — verified manually
// against a real ghost lease — despite older notes here claiming it was
// Chromium-only. On an engine that ignores the `steal` dictionary member the
// request just queues behind the ghost, the capped wait below expires, and we
// park in degraded mode — the same outcome the old skip produced, one
// `LEADER_ELECTION_WAIT_MS` later.

type BroadcastMessage =
  | { type: 'leader-ping' }
  | { type: 'leader-announce' }
  | {
      type: 'rpc-req';
      fromTab: string;
      id: string;
      payload: Record<string, unknown>;
    }
  | {
      type: 'rpc-res';
      toTab: string;
      id: string;
      ok: true;
      data: unknown;
    }
  | {
      type: 'rpc-res';
      toTab: string;
      id: string;
      ok: false;
      error: string;
    };

export class ClientDbWorker {
  private worker: Worker | null = null;
  private bc: BroadcastChannel | null = null;
  private role: Role = 'initializing';
  private tabId = (crypto as Crypto & { randomUUID?: () => string }).randomUUID
    ? crypto.randomUUID()
    : Math.random().toString(36).slice(2);
  private nextId = 1;
  private pending = new Map<string, PendingRequest>();
  private workerUrl: string;
  private wasmUrl: string;
  private opts: ClientDbOptions;
  /** Lock + channel names scoped to this instance's database. */
  private leaderLockName: string;
  private rpcChannelName: string;
  private ready = false;

  /** Set by `destroy()`. An in-flight `doInit` (the election waits span
   *  seconds) checks this after every await so a superseded instance goes
   *  silent instead of parking in 'failed' and surfacing a stale error. */
  private destroyed = false;
  private seeded = true;
  private initPromise: Promise<void> | null = null;
  private seedPromise: Promise<void> | null = null;
  private _initError: Error | undefined = undefined;
  private _unsupportedEnvironment = false;

  /** Known browser capability limit, rather than an unexpected database failure. */
  get unsupportedEnvironment(): boolean {
    return this._unsupportedEnvironment;
  }
  /** Resolves the leader lock's "hold forever" promise so `destroy()` can
   *  release the lock instead of leaking it until tab unload — otherwise an
   *  HMR cycle (which calls `destroy()` but keeps the page alive) leaves a
   *  ghost lock that the next instance can't reclaim on Firefox/Safari. */
  private releaseLeaderHold: (() => void) | null = null;
  /** Aborts a still-queued (not-yet-granted) leader-lock request on destroy. */
  private leaderLockAbort: AbortController | null = null;
  /** Resolved when we become leader (own the DB locally). */
  private onBecameLeader!: () => void;
  private leadershipGained: Promise<void>;
  /** Resolved when we observe an announce from another leader tab. */
  private onObservedLeader!: () => void;
  private leaderObserved: Promise<void>;

  get initError(): Error | undefined {
    return this._initError;
  }

  constructor(wasmUrl: string, workerUrl?: string, opts?: ClientDbOptions) {
    this.wasmUrl = wasmUrl;
    this.workerUrl = workerUrl ?? '';
    this.opts = opts ?? {};
    const dbName = this.opts.dbName ?? DEFAULT_DB_NAME;
    this.leaderLockName = `${LEADER_LOCK_PREFIX}:${dbName}`;
    this.rpcChannelName = `${RPC_CHANNEL_PREFIX}:${dbName}`;
    this.leadershipGained = new Promise<void>(r => {
      this.onBecameLeader = r;
    });
    this.leaderObserved = new Promise<void>(r => {
      this.onObservedLeader = r;
    });
  }

  async init(baseUrl?: string): Promise<void> {
    if (this.initPromise) return this.initPromise;
    this.initPromise = this.doInit(baseUrl);

    return this.initPromise;
  }

  private async doInit(baseUrl?: string): Promise<void> {
    if (!this.workerUrl) {
      throw new Error(
        'ClientDbWorker requires a workerUrl. Pass the URL to client-db-worker.js.',
      );
    }

    // Web Locks and OPFS — the two browser APIs the local database depends on —
    // are only exposed in a *secure context*. Served over plain HTTP on a
    // non-localhost origin (e.g. a self-hosted `http://host.local:9883`
    // deployment), `navigator.locks` is `undefined`, so the leader election
    // below would throw an opaque `TypeError` and leave the ClientDb
    // half-initialized — the app then renders empty, unpersisted resources with
    // no explanation. Park cleanly in server-only mode instead, with an
    // actionable message, exactly like the ghost-leader degraded path below.
    if (typeof navigator === 'undefined' || !navigator.locks) {
      this.role = 'failed';
      this._unsupportedEnvironment = true;
      this._initError = new Error(
        'Local caching and offline support are disabled: this site is served ' +
          'over an insecure connection (plain HTTP on a non-localhost origin), ' +
          'where the browser withholds the Web Locks and OPFS APIs the local ' +
          'database needs. The app still works, reading directly from the ' +
          'server. To enable local caching and offline support, serve the app ' +
          'over HTTPS (or open it via localhost).',
      );
      console.info('[ClientDb]', this._initError.message);

      return;
    }

    this.bc = new BroadcastChannel(this.rpcChannelName);
    this.bc.onmessage = (event: MessageEvent<BroadcastMessage>) =>
      this.handleBroadcast(event.data);

    // Bid for leadership. Normal queue request — callback fires when we own
    // the lock (immediately if no leader, or after the current one closes).
    this.requestLeaderLock(baseUrl, false);

    // Ping any existing leader so it can announce itself. The announce also
    // fires unprompted when a tab first becomes leader, so this is mainly for
    // the case where we open AFTER the leader announced.
    this.bc.postMessage({ type: 'leader-ping' } satisfies BroadcastMessage);

    // Wait briefly for: us-as-leader, an announce from a healthy leader, or
    // timeout. A timeout here means a ghost leader holds the
    // `navigator.locks` lease but isn't responding on the BC — its bundle
    // crashed, was HMR-killed, or its tab is background-throttled into
    // ignoring BC messages.
    const endElection = perfSpan('clientdb.election');
    const winner = await Promise.race([
      this.leadershipGained.then(() => 'leader' as const),
      this.leaderObserved.then(() => 'follower' as const),
      new Promise<'timeout'>(resolve =>
        setTimeout(() => resolve('timeout'), LEADER_ELECTION_WAIT_MS),
      ),
    ]);
    endElection({ winner });

    if (winner === 'timeout') {
      // This instance may have been superseded while the election timer ran
      // (agent switch / HMR teardown). A destroyed instance must not park
      // itself in 'failed' or surface an error the replacement already
      // resolved.
      if (this.destroyed) return;

      // Forcibly take the lock from the ghost leader. The previous
      // callback gets aborted by the browser; we run `becomeLeader` from
      // this new callback.
      console.warn(
        `[ClientDb] no leader-announce in ${LEADER_ELECTION_WAIT_MS}ms; stealing OPFS lock from suspected ghost leader`,
      );
      this.requestLeaderLock(baseUrl, true);

      // Wait for the steal callback to run `becomeLeader` TO COMPLETION —
      // `leadershipGained` only resolves after the worker's wasm import and
      // OPFS open, which legitimately takes several seconds on a cold dev
      // server. The old cap reused LEADER_ELECTION_WAIT_MS (2s) here and
      // produced false "reclaiming did not succeed" errors for steals that
      // were succeeding, just slowly. The wait ends early on success, on
      // another tab winning, or on a real init error (e.g. the ghost is a
      // live throttled tab whose worker still holds the OPFS file handle —
      // a stolen Web Lock can't take that).
      const stolen = await Promise.race([
        this.leadershipGained.then(() => 'stolen' as const),
        this.leaderObserved.then(() => 'follower' as const),
        (async () => {
          const deadline = Date.now() + STEAL_SETTLE_WAIT_MS;

          while (Date.now() < deadline) {
            await new Promise(resolve => setTimeout(resolve, 250));
            if (this._initError || this.destroyed)
              return 'open-failed' as const;
          }

          return 'still-stuck' as const;
        })(),
      ]);

      if (this.destroyed) return;

      if (stolen === 'open-failed') {
        // The steal took the lock but leader init failed — `_initError`
        // carries the real cause (usually the OPFS handle still held by a
        // live background tab). Surface that instead of a generic message.
        this.role = 'failed';
        console.warn('[ClientDb]', this._initError?.message);

        return;
      }

      if (stolen === 'still-stuck') {
        // Either the engine ignored `steal` (the request queued behind the
        // ghost) or the steal callback hasn't run. We stay recoverable: the
        // queued request fires `becomeLeader` the moment the holding
        // tab/worker closes, and a late `leader-announce` flips us to
        // follower.
        this.role = 'failed';
        this._initError = new Error(
          'ClientDb is running without its local cache: another tab — or a ' +
            'leftover worker — on this site holds the local database, and ' +
            'reclaiming the lock did not succeed. The app works normally ' +
            'meanwhile (reading from the server directly), and recovers on ' +
            'its own when that tab closes. To recover now, close other tabs ' +
            'of this site and reload.',
        );
        console.warn('[ClientDb]', this._initError.message);

        return;
      }
    }

    if (this.destroyed) return;

    this.ready = true;
  }

  /**
   * Bid for the db-scoped leader lock. Detached from the await chain — the callback's
   * "hold forever" promise (line below) is what keeps the lock owned
   * until tab close. `steal: true` is used by the recovery path in
   * `doInit` to forcibly take the lock from a ghost leader (a previous
   * holder whose BC listener is dead).
   *
   * Re-entrancy: `becomeLeader` short-circuits if the worker is already
   * spawned, so the rare case where the normal queue request finally
   * fires after we already stole is harmless.
   */
  private requestLeaderLock(baseUrl: string | undefined, steal: boolean): void {
    // `steal` and `signal` are mutually exclusive in the Web Locks spec, so
    // the abort path only applies to the normal queued request (the
    // Chromium-only steal recovery doesn't need it).
    let opts: LockOptions;

    if (steal) {
      opts = { mode: 'exclusive', steal: true };
    } else {
      this.leaderLockAbort = new AbortController();
      opts = { mode: 'exclusive', signal: this.leaderLockAbort.signal };
    }

    void navigator.locks
      .request(this.leaderLockName, opts, async () => {
        try {
          await this.becomeLeader(baseUrl);
        } catch (e) {
          this._initError = asInitError(e);
          // Release the lock so another tab can try.
          throw e;
        }

        return new Promise<void>(resolve => {
          // Hold the lock until the tab unloads OR `destroy()` releases it
          // (HMR / explicit teardown). Resolving here frees the lock so the
          // next instance — or a queued follower — can take over immediately,
          // rather than leaving a ghost lock that Firefox/Safari can't steal.
          this.releaseLeaderHold = resolve;
        });
      })
      .catch(e => {
        // A deliberate abort from `destroy()` (the request was still queued)
        // is teardown, not a failure — ignore it.
        if (e instanceof DOMException && e.name === 'AbortError') return;

        // Rejects if the callback throws OR if our hold was aborted by
        // another tab stealing the lock. The latter is fine if we're
        // already past `becomeLeader` (we just lost leadership); only
        // surface as a hard error if init never completed on a live
        // instance — a destroyed one has been superseded.
        if (!this.worker && !this.destroyed) {
          this._initError = asInitError(e);
        }
      });
  }

  /**
   * Called when our `navigator.locks.request` callback fires. Spawn the
   * worker, init WASM, take ownership of OPFS, and start serving follower
   * RPCs. Idempotent: if a previous lock callback already ran (e.g. we
   * issued both a queue-request and a steal-request, and the queue one
   * resolved last), the second call is a no-op.
   */
  private async becomeLeader(baseUrl?: string): Promise<void> {
    if (this.worker) return;
    const endSpawn = perfSpan('clientdb.workerSpawn');
    this.worker = new Worker(this.workerUrl, { type: 'module' });
    endSpawn();

    this.worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
      const { id, type, ...rest } = event.data;
      const pending = this.pending.get(String(id));
      if (!pending) return;
      this.pending.delete(String(id));

      if (type === 'error') {
        pending.reject(new Error((rest as { message: string }).message));
      } else {
        pending.resolve((rest as { data?: unknown }).data);
      }
    };

    this.worker.onerror = (event: ErrorEvent) => {
      console.error('[ClientDb Worker Error]', event.message);
    };

    const endWorkerInit = perfSpan('clientdb.workerInit');
    const timings = (await this.sendToWorker({
      type: 'init',
      wasmUrl: this.wasmUrl,
      baseUrl,
      dbName: this.opts.dbName,
      dbKey: this.opts.dbKey,
      migrateLegacy: this.opts.migrateLegacy,
    })) as ClientDbInitTimings | undefined;
    endWorkerInit(timings);

    // Fold the worker-side WASM/OPFS boot (otherwise invisible to the
    // main-thread trace) into `__atomicPerf` as discrete marks.
    if (timings) {
      perfMark('clientdb.wasm.import', { ms: timings.wasmImportMs });
      perfMark('clientdb.wasm.instantiate', { ms: timings.wasmInstantiateMs });
      perfMark('clientdb.opfs.dbOpen', { ms: timings.dbOpenMs });
    }

    this.role = 'leader';
    // Recover from a prior `'failed'` (leadership-timeout) state if the lock
    // finally became acquirable: clear the init error, mark ready, and let
    // `waitForReady` resolve true on subsequent calls.
    this._initError = undefined;
    this.ready = true;
    this.onBecameLeader();
    this.bc?.postMessage({
      type: 'leader-announce',
    } satisfies BroadcastMessage);
  }

  private handleBroadcast(msg: BroadcastMessage): void {
    switch (msg.type) {
      case 'leader-ping':
        if (this.role === 'leader') {
          this.bc?.postMessage({
            type: 'leader-announce',
          } satisfies BroadcastMessage);
        }

        break;

      case 'leader-announce':
        if (this.role !== 'leader') {
          // Recover from a prior `'failed'` state if a leader finally
          // announces itself (the stale tab woke up, or a fresh tab took
          // leadership). Clearing initError + ready=true lets cached
          // `waitForReady` callers proceed.
          if (this.role === 'failed') {
            this._initError = undefined;
            this.ready = true;
          }

          this.role = 'follower';
          this.onObservedLeader();
        }

        break;

      case 'rpc-req':
        if (this.role !== 'leader') return;
        // A follower sent us a DB call. Forward to our worker and broadcast
        // the result back keyed by the requester's tab id.
        this.sendToWorker(msg.payload as Record<string, unknown>).then(
          data => {
            this.bc?.postMessage({
              type: 'rpc-res',
              toTab: msg.fromTab,
              id: msg.id,
              ok: true,
              data,
            } satisfies BroadcastMessage);
          },
          err => {
            this.bc?.postMessage({
              type: 'rpc-res',
              toTab: msg.fromTab,
              id: msg.id,
              ok: false,
              error: err instanceof Error ? err.message : String(err),
            } satisfies BroadcastMessage);
          },
        );
        break;

      case 'rpc-res':
        if (msg.toTab !== this.tabId) return;

        {
          const pending = this.pending.get(msg.id);
          if (!pending) return;
          this.pending.delete(msg.id);
          if (msg.ok) pending.resolve(msg.data);
          else pending.reject(new Error(msg.error));
        }

        break;
    }
  }

  /* ------------------------------- Public API ------------------------------ */

  async getResource(subject: string): Promise<string | null> {
    const r = await this.send({ type: 'getResource', subject });

    return (r as string | null) ?? null;
  }

  /**
   * Combined cold-load fetch: returns both the resource's JSON-AD and
   * its Loro snapshot in a single worker round-trip. Halves the
   * postMessage traffic for the cold-load path (every mounted
   * `useResource` calls `fetchResourceWithLocalFallback`, which used to
   * do two sequential `await`s here).
   */
  async getResourceWithSnapshot(
    subject: string,
  ): Promise<{ jsonAd: string | null; snapshot: Uint8Array | null }> {
    const r = (await this.send({
      type: 'getResourceWithSnapshot',
      subject,
    })) as { jsonAd: string | null; snapshot: Uint8Array | null } | null;

    return r ?? { jsonAd: null, snapshot: null };
  }

  async putResource(jsonAd: string): Promise<void> {
    await this.send({ type: 'putResource', jsonAd });
  }

  /**
   * Atomic put: JSON-AD index entry + optional Loro snapshot in one
   * worker postMessage. Either both forms land or neither does —
   * the previous shape (separate `putResource` + `putLoroSnapshot`
   * calls) was the source of OPFS half-states under load.
   */
  async putResourceWithSnapshot(
    subject: string,
    jsonAd: string,
    snapshot?: Uint8Array,
  ): Promise<void> {
    await this.send({
      type: 'putResourceWithSnapshot',
      subject,
      jsonAd,
      snapshot,
    });
  }

  /** Put many resources in a single worker round-trip. The worker
   *  processes them in order — caller-side ordering is preserved — but
   *  the postMessage overhead amortises to ~one round-trip total
   *  instead of N. Used by the bootstrap seed loop (70 properties
   *  used to mean 70 sequential round-trips). */
  async putResources(jsonAds: string[]): Promise<void> {
    if (jsonAds.length === 0) return;
    await this.send({ type: 'putResources', jsonAds });
  }

  async applyCommit(commitJsonAd: string): Promise<void> {
    await this.send({ type: 'applyCommit', commitJsonAd });
  }

  async removeResource(subject: string): Promise<void> {
    await this.send({ type: 'removeResource', subject });
  }

  async query(opts: ClientDbQueryOpts = {}): Promise<ClientDbQueryResult> {
    const r = await this.send({ type: 'query', ...opts });

    return r as ClientDbQueryResult;
  }

  async search(
    query: string,
    opts: {
      limit?: number;
      parents?: string | string[];
      filters?: Record<string, string | number | string[]>;
    } = {},
  ): Promise<string[]> {
    const r = await this.send({
      type: 'search',
      query,
      limit: opts.limit,
      parents: opts.parents,
      filters: opts.filters,
    });

    return (r as string[]) ?? [];
  }

  async allSubjects(): Promise<string[]> {
    const r = await this.send({ type: 'allSubjects' });

    return r as string[];
  }

  async populate(): Promise<void> {
    await this.send({ type: 'populate' });
  }

  /**
   * Persist everything written so far, and resolve once it is durable.
   *
   * Writes commit without fsync for throughput and are only persisted by a
   * later Immediate commit, which the worker otherwise schedules on a 1s
   * tick. Anything that would lose un-persisted writes — a reload, going
   * offline — has no way to know whether that tick has landed. This is that
   * signal.
   */
  async flush(): Promise<void> {
    await this.send({ type: 'flush' });
  }

  async exportAllResources(): Promise<string> {
    const r = await this.send({ type: 'exportAllResources' });

    return r as string;
  }

  async importAllResources(jsonArray: string): Promise<number> {
    const r = await this.send({ type: 'importAllResources', jsonArray });

    return r as number;
  }

  async getLoroSnapshot(subject: string): Promise<Uint8Array | null> {
    const r = await this.send({ type: 'getLoroSnapshot', subject });

    return (r as Uint8Array | null) ?? null;
  }

  /** Who signed `subject`'s history, from the envelopes this client applied
   *  itself (`atomic_lib::envelopes`). Null when the WASM build predates the
   *  accessor or the worker is unavailable. */
  async historyAttribution(
    subject: string,
  ): Promise<HistoryAttribution | null> {
    try {
      const r = await this.send({ type: 'historyAttribution', subject });

      return parseHistoryAttribution(r);
    } catch {
      return null;
    }
  }

  async putBlob(hash: Uint8Array, data: Uint8Array): Promise<void> {
    await this.send({ type: 'putBlob', hash, data });
  }

  async getBlob(hash: Uint8Array): Promise<Uint8Array | null> {
    const r = await this.send({ type: 'getBlob', hash });

    return (r as Uint8Array | null) ?? null;
  }

  async blake3Hash(data: Uint8Array): Promise<Uint8Array> {
    const r = await this.send({ type: 'blake3Hash', data });

    return r as Uint8Array;
  }

  async getAllVersionVectors(): Promise<
    Record<string, Record<string, number>>
  > {
    const r = await this.send({ type: 'getAllVersionVectors' });

    return (r as Record<string, Record<string, number>>) ?? {};
  }

  /** Version vectors for one drive's resources only (parent-index walk),
   *  instead of every resource in every drive. */
  async getVersionVectorsForDrive(
    drive: string,
  ): Promise<Record<string, Record<string, number>>> {
    const r = await this.send({ type: 'getVersionVectorsForDrive', drive });

    return (r as Record<string, Record<string, number>>) ?? {};
  }

  /**
   * Seal this drive's history into one Cloud Vault object.
   *
   * Resolves to `null` when nothing has changed since this lane's cursor, so a
   * periodic backup skips the upload rather than storing an object every tick.
   * Since incremental cursors landed that is the ordinary outcome for an idle
   * device rather than a rare one.
   *
   * `kind` says whether this pass produced an incremental `'pack'` or a
   * self-sufficient `'checkpoint'`. The cadence is decided in Rust so every
   * host agrees, but the caller must read it: a checkpoint uploads under a
   * different object kind and has to be published afterwards.
   *
   * The bytes come back already encrypted — the caller uploads ciphertext and
   * never sees drive contents. See `helpers/managed/vault.ts` for the
   * control-plane half.
   */
  async vaultExport(
    driveSubject: string,
    key: Uint8Array,
    keyEpoch: number,
    drivePseudonym: string,
    devicePubkey: string,
    segment: number,
    checkpointN: number,
    driveHasCheckpoint: boolean,
    observedLanes: Record<string, number>,
  ): Promise<{
    objectKey: string;
    sealed: Uint8Array;
    kind: 'pack' | 'checkpoint';
    resources: number;
    unchanged: number;
    tombstones: number;
    coverage: Record<string, number>;
  } | null> {
    const r = await this.send({
      type: 'vaultExport',
      driveSubject,
      key,
      keyEpoch,
      drivePseudonym,
      devicePubkey,
      segment,
      checkpointN,
      driveHasCheckpoint,
      observedLanes,
    });

    return (r ?? null) as {
      objectKey: string;
      sealed: Uint8Array;
      kind: 'pack' | 'checkpoint';
      resources: number;
      unchanged: number;
      tombstones: number;
      coverage: Record<string, number>;
    } | null;
  }

  /**
   * Merge downloaded Cloud Vault objects into this store.
   *
   * Pass everything the vault holds. The importer plans its own order from the
   * newest checkpoint's coverage and observed maps — a checkpoint's tombstone
   * has to win over an older segment that still holds the resource, and a
   * segment written *after* the checkpoint has to win over the checkpoint. That
   * decision lives in `plan_restore` (`lib/src/vault/sync.rs`) rather than
   * being duplicated in every host's JS.
   */
  async vaultImport(
    key: Uint8Array,
    keyEpoch: number,
    drivePseudonym: string,
    devicePubkey: string,
    objects: { objectKey: string; sealed: Uint8Array }[],
  ): Promise<{
    packsRead: number;
    resourcesRestored: number;
    tombstonesApplied: number;
    objectsSkipped: number;
    objectsUnreadable: number;
  }> {
    const r = await this.send({
      type: 'vaultImport',
      key,
      keyEpoch,
      drivePseudonym,
      devicePubkey,
      objects,
    });

    return r as {
      packsRead: number;
      resourcesRestored: number;
      tombstonesApplied: number;
      objectsSkipped: number;
      objectsUnreadable: number;
    };
  }

  /**
   * Record that a sealed segment is durably in the vault.
   *
   * Sealing and storing are separate steps: `vaultExport` produces bytes and
   * the caller uploads them afterwards. Until this is called the lane's
   * progress stays provisional, so a failed upload is retried against the same
   * view of what has been backed up.
   */
  async vaultCommitSegment(
    drivePseudonym: string,
    devicePubkey: string,
    segment: number,
  ): Promise<void> {
    await this.send({
      type: 'vaultCommitSegment',
      drivePseudonym,
      devicePubkey,
      segment,
    });
  }

  get isReady(): boolean {
    return this.ready && this.seeded;
  }

  /** True once the WASM worker is initialized — independent of the
   *  bootstrap seed. Lookups for resources that aren't part of the
   *  bootstrap (i.e. user data) only need this; gating them on the seed
   *  blocks every cold-load useResource on a few hundred milliseconds
   *  of property puts they don't even depend on. */
  get isInitialized(): boolean {
    return this.ready;
  }

  setSeedPromise(promise: Promise<void>): void {
    this.seeded = false;
    this.seedPromise = promise.then(() => {
      this.seeded = true;
    });
  }

  /** Resolves when the WASM worker is initialized (lookups can run).
   *  Does NOT wait for the bootstrap seed — see {@link waitForReady}. */
  async waitForInit(): Promise<boolean> {
    if (this.ready) return true;
    if (!this.initPromise) return false;

    try {
      await this.initPromise;

      return this.ready;
    } catch {
      return false;
    }
  }

  async waitForReady(): Promise<boolean> {
    if (this.ready && this.seeded) return true;
    if (!this.initPromise) return false;

    try {
      await this.initPromise;
      if (this.seedPromise) await this.seedPromise;

      return this.ready && this.seeded;
    } catch {
      return false;
    }
  }

  destroy(): void {
    this.destroyed = true;
    // Release the leader lock FIRST. If we're the leader, resolving the hold
    // frees the `navigator.locks` lease; if we're still queued, abort the
    // pending request. Without this, `destroy()` (notably the HMR dispose
    // hook) leaks the lock for the page's lifetime — a ghost leader the next
    // instance can't reclaim until it steals.
    this.releaseLeaderHold?.();
    this.releaseLeaderHold = null;
    this.leaderLockAbort?.abort();
    this.leaderLockAbort = null;
    this.bc?.close();
    this.worker?.terminate();
    this.bc = null;
    this.worker = null;
    this.ready = false;
    this.seeded = true;
    this.initPromise = null;
    this.seedPromise = null;

    for (const [, pending] of this.pending) {
      pending.reject(new Error('ClientDb worker destroyed'));
    }

    this.pending.clear();
  }

  /* ---------------------------- Internal send ----------------------------- */

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private async send(msg: Record<string, any>): Promise<unknown> {
    // Websocket fanout can call into the DB before init() has resolved
    // (leadership election + leader announce takes a few ticks). Wait for
    // init rather than rejecting — the caller already started init, we just
    // need to let it finish.
    if (this.role === 'initializing' && this.initPromise) {
      await this.initPromise;
    }

    if (this.role === 'leader') {
      return this.sendToWorker(msg);
    }

    if (this.role === 'follower') {
      return this.sendToLeader(msg);
    }

    if (this.role === 'failed') {
      // Leadership election timed out and we're parked. Fail fast so callers
      // like `computeDriveSyncState` and `useChildren` proceed in degraded
      // mode (in-memory only) instead of awaiting forever.
      throw new Error(
        `ClientDb unavailable: ${this._initError?.message ?? 'init failed'}`,
      );
    }

    throw new Error('ClientDbWorker send() called before init() completed');
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private sendToWorker(msg: Record<string, any>): Promise<unknown> {
    if (!this.worker) {
      return Promise.reject(new Error('ClientDb worker not initialized'));
    }

    const id = String(this.nextId++);

    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker!.postMessage({ ...msg, id } as unknown as WorkerRequest);
    });
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private sendToLeader(msg: Record<string, any>): Promise<unknown> {
    if (!this.bc) {
      return Promise.reject(
        new Error('ClientDb BroadcastChannel not initialized'),
      );
    }

    const id = String(this.nextId++);

    return new Promise((resolve, reject) => {
      // If the leader tab dies between sending the request and the
      // response coming back, the BroadcastChannel doesn't surface a
      // "peer closed" event — the pending entry sits forever.
      // Time out after 30 s. The caller can retry; by then a new
      // leader will usually have been elected via navigator.locks.
      const timer = setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(
            new Error(
              `ClientDb sendToLeader timed out after 30s — leader tab may have closed.`,
            ),
          );
        }
      }, 30_000);

      this.pending.set(id, {
        resolve: (data: unknown) => {
          clearTimeout(timer);
          resolve(data);
        },
        reject: (e: Error) => {
          clearTimeout(timer);
          reject(e);
        },
      });
      this.bc!.postMessage({
        type: 'rpc-req',
        fromTab: this.tabId,
        id,
        payload: msg,
      } satisfies BroadcastMessage);
    });
  }
}
