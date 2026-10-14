import { ClientDbWorker, perfSpan, StoreEvents, type Store } from '@tomic/lib';
// Vite resolves the bundled worker from the lib's dist and gives us a URL
// pointing at the asset it copies into the build output.
import clientDbWorkerUrl from '@tomic/lib/client-db.worker.js?url';

import {
  agentDbFingerprint,
  getOrCreateSessionDbKey,
  getSessionDbKey,
  hasWrappedDbKey,
  waitForSessionDbKey,
} from './localDbKey';
import { compiledAtomicWasm, wasmJsUrl } from './wasmUrls';

// Track the current worker so we can terminate it on HMR reload and on
// agent switches.
let currentWorker: ClientDbWorker | undefined;
// The agent subject the current worker's database belongs to. `null` means
// no start has happened yet (undefined is a real identity: signed out).
let currentIdentity: string | undefined | null = null;
// Identity switches are serialized so a rapid sign-out → sign-in can't
// interleave two worker (re)starts against the same OPFS files.
let restartChain: Promise<void> = Promise.resolve();
let unsubscribeAgentListener: (() => void) | undefined;

/** The shared plaintext database for signed-out browsing (public data only). */
const ANON_DB_NAME = 'atomic_data.anon.redb';

/**
 * Initialize the WASM ClientDb (a dedicated Worker; one leader per origin and
 * database via `navigator.locks` — see lib/src/client-db.ts) and attach it to
 * the Store. Uses OPFS for persistent storage — data survives page reloads.
 *
 * Each agent gets its own database file, encrypted with a per-agent key
 * (see `localDbKey.ts`), so one agent's cached private data is unreadable
 * after sign-out or to a different agent on the same origin. Signed-out
 * sessions use a shared plaintext database. On agent change the worker is
 * torn down and restarted against the new identity's database.
 */
export function initClientDb(
  store: Store,
  options: { deferAnonymous?: boolean } = {},
): void {
  // NOT `SharedWorker`: the implementation moved to a dedicated Worker long
  // ago, and Android WebView (the Tauri mobile app) has no SharedWorker — a
  // stale SharedWorker guard silently disabled the entire local database
  // there, so every collection query fell back to the server and local-only
  // drives (the demo) rendered empty. Missing locks/OPFS on insecure
  // contexts is handled inside ClientDbWorker with a clear message.
  if (typeof Worker === 'undefined') return;

  // Announce the attach before starting it: deriving the database name and
  // unwrapping the agent's key below takes a few hundred ms, and React renders
  // (and starts fetching) in the meantime. Fetches that would otherwise fail a
  // resource in that window ("Offline: resource not available locally") use
  // this to wait out the attach instead — see Store.expectClientDb.
  store.expectClientDb();

  // Routes that immediately provision an identity do not need to open and
  // seed an anonymous database only to flush and destroy it moments later.
  const initialAgent = store.getAgent()?.subject;

  if (!options.deferAnonymous || initialAgent) {
    scheduleStart(store, initialAgent);
  } else if (currentIdentity === null) {
    // Preserve the identity boundary even without opening its worker. The
    // new agent must use WASM's bundled defaults, not a copy of the signed-out
    // Store. Treating it as a first page start also writes a transient seed
    // fingerprint, forcing unnecessary full reseeding on the next reload.
    currentIdentity = undefined;
  }

  unsubscribeAgentListener?.();
  unsubscribeAgentListener = store.on(StoreEvents.AgentChanged, agent => {
    scheduleStart(store, agent?.subject);
  });

  // Vite HMR: accept updates and re-initialize cleanly.
  if (import.meta.hot) {
    import.meta.hot.dispose(() => {
      unsubscribeAgentListener?.();
      unsubscribeAgentListener = undefined;
      currentWorker?.destroy();
      currentWorker = undefined;
    });
  }
}

function scheduleStart(store: Store, agentSubject: string | undefined): void {
  // Detach synchronously on identity change: a caller can save immediately
  // after setAgent(), before the serialized restart has derived the new key.
  // It must not write to the previous identity's worker (or its destroyed RPC).
  if (currentIdentity !== agentSubject) store.setClientDb(undefined);
  restartChain = restartChain
    .then(() => startForIdentity(store, agentSubject))
    .catch(err => {
      console.warn('[ClientDb] Failed to (re)start for identity:', err);
    });
}

/**
 * The database file for an agent: content-addressed by the agent subject so
 * names stay valid OPFS filenames whatever characters a DID contains.
 */
async function dbNameForAgent(agentSubject: string): Promise<string> {
  return `atomic_data.${await agentDbFingerprint(agentSubject)}.redb`;
}

/**
 * The encryption key for an agent's database, preferring the active-session
 * record. A wrapped record without a session record means a sign-in is
 * unwrapping it right now (`ensureDbKeyOnSignIn` runs alongside the
 * AgentChanged event, announced by `trackDbKeySignIn`) — wait for that instead of generating a fresh key that
 * couldn't open the existing encrypted file.
 *
 * Returns null when there is a wrapped record but no session key, which means
 * this agent's database is real, encrypted under a key we cannot reach on this
 * page load, and reachable again the moment they sign in with their secret.
 * There is nothing useful to open in that state and a fresh key is actively
 * harmful — it opens as the wrong key, which is what used to get the file
 * discarded — so the caller starts no worker at all and the store runs
 * server-only until a sign-in heals it.
 */
async function resolveDbKey(agentSubject: string): Promise<Uint8Array | null> {
  const existing = await getSessionDbKey(agentSubject);

  if (existing) return existing;

  if (await hasWrappedDbKey(agentSubject)) {
    const key = await waitForSessionDbKey(agentSubject);

    if (key) return key;

    // The sign-in never delivered the key (e.g. an agent restored from a
    // non-extractable keypair, where no secret enters JS).
    console.warn(
      '[ClientDb] wrapped key present but no session key appeared; leaving ' +
        'the existing database closed. Sign in with the agent secret or ' +
        'recovery code to unwrap its key.',
    );

    return null;
  }

  return getOrCreateSessionDbKey(agentSubject);
}

async function startForIdentity(
  store: Store,
  agentSubject: string | undefined,
): Promise<void> {
  // AgentChanged also fires for same-identity re-signins; only an actual
  // identity change warrants tearing down the worker.
  if (store.getAgent()?.subject !== agentSubject) return;
  if (currentWorker && currentIdentity === agentSubject) return;

  const isFirstStart = currentIdentity === null;
  currentIdentity = agentSubject;

  if (currentWorker) {
    const previous = currentWorker;
    currentWorker = undefined;

    // Finish queued writes and fsync before releasing this identity's OPFS
    // lock. Abrupt termination rejected writes and could discard recent edits.
    try {
      if (await previous.waitForReady()) await previous.flush();
    } catch (error) {
      store.notifyError(
        error instanceof Error ? error : new Error(String(error)),
      );
    } finally {
      previous.destroy();
    }
  }

  // Another identity may have arrived while the previous worker flushed.
  // Do not briefly attach its predecessor and release saves into the wrong DB.
  if (store.getAgent()?.subject !== agentSubject) return;

  let dbName = ANON_DB_NAME;
  let dbKey: Uint8Array | undefined;
  // Only an unrecoverable key justifies discarding the file it can't open.
  // A wrapped record is a path back to the real key, so its absence is the
  // one case where nothing is lost by starting over (see `client-db-open.ts`).
  let discardUndecryptable = false;

  if (agentSubject) {
    dbName = await dbNameForAgent(agentSubject);
    const resolved = await resolveDbKey(agentSubject);

    // No key we could use, and the database is not ours to replace. Leave
    // `currentWorker` unset so the next AgentChanged — the sign-in that
    // unwraps the key — comes back through here and starts it properly.
    if (!resolved) return;

    dbKey = resolved;
    discardUndecryptable = !(await hasWrappedDbKey(agentSubject));
  }

  if (store.getAgent()?.subject !== agentSubject) return;

  const wasmUrl = wasmJsUrl();

  const clientDb = new ClientDbWorker(wasmUrl, clientDbWorkerUrl, {
    dbName,
    dbKey,
    // Adopt the pre-split single `atomic_data.redb` (which may hold
    // local-only data with no server fallback) into whichever identity is
    // active at upgrade time. No-ops once it's gone.
    migrateLegacy: true,
    discardUndecryptable,
    // Fetched and compiled once for the whole page, starting in index.html.
    wasmModule: compiledAtomicWasm(),
  });
  currentWorker = clientDb;

  const serializeResource = (subject: string): string | undefined => {
    const resource = store.resources.get(subject);
    if (!resource) return undefined;

    // Skip resources whose commits haven't reached the server. Two cases:
    //   1. Unsaved placeholders (e.g. `TableNewRow`'s pre-created empty
    //      row): `signChanges` was called — flipping `new=false` and
    //      queueing a commit — but the outbox never drained it. Seeding these
    //      turns them into phantom children that accumulate every reload.
    //   2. Offline-applied resources: the local-only save path already
    //      persists them directly via `clientDb.putResource`. Seeding
    //      again here is redundant.
    // Genuinely-saved resources have an empty pending queue by the time
    // this seeder runs, so they are the ones that actually land in OPFS.
    if (resource.hasPendingCommits || resource.new) return undefined;

    const obj: Record<string, unknown> = { '@id': resource.subject };
    let hasProps = false;

    for (const [key, value] of resource.getEntries()) {
      if (value instanceof Uint8Array) continue;
      obj[key] = value;
      hasProps = true;
    }

    if (!hasProps) return undefined;

    return JSON.stringify(obj);
  };

  /**
   * The resource's Loro history, when it has one. The seed must store that
   * rather than let the database rebuild a document from the propvals: a
   * rebuilt document carries the same values under a fresh peer id, so its
   * version vector looks ahead of the server's and the next drive reconcile
   * asks this tab to push it back (which a read-only member cannot).
   */
  const snapshotFor = (subject: string): Uint8Array | undefined => {
    const resource = store.resources.get(subject);
    if (!resource?.hasLoroDoc()) return undefined;

    const doc = resource.getLoroDoc();

    if (!doc || doc.oplogVersion().toJSON().size === 0) return undefined;

    return doc.export({ mode: 'snapshot' });
  };

  /** Write `subjects` in order. Those without a Loro history go in one
   *  batch; each one with a history is written with its snapshot. Returns
   *  how many were written. */
  const seed = async (subjects: string[]): Promise<number> => {
    const plain: string[] = [];
    const withHistory: {
      subject: string;
      jsonAd: string;
      snapshot: Uint8Array;
    }[] = [];

    for (const subject of subjects) {
      const jsonAd = serializeResource(subject);
      if (jsonAd === undefined) continue;

      const snapshot = snapshotFor(subject);

      if (snapshot) {
        withHistory.push({ subject, jsonAd, snapshot });
      } else {
        plain.push(jsonAd);
      }
    }

    await clientDb.putResources(plain).catch(() => {});

    for (const { subject, jsonAd, snapshot } of withHistory) {
      await clientDb
        .putResourceWithSnapshot(subject, jsonAd, snapshot)
        .catch(() => {});
    }

    return plain.length + withHistory.length;
  };

  /** Compute a cheap fingerprint of the in-memory bootstrap state.
   *  Includes the resource count and a deterministic checksum of the
   *  sorted subject list. A change to any bundled `lib/defaults/*.json`
   *  changes the count or the subjects, so the fingerprint flips and
   *  the seed re-runs on the next page load. Subsequent loads with
   *  unchanged bootstrap data skip the seed entirely. */
  const computeBootstrapFingerprint = (): string => {
    const subjects: string[] = [];

    for (const r of store.resources.values()) {
      if (r.loading || r.new || r.hasPendingCommits) continue;
      subjects.push(r.subject);
    }

    subjects.sort();
    // FNV-1a 32-bit hash of the sorted subject list. Cheap, deterministic,
    // good enough to detect added/removed bootstrap resources. We don't
    // need crypto-grade — the worst-case collision means we miss a
    // reseed on a single deployment, which the next deployment fixes.
    let hash = 0x811c9dc5;

    for (const s of subjects) {
      for (let i = 0; i < s.length; i++) {
        hash ^= s.charCodeAt(i);
        hash = Math.imul(hash, 0x01000193);
      }

      hash ^= 0x2c;
      hash = Math.imul(hash, 0x01000193);
    }

    return `${subjects.length}:${(hash >>> 0).toString(16)}`;
  };

  // Per-database: each identity's database seeds independently.
  const FINGERPRINT_KEY = `atomic.client-db.bootstrap-fingerprint.${dbName}`;
  const currentFingerprint = computeBootstrapFingerprint();
  const storedFingerprint =
    typeof localStorage !== 'undefined'
      ? localStorage.getItem(FINGERPRINT_KEY)
      : null;
  const bootstrapChanged = storedFingerprint !== currentFingerprint;

  // Start init — this creates the Worker immediately (sync) and
  // sends the WASM init message (async). Messages sent to the worker
  // before WASM loads will queue and process after init.
  // After WASM is ready, seed the DB from the Store's in-memory map
  // so tables/queries work even without OPFS persistence.
  const endClientDbInit = perfSpan('clientdb.init');
  const initPromise = clientDb.init(store.getServerUrl()).then(async () => {
    endClientDbInit();

    // The memory seed may ONLY run on the very first start of this page
    // load. On an identity switch, `store.resources` still holds the
    // previous session's resources — seeding those would copy one agent's
    // private data into another identity's (or the anonymous) database,
    // exactly what the per-agent split exists to prevent. A fresh
    // per-agent database gets its ~200 bundled defaults from the
    // Rust-side `populate::bootstrap` instead.
    if (
      !isFirstStart ||
      currentWorker !== clientDb ||
      store.getAgent()?.subject !== agentSubject
    )
      return;

    const endPostInit = perfSpan('clientdb.postInit');
    // Skip the seed entirely when:
    //   - The WASM DB is already populated from OPFS (prior session), AND
    //   - The bundled bootstrap data hasn't changed since the last seed
    //     (fingerprint matches).
    //
    // First load: localStorage has no fingerprint → seeds.
    // Subsequent loads with same code: fingerprints match + OPFS has
    //   data → skips. Saves ~200 wasm-bindgen crossings (~1-2s on slow
    //   runners) per cold load.
    // Version bumps that add/remove bootstrap resources: fingerprint
    //   mismatch → reseeds (one-time cost for that version).
    let opfsHasData = false;

    const endAllSubjects = perfSpan('clientdb.allSubjects');
    // Subjects already in the WASM DB. The Rust `ClientDb` runs
    // `populate::bootstrap` inside `init_redb_opfs`, so on a fresh OPFS the
    // ~200 bundled defaults are ALREADY present here — re-seeding them from JS
    // is ~1s of redundant wasm-bindgen crossings. We skip any subject the DB
    // already has and only seed what's genuinely missing (drive, agent,
    // fetched resources).
    const existingSet = new Set<string>();

    // Listing every subject reads the whole database (0.25 s at 10k
    // resources, in front of the first reads of the screen). When the
    // bundled defaults are unchanged since the last start there is nothing
    // to decide, so skip it.
    if (!bootstrapChanged && storedFingerprint !== null) {
      endAllSubjects({ skipped: true });
      endPostInit({ seeded: false, skipped: true });

      return;
    }

    try {
      const existing = await clientDb.allSubjects();
      for (const s of existing) existingSet.add(s);
      opfsHasData = existing.length > 0;
    } catch {
      // allSubjects failed — proceed with seed as fallback.
    }

    endAllSubjects({ count: existingSet.size });

    if (opfsHasData && !bootstrapChanged) {
      console.info(
        `[ClientDb] bootstrap fingerprint unchanged (${currentFingerprint}) and OPFS populated, skipping seed`,
      );
      endPostInit({ seeded: false, opfsSubjects: existingSet.size });

      return;
    }

    // Seed the WASM DB from resources already in the Store.
    // Properties must be seeded FIRST so that subsequent resources
    // can be parsed with correct datatype validation.
    const propertyClass = 'https://atomicdata.dev/classes/Property';
    const isAProp = 'https://atomicdata.dev/properties/isA';
    const properties: string[] = [];
    const others: string[] = [];

    let skippedAlreadyPresent = 0;

    // The bundled-defaults fingerprint doubles as a version stamp. We may skip
    // re-seeding subjects the Rust-side bootstrap already populated ONLY when we
    // can trust those values are current — i.e. a genuine first visit, where
    // `init_redb_opfs` just ran `populate::bootstrap` against a fresh OPFS with
    // THIS build's defaults. On a version change (`storedFingerprint` present
    // but different) a default's *value* may have changed under an existing
    // subject, and the Rust bootstrap skips existing OPFS — so we must reseed
    // unfiltered to overwrite. That full reseed is a one-time ~1s cost per
    // version bump; the common first-visit and warm paths stay fast.
    const trustWasmDefaults = storedFingerprint === null;

    for (const resource of store.resources.values()) {
      if (!resource.loading && !resource.new && resource.subject) {
        // Already populated by the Rust-side bootstrap — don't pay the
        // wasm-bindgen crossing to re-insert identical data.
        if (trustWasmDefaults && existingSet.has(resource.subject)) {
          skippedAlreadyPresent++;
          continue;
        }

        const isA = resource.get(isAProp);
        const isProperty = Array.isArray(isA) && isA.includes(propertyClass);

        if (isProperty) {
          properties.push(resource.subject);
        } else {
          others.push(resource.subject);
        }
      }
    }

    // Properties must be seeded first so subsequent resources parse with
    // correct datatype validation. Used to be 70 sequential `putResource`
    // round-trips (~350 ms of dead time on cold start); batch them into
    // one worker call. The worker still processes them in order, so the
    // datatype-priming property is preserved.
    const endSeed = perfSpan('clientdb.seed');
    const seededProperties = await seed(properties);

    // Then seed everything else in one batch too.
    const seededOthers = await seed(others);
    endSeed({
      properties: seededProperties,
      others: seededOthers,
    });

    // Persist the fingerprint AFTER the seed lands so a crashed seed
    // forces a retry on the next load (the stored value would still
    // be the old/empty fingerprint, mismatching the new bundle).
    if (typeof localStorage !== 'undefined') {
      try {
        localStorage.setItem(FINGERPRINT_KEY, currentFingerprint);
      } catch {
        // Quota or privacy mode — non-fatal, just means we'll reseed
        // next load.
      }
    }

    console.info(
      `[ClientDb] seeded ${seededProperties} properties + ${seededOthers} resources, skipped ${skippedAlreadyPresent} already in WASM DB (fingerprint ${currentFingerprint}${bootstrapChanged && storedFingerprint ? `, was ${storedFingerprint}` : ''})`,
    );
    endPostInit({
      seeded: true,
      properties: seededProperties,
      others: seededOthers,
      skippedAlreadyPresent,
    });
  });

  // Tell the clientDb to wait for seeding before reporting as ready.
  clientDb.setSeedPromise(initPromise);

  // Attach to store right after init() is called (worker exists now).
  // This lets addResource() forward to the worker even during init.
  store.setClientDb(clientDb);

  initPromise
    .then(() => {
      // An identity switch may have superseded this worker while its init
      // (leader election spans seconds) was still running. A destroyed
      // worker must not re-attach itself over its replacement or surface
      // errors the replacement already resolved.
      if (
        currentWorker !== clientDb ||
        store.getAgent()?.subject !== agentSubject
      )
        return;

      // Re-emit so the sync page picks up clientDbReady: true.
      // The previous "safety net" reseed at this point — every
      // resource in `store.resources` re-pushed to the WASM index
      // through wasm-bindgen — was solving a race that already had a
      // guard: `ClientDbWorker.send()` awaits its own `initPromise`
      // before forwarding to the worker, so any `addResource →
      // clientDb.putResourceWithSnapshot` call that landed during the
      // init window queued automatically. The reseed was paying ~1s
      // of wasm-bindgen crossings every cold load for zero new state.
      store.setClientDb(clientDb);

      // init() resolves even when the local DB parked in a degraded,
      // server-only mode (insecure context with no Web Locks/OPFS, or a
      // ghost-leader lock it couldn't reclaim). Surface that to the user —
      // otherwise the app silently renders empty, unpersisted resources with
      // no explanation of why local caching/offline isn't working.
      // The demo explains a storage problem on its own page; a toast with
      // the same text beside it only doubled it.
      if (
        clientDb.initError &&
        !clientDb.unsupportedEnvironment &&
        window.location.pathname !== '/app/demo'
      ) {
        store.notifyError(clientDb.initError);
      }
    })
    .catch(err => {
      if (
        currentWorker !== clientDb ||
        store.getAgent()?.subject !== agentSubject
      )
        return;

      console.warn('[ClientDb] Failed to initialize:', err);
      // Re-emit so the Sync page can show the error (clientDbError).
      // clientDb.initError was populated in the send() catch inside doInit.
      store.setClientDb(clientDb);
      if (window.location.pathname !== '/app/demo')
        store.notifyError(clientDb.initError ?? err);
    });
}
