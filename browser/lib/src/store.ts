import {
  mergeHistoryAttributions,
  parseHistoryAttribution,
  type HistoryAttribution,
} from './history-attribution.js';
import { ulid } from 'ulidx';
import type { Agent } from './agent.js';
import { canonicalDriveHash } from './canonical-drive-hash.js';
import {
  removeCookieAuthentication,
  setCookieAuthentication,
  signRequest,
} from './authentication.js';
import { Client, type FileOrFileLike } from './client.js';
import { CommitBuilder, commitIdOf, type Commit } from './commit.js';
import { datatypeFromUrl, type Datatype } from './datatypes.js';
import {
  AtomicError,
  ErrorType,
  isTransportError,
  LOCAL_ONLY_NOT_FOUND_MESSAGE,
  NOT_AVAILABLE_LOCALLY_MESSAGE,
} from './error.js';
import { EventManager } from './EventManager.js';
import { hasBrowserAPI } from './hasBrowserAPI.js';
import { collections } from './ontologies/collections.js';
import { commits } from './ontologies/commits.js';
import { core } from './ontologies/core.js';
import { server, type Server } from './ontologies/server.js';
import type { OptionalClass, UnknownClass } from './ontology.js';
import { JSONADParser } from './parse.js';
import { Resource, unknownSubject } from './resource.js';
import {
  type SearchOpts,
  type SemanticSearchOpts,
  buildSearchSubject,
  buildSemanticSearchSubject,
} from './search.js';
import { stringToSlug } from './stringToSlug.js';
import { bytesToHex, hexToBytes, type JSONValue } from './value.js';
import { WSClient } from './websockets.js';
import { withDeadline } from './withDeadline.js';
import { BLOB, endpoints, INTERNAL_ID } from './urls.js';
import { initOntologies } from './ontologies/index.js';
import { decodeB64, encodeB64Url } from './base64.js';
import {
  encodeGenesisCert,
  privateDriveCert,
  subjectForSignature,
  type GenesisCert,
} from './genesis.js';
import type {
  ClientDbWorker,
  ClientDbQueryOpts,
  ClientDbQueryResult,
} from './client-db.js';
import { DrivePresenceManager } from './presence.js';
import { perfMark, perfSpan } from './perf-trace.js';
import {
  LocalOutbox,
  isTerminalCommitError,
  isUnrecoverableCommitError,
  type OutboxEntry,
} from './local-outbox.js';

/** Function called when a resource is updated or removed */
type ResourceCallback<C extends OptionalClass = UnknownClass> = (
  resource: Resource<C>,
) => void;
/** Callback for Loro CRDT document sync updates */
type LoroSyncCallback = (update: Uint8Array) => void;
/** Callback for Loro ephemeral updates (cursors, presence) */
type LoroEphemeralCallback = (update: Uint8Array) => void;
/** Callback for drive-scoped presence updates */
type PresenceCallback = (update: Uint8Array) => void;
type SubjectCallback = (subject: string) => void;
/** Callback called when the stores agent changes */
type AgentCallback = (agent: Agent | undefined) => void;
type ErrorCallback = (e: Error) => void;
type ConnectionStateCallback = (connected: boolean) => void;
type SyncStatusCallback = (status: StoreSyncStatus) => void;
type CommitLogCallback = (entries: CommitLogEntry[]) => void;

type ServerURLCallback = (serverURL: string) => void;
type DriveCallback = (drive: string) => void;

/** Called when the server reports vector index activity for a drive (via websocket). */
export type IndexingStatusCallback = (indexing: boolean) => void;

/** How long a migration fetch may take before the answer stops being useful.
 *  These are servers the device may never reach; sign-in must not wait on
 *  them. */
const LEGACY_FETCH_DEADLINE_MS = 5_000;

type Fetch = typeof fetch;
type CreateResourceOptions = {
  /** Optional subject of the new resource, if not given the store will generate a random subject */
  subject?: string;
  /** Parent the subject belongs to, defaults to the serverUrl */
  parent?: string;
  /** Set to true if the resource should not have a parent. (For example Drives don't have parents) */
  noParent?: boolean;
  /** Subject(s) of the resources class */
  isA?: string | string[];
  /** Any additional properties the resource should have */
  propVals?: Record<string, JSONValue>;
  /** Set to true if the resource should have a DID as subject. Defaults to `true` for `did:ad` agents, otherwise `false`. */
  did?: boolean;
  /** When set, the resource is minted from this cert (deterministic DID)
   *  instead of a random-nonce certificate. */
  genesisCert?: GenesisCert;
};

export interface StoreOpts {
  /** The default store URL, where to send commits and where to create new instances */
  serverUrl?: string;
  /** Default Agent, used for signing commits. Is required for posting things. */
  agent?: Agent;
  /**
   * Whether to open a WebSocket to `serverUrl` right away. Defaults to true.
   *
   * `false` is for a `serverUrl` that is known not to run an atomic-server:
   * the managed deployment serves this app from a shared origin that is a
   * plain static host, and a socket to it can only fail — every few seconds,
   * forever, with an error toast each time. The URL is still needed (relative
   * subjects resolve against it), so it is kept; only the connection is not
   * attempted. A later `setServerUrl` to a real node connects as usual.
   */
  connect?: boolean;
}

export interface StoreSyncStatus {
  serverConnected: boolean;
  /** Last WebSocket/server connection error, if the server is currently offline. */
  serverConnectionError?: string;
  /** True iff EITHER the WS-driven drive sync is mid-handshake OR
   * the outbox is currently draining. */
  syncInProgress: boolean;
  /** Everything locally edited but not yet acked by the server: outbox
   *  entries (minus blocked), in-flight `save()`s, AND saves still parked
   *  in a UI debounce timer (`startScheduledSave`). `0` means "safe to
   *  reload/navigate — nothing will be lost". */
  pendingDirtyCount: number;
  /** Entries parked on an unrecoverable error (e.g. `401 Unauthorized`): kept
   *  for visibility but no longer retried. Excluded from `pendingDirtyCount`
   *  (they aren't "in progress"). A fresh edit re-arms them. */
  blockedCount: number;
  serverUrl: string;
  /** `undefined` when no drive has been selected (cold open before
   *  `setDrive`). Callers must handle the absent case rather than
   *  treat the server URL as a stand-in drive — a bare host URL is
   *  not a real drive subject. */
  drive: string | undefined;
  clientDbReady: boolean;
  /** True if a ClientDb was attached to the store (regardless of readiness). */
  clientDbAttached: boolean;
  /** Message of the error that prevented ClientDb init, if init has failed. */
  clientDbError?: string;
  lastDriveSync?: {
    drive: string;
    count: number;
    timestamp: number;
  };
  /** Set when the server refused the last SYNC_PUSH for a drive
   *  (`SYNC_REJECTED`: no write right, quota, not enrolled). Local edits
   *  are kept and offered again on the next handshake. Cleared by the
   *  next successful sync of that drive. */
  lastDriveSyncError?: {
    drive: string;
    message: string;
    timestamp: number;
  };
}

/** Compact representation of all Loro version vectors in a drive, for sync comparison. */
export interface DriveSyncState {
  drive: string;
  driveHash: string;
  /** Unique peer IDs across all resources, sorted. Counter arrays are indexed by this. */
  peers: string[];
  /** subject → counter array (indexed by `peers`). */
  resources: Record<string, number[]>;
}

export interface CommitLogPropertySummary {
  property: string;
  value: JSONValue;
  /**
   * `changed` — value differs from the prior commit (or this is the first
   * commit we've logged for the subject).
   * `removed` — present in the prior commit but absent now.
   */
  changeType: 'changed' | 'removed';
}

export interface CommitLogEntry {
  id: string;
  timestamp: number;
  direction: 'outgoing' | 'incoming';
  /**
   * - `pending`  — locally signed, queued, not yet posted to the server.
   * - `sent`     — server accepted the commit.
   * - `failed`   — server rejected, or the network call threw.
   * - `received` — incoming commit pushed to us by the server.
   */
  status: 'pending' | 'sent' | 'failed' | 'received';
  subject: string;
  signer?: string;
  previousCommit?: string;
  commitId?: string;
  hasLoroUpdate: boolean;
  destroy: boolean;
  summary: string;
  propertySummaries?: CommitLogPropertySummary[];
  error?: string;
}

/** These Events trigger certain Handlers */
export enum StoreEvents {
  /**
   * Whenever `Resource.save()` is called, so only when the user of this library
   * performs a save action.
   */
  ResourceSaved = 'resource-saved',
  /** User perform a Remove action */
  ResourceRemoved = 'resource-removed',
  /**
   * User explicitly created a Resource through a conscious action, e.g. through
   * the SideBar.
   */
  ResourceManuallyCreated = 'resource-manually-created',
  /** Event that gets called whenever the stores agent changes */
  AgentChanged = 'agent-changed',
  /** Event that gets called whenever the server url changes */
  ServerURLChanged = 'server-url-changed',
  /** Event that gets called whenever the drive changes */
  DriveChanged = 'drive-changed',
  /** Event that gets called whenever the websocket/server connection changes */
  ConnectionChanged = 'connection-changed',
  /** Event that gets called whenever sync/debug status changes */
  SyncStatusChanged = 'sync-status-changed',
  CommitLogChanged = 'commit-log-changed',
  /**
   * Fires every time a resource is added, merged, or replaced in the store —
   * for both local commits and remote `UPDATE` pushes. This is the single
   * signal that drives live collection membership: a `useCollection` listener
   * checks if the changed resource matches its filter and updates the cached
   * page in place, so a remote chat message no longer triggers a `/query`
   * refetch storm across every visible collection.
   */
  ResourceUpdated = 'resource-updated',
  /** Event that gets called whenever the store encounters an error */
  Error = 'error',
  /**
   * Vector search indexing for a drive root (from websocket `INDEX_STATUS`).
   * Use `store.on(StoreEvents.Indexing, driveSubject, callback)`.
   */
  Indexing = 'indexing',
}

export interface ImportJsonADOptions {
  /** Where the resources will be imported to  */
  parent: string;
  /** Danger: Replaces Resources with matching subjects, even if they are not Children of the specified Parent. */
  overwriteOutside?: boolean;
}

export interface AddResourcesOpts {
  /** If true, the resource will not be compared to the existing resource in the store. This is useful when you want to force an update. */
  skipCommitCompare?: boolean;
  replaceLoroDocsFromRemote?: boolean;
  /** If the resource was fetched via an alias, we should record that alias. */
  alias?: string;
}

/** Mirrors `SUBDOMAIN` in the server's `lib/src/urls.rs` (not yet part of a
 *  generated ontology). Serves the drive on its own subdomain. */
const SUBDOMAIN_PROP = 'https://atomicdata.dev/properties/subdomain';

/**
 * Opt-in tracing for search, mirroring `ws-debug`:
 * `localStorage.setItem('search-debug', '1')`.
 *
 * These lines used to be bare `console.debug`, on the assumption that browsers
 * hide that behind a "Verbose" log level. Chrome does; Safari's Web Inspector
 * shows Debug messages by default, so every visitor there saw the query, the
 * full search URL and the result count for each search — several per page
 * load. Diagnostics have to be asked for, not opted out of.
 */
const SEARCH_DEBUG =
  typeof localStorage !== 'undefined' &&
  localStorage.getItem('search-debug') === '1';

function searchDebug(...args: unknown[]): void {
  if (SEARCH_DEBUG) {
    console.debug(...args);
  }
}

export interface CreateDriveOpts {
  /** Shown on the drive page. Personal drives default to 'Your personal drive.'. */
  description?: string;
  /** Subdomain to serve the drive on (e.g. 'my-drive'). */
  subdomain?: string;
  /** Name to persist on the Agent resource as part of the same commit that
   *  links `privateDrive`. Only applies to personal drives — avoids a
   *  separate save for callers (e.g. dev-drive) that want the agent to be
   *  renderable as a named resource right away. */
  agentName?: string;
  /** A personal drive is the agent's derived home DID (same subject on every
   *  device). It is linked as `privateDrive` for older clients and hosts the
   *  saved-drives switcher list. A non-personal drive is pushed onto that
   *  list. Defaults to true. */
  personal?: boolean;
}

/**
 * Handlers are functions that are called when a certain event occurs.
 */
type StoreEventHandlers = {
  [StoreEvents.ResourceSaved]: ResourceCallback;
  [StoreEvents.ResourceRemoved]: SubjectCallback;
  [StoreEvents.ResourceManuallyCreated]: ResourceCallback;
  [StoreEvents.AgentChanged]: AgentCallback;
  [StoreEvents.ServerURLChanged]: ServerURLCallback;
  [StoreEvents.DriveChanged]: DriveCallback;
  [StoreEvents.ConnectionChanged]: ConnectionStateCallback;
  [StoreEvents.SyncStatusChanged]: SyncStatusCallback;
  [StoreEvents.CommitLogChanged]: CommitLogCallback;
  [StoreEvents.ResourceUpdated]: ResourceCallback;
  [StoreEvents.Error]: ErrorCallback;
  /** Only used via `on(Indexing, drive, cb)`; not emitted through EventManager. */
  [StoreEvents.Indexing]: IndexingStatusCallback;
};

export interface ResourceTreeTemplate {
  [property: string]: true | ResourceTreeTemplate;
}

/** Ingress source for {@link IncomingChange}. One enum for every
 * code path that produces resource state. */
export type ChangeSource =
  | 'ws-pending-get'
  | 'ws-sub-push'
  | 'ws-sync-push'
  | 'ws-query-update'
  | 'http-fetch'
  | 'local-pre-push'
  | 'local-acked'
  | 'local-post'
  | 'offline-replay';

/** One authoritative-or-local resource update. Either `loroBytes`
 * (WS paths) or `resource` (HTTP/local/offline) must be set. */
export interface IncomingChange {
  subject: string;
  loroBytes?: Uint8Array;
  resource?: Resource;
  /** `did:ad:commit:<sig>` — used for echo dedup on the loroBytes path. */
  commitId?: string;
  source: ChangeSource;
  receivedAt?: number;
  forceNotify?: boolean;
  replaceLoroDocsFromRemote?: boolean;
}

/** Returns True if the client has WebSocket support */
const supportsWebSockets = () => typeof WebSocket !== 'undefined';

/**
 * How long a fetch that is about to fail a resource will wait for the app's
 * local database to attach. It is a boot-time event — `initClientDb` derives a
 * database name and unwraps a key first — so it either happens within seconds
 * of the page loading or not at all. Only ever waited on paths that would
 * otherwise fail the resource permanently, and only when a database was
 * actually announced (see `Store.expectClientDb`).
 */
const CLIENT_DB_ATTACH_GRACE = 5000;

/**
 * The server-managed props that `Resource.rebuildCacheFromLoro` preserves even
 * when a Loro doc carries no delta for them (drive/parent/lastCommit/createdAt).
 * A resource that has ONLY these — no class, no user content — is a skeleton,
 * not a renderable resource. Used by the OPFS cold-load guard to decide whether
 * a local hit is authoritative. Keep in sync with the `serverManaged` list in
 * resource.ts.
 */
const SERVER_MANAGED_SKELETON_PROPS: ReadonlySet<string> = new Set([
  commits.properties.lastCommit,
  commits.properties.createdAt,
  'https://atomicdata.dev/properties/createdBy',
  'https://atomicdata.dev/properties/drive',
  core.properties.parent,
]);

/**
 * Cheap equality for commit-log property values. Strict `===` would always
 * report arrays/objects as different even when their contents match, so the
 * commit log would treat untouched array properties (e.g. `isA`) as
 * "changed" on every commit. JSON-stringifying for the few rich values is a
 * bounded cost — propvals are tiny and we only do this on log entry build.
 */
function commitLogValuesEqual(
  a: unknown | undefined,
  b: unknown | undefined,
): boolean {
  if (a === b) return true;
  if (a === undefined || b === undefined) return false;
  if (typeof a !== typeof b) return false;
  if (typeof a !== 'object') return false;

  try {
    return JSON.stringify(a) === JSON.stringify(b);
  } catch {
    return false;
  }
}

/**
 * An in memory store that has a bunch of usefful methods for retrieving Atomic
 * Data Resources. It is also resposible for keeping the Resources in sync with
 * Subscribers (components that use the Resource), and for managing the current
 * Agent (User).
 */
export class Store {
  /** A list of all functions that need to be called when a certain resource is updated */
  public subscribers: Map<string, ResourceCallback[]>;
  private loroSyncSubscribers: Map<string, LoroSyncCallback[]> = new Map();
  private loroEphemeralSubscribers: Map<string, LoroEphemeralCallback[]> =
    new Map();
  private presenceSubscribers: Map<string, PresenceCallback[]> = new Map();
  /** One presence manager per drive; managers remove themselves when
   *  their last subscriber leaves. */
  private presenceManagers: Map<string, DrivePresenceManager> = new Map();
  private injectedFetch: Fetch;
  /** The base URL of an Atomic Server. Where commits, search, and
   *  new-instance requests are sent. */
  private serverUrl: string;
  /**
   * A server URL that was set with `connect: false` — an origin known to run
   * no atomic-server. Remembered so a later `setServerUrl`/`setDrive` back to
   * the same URL (the drive defaults to it) does not open the socket after
   * all. Switching to any other URL connects as usual.
   */
  private serverUrlWithoutSocket?: string;
  /** The current Drive subject (DID or HTTP URL). `undefined` until
   *  `setDrive` is called — there is no implicit fallback to the
   *  server URL: a host URL is not a real drive subject and treating
   *  it as one made drive-scoped paths (SYNC_VV, `encodeSub`,
   *  collection filters) walk or subscribe to nothing. */
  private drive: string | undefined;
  /** All the resources of the store */
  private _resources: Map<string, Resource>;
  /** Mapping from HTTP aliases to primary subjects (e.g. DIDs) */
  private aliases: Map<string, string> = new Map();

  /** List of resources that have parents that are not saved to the server, when a parent is saved it should also save its children */
  private batchedResources: Map<string, Set<string>> = new Map();

  /** Subject → in-flight `fetchResourceFromServer` promise. Two parallel
   *  `useResource(X)` calls that both miss the cache share one network
   *  round-trip instead of each firing their own. Cleared in `finally`
   *  so subsequent calls (e.g. a forced refresh after a known change)
   *  can re-fetch. Keyed by normalized subject. */
  private _inFlightFetches: Map<string, Promise<Resource>> = new Map();

  /** Subjects with a gap-recovery fetch in flight. A delta that cannot apply
   *  triggers one full-state fetch; this stops a burst of unappliable deltas
   *  for the same subject from firing one fetch each. */
  private _gapRecoveries: Set<string> = new Set();

  /** Agent subjects already re-checked against the server this session — see
   *  the agent branch in {@link fetchResourceWithLocalFallback}. */
  private _revalidatedAgents: Set<string> = new Set();

  /** Current Agent, used for signing commits. Is required for posting things. */
  private agent?: Agent;
  /** Mapped from origin to websocket */
  private webSockets: Map<string, WSClient>;

  /** Optional WASM-backed client-side database running in a Web Worker. */
  private clientDb?: ClientDbWorker;
  /** Whether one is on its way — see {@link expectClientDb}. */
  private clientDbExpected = false;
  /** Callbacks parked in {@link waitForClientDb} until the attach happens. */
  private clientDbWaiters = new Set<() => void>();
  /**
   * Single durable queue replacing the old `dirtyForSync` Set +
   * `atomic.dirtyForSync` + `atomic.offline.<subject>` quartet.
   * Constructor callback re-emits `SyncStatusChanged` so subscribers
   * see queue-size changes without a manual `markDirtyForSync` call.
   */
  public readonly outbox: LocalOutbox = new LocalOutbox(() => {
    this.emitSyncStatus();
    this.scheduleOutboxDrain();
  });
  private outboxDrainTimer: ReturnType<typeof setTimeout> | undefined;
  /**
   * Macrotask-debounced auto-drain. Every local Loro op (`set`,
   * `loroSetProperty`, etc.) marks the subject dirty via
   * `outbox.markDirty`; we schedule a drain on the NEXT macrotask
   * so a burst of `set()` calls in one logical save boundary
   * coalesces into one drain pass.
   *
   * Why setTimeout and not queueMicrotask: microtasks run between
   * every `await` point, which means `await resource.set('a'); await
   * resource.set('b')` would drain after `a` (splitting the save
   * into two commits). setTimeout(0) defers past all current sync
   * + microtask work to the next macrotask cycle.
   *
   * Post-drain re-check: if entries remain after the drain completes
   * (typing during the `await postCommit` round-trip leaves the
   * subject dirty — see `hasOpsPastSaveCursor` in
   * `drainOutboxSubject`), schedule another drain so the new ops
   * land instead of stranding until the next user keystroke.
   */
  private scheduleOutboxDrain(): void {
    if (!this._serverConnected) return;
    if (this.outbox.size === 0) return;
    if (!this.getAgent()) return;
    // Wake when the soonest entry is due (0 = due now), honoring per-entry
    // backoff. Always (re)schedule to the soonest time rather than bailing on
    // an existing timer: a fresh edit (due now) must not wait behind a failing
    // entry's backoff window, and a drain that skipped only-backing-off entries
    // must still re-arm so they retry when due.
    const dueAt = this.outbox.nextDueAt();

    // `undefined` means nothing is drainable (e.g. every entry is blocked on an
    // unrecoverable 401). Don't arm a timer — those wait for a fresh edit.
    if (dueAt === undefined) {
      if (this.outboxDrainTimer) clearTimeout(this.outboxDrainTimer);
      this.outboxDrainTimer = undefined;

      return;
    }

    const delay = Math.max(0, dueAt - Date.now());
    if (this.outboxDrainTimer) clearTimeout(this.outboxDrainTimer);
    this.outboxDrainTimer = setTimeout(() => {
      this.outboxDrainTimer = undefined;
      if (!this._serverConnected) return;
      void this.syncDirtyResources().catch(() => undefined);
    }, delay);
  }
  /**
   * Whether the Store has an active connection to the server.
   * Driven by WebSocket open/close events. When false, commits are stored
   * locally and synced when the connection is restored.
   */
  private _serverConnected = false;
  private _serverConnectionError: string | undefined;
  private _driveSyncInProgress = false;
  /**
   * Saves that a UI layer has scheduled (e.g. `useValue`'s commit
   * debounce) but whose `save()` hasn't run yet. During that window the
   * edit is only in memory — not in the outbox, not `isSaving` — so
   * without this counter `getSyncStatus()` reports fully-synced while a
   * write is still pending in a timer, and a reload loses it. See
   * `planning/completed/outbox-drain-data-loss-race.md`.
   */
  private _scheduledSaves = 0;
  private _lastDriveSyncError?: {
    drive: string;
    message: string;
    timestamp: number;
  };
  private _lastDriveSync?: {
    drive: string;
    count: number;
    timestamp: number;
  };
  /** Every drive whose sync finished this session. `_lastDriveSync` only
   *  remembers the most recent one, which is not enough to answer "is the
   *  local index populated for THIS drive" once more than one is in play —
   *  see `hasCompletedDriveSyncFor`. */
  private _syncedDrives = new Set<string>();
  private _commitLog: CommitLogEntry[] = [];
  /**
   * Per-subject ACCUMULATED Loro snapshot bytes (genesis + every commit seen
   * so far), used by `summarizeCommitProperties` to diff each new commit and
   * show ONLY the properties it changed. A non-genesis commit's `loroUpdate`
   * is a delta, so the diff must be against this running full state — diffing
   * against the bare delta would make untouched properties look removed.
   */
  private _commitLogPriorSnapshots = new Map<string, Uint8Array>();

  private eventManager = new EventManager<StoreEvents, StoreEventHandlers>();

  /**
   * Subjects that were just manually created via {@link notifyResourceManuallyCreated},
   * keyed to the timestamp of the notification. Late `useEffect` subscribers
   * miss the fire-and-forget event when navigation completes faster than the
   * new component mounts; they read this map via {@link consumeRecentlyCreated}
   * to learn the resource is fresh.
   */
  private recentlyCreatedSubjects: Map<string, number> = new Map();

  private vectorIndexingSubscribers = new Map<
    string,
    Set<IndexingStatusCallback>
  >();

  private client: Client;

  public constructor(opts: StoreOpts = {}) {
    initOntologies();
    this._resources = new Map();
    this.webSockets = new Map();
    this.subscribers = new Map();

    if (opts.serverUrl) {
      this.setServerUrl(opts.serverUrl, { connect: opts.connect ?? true });
    }

    if (opts.agent) this.setAgent(opts.agent);

    // Initialize drive from localStorage if available.
    // No fallback to `serverUrl`: a bare host URL is not a real drive
    // subject — it carries no resources of its own, and the server's
    // `SYNC_VV` handler used to walk every `Tree::Resources` row
    // trying to enumerate "what's in" that pseudo-drive (the non-DID
    // branch in `lib/src/sync/engine.rs::collect_drive_subjects`).
    // `undefined` = no drive selected; the WS `handleOpen` skips
    // `startVVSync` when this is `undefined`, leaving the per-conn
    // actor free for the GET that almost always follows on share-
    // link / welcome-page cold opens.
    //
    // A stored *bare origin* (`https://host`) is not a drive — that used
    // to be the pre-DID stand-in for "no workspace selected". A stored
    // HTTP URL *with a path* is a real legacy drive subject and is
    // restored; `setDrive` will not treat it as a server switch.
    let storedDrive: string | undefined = undefined;

    if (typeof window !== 'undefined') {
      const raw = localStorage.getItem('drive');

      if (raw) {
        try {
          storedDrive = JSON.parse(raw);
        } catch {
          // ignore corrupt value
        }
      }
    }

    if (
      storedDrive &&
      (Client.isHttpDriveSubject(storedDrive) ||
        !(
          storedDrive.startsWith('http://') ||
          storedDrive.startsWith('https://')
        ))
    ) {
      this.drive = storedDrive;
    } else {
      this.drive = undefined;
    }

    // Local-only drives (e.g. the demo workspace) survive reloads: their
    // resources live in OPFS, so the routing decisions that keep them off
    // the wire must be restored before any save/subscribe runs.
    if (typeof window !== 'undefined') {
      try {
        const rawLocalOnly = localStorage.getItem('atomic.localOnlyDrives');

        if (rawLocalOnly) {
          this.localOnlyDrives = new Set(JSON.parse(rawLocalOnly));
        }
      } catch {
        // ignore corrupt value
      }
    }

    this.client = new Client(this.injectedFetch);

    // Rehydrate the commit log from the outbox so the Sync page
    // shows what's queued instead of "No activity recorded" after
    // a reload. The outbox itself is already populated by its
    // constructor — that handles both the new `atomic.outbox` key
    // and the one-shot migration from the legacy
    // `atomic.dirtyForSync` + `atomic.offline.<subject>` shape.
    for (const entry of this.outbox.pending()) {
      this.hydrateCommitLogFromOutbox(entry);
    }

    // We need to bind this method because it is passed down by other functions
    this.getAgent = this.getAgent.bind(this);
    this.setAgent = this.setAgent.bind(this);
  }

  /** All the resources of the store */
  public get resources(): Map<string, Resource> {
    return this._resources;
  }

  /** Inject a custom fetch implementation to use when fetching resources over http */
  public injectFetch(fetchOverride: Fetch) {
    this.injectedFetch = fetchOverride;
    this.client.setFetch(fetchOverride);
  }

  /**
   * Set a ClientDbWorker for local indexed queries and resource caching.
   * The worker runs the WASM ClientDb in a background thread.
   * Call this after constructing the Store — the worker initializes lazily.
   */
  /**
   * Declare that a local database is being attached, before it is ready to
   * attach. `initClientDb` derives the agent's database name and unwraps its
   * key before it can call {@link setClientDb}, and React renders (and starts
   * fetching) in the meantime — so a fetch in that window has to be able to
   * tell "no local database in this app" from "not attached yet". Only the
   * former should conclude a resource isn't stored locally.
   *
   * Call it synchronously at app start, and only when a database really is
   * coming: an app that opts out never waits.
   */
  public expectClientDb(): void {
    this.clientDbExpected = true;
  }

  /**
   * Resolves `true` once a ClientDb is attached, `false` if none arrives
   * within `timeoutMs` — or immediately, if none was ever expected.
   *
   * Public because the attach lands a few hundred ms after boot and a few
   * hundred ms after each agent change, and anything that needs the local
   * database right after sign-in (a vault restore, a first backup) would
   * otherwise read `getClientDb()` as "this app has no database".
   */
  public waitForClientDb(timeoutMs: number): Promise<boolean> {
    if (this.clientDb) return Promise.resolve(true);
    if (!this.clientDbExpected) return Promise.resolve(false);

    return new Promise<boolean>(resolve => {
      const done = () => {
        clearTimeout(timer);
        this.clientDbWaiters.delete(done);
        resolve(true);
      };

      const timer = setTimeout(() => {
        this.clientDbWaiters.delete(done);
        resolve(false);
      }, timeoutMs);

      this.clientDbWaiters.add(done);
    });
  }

  public setClientDb(clientDb: ClientDbWorker): void {
    // `initClientDb` calls this three times per page load (eager,
    // post-init, post-init-error) to refresh sync status. Only the
    // first call introduces a new worker; the others just want
    // `emitSyncStatus`.
    this.clientDb = clientDb;

    // Release fetches that started before the attach and would otherwise be
    // about to fail a resource this database can answer for.
    for (const waiter of [...this.clientDbWaiters]) waiter();

    this.emitSyncStatus();
  }

  /**
   * The drive a resource belongs to — the root of its `parent` chain,
   * resolved against the in-memory store.
   */
  private driveOf(subject: string): string {
    let current = subject;
    const seen = new Set<string>();

    for (let i = 0; i < 64; i++) {
      if (seen.has(current)) break;

      seen.add(current);
      const parent = this.resources.get(current)?.get(core.properties.parent);

      if (typeof parent !== 'string' || !parent || parent === current) {
        return current;
      }

      current = parent;
    }

    return current;
  }

  /** Drives that exist only on this client (e.g. the demo workspace).
   *  Their resources are fully functional locally — OPFS persistence,
   *  commit history, presence — but never touch a server: no outbox
   *  drains, no websocket subscriptions, no server fetches. Persisted
   *  to localStorage so a reload keeps treating them as local. */
  private localOnlyDrives = new Set<string>();

  /** Mark a drive as local-only. Must be called BEFORE the drive's first
   *  `save()` — registration is what routes saves away from the outbox. */
  public registerLocalOnlyDrive(drive: string): void {
    this.localOnlyDrives.add(drive);

    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(
        'atomic.localOnlyDrives',
        JSON.stringify([...this.localOnlyDrives]),
      );
    }
  }

  /** Forget a local-only drive (e.g. after deleting a demo workspace),
   *  keeping the persisted registration set bounded. */
  public unregisterLocalOnlyDrive(drive: string): void {
    if (!this.localOnlyDrives.delete(drive)) return;

    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(
        'atomic.localOnlyDrives',
        JSON.stringify([...this.localOnlyDrives]),
      );
    }
  }

  public isLocalOnlyDrive(drive: string): boolean {
    return this.localOnlyDrives.has(drive);
  }

  /**
   * True when `subject` is an HTTP(S) URL whose origin is not this
   * store's home server. Opening that resource must not move the
   * session: fetch it from its own origin, keep `serverUrl` here.
   */
  public isForeignOriginSubject(subject: string): boolean {
    if (!subject.startsWith('http://') && !subject.startsWith('https://')) {
      return false;
    }

    try {
      return new URL(subject).origin !== new URL(this.serverUrl).origin;
    } catch {
      return false;
    }
  }

  /**
   * Live SUB / SYNC_VV / presence go to the home server. Skip drives it
   * cannot serve: local-only workspaces, and HTTP drives that live on
   * another origin (fetched cross-origin, never subscribed here).
   */
  public isLiveSyncedDrive(drive: string): boolean {
    if (!drive || this.isLocalOnlyDrive(drive)) return false;

    return !this.isForeignOriginSubject(drive);
  }

  /**
   * Promote a local-only drive to a synced one: stop excluding it, then run
   * the normal drive reconcile against the connected server, which pushes the
   * drive's resources up (a local-only drive was never a special code path —
   * just one the sync engine was told to skip).
   *
   * Server-agnostic by design: a self-hosted server accepts the drive (open
   * admission); a managed node accepts it only if the drive is already
   * enrolled in its control plane — that enrollment is NOT this method's job
   * (it lives in the SaaS/managed layer). If the server rejects the pushed
   * commits, the drive simply stays local and the caller surfaces the error.
   *
   * Requires an active server connection. Resolves once the reconcile has been
   * kicked off; the actual push completes asynchronously (watch sync status).
   */
  public async promoteLocalDrive(drive: string): Promise<void> {
    const normalized = this.normalizeSubject(drive);

    if (!this.isLocalOnlyDrive(normalized)) return;

    if (!this._serverConnected) {
      throw new AtomicError(
        'Connect to a server before syncing this workspace.',
        ErrorType.Server,
      );
    }

    // Order matters: unregister first so the subscribe/reconcile below is no
    // longer skipped by the local-only guards.
    this.unregisterLocalOnlyDrive(normalized);
    this.subscribeWebSocket(normalized);

    const ws =
      this.getDefaultWebSocket() ?? this.getWebSocketForSubject(normalized);
    await ws?.resyncDrive(normalized);
  }

  /**
   * Whether a subject belongs to a local-only drive. Resolution mirrors
   * the server's rights check: the resource's stable `drive` propval
   * first, the in-memory parent chain as fallback. Best-effort — a
   * subject that isn't hydrated yet resolves through `driveOf` to
   * itself, so callers on cold paths should consult it AFTER local
   * (OPFS) hydration has run.
   */
  public isLocalOnlySubject(subject: string): boolean {
    if (this.localOnlyDrives.size === 0) return false;

    const normalized = this.normalizeSubject(subject);

    if (this.localOnlyDrives.has(normalized)) return true;

    const resource = this.resources.get(
      this.aliases.get(normalized) ?? normalized,
    );
    const drive = resource?.get('https://atomicdata.dev/properties/drive');

    if (typeof drive === 'string' && this.localOnlyDrives.has(drive)) {
      return true;
    }

    return this.localOnlyDrives.has(this.driveOf(normalized));
  }

  /** Returns the ClientDbWorker if one has been set (may still be initializing). */
  public getClientDb(): ClientDbWorker | undefined {
    return this.clientDb;
  }

  public getCommitLog(): CommitLogEntry[] {
    return [...this._commitLog];
  }

  /**
   * Surface a hydrated outbox entry in `_commitLog` as a `pending` row
   * so the Sync page shows what's queued after a reload, not
   * "No activity recorded". Under sign-at-drain the outbox doesn't
   * hold a signed envelope (except for `signedGenesis`); the pending
   * row just records "this subject has unsynced edits."
   */
  private hydrateCommitLogFromOutbox(entry: OutboxEntry): void {
    if (entry.signedGenesis) {
      const commit = entry.signedGenesis;
      this.pushCommitLog({
        timestamp: Date.now(),
        direction: 'outgoing',
        status: 'pending',
        subject: commit.subject,
        signer: commit.signer,
        previousCommit: commit.previousCommit,
        commitId: commit.signature
          ? `did:ad:commit:${commit.signature}`
          : undefined,
        hasLoroUpdate: !!commit.loroUpdate,
        destroy: !!commit.destroy,
        summary: this.summarizeCommit(commit),
        propertySummaries: this.summarizeCommitProperties(commit),
      });
    } else {
      this.pushCommitLog({
        timestamp: entry.enqueuedAt,
        direction: 'outgoing',
        status: 'pending',
        subject: entry.subject,
        destroy: false,
        hasLoroUpdate: true,
        summary: '(unsynced Loro edits)',
      });
    }
  }

  /**
   * Sync all queued writes to the server. Delegates to
   * {@link LocalOutbox.drain} which owns idempotency (concurrent
   * calls share the in-flight promise — the structural version of
   * the `5c168355` re-entrance fix).
   *
   * For each entry the outbox calls back into {@link drainOutboxSubject},
   * which exports the subject's Loro delta, signs one commit and posts it.
   */
  public async syncDirtyResources(): Promise<void> {
    if (this.outbox.size === 0 || !this.getAgent()) return;
    perfMark('store.syncDirtyResources.subjects', { count: this.outbox.size });
    this.emitSyncStatus();

    try {
      await this.outbox.drain({
        sort: this.sortOutboxEntries,
        tierOf: this.outboxTierOf,
        drainSubject: this.drainOutboxSubject,
        isTerminalError: (_entry, e) => {
          const msg = e instanceof Error ? e.message : String(e);
          const code = e instanceof AtomicError ? e.code : undefined;

          return isTerminalCommitError(msg, code);
        },
        onTerminalDrop: (entry, e) => {
          const msg = e instanceof Error ? e.message : String(e);
          // A redundant genesis commit (the resource already exists on the
          // server) is a benign reconciliation drop, not a lost write — the
          // data is already there. These can arrive in bulk when local state
          // lost its `lastCommit` chain (e.g. after switching servers), so
          // alarming the user with an error toast per commit is pure noise.
          // Other terminal drops may mean a genuinely lost edit, so those still
          // surface — silent discards are worse than visible recoveries there.
          const isRedundantGenesis = msg.includes(
            'is_genesis: true, but the resource already exists',
          );

          if (isRedundantGenesis) {
            console.debug(
              `Dropped redundant genesis commit for ${entry.subject} (already on server)`,
            );
          } else {
            this.notifyError(
              new Error(
                `Dropped stuck commit for ${entry.subject.slice(0, 60)}…: ${msg}`,
              ),
            );
          }

          // Best-effort: refetch the resource so the local copy aligns with
          // whatever the server already has. Skip client-only placeholder
          // subjects (`_new:`/`_local:`) — they never exist on the server, so
          // there's nothing to align with, and merging back a "not found"
          // response would reset `Resource.new`, re-arming the local-change
          // subscriber's dirty-tracking for the next edit and looping this
          // exact drop (see the `_new:` guard in `resource.ts`'s Loro
          // subscription).
          if (
            !entry.subject.startsWith('_new:') &&
            !entry.subject.startsWith('_local:')
          ) {
            this.fetchResourceFromServer(entry.subject).catch(() => undefined);
          }
        },
        isBlockingError: (_entry, e) => {
          const msg = e instanceof Error ? e.message : String(e);
          const code = e instanceof AtomicError ? e.code : undefined;

          return isUnrecoverableCommitError(msg, code);
        },
        onBlocked: (entry, e) => {
          const msg = e instanceof Error ? e.message : String(e);
          // Stopped retrying, but the entry stays queued + visible. Tell the
          // user once; a fresh edit (`markDirty`) re-arms it automatically.
          this.notifyError(
            new Error(
              `Could not sync ${entry.subject.slice(0, 60)}… — ${msg} ` +
                `Not retrying; edit again once you have access.`,
            ),
          );
        },
      });
    } finally {
      this.emitSyncStatus();
      // Re-arm for entries that remain — including ones skipped this pass
      // because they're still inside their backoff window (those fire no
      // `onChange`, so without this re-arm they would strand). `scheduleOutbox-
      // Drain` computes the next wake from `nextDueAt()`.

      if (this.outbox.size > 0) {
        this.scheduleOutboxDrain();
      }
    }
  }

  /**
   * Outbox sort order: agents → current drive → everything else,
   * with shallow-parent before deep within the last tier. Agents
   * must exist on the server before their commits validate; the
   * drive must exist before its children's `parent` references
   * resolve.
   */
  private sortOutboxEntries = (
    entries: readonly OutboxEntry[],
  ): OutboxEntry[] => {
    return [...entries].sort((a, b) => {
      const [pa, da] = this.outboxTier(a.subject);
      const [pb, db] = this.outboxTier(b.subject);
      if (pa !== pb) return pa - pb;

      return da - db;
    });
  };

  /**
   * The ordering tier of an outbox subject: `[priority, depth]`. Entries in
   * one tier have no ordering dependency on each other, so the outbox drains
   * them concurrently (pipelined COMMITs) and barriers between tiers; see
   * `OutboxDrainContext.tierOf`. Subjects whose resource is not loaded
   * report depth 0, as the sort always did.
   */
  private outboxTier(subject: string): [number, number] {
    let priority = 2;
    if (subject.startsWith('did:ad:agent:')) priority = 0;
    else if (subject === this.drive) priority = 1;

    let depth = 0;
    let current = subject;

    while (depth < 20) {
      const r = this.resources.get(current);
      if (!r) break;
      const parent = r.get(core.properties.parent) as string | undefined;
      if (!parent || parent === current) break;
      depth++;
      current = parent;
    }

    return [priority, depth];
  }

  private outboxTierOf = (entry: OutboxEntry): string => {
    const [priority, depth] = this.outboxTier(entry.subject);

    return `${priority}:${depth}`;
  };

  /**
   * Drain one subject's outbox entry under sign-at-drain. Steps:
   *
   *  1. If a `signedGenesis` envelope is queued (DID-derived subject
   *     whose POST hadn't acked yet), POST it. Server idempotently
   *     applies. On success: clear genesis, run the wasNew pipeline
   *     (subscribeWebSocket + saveBatchForParent), advance the Loro
   *     save cursor on the resource so subsequent delta exports start
   *     from this version.
   *  2. If the subject has accumulated local Loro ops (`markDirty` was
   *     called since the last successful drain), export the delta,
   *     sign ONE commit, POST. On
   *     success: clear dirty, `setLastCommitValue`, advance cursor.
   *
   *  Resource must be loaded in the store; cold drains for unloaded
   *  subjects fall through to a `getResource` (OPFS-first, then server)
   *  that rehydrates the Loro state before signing — but only once
   *  clientDb is ready. (On failure the entry stays dirty and the
   *  next drain trigger retries.)
   *
   *  Re-posting a server-applied commit is safe thanks to idempotent
   *  replay accept.
   */
  private drainOutboxSubject = async (subject: string): Promise<void> => {
    let entry = this.outbox.getEntry(subject);
    if (!entry) return;

    // A `_new:` subject has no derived DID yet — it must be sign-genesis'd
    // (which renames it to `did:ad:<sig>`) before it can be POSTed.
    // Reaching the drain with one is a bug in the save path: the server
    // rejects `subject: "_new:…"` with a 500 ("Unable to parse string as
    // URL") and the failed POST reschedules the drain, storming the server
    // forever. Drop the stray dirty bit rather than retry an un-POSTable
    // commit. The genesis derivation happens in `_saveInner`/`newResource`.
    if (subject.startsWith('_new:')) {
      this.outbox.clearGenesis(subject);
      this.outbox.clearDirty(subject);
      this.emitSyncStatus();

      return;
    }

    const endpoint = new URL('/commit', this.serverUrl).toString();

    // Step 1: POST the pre-signed genesis if present. The genesis
    // commit's `loroUpdate` was captured in `signChanges` at sign
    // time; `_loroVersionAtLastSave` was advanced THERE to the same
    // version. So we do NOT advance the cursor again here — doing so
    // would silently drop any ops the user typed between
    // `setGenesisCommit` and this drain pass (they're past the
    // genesis's captured version but would be marked "saved" by an
    // overzealous `markLoroSaved()`). Step 2 below picks those up.
    const postedGenesis = !!entry.signedGenesis;

    if (entry.signedGenesis) {
      const genesis = entry.signedGenesis;
      const created = await this.postCommit(genesis, endpoint);
      const commitId = commitIdOf(created);
      const resource = this.resources.get(subject);

      if (resource && commitId) {
        resource.setLastCommitValue(commitId);
        resource.applyToStore('local-acked', { commitId });
        resource.markSynced();
        await this.maybePushBlobForResource(resource).catch(() => undefined);
        // wasNew pipeline — first-time subscribe + save batched children
        this.subscribeWebSocket(subject);
        await this.saveBatchForParent(subject);
        // The genesis POST IS a save — fire `ResourceSaved` so listeners
        // waiting on first persistence run. The FilePicker, for example,
        // can't upload a file until its parent resource exists on the
        // server, so it sets `https://placeholder` and schedules the real
        // upload on `ResourceSaved`. When a resource is created via genesis
        // alone (no follow-up Loro delta), step 2 below short-circuits and
        // never notifies — so without this the scheduled upload never runs
        // and the placeholder is left dangling.
        this.notifyResourceSaved(resource);
      }

      this.outbox.clearGenesis(subject);
      entry = this.outbox.getEntry(subject);

      if (!entry) {
        this.emitSyncStatus();

        return;
      }
    }

    // Step 2: sign and POST the accumulated Loro delta, if any.
    let resource = this.resources.get(subject);

    if (!resource) {
      // Cold drain: resource not in memory. Typical shape: the entry was
      // restored from localStorage after a page load, and nothing on the
      // current page renders this subject — so no view will EVER load it,
      // and waiting for "the hydration path" would strand the entry (and
      // `pendingDirtyCount`) forever. Load it ourselves and drain on top.
      //
      // Critical ordering: do NOT load before clientDb (OPFS) is ready.
      // The OPFS snapshot is where unsynced local edits live; loading
      // server state instead would export an empty delta and clear the
      // dirty bit, silently dropping them. Until it's ready, leave the
      // entry dirty — the next drain pass retries.
      if (this.clientDb && !this.clientDb.isReady) {
        this.emitSyncStatus();

        return;
      }

      // OPFS-first, then server. Throws on hard failure (offline DID,
      // network error) — the outbox failure/backoff machinery takes over.
      resource = await this.getResource(subject);

      if (resource.error) {
        throw resource.error;
      }
    }

    // Cold-drain extension: even if there's a Resource object in
    // `this.resources` for the subject, treat it as "not hydrated"
    // when it's still loading and has no Loro doc state. A fresh
    // placeholder (`getResourceLoading` cold-call before clientDb
    // hydrate completes) shows up here as `loading=true` with an
    // empty Loro doc — draining it would `exportLoroDeltaForDrain →
    // undefined → clearDirty`, permanently dropping the
    // localStorage-restored offline edit before its real state has
    // a chance to land.
    const hasLoroState =
      resource.hasLoroDoc() && !!resource.getLoroDoc()?.oplogVersion();

    if (resource.loading && !hasLoroState) {
      this.emitSyncStatus();

      return;
    }

    const agent = this.getAgent();
    if (!agent) return;

    // Offline-edit recovery: if this subject went dirty while offline, the
    // outbox holds the last-synced version, and the ops past it live ONLY in
    // the OPFS snapshot until the ClientDb hydration lands. That makes two
    // rules absolute here:
    //
    //  1. Do not drain before the ClientDb is ready. A reconnect reload can
    //     hydrate this resource from the SERVER first (the WS GET wins the
    //     race against OPFS on a fast boot) — a doc with Loro state, so the
    //     cold-drain guard above doesn't catch it, but WITHOUT the offline
    //     ops. Exporting from it re-encodes ops the server already has; the
    //     server acks the no-op, `caughtUp` clears the dirty bit, and the
    //     offline edit is silently orphaned in OPFS — the CI-traced shape of
    //     sync.spec's "offline edits sync to server" failure (a fresh device
    //     kept reading the pre-offline title while every gate showed green).
    //  2. Once ready, import the OPFS snapshot BEFORE the first export — not
    //     only after an empty one. The poisoned export above is NOT empty,
    //     so an empty-export fallback never runs for it.
    //
    // Then rewind the cursor to the synced baseline so the export emits the
    // offline delta. No-op during normal online operation (`baseVersion` is
    // only set on the offline path).
    if (entry.baseVersion) {
      if (this.clientDb && !this.clientDb.isReady) {
        this.emitSyncStatus();

        return;
      }

      if (this.clientDb?.isReady) {
        try {
          const { jsonAd, snapshot } =
            await this.clientDb.getResourceWithSnapshot(subject);

          if (jsonAd) {
            this.hydrateResourceFromJson(subject, JSON.parse(jsonAd));
          }

          const refreshed = this.resources.get(subject);

          if (refreshed && snapshot && snapshot.length > 0) {
            // OPFS stores a full snapshot — replace any server-hydrated doc
            // that raced ahead of the offline local state.
            refreshed.importLoroUpdate(snapshot, true);
          }

          if (refreshed) resource = refreshed;
        } catch (e) {
          console.warn(
            `[Outbox] OPFS rehydrate before offline drain failed for ${subject}:`,
            e,
          );
        }
      }

      resource.restoreSaveCursor(entry.baseVersion);
    }

    const lastCommit = resource.getLastCommitForChain();
    const isFirstCommit = !lastCommit;
    // Tag this commit's Loro change with a unique token so the oplog keeps
    // a distinct Change per Atomic commit — `getLoroHistory` buckets by it
    // to reconstruct one version per commit. The token only needs to be
    // unique within the doc's oplog (including across reloads, since a
    // rehydrated doc carries its old tokens), so combine wall-clock time
    // with a monotonic counter.
    const commitToken = `c-${this.randomPart()}`;
    // Capture {bytes, version} atomically so the cursor advances to
    // the version that's in this commit — not to a later one that
    // arrived during the await on `postCommit`.
    let exported = resource.exportLoroDeltaForDrain(isFirstCommit, commitToken);

    if (!exported) {
      if (entry.baseVersion && postedGenesis) {
        // Genesis already captured the doc. An empty follow-up is "caught
        // up", not "OPFS not ready" — leaving dirty here is what stranded
        // `offline-create-then-online` (pendingDirtyCount stuck at 1,
        // hasSignedGenesis false, drain spinning).
        this.outbox.clearBaseVersion(subject);
        this.outbox.clearDirty(subject);
        this.emitSyncStatus();

        return;
      }

      if (entry.baseVersion) {
        console.warn(
          `[Outbox] empty Loro export for ${subject} with offline baseVersion; leaving dirty for retry`,
        );
        this.emitSyncStatus();

        return;
      }

      this.outbox.clearBaseVersion(subject);
      this.outbox.clearDirty(subject);
      this.emitSyncStatus();

      return;
    }

    const { bytes: delta, versionAfterExport } = exported;
    const builder = new CommitBuilder(subject);
    builder.setLoroUpdate(delta);
    const commit = await builder.sign(agent);

    const created = await this.postCommit(commit, endpoint);
    const commitId = commitIdOf(created);

    if (commit.signature) {
      resource.appliedCommitSignatures.add(commit.signature);
    }

    if (commitId) {
      resource.setLastCommitValue(commitId);
      resource.applyToStore('local-acked', { commitId });
    }

    // Advance the cursor to the version that was IN this commit, not
    // to current oplog version — any local ops added during the
    // `await postCommit` round-trip are post-commit and must remain
    // dirty until the next drain pass.
    resource.markLoroSavedAt(versionAfterExport);

    // The offline baseline (if any) has now been exported and acked — the
    // cursor sits at or past it, so drop it. Any still-dirty ops past the
    // cursor are online edits with the live cursor as their baseline.
    this.outbox.clearBaseVersion(subject);

    // Did this commit capture everything, or did the user type more
    // during the `await postCommit` round-trip? Compute BEFORE firing
    // `notifyResourceSaved` so the `_dirty` flag is already cleared
    // when `UnsavedIndicator`'s ResourceSaved handler re-reads
    // `hasUnsavedChanges()` — otherwise it reads a stale `true` and the
    // editable-title `*` never clears (rename-regression e2e).
    const caughtUp = !resource.hasOpsPastSaveCursor();

    if (caughtUp) {
      resource.markSynced();
      this.outbox.clearDirty(subject);

      // Persist the now-synced state to the local ClientDb (OPFS). The
      // `applyToStore('local-acked')` above ran while this subject still had a
      // pending outbox entry, so `addResource`'s `!hasPendingCommits` gate
      // skipped the snapshot write. `clearDirty` just removed the entry, so
      // `hasPendingCommits` is false now — re-run the persist. Without this an
      // edit reaches the server but the local cache keeps the pre-edit
      // snapshot, and a reload reads the stale state (the WS commit echo is
      // deduped by commitId, so it won't re-persist it either).
      //
      // Queue the put BEFORE `ResourceSaved` so listeners that re-query
      // (table totals) post onto the same worker after this write, not
      // against the pre-edit index.
      this.addResource(resource, { skipCommitCompare: true });
    } else {
      this.outbox.markDirty(subject);
    }

    this.notifyResourceSaved(resource);
    await this.maybePushBlobForResource(resource).catch(() => undefined);

    this.emitSyncStatus();
  };

  /**
   * Compute the drive sync state: a hash summarizing all resources' Loro
   * version vectors, plus the individual VV data for diff computation.
   * Used by the sync protocol to determine what needs syncing.
   */
  public async computeDriveSyncState(drive: string): Promise<DriveSyncState> {
    // Collect VVs from WASM DB (persisted snapshots)
    let allVVs: Record<string, Record<string, number>> = {};

    if (this.clientDb) {
      try {
        // Scoped to THIS drive via the same parent-index walk the server uses
        // (`collect_drive_subjects`): O(this drive) instead of O(every resource
        // in every drive). It also keeps foreign-drive subjects out of the VV
        // we send — the server treats a client-known subject it doesn't have in
        // the drive as a pull/remove candidate, so an unscoped VV made every
        // single-drive sync reason about unrelated drives' resources.
        const endVV = perfSpan('clientdb.getVersionVectorsForDrive');
        allVVs = await this.clientDb.getVersionVectorsForDrive(drive);
        endVV({ count: Object.keys(allVVs).length });
      } catch {
        // WASM DB may not be ready yet
      }
    }

    // Also collect from in-memory resources that belong to this drive.
    // Covers freshly created resources not yet persisted to the WASM DB.
    for (const [subject, resource] of this.resources) {
      if (allVVs[subject]) continue;

      // Only include resources belonging to this drive
      const parent = resource.get(core.properties.parent) as string | undefined;

      if (subject !== drive && parent !== drive) continue;

      const doc = resource.getLoroDoc?.();

      if (!doc) continue;

      // Debug: inspect the VV
      try {
        const vv = doc.oplogVersion?.();

        // VersionVector from loro-crdt has toJSON() → Map<PeerID, number>
        if (vv && typeof vv.toJSON === 'function') {
          const vvMap: Record<string, number> = {};
          const jsonMap = vv.toJSON() as Map<string, number>;

          for (const [peerId, counter] of jsonMap) {
            vvMap[String(peerId)] = Number(counter);
          }

          if (Object.keys(vvMap).length > 0) {
            allVVs[subject] = vvMap;
          }
        }
      } catch {
        // Loro doc may not be fully initialized
      }

      // If VV is empty but resource exists and isn't new, include it with
      // an empty VV so the server knows we have it (even if we can't diff).
      // This happens when Loro state was clobbered by a merge from server
      // JSON-AD that doesn't include the snapshot.
      if (!allVVs[subject] && !resource.new) {
        allVVs[subject] = {};
      }
    }

    // F1 interim (planning/unified-sync.md): the outbox drain is the only
    // writer for dirty subjects — signs a commit, rights-checked on the
    // hub. VV sync must cover only subjects the outbox doesn't know about.
    // A subject with a pending outbox entry (mid-backoff, or just not
    // drained yet this pass) would otherwise show up "ahead" in the VV we
    // send here, and the server answers by requesting a `SYNC_PUSH` of the
    // raw (unsigned) Loro bytes for it — bypassing rights checks entirely
    // for that edit. Dropping it here means the server sees no VV for the
    // subject and won't ask; the drain picks it up once its backoff clears.
    for (const subject of Object.keys(allVVs)) {
      if (this.outbox.hasPending(subject)) {
        delete allVVs[subject];
      }
    }

    // Collect unique peer IDs across all resources
    const peerSet = new Set<string>();

    for (const vv of Object.values(allVVs)) {
      for (const peerId of Object.keys(vv)) {
        peerSet.add(peerId);
      }
    }

    const peers = [...peerSet].sort();
    const peerIndex = new Map(peers.map((p, i) => [p, i]));

    // Build compact resource VV list (counters indexed by peers array)
    const resources: Record<string, number[]> = {};

    for (const [subject, vv] of Object.entries(allVVs)) {
      const counters = new Array(peers.length).fill(0);

      for (const [peerId, counter] of Object.entries(vv)) {
        const idx = peerIndex.get(peerId);

        if (idx !== undefined) {
          counters[idx] = counter;
        }
      }

      resources[subject] = counters;
    }

    // Canonical hash, byte-identical to the Rust server (see
    // `canonicalDriveHash` / planning/drive-reconciliation.md Phase 1).
    const driveHash = await canonicalDriveHash(resources);

    return { drive, driveHash, peers, resources };
  }

  /**
   * Query the local WASM database. Returns null if no ClientDb is available.
   * This runs in a Web Worker and does not block the main thread.
   */
  public async queryLocalDb(
    opts: ClientDbQueryOpts,
  ): Promise<ClientDbQueryResult | null> {
    if (!this.clientDb) return null;

    // Wait for the DB to be ready
    if (!this.clientDb.isReady) {
      const ready = await this.clientDb.waitForReady();

      if (!ready) return null;
    }

    try {
      return await this.clientDb.query(opts);
    } catch (e) {
      console.warn('[ClientDb] query failed:', e);

      return null;
    }
  }

  /**
   * Try to load a resource from the WASM DB (OPFS).
   * Returns the Resource if found, or null if not available.
   */
  private async fetchResourceFromClientDb(
    subject: string,
  ): Promise<Resource | null> {
    if (!this.clientDb) return null;

    if (!this.clientDb.isReady) {
      const ready = await this.clientDb.waitForReady();

      if (!ready) return null;
    }

    try {
      const jsonAd = await this.clientDb.getResource(subject);
      if (!jsonAd) return null;

      return this.hydrateOfflineReplay(subject, JSON.parse(jsonAd));
    } catch {
      return null;
    }
  }

  /** Build a Resource from a parsed JSON-AD object, hydrate Loro,
   *  and route through the unified ingress with `offline-replay`
   *  source. Used by both the OPFS-cold-load path and the
   *  per-page-reload outbox restore path. */
  private hydrateOfflineReplay(
    subject: string,
    parsed: Record<string, unknown>,
  ): Resource {
    const resource = new Resource(subject);
    resource.applyHydratedValues(
      Object.entries(parsed).filter(([key]) => key !== '@id') as [
        string,
        JSONValue,
      ][],
    );
    resource.getLoroDoc();
    resource.loading = false;
    this.applyIncoming({
      subject: resource.subject,
      resource,
      source: 'offline-replay',
    });

    return resource;
  }

  /**
   * Normalizes a subject: if it is a relative path, it becomes a full URL using the server's base URL.
   * DIDs and full HTTP URLs are returned as-is.
   */
  /** Normalize then alias-resolve a user-supplied subject to its
   *  canonical key (the one used in the resources Map). */
  private resolveSubject(subject: string): string {
    const normalized = this.normalizeSubject(subject);

    return this.aliases.get(normalized) ?? normalized;
  }

  /**
   * True when `subject` is a placeholder (`_new:…`) that has since been aliased
   * to a real subject — i.e. the draft it stood for has been persisted.
   *
   * Lets a view tell apart the two reasons a collection can grow: one of its
   * own drafts materialising, versus a resource arriving from elsewhere (a
   * peer, or another tab). Those need opposite handling, and without a way to
   * distinguish them a view has to guess.
   */
  public isAliased(subject: string): boolean {
    return this.aliases.has(this.normalizeSubject(subject));
  }

  /** Resolve a (possibly aliased) subject to its cached Resource. */
  private getResolved(subject: string): Resource | undefined {
    return this.resources.get(this.resolveSubject(subject));
  }

  /** Mark a resource as errored + not-loading + notify. No-op if
   *  the subject isn't in the store. */
  private failResource(subject: string, error: Error): void {
    const resource = this.getResolved(subject);
    if (!resource) return;
    resource.loading = false;
    resource.setError(error);
    this.notify(resource);
  }

  /**
   * Returns true if this store owns the given subject — i.e. local
   * Loro edits to it should be POSTed to our server. Used by the
   * sign-at-drain dirty filter: external-domain HTTP subjects and
   * derived commit-detail resources accept Loro hydration locally
   * but must not reach our `/commit` endpoint.
   */
  public isOwnedSubject(subject: string): boolean {
    if (subject.startsWith('did:ad:commit:')) return false;
    if (subject.startsWith('did:')) return true;
    // `_new:` is the client-only transient subject between
    // `getResourceLoading` and the DID derive in `signChanges`.
    // `_local:` is Rust-side and shouldn't appear here.
    if (subject.startsWith('_new:')) return true;

    if (subject.startsWith('http://') || subject.startsWith('https://')) {
      try {
        const url = new URL(subject);

        // Query/endpoint URLs (`/query?page_size=…`, search, etc.) carry
        // query params. They're transient server-computed projections
        // that happen to be Loro-backed locally for client-side sorting
        // — NOT committable resources. A real resource subject never has
        // query params (commits strip them via `removeQueryParamsFromURL`).
        // Without this guard the Loro subscriber marks these dirty, they
        // enter the outbox, and the drain can never POST a commit for a
        // `/query?…` endpoint → `pendingDirtyCount` never reaches 0 and
        // every `waitForSynced` / offline-sync flow strands. (sync:219.)
        if (url.search) return false;

        return url.origin === new URL(this.serverUrl).origin;
      } catch {
        return false;
      }
    }

    return false;
  }

  public normalizeSubject(subject: string): string {
    const stripLeadingSlash = (value: string) =>
      value.startsWith('/') ? value.slice(1) : value;
    const maybeTempSubject = stripLeadingSlash(subject);

    // Internal temporary subjects (used during newResource before DID
    // derivation) are returned verbatim — they must not be resolved as URLs.
    if (
      maybeTempSubject.startsWith('_new:') ||
      maybeTempSubject.startsWith('_local:')
    ) {
      return maybeTempSubject;
    }

    // DIDs are returned as-is — new URL() would mangle base64 characters (+, /, =)
    if (subject.startsWith('did:')) {
      return subject;
    }

    // HTTP URLs are normalized
    if (subject.startsWith('http://') || subject.startsWith('https://')) {
      try {
        const url = new URL(subject);

        // Remove trailing slash if it's not the root
        if (url.pathname.length > 1 && url.href.endsWith('/')) {
          return url.href.slice(0, -1);
        }

        return url.href;
      } catch (e) {
        return subject;
      }
    }

    // Relative path - resolve to full URL
    // This also handles trailing slashes consistently
    try {
      const url = new URL(subject, this.serverUrl);

      if (url.pathname.length > 1 && url.href.endsWith('/')) {
        return url.href.slice(0, -1);
      }

      return url.href;
    } catch (e) {
      return subject;
    }
  }

  /**
   * Repair a document that has fallen behind: fetch full state and replace the
   * local doc with it.
   *
   * The live channel is deltas, and it has no way to say "you are missing
   * something". A receiver that misses one update queues every later one as
   * pending, which looks exactly like a document that quietly stopped syncing.
   * `SYNC_VV` already handles this at connect time; this is the mid-session
   * equivalent, triggered by the one signal available — an import that could
   * not fully apply.
   *
   * Failures are swallowed on purpose. This runs off the back of an incoming
   * update, the caller keeps its existing (stale but usable) state either way,
   * and a network error here should not surface as an error on a document the
   * user can still read.
   */
  private recoverFromIncompleteImport(subject: string, source?: string): void {
    if (this._gapRecoveries.has(subject)) return;

    this._gapRecoveries.add(subject);
    console.warn(
      `[Store] incomplete Loro import for ${subject.slice(0, 60)} ` +
        `(source: ${source ?? 'unknown'}) — missing base state, fetching a full ` +
        `snapshot to catch up.`,
    );

    this.fetchResourceFromServer(subject, { forceOverride: true })
      .catch(() => undefined)
      .finally(() => {
        this._gapRecoveries.delete(subject);
      });
  }

  /**
   * Single ingress for resource state from any source: subject
   * normalisation, commit-id dedup, Loro hydration, atomic OPFS
   * persist, one `notify` — in that order.
   */
  public applyIncoming(
    change: IncomingChange,
  ): 'applied' | 'deduped' | 'invalid' {
    // Resource-direct path: caller is the authoritative producer.
    if (change.resource) {
      const alias =
        change.subject !== change.resource.subject ? change.subject : undefined;
      this.addResource(change.resource, {
        skipCommitCompare: true,
        alias,
        replaceLoroDocsFromRemote: change.replaceLoroDocsFromRemote,
      });

      return 'applied';
    }

    if (!change.loroBytes) return 'invalid';

    const subject = this.normalizeSubject(change.subject);
    const existing = this.resources.get(this.aliases.get(subject) ?? subject);

    // Echo dedup: same commitId as cached lastCommit ⇒ no-op.
    if (
      !change.forceNotify &&
      change.commitId &&
      existing &&
      !existing.loading &&
      !existing.new &&
      existing.get(commits.properties.lastCommit) === change.commitId
    ) {
      return 'deduped';
    }

    const resource =
      existing ?? this.getResourceLoading(subject, { newResource: false });
    // A GET response carrying the SNAPSHOT flag is authoritative full state
    // (`replaceLoroDocsFromRemote`). REPLACE rather than merge it — merging a
    // full snapshot into a doc the client already seeded with partial state (a
    // SUB push that delivered only some props) can surface only the seed's
    // props, leaving the resource class-less (the "deeply broken drive"). Don't
    // replace a commit-detail delta, and don't clobber unsaved local edits.
    //
    // `hasUnsavedChanges()` is in-memory only, so it's blind on a cold
    // reload: a WS reconnect can deliver the server's stale (pre-offline-
    // edit) snapshot for a subject whose offline edit only exists in
    // clientDb + the outbox's durable (localStorage-backed) dirty bit —
    // nothing has called `set()` on THIS freshly-created Resource object
    // yet. Without also checking `outbox.hasPending`, `replace: true`
    // wipes the doc via `resetLoroState()` before the OPFS-based local
    // hydration (`fetchResourceWithLocalFallback`) gets a chance to merge
    // the offline edit back in — silently dropping it. See
    // `hydrateResourceFromJson`'s sibling comment for why that path
    // deliberately does NOT gate the OPPOSITE decision (whether to
    // hydrate at all) on this same durable bit — this is a different,
    // narrower gate: only whether a destructive replace is safe.
    const replace =
      !!change.replaceLoroDocsFromRemote &&
      !subject.startsWith('did:ad:commit:') &&
      !resource.hasUnsavedChanges() &&
      !this.outbox.hasPending(subject);
    const { complete } = resource.importLoroUpdate(change.loroBytes, replace);

    // Commit-detail resources (`did:ad:commit:<sig>`) carry a single
    // commit's `loroUpdate`, which is a DELTA by design — importing it
    // into a fresh doc legitimately leaves "pending" ops (the base it
    // builds on lives in the committed-to resource, not here). They are
    // exempt from the incomplete-import guard below; otherwise every
    // commit fetched on refresh (e.g. <CommitDetail> in a chatroom)
    // would be failed and vanish.
    const isCommitDetail = subject.startsWith('did:ad:commit:');

    // Incomplete import: the bytes couldn't fully apply (missing base
    // ops left pending). The resource has whatever it had before plus
    // `lastCommit` — but NOT the real Loro-backed props. Without this
    // guard it would flip to `loading=false` and render as an empty
    // "loaded" resource (only `subject` + `lastCommit` showing), with
    // no error anywhere. Surface it instead. Skip the failure if the
    // resource already had usable content from a prior good import
    // (a late/partial live push shouldn't blow away a good state).
    if (!complete && !isCommitDetail) {
      if (!resource.get(core.properties.isA)) {
        console.warn(
          `[Store] applyIncoming: incomplete Loro import for ${subject.slice(0, 60)} ` +
            `(source: ${change.source}) — server sent a delta this client can't apply ` +
            `(missing base state). Surfacing as error.`,
        );
        if (change.commitId) resource.setLastCommitValue(change.commitId);
        this.failResource(
          subject,
          new Error(
            'Sync error: received an incomplete update for this resource ' +
              '(missing base state). Try reloading; if it persists, the ' +
              "local cache may be out of sync with the server's history.",
          ),
        );

        return 'invalid';
      }

      // The resource already has usable content, so failing it would throw
      // away good state for the sake of an update we couldn't apply. The old
      // code took the other extreme and fell through to `return 'applied'`,
      // which is how a collaborator's text went missing in silence: one
      // delta arrives whose base ops we never saw, Loro parks it as pending,
      // and every later delta parks behind it. No error, no indicator — the
      // document simply stops being live until someone reloads.
      //
      // Ask for full state instead. `forceOverride` replaces rather than
      // merges, which is what closes the gap; `applyIncoming`'s own guards
      // still refuse to clobber unsaved local edits or a pending outbox.
      //
      // Deliberately NOT stamping `lastCommit` here. We did not apply that
      // commit, and claiming it would make the echo-dedup at the top of this
      // method drop the very fetch being issued to repair the gap.
      this.recoverFromIncompleteImport(subject, change.source);
      resource.loading = false;
      this.addResource(resource, { skipCommitCompare: true });

      return 'invalid';
    }

    if (change.commitId) resource.setLastCommitValue(change.commitId);
    resource.loading = false;
    this.addResource(resource, { skipCommitCompare: true });

    return 'applied';
  }

  /**
   * Persist + notify a Resource into the store. Most callers
   * should prefer {@link applyIncoming}, which adds an explicit
   * `source` tag and a commit-id dedup. This direct entry is kept
   * for tests/benches and for paths that already own a Resource
   * but don't care about source attribution.
   */
  public addResource(
    resource: Resource,
    {
      skipCommitCompare,
      alias,
      replaceLoroDocsFromRemote,
    }: AddResourcesOpts = {},
  ): void {
    // The resource might be new and not have a store yet. We set it here.
    resource.setStore(this);

    const subject = this.normalizeSubject(resource.subject);

    if (alias) {
      const normalizedAlias = this.normalizeSubject(alias);

      if (normalizedAlias !== subject) {
        this.aliases.set(normalizedAlias, subject);
      }
    }

    if (resource.subject !== subject) {
      resource.setSubject(subject);
    }

    // Incomplete resources may miss some properties
    if (resource.get(core.properties.incomplete)) {
      // If there is a resource with the same subject, we won't overwrite it with an incomplete one
      const existing = this.resources.get(subject);

      if (existing && !existing.loading) {
        return;
      }
    }

    const storeResource = this.resources.get(subject);

    // Check if the resource has the same last commit as the one already in the store, if so, we don't want to notify so we don't trigger rerenders.
    if (!skipCommitCompare) {
      if (
        storeResource &&
        !storeResource.hasClasses(collections.classes.collection) &&
        !storeResource.loading &&
        !storeResource.new &&
        storeResource.get(commits.properties.lastCommit) ===
          resource.get(commits.properties.lastCommit)
      ) {
        return;
      }
    }

    // If the resource is already in the store, we merge it so code that
    // depends on the resource will get the new values.
    // EXCEPT: if the existing resource has unsaved local changes (dirty),
    // don't overwrite it with the server's version. The local changes
    // need to be synced first.
    if (storeResource) {
      storeResource.merge(resource.__internalObject, {
        replaceLoroDocs: replaceLoroDocsFromRemote,
      });
    } else {
      this.resources.set(subject, resource.__internalObject);
    }

    const emitResource = storeResource ?? resource.__internalObject;

    // Atomic put queued BEFORE notify. The worker's serialised
    // queue means a follow-up `queryLocalDb` (e.g. from
    // Collection.refresh in a notify listener) sees the new
    // resource. Skip for new/loading/incomplete/unsynced — those are
    // persisted by the save path once they are real, or are
    // placeholders.
    if (
      this.clientDb &&
      // A Collection is a derived query result, not a record: a page is either
      // assembled from `queryLocalDb` over the index or fetched from the
      // server, and neither ever reads it back out of the local database.
      // Writing it there costs a full index rebuild and an fsync for something
      // nothing reads — and because collections are deliberately exempt from
      // the `lastCommit` skip above, they are re-added (and so re-written) on
      // every refresh. Building one table from a template wrote a single
      // collection page seven times.
      !resource.hasClasses(collections.classes.collection) &&
      // Skip persisting when the worker has a known init failure (e.g.
      // OPFS leader-election couldn't steal the lock — Firefox doesn't
      // support `navigator.locks.request({ steal: true })`). Without this
      // gate every single `addResource` would queue a `putResourceWithSnapshot`
      // that fails with the same error, flooding the console with one
      // stack trace per resource. The worker itself has already warned
      // once when init failed — that single line is the actionable signal.
      !this.clientDb.initError &&
      !resource.loading &&
      !resource.new &&
      !resource.hasPendingCommits &&
      !resource.get(core.properties.incomplete)
    ) {
      try {
        const jsonAd = resourceToJsonAd(resource);

        if (jsonAd) {
          const doc = resource.getLoroDoc?.();
          const snapshot = doc?.export({ mode: 'snapshot' });

          // One local-DB write costs ~9ms, three quarters of it rebuilding
          // this resource's index entries. `addResource` runs on every merge
          // and every notify, so the same unchanged state was being written
          // repeatedly — a table built from a template did 64 writes for 15
          // resources. Hash what we are about to write and skip the write when
          // it matches the last one for this subject.
          //
          // Deliberately a content hash rather than `lastCommit`: local edits
          // and merges change state without advancing it. The hash covers the
          // Loro snapshot too, so a CRDT-only change still writes. A collision
          // would skip one cache write, which the server copy repairs — this
          // is a cache, not the record.
          const stamp = hashPersistedState(jsonAd, snapshot);

          if (this.lastPersistedStamp.get(resource.subject) !== stamp) {
            this.lastPersistedStamp.set(resource.subject, stamp);
            this.clientDb
              .putResourceWithSnapshot(resource.subject, jsonAd, snapshot)
              .catch(e => {
                // Failed write: drop the stamp so the next attempt is not
                // skipped as a duplicate of a write that never landed.
                this.lastPersistedStamp.delete(resource.subject);
                console.error(
                  `[ClientDb] put failed for ${resource.subject.slice(0, 60)}:`,
                  e,
                );
              });
          }
        }
      } catch (e) {
        console.error(
          `[ClientDb] put serialization threw for ${resource.subject.slice(0, 60)}:`,
          e,
        );
      }
    }

    this.notify(emitResource);
  }

  /**
   * Create a new resource.
   *
   * When `did` is `true` (the default) the genesis commit is signed locally so
   * the resource's real DID (`did:ad:<signature>`) is known immediately — no
   * server round-trip required.  An agent must be set on the store for DID
   * resources.
   *
   * The resource is **not** pushed to the server yet; call `resource.save()`
   * to persist it.
   */
  public async newResource<C extends OptionalClass = UnknownClass>({
    subject,
    parent,
    isA,
    propVals,
    noParent,
    did,
    genesisCert,
  }: CreateResourceOptions = {}): Promise<Resource<C>> {
    const shouldUseDid =
      did ?? this.getAgent()?.subject?.startsWith('did:ad:agent:') ?? false;
    const normalizedParent = parent
      ? this.normalizeSubject(parent)
      : this.normalizeSubject(this.serverUrl);

    const normalizedIsA = Array.isArray(isA) ? isA : [isA];

    const DRIVE_PROP = 'https://atomicdata.dev/properties/drive';
    const GENESIS_PROP = 'https://atomicdata.dev/properties/genesis';

    // The immutable `drive` this resource lives in — its parent's drive, or the
    // parent itself when the parent is a drive root. Resolved from the local
    // cache (sync, no network). Undefined for a top-level (noParent) resource.
    const resolvedDrive = noParent
      ? undefined
      : ((this.resources.get(normalizedParent)?.get(DRIVE_PROP) as
          | string
          | undefined) ?? normalizedParent);

    // Mint the DID up front from a self-verifying genesis certificate (mirrors
    // `lib/src/commit.rs::create_did`): the cert's fields — signer, createdAt,
    // nonce, parent, drive — are all known at creation, so the resource carries
    // its real `did:ad:<cert-signature>` from birth. No `_new:` placeholder, no
    // post-sign rename. A caller-supplied subject (incl. `did:ad:agent:`, whose
    // identity is its public key, not a cert) is used verbatim.
    let newSubject: string;
    let genesisCertB64: string | undefined;

    if (genesisCert) {
      const minted = await this.mintFromCert(genesisCert);
      newSubject = subject ?? minted.did;
      genesisCertB64 = minted.certB64;
    } else if (subject) {
      newSubject = subject;
    } else if (shouldUseDid) {
      const minted = await this.mintCertDid(
        noParent ? '' : normalizedParent,
        resolvedDrive ?? '',
      );
      newSubject = minted.did;
      genesisCertB64 = minted.certB64;
    } else {
      newSubject = this.createHTTPSubject(normalizedParent);
    }

    const resource = this.getResourceLoading(newSubject, { newResource: true });

    // Carry the inline cert (mirrors `commit.rs:299`): the server verifies the
    // DID against it and materializes createdBy/createdAt/parent/drive from it.
    if (genesisCertB64) {
      await resource.set(GENESIS_PROP, genesisCertB64, false);
    }

    if (normalizedIsA[0]) {
      await resource.addClasses(...(normalizedIsA as string[]));
    }

    if (!noParent) {
      await resource.set(core.properties.parent, normalizedParent);
      // The same value that seeded the cert's immutable `drive` above; the
      // server's rights check consults this stable grant instead of walking a
      // parent that may not be materialized yet (the parent-before-child 401
      // cascade). `validate:false` skips the ontology fetch.
      await resource.set(DRIVE_PROP, resolvedDrive ?? normalizedParent, false);
    }

    if (propVals) {
      for (const [key, value] of Object.entries(propVals)) {
        await resource.set(key, value);
      }
    }

    // Sign the genesis commit locally now — its subject is already the cert DID,
    // so `signChanges` derives nothing and renames nothing — then STASH it ON
    // THE RESOURCE (not the outbox). Creating a resource must not persist it;
    // only `save()` does (it moves the stash into the outbox). So a
    // created-but-never-saved resource (e.g. an unfilled `TableNewRow`) is never
    // POSTed. This is the only remaining `signChanges` call site.
    if ((shouldUseDid && !subject) || genesisCert) {
      const genesisCommit = await resource.signChanges(this.getAgent()!);
      resource.stashGenesis(genesisCommit);
    }

    return resource;
  }

  /**
   * Creates a new Drive for the current Agent, saves it, links it into the
   * agent's drive list, and gives it a default Ontology. Returns the Drive's
   * Resource (already saved).
   *
   * This is the canonical way to create a drive — EVERY drive-creation flow
   * (onboarding, dev-drive, the New Drive dialog) must go through it, so
   * drive invariants (permissions, switcher list, default ontology) live in
   * exactly one place.
   */
  public async createDrive(
    name: string,
    opts: CreateDriveOpts = {},
  ): Promise<Resource> {
    const { description, subdomain, agentName, personal = true } = opts;
    const agent = this.getAgent();

    if (!agent?.subject) {
      throw new Error('Cannot create a drive without an Agent');
    }

    const propVals: Record<string, JSONValue> = {
      [core.properties.name]: name,
      [core.properties.write]: [agent.subject],
      [core.properties.read]: [agent.subject],
    };

    const resolvedDescription =
      description ?? (personal ? 'Your personal drive.' : undefined);

    if (resolvedDescription !== undefined) {
      propVals[core.properties.description] = resolvedDescription;
    }

    if (subdomain) {
      propVals[SUBDOMAIN_PROP] = subdomain;
    }

    if (personal) {
      const existingDid = await this.resolvePrivateDriveSubject(agent);
      const existing = this._resources.get(existingDid);

      if (existing && !existing.new && !existing.error) {
        const oldPointer = await this.linkPrivateDrive(
          existing,
          agent.subject,
          agentName,
        );
        await this.maybeMigrateOldPrivateDrive(existing, [
          oldPointer,
          agent.initialDrive,
        ]);

        return existing;
      }
    }

    // An additional drive is only useful if the user can find it again, and
    // the only place it gets listed is the personal drive. So having one is a
    // precondition, checked before anything is written rather than after.
    //
    // Doing it afterwards produced the worst of both: the drive was created,
    // the listing failed, and the dialog said "Drive created" — leaving a real
    // resource the user had just been told about and could not find. Failing
    // here means nothing is made and the reason is the one thing they see.
    const privateDriveResource = personal
      ? undefined
      : await this.ensurePrivateDrive();

    const genesisCert = personal
      ? privateDriveCert(decodeB64(await agent.getPublicKey()))
      : undefined;

    // Pin the personal drive to the derived subject. `newResource` would
    // otherwise mint one by signing the certificate through the agent's
    // provider — the same non-deterministic signature this method just looked
    // the drive up by, so the drive would be created under a subject no
    // subsequent lookup could ever find.
    const personalSubject = personal
      ? await this.resolvePrivateDriveSubject(agent)
      : undefined;

    const drive = await this.newResource({
      isA: server.classes.drive,
      noParent: true,
      propVals,
      genesisCert,
      subject: personalSubject,
    });

    await drive.save();

    if (personal) {
      const oldPointer = await this.linkPrivateDrive(
        drive,
        agent.subject,
        agentName,
      );
      await this.maybeMigrateOldPrivateDrive(drive, [
        oldPointer,
        agent.initialDrive,
      ]);
    } else {
      await this.addToSavedDrives(drive, privateDriveResource!);
    }

    // Every drive gets a default Ontology: the home for classes and
    // properties created inside the drive (e.g. table Row classes), so they
    // don't pile up directly under the drive itself. Skip if a previous
    // device already created one — two random ontology DIDs would fork.
    if (!drive.get(server.properties.defaultOntology)) {
      await this.createDefaultOntology(drive);
    }

    return drive;
  }

  /**
   * Makes `drive` the agent's personal/home drive: seeds the saved-drives
   * switcher list with itself and links it on the Agent resource (optionally
   * naming the agent in the same commit).
   */
  /**
   * Seeds the switcher list on `drive` and, when a complete Agent resource is
   * available, writes `privateDrive` for older clients.
   *
   * Returns a previous `privateDrive` pointer when it named a different
   * subject, so migration can union that drive's lists. The pointer is
   * captured before this write — otherwise migration would only ever see
   * the derived DID it just stored.
   */
  private async linkPrivateDrive(
    drive: Resource,
    agentSubject: string,
    agentName?: string,
  ): Promise<string | undefined> {
    // The user's saved-drives switcher list lives on the personal DRIVE itself
    // (the per-user home index), not on the Agent. Seed it with this drive so
    // it shows up in the switcher. This must be a second commit: the drive's
    // real `did:ad:` subject is only derived at save (before save it's a
    // `_new:` placeholder), so we can't reference it in the creation commit.
    drive.push(server.properties.drives, [drive.subject], true);
    await drive.save();

    // Capture any local pointer before the server fetch. A failed GET
    // applies an error stub into the same map slot and would otherwise
    // erase the only copy of the old home subject.
    const prior = this._resources.get(agentSubject);
    const localPointer = prior?.isReady()
      ? (prior.get(core.properties.personalDrive) as string | undefined)
      : undefined;

    // Prefer a fresh server copy when we can get one. A stale/partial
    // local Agent (clientDb cache, previous incomplete load) would let
    // `set/save` commit a Loro snapshot that only carries the properties
    // we write here — `isA` / `publicKey` / `read` never make it into
    // the outgoing snapshot, and the edit form later errors with
    // "<class> is not a Class". HTTP (not WS): onboarding can still be
    // authenticated as a previous agent on the socket.
    let agentResource: Resource | undefined;

    try {
      agentResource = await this.fetchResourceFromServer(agentSubject, {
        noWebSocket: true,
      });

      if (agentResource.error) {
        throw agentResource.error;
      }
    } catch {
      // Offline / local-only. An error stub is not usable — writing on
      // it would mint a partial Agent Loro doc. The derived DID is
      // identity; the pointer is only a cache for older clients.
      agentResource = prior?.isReady() ? prior : undefined;
    }

    const oldPointer = agentResource?.isReady()
      ? ((agentResource.get(core.properties.personalDrive) as
          | string
          | undefined) ?? localPointer)
      : localPointer;

    if (!agentResource || !agentResource.isReady()) {
      return oldPointer && oldPointer !== drive.subject
        ? oldPointer
        : undefined;
    }

    await agentResource.set(
      core.properties.personalDrive,
      drive.subject,
      false,
    );

    if (agentName) {
      await agentResource.set(core.properties.name, agentName, false);
      const currentIsA = (agentResource.get(core.properties.isA) ??
        []) as string[];

      if (!currentIsA.includes(core.classes.agent)) {
        await agentResource.set(
          core.properties.isA,
          [...currentIsA, core.classes.agent],
          false,
        );
      }
    }

    await agentResource.save();

    return oldPointer && oldPointer !== drive.subject ? oldPointer : undefined;
  }

  /**
   * Adds a non-personal (additional) drive to the saved-drives switcher list
   * on the agent's derived personal drive. Materializes that drive if needed.
   */
  private async addToSavedDrives(
    drive: Resource,
    privateDriveResource: Resource,
  ): Promise<void> {
    const already = privateDriveResource.getSubjects(server.properties.drives);

    if (!already.includes(drive.subject)) {
      privateDriveResource.push(server.properties.drives, [drive.subject]);
      await privateDriveResource.save();
    }
  }

  /**
   * Union any previous home's lists onto the derived drive and keep the old
   * drive as an ordinary workspace. Best-effort: does not block sign-in or
   * first write.
   *
   * Takes several candidates because the old home is recorded in two places
   * that go missing independently:
   *
   * - `privateDrive` on the Agent **resource** — absent whenever the server
   *   holding the account never wrote one, which is the common case for a
   *   self-hosted account whose drives were made ad hoc.
   * - `initialDrive` from the agent **secret** — the only record left on a
   *   device that has never seen the old drive, since it travels with the key
   *   rather than with any server's data.
   *
   * An account predating the derivation can have either, both, or (for a
   * genuinely new agent) neither.
   */
  private async maybeMigrateOldPrivateDrive(
    derived: Resource,
    candidates: (string | undefined)[],
  ): Promise<void> {
    const seen = new Set<string>([derived.subject]);

    for (const candidate of candidates) {
      if (!candidate || seen.has(candidate)) {
        continue;
      }

      seen.add(candidate);

      // Per candidate: one unreachable old home must not strand the other.
      await this.migrateOneOldPrivateDrive(derived, candidate);
    }
  }

  /** Union one old home's lists onto `derived`. See the caller for why. */
  private async migrateOneOldPrivateDrive(
    derived: Resource,
    oldPointer: string,
  ): Promise<void> {
    try {
      let old = this._resources.get(oldPointer);

      if (!old || !old.isReady()) {
        try {
          old = await withDeadline(
            this.fetchResourceFromServer(oldPointer, { noWebSocket: true }),
            LEGACY_FETCH_DEADLINE_MS,
            undefined,
          );
        } catch {
          return;
        }
      }

      if (!old || old.error) {
        return;
      }

      const listProps = [
        server.properties.drives,
        core.properties.sharedWithMe,
        'https://atomicdata.dev/properties/favorites',
      ];

      for (const prop of listProps) {
        const incoming = old.getSubjects(prop);
        const have = new Set(derived.getSubjects(prop));
        const missing = incoming.filter(s => s && !have.has(s));

        if (missing.length > 0) {
          derived.push(prop, missing, true);
        }
      }

      const drives = new Set(derived.getSubjects(server.properties.drives));

      if (!drives.has(oldPointer)) {
        derived.push(server.properties.drives, [oldPointer], true);
      }

      if (derived.hasUnsavedChanges()) {
        await derived.save();
      }
    } catch {
      // Migration is nice, not load-bearing.
    }
  }

  /**
   * Creates the drive's default Ontology (titled "Ontology"), links it via
   * `defaultOntology`, and saves the drive. New classes/properties created in
   * the drive (table Row classes, columns, …) are organized under it instead
   * of directly under the drive.
   */
  public async createDefaultOntology(drive: Resource): Promise<Resource> {
    const ontology = await this.newResource({
      isA: core.classes.ontology,
      parent: drive.subject,
      propVals: {
        [core.properties.shortname]: 'ontology',
        [core.properties.name]: 'Ontology',
        [core.properties.description]:
          'The default ontology of this drive. Classes and properties created in this drive are organized here.',
        [core.properties.classes]: [],
        [core.properties.properties]: [],
        [core.properties.instances]: [],
      },
    });

    await ontology.save();

    await drive.set(server.properties.defaultOntology, ontology.subject);
    await drive.save();

    return ontology;
  }

  public async search(query: string, opts: SearchOpts = {}): Promise<string[]> {
    const parentScope = Array.isArray(opts.parents)
      ? opts.parents[0]
      : opts.parents;
    const hasFilters = Object.keys(opts.filters ?? {}).length > 0;
    searchDebug('[search] search()', {
      query,
      hasFilters,
      parents: opts.parents,
      serverConnected: this._serverConnected,
      clientDbReady: this.clientDb?.isReady ?? false,
    });

    // Local hits come from the durable KV index in ClientDb (title,
    // description, Loro body, 1-edit prefix fuzzy, PropValSub filters).
    const clientDb = this.clientDb;
    const kvResults =
      clientDb?.isReady && typeof clientDb.search === 'function'
        ? await clientDb.search(query, {
            limit: opts.limit ?? 30,
            parents: parentScope,
            filters: opts.filters,
          })
        : [];

    if (kvResults.length > 0) {
      searchDebug('[search] local kv →', kvResults.length, kvResults);
    }

    // Offline: hosted `/search` is unreachable. Return whatever the local
    // index has (empty if ClientDb is down).
    if (!this._serverConnected) {
      searchDebug('[search] OFFLINE kv →', kvResults.length, kvResults);

      return kvResults;
    }

    // Merge with hosted `/search` (same KV engine) so OPFS lag still
    // picks up hits the server already indexed.
    const searchSubject = buildSearchSubject(this.serverUrl, query, opts);
    searchDebug('[search] server search →', searchSubject);
    // Search URLs are dynamic query resources without commit identities. Keeping
    // one in the normal resource cache makes a later retry merge against the
    // previous response and discard it as "unchanged", even when `/search` now
    // returns new matches. Evict only the in-memory synthetic resource so every
    // retry observes the server's current result set.
    this._resources.delete(this.resolveSubject(searchSubject));
    const searchResource = await this.fetchResourceFromServer(searchSubject, {
      noWebSocket: true,
    });
    const results = searchResource.get(server.properties.results) ?? [];
    searchDebug('[search] server search returned', results.length);

    return [...new Set([...kvResults, ...results])].slice(0, opts.limit ?? 30);
  }

  public async semanticSearch(
    query: string,
    opts: SemanticSearchOpts = {},
  ): Promise<{ subject: string; chunk: string }[]> {
    const vectorSearchSubject = buildSemanticSearchSubject(
      this.serverUrl,
      query,
      opts,
    );
    const vectorSearchResource = await this.fetchResourceFromServer(
      vectorSearchSubject,
      {
        noWebSocket: true,
      },
    );
    const results = vectorSearchResource.get(server.properties.results) ?? [];
    const chunks =
      vectorSearchResource.get(server.properties.searchChunks) ?? [];

    if (!Array.isArray(chunks) || results.length !== chunks.length) {
      throw new Error('Results and chunks length mismatch');
    }

    return results.map((result, index) => ({
      subject: result,
      chunk: chunks[index] as string,
    }));
  }

  /** Checks if a subject is free to use */
  public async checkSubjectTaken(subject: string): Promise<boolean> {
    const r = this.resources.get(subject);

    if (r?.isReady() && !r?.new) {
      return true;
    }

    try {
      const signInfo = this.agent
        ? { agent: this.agent, serverURL: this.getServerUrl() }
        : undefined;

      const { createdResources } = await this.client.fetchResourceHTTP(
        subject,
        {
          method: 'GET',
          signInfo,
        },
      );

      if (createdResources.find(res => res.subject === subject)?.isReady()) {
        return true;
      }
    } catch (_) {
      // If the resource doesn't exist, we can use it
    }

    return false;
  }

  /**
   * Checks is a set of URL parts can be combined into an available subject.
   * Will retry until it works.
   */
  public async buildUniqueSubjectFromParts(
    parts: string[],
    parent?: string,
  ): Promise<string> {
    const path = parts.map(part => stringToSlug(part)).join('/');
    const parentUrl = parent ?? this.getServerUrl();

    return this.findAvailableSubject(path, parentUrl);
  }

  /**
   * Creates a placeholder subject for a brand-new resource. When the current
   * agent is DID-based, returns a temporary `_new:{random}` key that gets
   * replaced with the real `did:ad:...` on first commit (matching
   * `newResource()`'s shouldUseDid path). Otherwise builds a random HTTP
   * subject under `parent` or the server root.
   *
   * Without this branch, callers like `useNewForm` would mint an HTTP
   * subject such as `http://localhost:9883/01k…` that a DID-agent has no
   * edit rights on — saves fail with "Agent does not have edit rights".
   */
  public createSubject(parent?: string): string {
    const agentSubject = this.getAgent()?.subject;

    if (agentSubject?.startsWith('did:ad:agent:')) {
      return `_new:${this.randomPart()}`;
    }

    return this.createHTTPSubject(parent ?? this.serverUrl);
  }

  /**
   * A unique, non-resource identifier — a plain unique string for callers that
   * need one but are NOT creating an Atomic resource (e.g. AI SDK message ids).
   * Never a `_new:` or `did:ad:` subject, so it can't be mistaken for one.
   */
  public newLocalId(): string {
    return ulid();
  }

  /**
   * Mint a resource's identity from a self-verifying genesis certificate
   * (mirrors `lib/src/commit.rs::create_did`). The DID is the agent's signature
   * over the cert, so the resource carries its real `did:ad:` from creation —
   * no `_new:` placeholder, no post-sign rename. `parent`/`drive` are the
   * immutable birth context (empty string when absent). Returns the DID and the
   * base64url cert to store inline as the `genesis` propval.
   */
  private async mintCertDid(
    parent: string,
    drive: string,
  ): Promise<{ did: string; certB64: string }> {
    const agent = this.getAgent();

    if (!agent) {
      throw new Error(
        'Cannot create a DID resource without an agent. Set an agent on the store first.',
      );
    }

    const cert: GenesisCert = {
      signerPubkey: decodeB64(await agent.getPublicKey()),
      createdAt: Date.now(),
      nonce: crypto.getRandomValues(new Uint8Array(16)),
      parent,
      drive,
    };
    const certBytes = encodeGenesisCert(cert);

    return {
      did: subjectForSignature(await agent.signBytes(certBytes)),
      certB64: encodeB64Url(certBytes),
    };
  }

  private async mintFromCert(
    cert: GenesisCert,
  ): Promise<{ did: string; certB64: string }> {
    const agent = this.getAgent();

    if (!agent) {
      throw new Error(
        'Cannot create a DID resource without an agent. Set an agent on the store first.',
      );
    }

    const certBytes = encodeGenesisCert(cert);

    return {
      did: subjectForSignature(await agent.signBytes(certBytes)),
      certB64: encodeB64Url(certBytes),
    };
  }

  /** The agent's derived personal-drive DID. Same key → same subject. */
  public async privateDriveSubject(): Promise<string> {
    const agent = this.getAgent();

    if (!agent) {
      throw new Error('Cannot derive a personal drive without an agent');
    }

    return this.resolvePrivateDriveSubject(agent);
  }

  /**
   * `Agent.privateDriveSubject`, with one fallback: an agent restored from a
   * non-extractable keypair that was stored before the derived subject was
   * recorded beside it (a session predating that field) can neither read the
   * cached value nor recompute it. The pointer `linkPrivateDrive` wrote onto
   * the Agent resource is the durable copy, so read it from there — local
   * copy first, then the server — and cache it on the agent for this session.
   * Without this, every returning account on such a device fails at "Cannot
   * work out this account's private drive" instead of opening its home.
   */
  private async resolvePrivateDriveSubject(agent: Agent): Promise<string> {
    try {
      return await agent.privateDriveSubject();
    } catch (error) {
      if (!agent.subject) throw error;

      const pointer = await this.personalDrivePointer(agent.subject);

      if (!pointer) throw error;

      agent.privateDrive = pointer;

      return pointer;
    }
  }

  /** The `personalDrive` recorded on the Agent resource, if any. */
  private async personalDrivePointer(
    agentSubject: string,
  ): Promise<string | undefined> {
    const read = (resource: Resource | undefined) =>
      resource?.isReady()
        ? (resource.get(core.properties.personalDrive) as string | undefined)
        : undefined;

    const local = read(this._resources.get(agentSubject));

    if (local) return local;

    try {
      return read(
        await this.fetchResourceFromServer(agentSubject, {
          noWebSocket: true,
        }),
      );
    } catch {
      return undefined;
    }
  }

  /**
   * Materialize the derived personal drive if needed and return it.
   * Repeat genesis for the same subject merges on the server.
   */
  public async ensurePrivateDrive(
    name = 'My drive',
    opts: Omit<CreateDriveOpts, 'personal'> = {},
  ): Promise<Resource> {
    // `createDrive` returns the cached drive untouched when it already has
    // one, which is what keeps this from renaming a home the user has titled.
    // Deliberately no lookup for a drive that is not in memory: a bounded
    // `getResource` cannot be cancelled, so the abandoned fetch outlives the
    // deadline and fails the drive this call then creates. Materializing is
    // therefore a sign-in action, not something boot repeats.
    return this.createDrive(name, {
      ...opts,
      personal: true,
    });
  }

  /**
   * Try the local WASM DB (OPFS) for a persisted copy of `subject` and hydrate
   * the store from it.
   *
   * @returns `true` when a local copy hydrated into something renderable,
   *   `false` when the database was asked and does not have it, and
   *   `undefined` when there was no database to ask — callers must not read
   *   that silence as "not stored locally".
   */
  /**
   * True when the resource carries enough state to stand on its own: a
   * class, or any property beyond the server-managed skeleton
   * (drive/parent/lastCommit/createdAt) that `rebuildCacheFromLoro`
   * preserves. A resource that passes this is worth more than a failed
   * fetch — it renders, and the alternative is showing the user nothing.
   */
  private hasRenderableContent(resource: Resource | undefined): boolean {
    if (!resource) return false;

    if (resource.get(core.properties.isA)) return true;

    return resource
      .getEntries()
      .some(([prop]) => !SERVER_MANAGED_SKELETON_PROPS.has(prop));
  }

  private async hydrateFromLocalDb(
    subject: string,
  ): Promise<boolean | undefined> {
    let hasLocalData = false;

    // Wait for the WASM DB to initialize (if one is set).
    // This is important on page reload: the DB may still be loading
    // but it has data from a previous session that we need.
    //
    // We deliberately wait only for `init` here, not the bootstrap
    // `seed`. The seed pushes in-memory default-property resources
    // into OPFS — useful for offline reload — but lookups in this
    // function are for user-data subjects that aren't part of the
    // bootstrap, so they don't depend on it. Gating useResource
    // cold-loads on the seed adds 200–500 ms of dead time on a
    // populated drive (70 sequential property puts + reseed loop).
    if (this.clientDb) {
      await this.clientDb.waitForInit();
    }

    // No database to ask. Say so rather than reporting a miss: the caller
    // decides what to do about it, and "we never asked" and "it isn't there"
    // lead to opposite conclusions when offline.
    if (!this.clientDb?.isInitialized) return undefined;

    // Try the WASM DB (OPFS) for persisted resources. One combined
    // round-trip instead of `getResource` + `getLoroSnapshot`: every
    // mounted useResource takes this path on cold-load, and each
    // worker postMessage costs ~ms; halving the round-trips visibly
    // reduces time-to-first-paint on a populated drive.
    {
      try {
        const { jsonAd, snapshot } =
          await this.clientDb.getResourceWithSnapshot(subject);
        const hasSnapshot = !!(snapshot && snapshot.length > 0);

        if (jsonAd) {
          hasLocalData = this.hydrateResourceFromJson(
            subject,
            JSON.parse(jsonAd),
          );
        }

        let importComplete = true;

        if (hasLocalData && hasSnapshot) {
          const resource = this.resources.get(subject);

          if (resource && !resource.hasUnsavedChanges()) {
            // Capture `complete`: the snapshot may be an unapplyable delta
            // (missing base ops, buffered by Loro as pending → nothing
            // materialises). The WS path (`applyIncoming`) already acts on this
            // signal; the OPFS path used to drop it on the floor.
            // OPFS snapshots are authoritative full state — replace, don't
            // merge into the JSON-AD-seeded doc. Merging minted a second
            // LoroList per array and flashed table/sidebar order on open.
            ({ complete: importComplete } = resource.importLoroUpdate(
              snapshot,
              true,
            ));
          }
        }

        // An OPFS hit is only authoritative if it actually hydrated to
        // something RENDERABLE. Otherwise we'd render a contentless resource
        // (bare subject as title, no body) with NO error that never recovers —
        // the "deeply broken folder" bug. There are several routes into that
        // contentless state, so we guard on the OUTCOME (is the resource
        // renderable?) rather than on any single cause:
        //   - nothing hydrated at all (`getEntries().length === 0`);
        //   - a skeleton JSON-AD with no snapshot (only the server-managed
        //     props survive, and no import ran to add a class);
        //   - an unapplyable-delta snapshot (`!importComplete`) that buffers as
        //     pending and materialises nothing, leaving only the skeleton.
        // In all of these the resource carries at most the server-managed
        // skeleton props that `rebuildCacheFromLoro` preserves
        // (drive/parent/lastCommit/createdAt) — `length` is > 0, so the old
        // `length === 0` guard missed it.
        //
        // Renderable ⇔ it has a class (`isA`) — covers commit-detail
        // (`isA: Commit`, whose delta `loroUpdate` legitimately leaves
        // `!importComplete`, mirroring the `applyIncoming` guard) — OR it has
        // real content beyond the skeleton AND that content actually applied
        // (a clean import). Anything else is treated as a miss: keep `loading`
        // so the UI shows a spinner, drop `hasLocalData` so the server GET
        // below repopulates it — or, offline, fails it with a real error
        // instead of leaving it silently broken. The slow (cache-cold) reload
        // dodges this naturally (ClientDb not initialized yet ⇒ OPFS skipped);
        // the fast service-worker reload is what hits it.
        if (hasLocalData) {
          const resource = this.resources.get(subject);
          const hasClass = !!resource?.get(core.properties.isA);
          const renderable =
            !!resource &&
            (hasClass ||
              (importComplete && this.hasRenderableContent(resource)));

          if (!renderable) {
            hasLocalData = false;

            if (resource) {
              resource.loading = true;
            }
          }
        }
      } catch (e) {
        console.warn(`[ClientDb] OPFS lookup failed for "${subject}":`, e);
      }
    }

    return hasLocalData;
  }

  /**
   * Try the local WASM DB first, then fall back to server.
   * If the WASM DB has the resource, it's used immediately (and a background
   * server fetch can refresh it later). This keeps the UI fast while the
   * network catches up.
   *
   * If both the WASM DB and the server fail (offline + cold cache),
   * the resource stays in `loading` state rather than throwing.
   */
  private async fetchResourceWithLocalFallback(
    subject: string,
    opts: FetchOpts = {},
  ): Promise<void> {
    let local = await this.hydrateFromLocalDb(subject);
    let hasLocalData = local === true;

    /**
     * Ask the local database again, if the first attempt had none to ask.
     *
     * The app attaches its ClientDb a few hundred milliseconds into boot —
     * `initClientDb` has to derive the agent's database name and unwrap its
     * key first — which is AFTER React's first render. A `useResource` that
     * mounts in that window finds no database, and the only thing it can
     * conclude from that silence is nothing at all. Offline that used to
     * become "Offline: resource not available locally", permanently: the
     * database attached moments later with the resource in it, but nothing
     * re-runs this fetch.
     *
     * So before any outcome that fails the resource, wait out the attach and
     * look again. A store that will never get a ClientDb (Node, SSR, the Sync
     * page's opt-out, Tauri's embedded server) never signalled `expectClientDb`
     * and so doesn't wait at all.
     */
    const askOnceAttached = async (): Promise<void> => {
      if (hasLocalData || local !== undefined) return;
      if (!(await this.waitForClientDb(CLIENT_DB_ATTACH_GRACE))) return;

      local = await this.hydrateFromLocalDb(subject);
      hasLocalData = local === true;
    };

    // Local-only subjects never exist on any server — the OPFS lookup
    // above is authoritative. Without this guard a cache miss would GET
    // the subject from the server (a guaranteed 404 that also leaks
    // local-only subjects onto the wire).
    if (this.isLocalOnlySubject(subject)) {
      await askOnceAttached();

      if (!hasLocalData) {
        this.failResource(
          subject,
          new AtomicError(LOCAL_ONLY_NOT_FOUND_MESSAGE, ErrorType.Transport),
        );
      }

      return;
    }

    // Try the server if connected. Skip if we have local data and are offline
    // to avoid overwriting good data with error responses.
    try {
      if (!this._serverConnected) {
        // Offline — use whatever local data we found. If there IS no local
        // data, surface the offline state to the caller rather than leaving
        // the resource stuck in `loading`.
        if (!hasLocalData) {
          // BUT: a page reload starts with the WS disconnected and reconnects
          // within a few hundred ms. Failing the resource as "offline" during
          // that handshake flashes an ErrorPage before the real load (the
          // user-visible "error state" flicker). Wait briefly for the WS; if it
          // connects, fetch from the server. Only fail if it stays down.
          const connected = await this.waitForServerConnected(5000);

          if (connected) {
            await this.fetchResourceFromServer(subject, opts);
          } else {
            // Nothing cancels this 5s wait if the resource gets resolved by
            // some OTHER path in the meantime — e.g. a subject that isn't
            // recognized as local-only (agent DIDs aren't parented under a
            // drive, so `isLocalOnlySubject` misses them) but gets created
            // and saved locally moments after this fetch started. Without
            // this check, the stale timeout below fires anyway and clobbers
            // that already-good resource back into an error state.
            const current = this.resources.get(subject);
            const alreadyResolved =
              current && current.loading === false && !current.error;

            // The five seconds just spent waiting for the server are five
            // seconds the local database had to attach. Ask it before
            // declaring the resource unavailable.
            await askOnceAttached();

            if (hasLocalData) return;

            if (!alreadyResolved) {
              this.failResource(
                subject,
                new AtomicError(
                  NOT_AVAILABLE_LOCALLY_MESSAGE,
                  ErrorType.Transport,
                ),
              );
            }
          }
        }
      } else if (hasLocalData) {
        // Online with local data: trust OPFS + live WS updates. SUB
        // on each drive produces SYNC_DIFF / SYNC_PUSH frames that
        // tell us about deltas, and DESTROY frames evict gone
        // subjects from the local cache. A background-verify GET per
        // cached resource used to live here as a belt-and-braces
        // catch for "deleted-while-disconnected" — but it fires for
        // every `useResource(...)` on every reload, producing the
        // user-observed N×{GET sub} storm on a populated drive. The
        // narrow case it covered (a destroy commit that landed while
        // we were disconnected AND not covered by SUB on reconnect)
        // is rare and recovers on the next live update.
        //
        // Agents are the exception, because that premise fails for them: they
        // belong to no drive, so no SUB covers them and nothing ever refreshes
        // the local copy. A cached agent can therefore be wrong forever — which
        // is what kept other people's names from appearing after the server
        // started allowing the read: every client already held a cached stub
        // and stopped asking. Re-check each agent once per session; after that
        // it is trusted like anything else.
        if (
          subject.startsWith('did:ad:agent:') &&
          !this._revalidatedAgents.has(subject)
        ) {
          this._revalidatedAgents.add(subject);
          await this.fetchResourceFromServer(subject, opts);
        }
      } else {
        // Online, no local data — server is our only source.
        await this.fetchResourceFromServer(subject, opts);
      }
    } catch (e) {
      // Server fetch failed with no local data. Surface the actual server
      // error (e.g. 401 Unauthorized) so callers (ErrorPage, GettingStartedFlow)
      // can react correctly. Only fall back to a generic offline message when
      // we have no other signal.
      await askOnceAttached();

      if (!hasLocalData) {
        this.failResource(
          subject,
          e instanceof Error ? e : new Error('Resource fetch failed'),
        );
      }
    }
  }

  /** Hydrate a Resource from a parsed JSON-AD object and add it to the store. Returns true if successful. */
  /**
   * Parse a JSON-AD string from the local DB and hydrate it into the store.
   * Used by collection page loads so members have their propvals available
   * for client-side sorting before the consumer's individual fetches happen.
   */
  public hydrateResourceFromJsonAd(subject: string, jsonAd: string): boolean {
    try {
      const parsed = JSON.parse(jsonAd) as Record<string, unknown>;

      return this.hydrateResourceFromJson(subject, parsed);
    } catch {
      return false;
    }
  }

  private hydrateResourceFromJson(
    subject: string,
    parsed: Record<string, unknown>,
  ): boolean {
    const existing = this.getResolved(subject);

    // Don't overwrite a resource that has a Loro snapshot with one that doesn't.
    if (
      existing &&
      existing.get(commits.properties.loroUpdate) &&
      !parsed[commits.properties.loroUpdate]
    ) {
      return true;
    }

    // Don't clobber an in-memory resource that has unsaved local edits
    // — `hydrateOfflineReplay` would overwrite the in-flight Loro state
    // with the (older) clientDb snapshot. The signal is in-memory only:
    // `hasUnsavedChanges()` (commitBuilder / `_dirty` between a `set()`
    // and the next drain).
    //
    // We deliberately do NOT gate on `hasPendingCommits` (the outbox
    // genesis/dirty bit): that survives reload via localStorage, so on
    // a cold load a freshly-created placeholder for an offline-saved
    // resource has `hasPendingCommits === true` but NO in-memory state
    // to protect. Gating on it skipped `hydrateOfflineReplay`, leaving
    // the placeholder stuck `loading: true` forever (offline file
    // upload never rendered; the snapshot import populated the doc but
    // `loading` never cleared). clientDb already holds the offline
    // state, so hydrating from it RESTORES the edit — it doesn't clobber
    // it.
    if (existing?.hasUnsavedChanges()) {
      return true;
    }

    this.hydrateOfflineReplay(subject, parsed);

    // If the outbox holds a dirty bit for this subject (offline edit
    // restored from localStorage), kick a drain now that the resource
    // is finally in the store. Without this nudge the drain would
    // either: (a) never fire — `hydrateOfflineReplay` doesn't go
    // through `set()`, so the Loro subscriber that normally schedules
    // drains stays silent; (b) have fired earlier (in
    // `setClientDb`'s auto-trigger) when the resource wasn't loaded
    // yet, hit the "no resource" cold-drain branch, and bailed.
    if (this.outbox.hasPending(subject)) {
      this.scheduleOutboxDrain();
    }

    return true;
  }

  /**
   * Always fetches the resource from the server then adds it to the store.
   */
  public async fetchResourceFromServer<C extends OptionalClass = UnknownClass>(
    /** The resource URL to be fetched */
    subject: string,
    opts: {
      /**
       * Fetch it from the `/path` endpoint of your server URL. This effectively
       * is a proxy / cache.
       */
      fromProxy?: boolean;
      /** Overwrites the existing resource and sets it to loading. */
      setLoading?: boolean;
      /** Do not use WebSockets, use HTTP(S) */
      noWebSocket?: boolean;
      /** HTTP Method, defaults to GET */
      method?: 'GET' | 'POST';
      /** HTTP Body for POSTing */
      body?: ArrayBuffer | string;
      /** Overwrites existing Loro state instead of merging */
      forceOverride?: boolean;
    } = {},
  ): Promise<Resource<C>> {
    const normalizedSubject = this.normalizeSubject(subject);

    // In-flight dedup. SideBarDrive and DrivePage both call
    // `useResource(drive)` on the same render → two parallel
    // `fetchResourceFromServer(drive)`. Without sharing, both fire
    // their own WS `GET` (visible as `did:ad:<drive> (×2)` in the
    // network log). Reuse the in-flight promise; the second caller
    // gets the same Resource handle the first eventually resolves to.
    //
    // Skip dedup for POST (different semantics — each is a write).
    // Skip dedup when `setLoading` is requested (caller explicitly
    // wants a fresh roundtrip + loading state). Skip for temporary
    // subjects (`_new:`/`_local:`) which never go to the network.
    const canDedup =
      opts.method !== 'POST' &&
      !opts.setLoading &&
      !normalizedSubject.startsWith('_new:') &&
      !normalizedSubject.startsWith('_local:');

    if (canDedup) {
      const inflight = this._inFlightFetches.get(normalizedSubject);
      if (inflight) return inflight as Promise<Resource<C>>;
    }

    const work = this._fetchResourceFromServerImpl<C>(subject, opts);

    if (canDedup) {
      const tracked = work.finally(() => {
        // Only clear if we're still the owner of the slot — a
        // re-entrant fetch that took the slot after us shouldn't be
        // wiped by our completion.
        if (this._inFlightFetches.get(normalizedSubject) === tracked) {
          this._inFlightFetches.delete(normalizedSubject);
        }
      });
      this._inFlightFetches.set(normalizedSubject, tracked);

      return tracked as Promise<Resource<C>>;
    }

    return work;
  }

  private async _fetchResourceFromServerImpl<
    C extends OptionalClass = UnknownClass,
  >(
    subject: string,
    opts: {
      fromProxy?: boolean;
      setLoading?: boolean;
      noWebSocket?: boolean;
      method?: 'GET' | 'POST';
      body?: ArrayBuffer | string;
      forceOverride?: boolean;
    },
  ): Promise<Resource<C>> {
    const normalizedSubject = this.normalizeSubject(subject);
    const isTemporarySubject =
      normalizedSubject.startsWith('_new:') ||
      normalizedSubject.startsWith('_local:');

    // Temporary local subjects are never fetchable from the server.
    // Return a local resource immediately and skip network traffic.
    if (isTemporarySubject) {
      const existing = this.resources.get(normalizedSubject);

      if (existing) {
        existing.loading = false;

        return existing as Resource<C>;
      }

      const local = new Resource<C>(normalizedSubject, true);
      local.loading = false;
      this.addResource(local, { skipCommitCompare: true });

      return local;
    }

    if (opts.setLoading) {
      const newR = new Resource<C>(subject);
      newR.loading = true;
      this.addResource(newR, { skipCommitCompare: true });
    }

    const fetchSubject =
      subject.startsWith('http') || subject.startsWith('did:ad:')
        ? subject
        : new URL(subject, this.serverUrl).toString();

    const ws = this.getWebSocketForSubject(fetchSubject);

    if (
      !opts.fromProxy &&
      !opts.noWebSocket &&
      supportsWebSockets() &&
      ws?.readyState === WebSocket.OPEN
    ) {
      await ws.fetch(fetchSubject);
    } else {
      const signInfo = this.agent
        ? { agent: this.agent, serverURL: this.getServerUrl() }
        : undefined;

      const { resource, createdResources } =
        await this.client.fetchResourceHTTP(fetchSubject, {
          from: opts.fromProxy ? this.getServerUrl() : undefined,
          method: opts.method,
          body: opts.body,
          signInfo,
          serverURL: this.getServerUrl(),
        });

      // `fetchResourceHTTP` reports failure by returning an EMPTY resource
      // carrying the error. Applying that when the server was merely
      // unreachable transplants the error onto the copy we already
      // hydrated (`Resource.merge` copies `error` while keeping propvals),
      // so the UI renders the resource's own avatar and title next to
      // "Error loading resource" — and nothing clears it. An unreachable
      // server is no evidence about the resource: keep what we have and
      // let the reconnect refetch settle it.
      if (
        isTransportError(resource.error) &&
        this.hasRenderableContent(this.resources.get(normalizedSubject))
      ) {
        const existing = this.resources.get(normalizedSubject)!;
        existing.loading = false;
        this.notify(existing);

        return existing as Resource<C>;
      }

      // Single chokepoint: the JSONADParser already hydrated each
      // resource, so we use the `resource:` ingress on
      // `applyIncoming` instead of calling `addResources` directly.
      // The `subject` arg becomes the alias if it differs from the
      // resolved subject (e.g. POST endpoint that returns the
      // canonical resource).
      this.applyIncoming({
        subject,
        resource,
        source: 'http-fetch',
        replaceLoroDocsFromRemote: !!opts.forceOverride,
      });

      const primarySubject = this.normalizeSubject(resource.subject);
      createdResources.forEach(r => {
        if (this.normalizeSubject(r.subject) !== primarySubject) {
          this.applyIncoming({
            subject: r.subject,
            resource: r,
            source: 'http-fetch',
            replaceLoroDocsFromRemote: !!opts.forceOverride,
          });
        }
      });
    }

    return this.resources.get(normalizedSubject)!;
  }

  public getAllSubjects(): string[] {
    return Array.from(this.resources.keys());
  }

  /** Returns the WebSocket for the current Server URL */
  public getDefaultWebSocket(): WSClient | undefined {
    return this.webSockets.get(this.getServerUrl());
  }

  /** Toggle WebSocket debug logging. Persisted in localStorage. */
  public setWebSocketDebug(enabled: boolean): void {
    for (const ws of this.webSockets.values()) {
      ws.debug = enabled;
    }

    if (typeof localStorage !== 'undefined') {
      if (enabled) {
        localStorage.setItem('ws-debug', '1');
      } else {
        localStorage.removeItem('ws-debug');
      }
    }
  }

  /** Opens a Websocket for some subject URL, or returns the existing one. */
  public getWebSocketForSubject(subject: string): WSClient | undefined {
    try {
      // DIDs are hosted on the current server, so use server URL for WebSocket
      let origin: string;

      if (subject.startsWith('did:')) {
        origin = new URL(this.serverUrl).origin;
      } else if (subject.startsWith('http')) {
        origin = new URL(subject).origin;
      } else {
        // Relative path - use server URL
        origin = new URL(this.serverUrl).origin;
      }

      return this.webSockets.get(origin);
    } catch (e) {
      throw new Error(
        `Could not open websocket for subject ${subject}: ${e.message}`,
      );
    }
  }

  /** Returns the base URL of the companion server */
  public getServerUrl(): string {
    return this.serverUrl;
  }

  /**
   * Who signed `subject`'s history: the verified signer per Loro change
   * token, from the signed envelopes the connected server kept
   * (`GET /history-attribution`, read-gated) merged with those this client
   * applied itself (ClientDb). Null when neither has anything. Never
   * guesses: a version whose token no envelope carries stays unattributed.
   */
  public async getHistoryAttribution(
    subject: string,
  ): Promise<HistoryAttribution | null> {
    const [remote, local] = await Promise.all([
      this.fetchHistoryAttributionFromServer(subject),
      this.getClientDb()?.historyAttribution(subject) ?? Promise.resolve(null),
    ]);

    return mergeHistoryAttributions(remote, local);
  }

  private async fetchHistoryAttributionFromServer(
    subject: string,
  ): Promise<HistoryAttribution | null> {
    if (!this.serverUrl) return null;

    try {
      const url = new URL('/history-attribution', this.serverUrl);
      url.searchParams.set('subject', subject);
      const agent = this.getAgent();
      // Sign the URL being fetched: the server rebuilds the signed message
      // from the request it received, query string included.
      const headers = agent
        ? await signRequest(url.toString(), agent, {
            Accept: 'application/json',
          })
        : { Accept: 'application/json' };
      const res = await fetch(url.toString(), { headers });

      if (!res.ok) return null;

      return parseHistoryAttribution(await res.json());
    } catch {
      return null;
    }
  }

  /**
   * Returns the Currently set Agent, returns null if there is none. Make sure
   * to first run `store.setAgent()`.
   */
  public getAgent(): Agent | undefined {
    return this.agent ?? undefined;
  }

  /**
   * Gets a resource by URL. Fetches and parses it if it's not available in the
   * store. Instantly returns an empty loading resource, while the fetching is
   * done in the background . If the subject is undefined, an empty non-saved
   * resource will be returned.
   */
  public getResourceLoading<C extends OptionalClass = UnknownClass>(
    subjectRaw: string = unknownSubject,
    opts: FetchOpts = {},
  ): Resource<C> {
    // Guard before normalization: 'unknown-subject' would otherwise be
    // resolved to `{serverUrl}/unknown-subject` and trigger a real fetch.
    //
    // The instance MUST be cached in `this.resources` — `useResource`
    // wraps `getResourceSnapshot`, whose identity check is
    // `snap.resource !== r.__internalObject`. Allocating a fresh
    // Resource on every call flips that identity each tick, the
    // snapshot tuple turns over, `useSyncExternalStore` reports a new
    // value, React re-renders, we loop. That's the "Too many
    // re-renders / getSnapshot should be cached" infinite render hang
    // any caller that passes `undefined` (e.g. `useResource(drive)`
    // before the drive setting hydrates) used to trigger.
    if (subjectRaw === unknownSubject || subjectRaw === null) {
      let resource = this.resources.get(unknownSubject) as
        | Resource<C>
        | undefined;

      if (!resource) {
        resource = new Resource<C>(unknownSubject, opts.newResource);
        resource.setStore(this);
        this.resources.set(unknownSubject, resource);
      }

      return resource;
    }

    const normalized = this.normalizeSubject(subjectRaw);
    // Commit DIDs identify the commit resource directly — they must never
    // resolve through the alias map. Without this guard, an alias added by
    // a prior fetch (e.g. `did:ad:commit:<sig>` accidentally aliased to the
    // committed-to subject during signing/hydration) sends the user to the
    // resource the commit edits instead of the commit itself.
    const resolved = normalized.startsWith('did:ad:commit:')
      ? normalized
      : (this.aliases.get(normalized) ?? normalized);
    const isNew =
      !!opts.newResource ||
      normalized.startsWith('_new:') ||
      normalized.startsWith('_local:');

    let resource = this.resources.get(resolved);

    if (!resource) {
      resource = new Resource<C>(normalized, isNew);
      if (!isNew) resource.loading = true;
      this.addResource(resource, { alias: normalized });
      if (!isNew) this.fetchResourceWithLocalFallback(normalized, opts);

      return resource;
    }

    if (
      !opts.allowIncomplete &&
      resource.loading === false &&
      !resource.error &&
      // Unlike `fetchResourceWithLocalFallback`, this recheck used to have no
      // local-only guard: a local-only resource that (for whatever reason)
      // carries a stale `incomplete` propval would get re-fetched from a
      // server it can never reach, on every render that omits
      // `allowIncomplete` — a guaranteed, silent failure.
      !this.isLocalOnlySubject(resolved)
    ) {
      // In many cases, a user will always need a complete resource.
      // This checks if the resource is incomplete and fetches it if it is.
      if (resource.get(core.properties.incomplete)) {
        resource.loading = true;
        this.addResource(resource);

        // An Agent DID is the one subject whose full state we can expect to
        // already have on this device: it's our own identity, or someone we
        // have seen. Ask the local database first — `fetchResourceWithLocalFallback`
        // only reaches for the server when the local copy is missing or is
        // itself an unrenderable stub. Going straight to the server made
        // showing your own name and avatar depend on a reachable server,
        // which is how an unreachable one turned `/app/show?subject=<your DID>`
        // into "Error loading resource" while `/app/agent` rendered you fine.
        if (resolved.startsWith('did:ad:agent:')) {
          this.fetchResourceWithLocalFallback(resolved, opts);
        } else {
          this.fetchResourceFromServer(resolved, opts);
        }
      }
    }

    return resource;
  }

  /**
   * Gets a resource by URL. Fetches and parses it if it's not available in the
   * store. Not recommended to use this for rendering, because it might cause
   * resources to be fetched multiple times.
   */
  public async getResource<C extends OptionalClass = UnknownClass>(
    subjectRaw: string,
  ): Promise<Resource<C>> {
    const resolved = this.resolveSubject(subjectRaw);
    const found = this.resources.get(resolved);

    if (found && found.isReady()) {
      return found;
    }

    /** Fix the case where a resource was previously requested but still not ready */
    if (found && !found.isReady()) {
      return new Promise((resolve, reject) => {
        const defaultTimeout = 10000;
        let timer: ReturnType<typeof setTimeout> | undefined;

        const cb: ResourceCallback<C> = res => {
          if (timer) clearTimeout(timer);
          this.unsubscribe(subjectRaw, cb);
          resolve(res);
        };

        this.subscribe(subjectRaw, cb);

        timer = setTimeout(() => {
          timer = undefined;
          this.unsubscribe(subjectRaw, cb);
          reject(
            new Error(
              `Async Request for subject "${subjectRaw}" timed out after ${defaultTimeout}ms.`,
            ),
          );
        }, defaultTimeout);
      });
    }

    // Local-only subjects never exist on any server, but on a cold load
    // the subject's drive isn't known yet — the `drive` prop lives in
    // the resource. When local-only drives exist, consult OPFS first:
    // hydrating restores the drive prop, and if the resource turns out
    // to be local-only, the local copy is authoritative. Without this,
    // the online path below GETs the subject from the server — a
    // guaranteed "not found" (plus a leaked local subject).
    if (resolved.startsWith('did:') && this.localOnlyDrives.size > 0) {
      const fromDb = await this.fetchResourceFromClientDb(resolved);

      if (fromDb && this.isLocalOnlySubject(resolved)) {
        return fromDb;
      }
    }

    // If offline and the resource can't be fetched via HTTP (DID subjects),
    // check in-memory store first, then try the WASM DB (OPFS).
    if (!this._serverConnected && resolved.startsWith('did:')) {
      const local = this.resources.get(resolved);

      if (local) {
        return local;
      }

      // Try the WASM DB — the resource may have been persisted to OPFS.
      const fromDb = await this.fetchResourceFromClientDb(resolved);

      if (fromDb) {
        return fromDb;
      }

      throw new Error(
        `Resource ${subjectRaw} not found locally and server is offline`,
      );
    }

    const result = await this.fetchResourceFromServer(resolved);

    // If the resource was not in the store yet, subscribe to changes so we don't return stale results when the resource is updated.
    // Commits are immutable — no need to subscribe for push updates.
    if (!result.hasClasses(commits.classes.commit)) {
      this.subscribeWebSocket(resolved);
    }

    return result;
  }

  /** Gets a property by URL. */
  public async getProperty(subject: string): Promise<Property> {
    // This leads to multiple fetches!
    const resource = await this.getResource(subject);

    if (resource === undefined) {
      throw Error(`Property ${subject} is not found`);
    }

    if (resource.error) {
      throw Error(`Property ${subject} cannot be loaded: ${resource.error}`);
    }

    const datatypeUrl = resource.get(core.properties.datatype);

    if (datatypeUrl === undefined) {
      throw Error(
        `Property ${subject} has no datatype: ${resource.debugValueSummary()}`,
      );
    }

    const shortname = resource.get(core.properties.shortname);

    if (shortname === undefined) {
      throw Error(
        `Property ${subject} has no shortname: ${resource.debugValueSummary()}`,
      );
    }

    const description = resource.get(core.properties.description);

    if (description === undefined) {
      throw Error(
        `Property ${subject} has no description: ${resource.debugValueSummary()}`,
      );
    }

    const classTypeURL = resource.get(core.properties.classtype)?.toString();

    const propery: Property = {
      subject,
      classType: classTypeURL,
      shortname: shortname.toString(),
      description: description.toString(),
      datatype: datatypeFromUrl(datatypeUrl.toString()),
      allowsOnly: resource.get(core.properties.allowsOnly),
    };

    return propery;
  }

  /**
   * This is called when Errors occur in some of the library functions.
   */
  public notifyError(e: Error | string): void {
    const error = e instanceof Error ? e : new Error(e);

    if (this.eventManager.hasSubscriptions(StoreEvents.Error)) {
      this.eventManager.emit(StoreEvents.Error, error);
    } else {
      throw error;
    }
  }

  /**
   * Whether the Store has an active WebSocket connection to the server.
   * Use this to decide whether to attempt server operations or store locally.
   */
  public get serverConnected(): boolean {
    return this._serverConnected;
  }

  /** Called by WebSocket client when connection state changes. */
  public setServerConnected(connected: boolean, error?: string): void {
    const nextError = connected ? undefined : error;

    if (
      this._serverConnected === connected &&
      this._serverConnectionError === nextError
    ) {
      return;
    }

    this._serverConnected = connected;
    this._serverConnectionError = nextError;

    if (!connected) {
      this._driveSyncInProgress = false;
    }

    console.info(`[Store] Server ${connected ? 'connected' : 'disconnected'}`);
    this.eventManager.emit(StoreEvents.ConnectionChanged, connected);
    this.emitSyncStatus();

    // Reconnect orchestration (auth → drain → VVSync → refetch) lives in
    // `WSClient.handleOpen`. Firing `syncDirtyResources` and
    // `refetchOfflineErroredResources` here would re-do the drain (the
    // outbox guard absorbs it) and race the refetch with the WS handshake.
    // Letting handleOpen own the sequence keeps one chain to reason about.
  }

  /**
   * Look at a resource again the way a first look does: the local database
   * first, the server only if that has nothing.
   *
   * For a cached failure the store has since been given the answer to. A
   * vault restore writes a drive straight into the local database; the copy
   * in memory is still the fetch that sent the user to the restore offer — a
   * 401 from before they signed in, or "not available locally". Asking the
   * server (`fetchResourceFromServer`) is the wrong repair: on an origin
   * without a node it asks the origin and gets `index.html` back, and the
   * user's own workspace opens as "Could not parse JSON".
   */
  public async reloadResource(subject: string): Promise<void> {
    const resolved = this.resolveSubject(subject);
    const resource = this.resources.get(resolved);

    if (resource) {
      resource.error = undefined;
      resource.loading = true;
      this.notify(resource);
    }

    await this.fetchResourceWithLocalFallback(resolved);
  }

  /**
   * When coming back online, re-fetch resources whose state was affected by
   * being offline:
   *   - errored because we couldn't reach the server (the offline fallback's
   *     own marker, or a fetch that threw), or
   *   - still stuck in `loading=true` (fetch started but never completed,
   *     e.g. because the server went down mid-flight).
   *
   * The transport check used to be `message.startsWith('Offline:')`, which
   * matched only the marker this file writes. A fetch that threw against an
   * unreachable server produced a raw `TypeError` ("NetworkError when
   * attempting to fetch resource") — the far more common way to get here —
   * and no reconnect ever retried it, so the resource stayed errored until
   * the user reloaded the page.
   *
   * Skips resources with pending commits — those are still in the outbox or
   * mid-drain; pulling a fresh server copy while a push is in flight races
   * the SYNC_PUSH echo and shows the user the pre-edit state until the echo
   * lands.
   *
   * Called from `WSClient.handleOpen` AFTER the outbox drain completes.
   */
  public refetchOfflineErroredResources(): void {
    for (const [subject, resource] of this.resources.entries()) {
      if (resource.hasPendingCommits) continue;
      const erroredOffline = isTransportError(resource.error);
      const stuckLoading = resource.loading && !resource.new;
      if (!erroredOffline && !stuckLoading) continue;

      resource.error = undefined;
      resource.loading = true;
      this.notify(resource);
      // On error, flip loading back so the resource isn't permanently
      // stuck in the loading state — `fetchResourceFromServer`'s own
      // applyIncoming path handles success.
      this.fetchResourceFromServer(subject).catch(e => {
        const r = this.resources.get(subject);

        if (r) {
          r.loading = false;
          r.setError(e instanceof Error ? e : new Error(String(e)));
          this.notify(r);
        }
      });
    }
  }

  public startDriveSync(): void {
    this._driveSyncInProgress = true;
    this.emitSyncStatus();
  }

  /**
   * Register a save that is scheduled (debounced) but not yet executed, so
   * sync status keeps reporting pending work during the debounce window.
   * MUST be balanced with exactly one `finishScheduledSave()` once the
   * save has settled (success or failure) or been superseded.
   */
  public startScheduledSave(): void {
    this._scheduledSaves++;
    this.emitSyncStatus();
  }

  /** Balance a `startScheduledSave()`. Call after the scheduled `save()`
   *  settles — not when the timer fires — so the counter overlaps the
   *  outbox/`isSaving` window instead of leaving a gap. */
  public finishScheduledSave(): void {
    this._scheduledSaves = Math.max(0, this._scheduledSaves - 1);
    this.emitSyncStatus();
  }

  public finishDriveSync(
    drive: string,
    count: number,
    timestamp: number,
  ): void {
    this._driveSyncInProgress = false;
    this._lastDriveSync = { drive, count, timestamp };

    if (drive) {
      this._syncedDrives.add(drive);

      if (this._lastDriveSyncError?.drive === drive) {
        this._lastDriveSyncError = undefined;
      }
    }

    this.emitSyncStatus();
  }

  /**
   * The server refused our SYNC_PUSH for `drive` outright (`SYNC_REJECTED`).
   * Nothing we sent landed, so the drive is not recorded as synced —
   * `hasCompletedDriveSyncFor` keeps answering false and collection queries
   * keep asking the server — and nothing local is cleared: the resources we
   * offered stay as they are and are offered again on the next handshake.
   * Distinct from `finishDriveSync` so a UI can show "your changes were
   * refused" instead of a green check.
   */
  public failDriveSync(drive: string, message: string): void {
    this._driveSyncInProgress = false;
    this._lastDriveSyncError = { drive, message, timestamp: Date.now() };

    if (drive) {
      this._syncedDrives.delete(drive);
    }

    this.emitSyncStatus();
  }

  /** True once a drive sync has finished FOR THIS DRIVE in this session.
   *
   * Used by collection queries to decide whether an empty local-DB result is
   * authoritative ("the table has no children") or ambiguous ("the index may
   * not be populated yet").
   *
   * Deliberately per-drive. This used to answer "has ANY sync finished", which
   * is a different question and wrong for every drive except the synced one: a
   * session that syncs the user's own (small, new) personal drive would then
   * treat an empty local result for a DIFFERENT drive — one never synced, so
   * its index is legitimately empty — as proof that the drive has no children.
   * The visible effect was a sidebar full of items while signed out (server
   * answers) that emptied on sign-in (local DB answers 0, and the 0 is
   * believed).
   *
   * An unknown drive returns false, so the caller falls back to the server.
   * That is the safe direction: a needless `/query` costs a round-trip, while
   * a wrongly-trusted empty silently hides the user's data. */
  public hasCompletedDriveSyncFor(drive: string | undefined): boolean {
    if (!drive) return false;

    return this._syncedDrives.has(drive);
  }

  public getSyncStatus(): StoreSyncStatus {
    // Saves that succeed first-try go straight to the server — they
    // never touch the outbox, so `outbox.size` alone misses them.
    // Without this, an editor that debounces its save and then exits
    // (Escape/blur) can return to a caller before the in-flight POST
    // completes; the next interaction races the previous commit.
    // Repro: rename-regression "two sequential renames".
    let inFlightSaves = 0;

    for (const r of this.resources.values()) {
      if (r.isSaving) inFlightSaves++;
    }

    return {
      serverConnected: this._serverConnected,
      serverConnectionError: this._serverConnectionError,
      syncInProgress:
        this._driveSyncInProgress ||
        this.outbox.isDraining ||
        inFlightSaves > 0 ||
        this._scheduledSaves > 0,
      // `_scheduledSaves` may briefly double-count a resource that is both
      // scheduled and already saving/outboxed — harmless for the "=== 0
      // means synced" contract this number exists for.
      pendingDirtyCount:
        this.outbox.size -
        this.outbox.blockedCount +
        inFlightSaves +
        this._scheduledSaves,
      blockedCount: this.outbox.blockedCount,
      serverUrl: this.serverUrl,
      drive: this.drive,
      clientDbReady: this.clientDb?.isReady ?? false,
      clientDbAttached: !!this.clientDb,
      clientDbError: this.clientDb?.initError?.message,
      lastDriveSync: this._lastDriveSync,
      lastDriveSyncError: this._lastDriveSyncError,
    };
  }

  public async notifyResourceSaved(resource: Resource): Promise<void> {
    await this.eventManager.emit(StoreEvents.ResourceSaved, resource);
  }

  public async notifyResourceManuallyCreated(
    resource: Resource,
  ): Promise<void> {
    const now = Date.now();
    // Prune stale entries: anything older than the longest plausible
    // consume window (5× the default 2s). Otherwise unsubscribed
    // creations accumulate forever — small leak in practice but
    // visible under fuzzing/bulk-creation tests.
    const cutoff = now - 10_000;

    for (const [subject, ts] of this.recentlyCreatedSubjects) {
      if (ts < cutoff) this.recentlyCreatedSubjects.delete(subject);
    }

    this.recentlyCreatedSubjects.set(resource.subject, now);
    await this.eventManager.emit(StoreEvents.ResourceManuallyCreated, resource);
  }

  /**
   * Returns true and clears the flag if {@link notifyResourceManuallyCreated}
   * fired for this subject within `windowMs`. Call from `useEffect` on mount
   * (not `useState`) — this mutates store state and is not safe to run during
   * render. The clear means only the first caller wins, which is fine for the
   * one-of-many-mounts race this is meant to plug.
   */
  public consumeRecentlyCreated(subject: string, windowMs = 2000): boolean {
    const ts = this.recentlyCreatedSubjects.get(subject);
    if (ts === undefined) return false;
    this.recentlyCreatedSubjects.delete(subject);

    return Date.now() - ts <= windowMs;
  }

  /** Parses the HTML document for `JSON-AD` data in <meta> tags, adds it to the store */
  public parseMetaTags(): void {
    const metaTags = document.querySelectorAll(
      'meta[property="json-ad-initial"]',
    );
    const parser = new JSONADParser();

    metaTags.forEach(tag => {
      const content = tag.getAttribute('content');

      if (content === null) {
        return;
      }

      // Decode base64 content safely as UTF-8
      const jsonString = new TextDecoder().decode(
        Uint8Array.from(atob(content), c => c.charCodeAt(0)),
      );
      const json = JSON.parse(jsonString);
      for (const r of parser.parse(json)) this.addResource(r);
    });
  }

  /**
   * Fetches all Classes and Properties from your current server, including external resources.
   * This helps to speed up time to interactive, but may not be necessary for all applications.
   */
  public async preloadPropsAndClasses(): Promise<void> {
    // TODO: use some sort of CollectionBuilder for this.
    await Promise.all([
      this.fetchResourceFromServer(this.buildPreloadUrl('/classes')),
      this.fetchResourceFromServer(this.buildPreloadUrl('/properties')),
    ]);
  }

  /** Sends an HTTP POST request to the server to the Subject. Parses the returned Resource and adds it to the store. */
  public async postToServer<R extends OptionalClass = Server.EndpointResponse>(
    url: string,
    data?: ArrayBuffer | string,
  ): Promise<Resource<R>> {
    return this.fetchResourceFromServer(url, {
      body: data,
      noWebSocket: true,
      method: 'POST',
    });
  }

  /** Build a `/classes` or `/properties` preload URL with the
   *  `include_external + include_nested + page_size=999` triple
   *  every preload uses. */
  private buildPreloadUrl(path: string): string {
    const url = new URL(path, this.serverUrl);
    url.searchParams.set('include_external', 'true');
    url.searchParams.set('include_nested', 'true');
    url.searchParams.set('page_size', '999');

    return url.toString();
  }

  /** Removes resource from this store, does not delete it from the server, use `resource.destroy()` to delete it from the server. */
  public removeResource(subjectRaw: string, shouldNotify = true): void {
    const resolved = this.resolveSubject(subjectRaw);

    // Tombstone in ClientDb (OPFS) so the resource doesn't reappear after a
    // page reload. The in-memory `resources` map is wiped on reload, but the
    // WASM DB persists; without this, cascade-deleted children survive
    // restart and re-render.
    //
    // Counted while it is in flight, because until the worker has written it
    // this deletion exists only in memory — reload now and the resource comes
    // back. `pendingDirtyCount === 0` is documented to mean "safe to reload,
    // nothing will be lost", and a delete that un-deletes itself is exactly
    // the kind of loss that claim is about. It was fire-and-forget, so the
    // status read as settled during the one window where it was not.
    if (this.clientDb) {
      this.startScheduledSave();
      void this.clientDb
        .removeResource(resolved)
        .catch(() => undefined)
        .then(() => this.finishScheduledSave());
    }

    // The stored state is gone, so the next write for this subject must not be
    // mistaken for a duplicate of it.
    this.lastPersistedStamp.delete(resolved);

    if (this.resources.delete(resolved)) {
      if (shouldNotify) {
        this.eventManager.emit(StoreEvents.ResourceRemoved, subjectRaw);
      }
    }
  }

  /**
   * Changes the Subject of a Resource. Checks if the new name is already taken,
   * errors if so.
   */
  public async renameSubject(
    resource: Resource,
    newSubjectRaw: string,
  ): Promise<void> {
    const newSubject = this.normalizeSubject(newSubjectRaw);
    Client.tryValidSubject(newSubject);
    const oldSubject = this.normalizeSubject(resource.subject);

    if (await this.checkSubjectTaken(newSubject)) {
      throw Error(`New subject name is already taken: ${newSubject}`);
    }

    resource.setSubject(newSubject);

    const subs = this.subscribers.get(oldSubject) ?? [];
    this.subscribers.set(newSubject, subs);
    this.removeResource(oldSubject);

    this.addResource(resource);
  }

  /**
   * Sets the current Agent, used for signing commits. Authenticates all open
   * websockets, and retries previously failed fetches.
   *
   * Warning: doing this stores the Private Key of the Agent in memory. This
   * might have security implications for your application.
   */
  public setAgent(agent: Agent | undefined): void {
    this.agent = agent;

    // The outbox is identity-scoped: rebind to this agent's own queue so a new
    // identity never drains a previous agent's commits (whose `did:ad:<sig>`
    // subjects can't be re-signed by anyone else — they'd 401 forever).
    this.outbox.rebind(agent?.subject);
    // Drain the now-loaded queue for this agent (no-ops if empty/offline).
    this.scheduleOutboxDrain();

    if (agent && agent.subject) {
      if (hasBrowserAPI()) {
        // Fire-and-forget here: this is a side effect on agent change,
        // not a precondition of a specific request. The HTTP request
        // path (`Client.fetchResourceHTTP`) re-installs the cookie if
        // it's missing, and awaits it there.
        setCookieAuthentication(this.serverUrl, agent).catch(() => undefined);
      }

      this.webSockets.forEach(ws => {
        ws.authenticate(true).catch(e => {
          this.notifyError(e);
        });
      });

      // Fire-and-forget: a returning pre-DID user should get their name and
      // drives back, but signing in must not block on it or fail because of
      // it.
      void this.adoptLegacyAgentIdentity(agent);
    } else {
      if (hasBrowserAPI()) {
        removeCookieAuthentication();
      }
    }

    this.eventManager.emit(StoreEvents.AgentChanged, agent);
  }

  /**
   * Carries a pre-DID identity's own details onto its DID.
   *
   * Before DIDs, an Agent lived at `https://server/agents/{pubkey}` — and that
   * resource is what holds the user's `name` and, crucially, the `drives` they
   * own. Signing in derives `did:ad:agent:{pubkey}` from the key and mints a
   * fresh Agent there: correct identity, empty resource. It then shadows the
   * real one permanently, so the user is not shown an error — they are shown
   * an account that looks brand new, with no name and no drives, which is what
   * empties the sidebar.
   *
   * The old subject survives only inside the secret ({@link
   * legacySubjectFromSecret}), so this runs on the client: the server never
   * sees a secret and cannot do this itself.
   *
   * Only ever FILLS IN. A property already set on the DID Agent is left alone,
   * so this converges after one run and a user who renames themselves later is
   * never reverted on the next sign-in. That also makes it safe for the
   * already-signed-in case, where a bare Agent is sitting at the DID and needs
   * merging into rather than replacing.
   */
  /**
   * Finds a pre-DID Agent's resource, given the subject its secret was issued
   * under.
   *
   * The secret records where the identity was *created*, which is not
   * necessarily where its data lives now — migrating a store moves every
   * resource onto the new server's origin. A secret issued by
   * `https://atomicdata.dev` is used to sign in to a staging or local copy of
   * that same data, and the old absolute URL then resolves to nothing (or, on
   * a machine with network access, to the real production server — which is
   * worse).
   *
   * So the path is what carries over, not the origin: `/agents/{pubkey}` on
   * *this* server is tried first. The original is kept as a fallback for the
   * case the secret really does describe another, still-live server.
   */
  /** Agents whose legacy migration has already been started — see
   *  `adoptLegacyAgentIdentity`. */
  private legacyAdoptionRuns = new Set<string>();

  private async fetchLegacyAgentResource(
    legacySubject: string,
  ): Promise<Resource | undefined> {
    const onThisServer = legacySubject.replace(
      /^https?:\/\/[^/]+/,
      this.serverUrl,
    );

    const candidates =
      onThisServer === legacySubject
        ? [legacySubject]
        : [onThisServer, legacySubject];

    for (const candidate of candidates) {
      try {
        // Bounded: these are servers this device may never reach, and an
        // unbounded await here is felt as a frozen sign-in rather than a slow
        // one. A late answer is no use once we have stopped waiting.
        const resource = await withDeadline(
          this.getResource(candidate),
          LEGACY_FETCH_DEADLINE_MS,
          undefined,
        );

        if (resource && !resource.error) return resource;

        console.warn(
          `[atomic] Previous account not readable at '${candidate}'${
            resource ? '' : ' (timed out)'
          }.`,
        );
      } catch {
        // Try the next candidate.
      }
    }

    return undefined;
  }

  /**
   * Everything an agent needs on the way in: a home drive that exists, and —
   * for a pre-DID account — the name and drives the old server holds.
   *
   * `setAgent` fires this and forgets it, and an app sets an agent more than
   * once while booting (a node's own agent, then the signed-in one, then a
   * rehydrate). Keyed on the agent, not a bare boolean: signing out and into a
   * different account must still run. The key is added before the first await
   * so concurrent callers collapse onto one run rather than racing.
   */
  private async adoptLegacyAgentIdentity(agent: Agent): Promise<void> {
    const legacySubject = agent.legacySubject;

    // Checked before the guard is claimed: an agent that gains a legacy
    // subject after the first `setAgent` must still be able to migrate.
    if (!legacySubject || !agent.subject) return;

    if (this.legacyAdoptionRuns.has(agent.subject)) return;

    this.legacyAdoptionRuns.add(agent.subject);

    try {
      const legacy = await this.fetchLegacyAgentResource(legacySubject);

      if (!legacy) {
        // Loud on purpose. This used to return in silence, so a migration that
        // never ran was indistinguishable from one that found nothing to do —
        // and the once-per-agent guard means it will not be retried.
        console.warn(
          `[atomic] Migration skipped: could not read the previous account at '${legacySubject}'.`,
        );

        return;
      }

      const current = await this.getResource(agent.subject);

      if (current.error) {
        console.warn(
          `[atomic] Migration skipped: this agent's own resource did not load (${current.error.message}).`,
        );

        return;
      }

      // Identity only. `drives` is deliberately NOT carried onto the Agent:
      // the two models keep that list in different places, and putting it back
      // where the old one had it is actively harmful — see
      // `adoptLegacyDriveList`.
      const carried: [string, unknown][] = [];

      for (const prop of [core.properties.name, core.properties.description]) {
        const existing = current.get(prop);
        const isEmpty =
          existing === undefined ||
          existing === null ||
          existing === '' ||
          (Array.isArray(existing) && existing.length === 0);

        if (!isEmpty) continue;

        const inherited = legacy.get(prop);

        if (inherited === undefined || inherited === null) continue;

        carried.push([prop, inherited]);
      }

      if (carried.length > 0) {
        for (const [prop, value] of carried) {
          await current.set(prop, value as never, false);
        }

        await current.save();
      }

      await this.adoptLegacyDriveList(agent, legacy, current);
    } catch (e) {
      // Best effort. A failure here leaves the user signed in with an empty
      // profile — bad, but not as bad as failing the sign-in itself. Say so:
      // an empty profile with no explanation reads as "migration is broken"
      // when it is usually one unreachable server.
      console.warn('[atomic] Migrating the previous account failed:', e);
    }
  }

  /**
   * Restores the drives a pre-DID user owned, into the list the app actually
   * reads.
   *
   * The two models disagree on where that list lives. The old server kept
   * `drives` on the Agent; the current one keeps it on the user's private
   * drive — the per-user home index — which is what `useSavedDrives` reads.
   * Copying the old list onto the Agent therefore restores nothing: "My
   * drives" stays empty because nothing looks there.
   *
   * Worse, it actively misleads. With no `privateDrive` set,
   * `fetchPrivateDriveSubject` falls back to `drives[0]` on the Agent — so
   * one arbitrary drive out of the whole list gets promoted to "Private
   * drive" and the other 52 vanish. These are ordinary drives the user owns,
   * not their private one.
   *
   * So the list goes on the private drive. Union, never replace: drives
   * already in the list stay, and one that was deliberately unstarred is not
   * resurrected on the next sign-in — only genuinely-missing ones are added.
   *
   * A migrated user usually has NO private drive: the old server never had the
   * concept, so nothing set `privateDrive`, and a legacy secret carries no
   * `initialDrive` either. Returning in that case — as this used to — skips
   * the adoption in precisely the situation the function exists for, which is
   * why "My drives" stayed empty while one drive was mislabelled "Private
   * drive". So provision one instead, the same way onboarding does.
   */
  /**
   * Whether a drive subject inherited from a pre-DID account is worth putting
   * in front of the user on THIS server.
   *
   * A years-old `drives` list is a history of everywhere its owner ever had a
   * drive, not a list of drives that exist here. A real one contained 53
   * entries, of which only 26 were well-formed and local: 11 pointed at
   * long-dead dev servers (`http://localhost:9883/…`,
   * `http://dawdawda.localhost:9883/…`) and 15 carried a subdomain spliced
   * into the path by the migration (`internal:/staging:/drive/…`).
   *
   * Adopting those verbatim is not merely untidy. A drive list is fetched, so
   * a `localhost` entry makes an app served from a public origin fire requests
   * at the machine of whoever signed in — which, if they happen to run a local
   * server on that port, quietly returns THEIR data. The rest 404 in a loop and
   * bury the console.
   *
   * So: keep DIDs (portable by construction) and subjects on this server's own
   * origin; drop everything else. A drive that genuinely lives elsewhere is not
   * lost — it is still on the legacy Agent, and "Open by URL" reaches it.
   */
  /**
   * `legacyOrigin` is the origin of the legacy Agent resource this list came
   * from. Drives sitting there are adoptable even though they are not on the
   * current server: that origin is the account being migrated away from, and
   * the user just authenticated against it, so it is not an arbitrary
   * third party. Without this a pre-DID account migrating to a desktop node
   * or a self-hosted server loses its entire drive list, since none of the
   * subjects can match the new home's origin.
   *
   * Everything else still has to be same-origin. That keeps the case this
   * filter exists for: a stale list naming `http://localhost:9883` must never
   * make a hosted app issue requests at the user's own machine.
   */
  private isAdoptableDriveSubject(
    subject: string,
    legacyOrigin?: string,
  ): boolean {
    if (subject.startsWith('did:')) return true;

    // The migration's mangled spelling. It survives serialization as a path
    // segment containing a colon, which is not a subject this server can
    // resolve — it is the `staging` subdomain welded onto the path.
    if (/\/[^/]+:\//.test(subject.replace(/^https?:\/\//, ''))) return false;

    try {
      const { origin } = new URL(subject);

      if (origin === new URL(this.serverUrl).origin) return true;

      return legacyOrigin !== undefined && origin === legacyOrigin;
    } catch {
      // Unparseable, and not a DID: nothing can be done with it.
      return false;
    }
  }

  private async adoptLegacyDriveList(
    agent: Agent,
    legacy: Resource,
    didAgent: Resource,
  ): Promise<void> {
    // An earlier build parked the list on the Agent. Treat that as a source
    // too, so an account migrated by that version is repaired rather than
    // stranded.
    // Where the legacy list came from — see `isAdoptableDriveSubject`.
    let legacyOrigin: string | undefined;

    try {
      legacyOrigin = new URL(legacy.subject).origin;
    } catch {
      legacyOrigin = undefined;
    }

    const inherited = [
      ...legacy.getSubjects(server.properties.drives),
      ...didAgent.getSubjects(server.properties.drives),
    ].filter(subject => this.isAdoptableDriveSubject(subject, legacyOrigin));

    if (inherited.length === 0) return;

    const privateDrive = await this.ensurePrivateDrive('My drive', {
      agentName: legacy.get(core.properties.name) as string | undefined,
    });

    if (privateDrive.error) return;

    const privateDriveSubject = privateDrive.subject;

    const already = new Set(privateDrive.getSubjects(server.properties.drives));
    const missing = inherited.filter(
      subject => subject !== privateDriveSubject && !already.has(subject),
    );

    if (missing.length === 0) return;

    privateDrive.push(server.properties.drives, missing, true);
    await privateDrive.save();
  }

  /**
   * Sets the Server base URL, without the trailing slash.
   *
   * `connect: false` keeps the socket closed — see `StoreOpts.connect`.
   */
  public setServerUrl(url: string, { connect = true } = {}): void {
    Client.tryValidSubject(url);

    if (url.substring(-1) === '/') {
      throw Error('baseUrl should not have a trailing slash');
    }

    const previous = this.serverUrl;

    this.serverUrl = url;

    // Switching servers: tear down the old socket and reset the connection
    // status. `serverConnected` / `serverConnectionError` describe *the current
    // server*, so a leftover socket is not just waste — it keeps retrying and
    // overwriting them, which surfaces the previous server's error on the new
    // server's card.
    if (previous && previous !== url) {
      const stale = this.webSockets.get(previous);

      if (stale) {
        stale.close();
        this.webSockets.delete(previous);
      }

      this.setServerConnected(false);
    }

    this.eventManager.emit(StoreEvents.ServerURLChanged, url);

    if (!connect) {
      this.serverUrlWithoutSocket = url;
    }

    if (supportsWebSockets()) {
      const userDisconnected =
        typeof localStorage !== 'undefined' &&
        localStorage.getItem('ws-disconnected') === '1';

      if (!userDisconnected && url !== this.serverUrlWithoutSocket) {
        this.openWebSocket(url);
      }
    }
  }

  /** Returns the current Drive subject, or `undefined` if no drive
   *  has been selected. Callers must handle the absent case rather
   *  than treat the server URL as a drive — see the type doc on
   *  `private drive` for why. */
  public getDrive(): string | undefined {
    return this.drive;
  }

  /** Sets the current Drive.
   *
   *  A DID (or other non-HTTP subject) is a drive. An HTTP URL with a
   *  path is also a drive — including one whose origin is not this
   *  store's home server. Those are fetched cross-origin; `serverUrl`
   *  stays put. Only a *bare* HTTP origin (`https://host`, no path) is
   *  treated as `setServerUrl`, and does not become `this.drive`. That
   *  split is what prevents SYNC_VV / encodeSub from running against a
   *  host URL, which `collect_drive_subjects` cannot enumerate cheaply.
   *
   *  Both forms still persist to localStorage and fire `DriveChanged`
   *  so AppSettings-style UI mirrors stay in sync.
   */
  public setDrive(drive: string): void {
    if (!drive) {
      this.drive = undefined;
    } else if (Client.isBareHttpOrigin(drive)) {
      this.setServerUrl(new URL(drive).origin);
    } else {
      this.drive = drive;
    }

    if (typeof window !== 'undefined') {
      localStorage.setItem('drive', JSON.stringify(drive));
    }

    this.eventManager.emit(StoreEvents.DriveChanged, drive);
  }

  /** Opens a WebSocket for this Atomic Server URL */
  public openWebSocket(url: string) {
    // Check if we're running in a webbrowser
    if (supportsWebSockets()) {
      if (this.webSockets.has(url)) {
        return;
      }

      this.webSockets.set(url, new WSClient(url, this));
    } else {
      console.warn('WebSockets not supported, no window available');
    }
  }

  /**
   * Force-reconnect to the server by dropping and recreating the WebSocket.
   *
   * Resolves once the new socket is open and `serverConnected` flips back
   * to `true`. Rejects with the connection error if the socket closes or
   * fails before that happens, or if `timeoutMs` elapses with no outcome.
   *
   * Returning a promise lets callers route reconnect failures through the
   * standard `store.notifyError(e)` pipeline (and therefore through the
   * global `StoreEvents.Error` toast) instead of polling sync status to
   * detect the failure themselves.
   */
  public reconnect(timeoutMs = 15000): Promise<void> {
    const url = this.serverUrl;

    if (!url) return Promise.resolve();

    return new Promise<void>((resolve, reject) => {
      let unsub: (() => void) | undefined;
      const timer = setTimeout(() => {
        unsub?.();
        reject(
          new Error(
            `Reconnect to ${url} timed out after ${timeoutMs}ms. Check that the server is running and reachable.`,
          ),
        );
      }, timeoutMs);

      unsub = this.on(StoreEvents.ConnectionChanged, connected => {
        if (connected) {
          clearTimeout(timer);
          unsub?.();
          resolve();
        } else if (this._serverConnectionError) {
          // A disconnect without an error message is the synchronous
          // teardown step below — keep waiting for the real outcome.
          clearTimeout(timer);
          unsub?.();
          reject(new Error(this._serverConnectionError));
        }
      });

      // Tear down + reopen. The `setServerConnected(false)` here fires
      // `ConnectionChanged` with `_serverConnectionError === undefined`,
      // which the listener above ignores.
      const existing = this.webSockets.get(url);

      if (existing) {
        existing.close();
        this.webSockets.delete(url);
      }

      if (typeof localStorage !== 'undefined') {
        localStorage.removeItem('ws-disconnected');
      }

      this.setServerConnected(false);
      this.openWebSocket(url);
    });
  }

  /** Close the WebSocket connection. Persists across refresh until reconnect(). */
  public disconnect(): void {
    const existing = this.webSockets.get(this.serverUrl);

    if (existing) {
      existing.close();
      this.webSockets.delete(this.serverUrl);
    }

    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('ws-disconnected', '1');
    }
  }

  /**
   * Subscribe to changes for a resource. The callback fires on every
   * `notify` for that subject (local commits + remote pushes).
   * Returns an unsubscriber. Per-property subscriptions are handled
   * separately by `Resource.on(ResourceEvents.LocalChange)`.
   */
  public subscribe(subject: string, callback: ResourceCallback): () => void {
    if (subject === undefined) {
      throw Error('Cannot subscribe to undefined subject');
    }

    const normalized = this.normalizeSubject(subject);

    return this.addLoroSubscriber(this.subscribers, normalized, callback, () =>
      this.subscribeWebSocket(normalized),
    );
  }

  /** v2 uses drive-level WS subscriptions — every resource in the drive
   *  is delivered through the single `SUB <drive>` sent in
   *  {@link WSClient.handleOpen}. The server's `CommitMonitor` fans
   *  CommitMessages out to drive subscribers when the commit's target
   *  lives under that drive. This per-resource entry-point is kept as
   *  a no-op for API stability — callers don't need to gate themselves.
   *  The lookup confirms the origin's WS exists. */
  public subscribeWebSocket(subject: string): void {
    if (!this._serverConnected) return;
    const normalized = this.normalizeSubject(subject);

    if (
      normalized === unknownSubject ||
      normalized.includes('/commits/') ||
      normalized.startsWith('did:ad:commit:') ||
      this.isLocalOnlySubject(normalized)
    ) {
      return;
    }

    try {
      this.getWebSocketForSubject(subject);
    } catch (e) {
      console.error(e);
    }
  }

  // === Loro CRDT Sync ===

  /** Add `callback` to `map[subject]` and return an unsubscriber.
   *  `onFirstAdd` fires when the list goes 0 → 1 (per-subject WS
   *  subscribe). `onLastRemove` fires when it goes 1 → 0 (WS
   *  unsubscribe). Used by both Loro sync and Loro ephemeral
   *  channels — same shape, different transport hooks. */
  private addLoroSubscriber<T>(
    map: Map<string, T[]>,
    subject: string,
    callback: T,
    onFirstAdd?: () => void,
    onLastRemove?: () => void,
  ): () => void {
    const existing = map.get(subject);

    if (existing) {
      existing.push(callback);
    } else {
      map.set(subject, [callback]);
      onFirstAdd?.();
    }

    return () => {
      const subs = map.get(subject);
      if (!subs) return;
      const filtered = subs.filter(c => c !== callback);

      if (filtered.length === 0) {
        map.delete(subject);
        onLastRemove?.();
      } else {
        map.set(subject, filtered);
      }
    };
  }

  /**
   * Subscribe to vector index activity for a drive: registers `callback` for
   * {@link StoreEvents.Indexing} and opens the websocket subscription
   * (`SUBSCRIBE_INDEX_STATUS`). The server sends an immediate `INDEX_STATUS`.
   * The returned function removes both the listener and the websocket subscription.
   */
  public subscribeIndexStatus(
    driveSubject: string,
    callback: IndexingStatusCallback,
  ): () => void {
    if (driveSubject === unknownSubject) {
      return () => {};
    }

    const unsubEvent = this.on(StoreEvents.Indexing, driveSubject, callback);

    try {
      const ws =
        this.getDefaultWebSocket() ?? this.getWebSocketForSubject(driveSubject);
      ws?.subscribeIndexStatus(driveSubject);
    } catch (e) {
      console.error(e);
    }

    return () => {
      unsubEvent();

      try {
        const ws =
          this.getDefaultWebSocket() ??
          this.getWebSocketForSubject(driveSubject);
        ws?.unsubscribeIndexStatus(driveSubject);
      } catch (e) {
        console.error(e);
      }
    };
  }

  /** Fan the payload of one `EPHEMERAL` frame out to the subscribers of
   *  its subject on the given channel map. */
  private dispatchLoroMessage<T extends (update: Uint8Array) => void>(
    map: Map<string, T[]>,
    subject: string,
    bytes: Uint8Array,
  ): void {
    const subs = map.get(subject);
    if (!subs) return;
    subs.forEach(cb => cb(bytes));
  }

  /**
   * Subscribe to Loro document sync updates for a resource.
   * Real-time CRDT synchronization — persistent changes go through commits.
   * @returns A function to unsubscribe.
   */
  public subscribeLoroSync(
    subject: string,
    callback: LoroSyncCallback,
  ): () => void {
    return this.addLoroSubscriber(
      this.loroSyncSubscribers,
      subject,
      callback,
      () => {
        if (this._serverConnected && !this.isLocalOnlySubject(subject)) {
          this.getWebSocketForSubject(subject)?.subscribeLoroSync(subject);
        }
      },
      () => {
        if (this._serverConnected && !this.isLocalOnlySubject(subject)) {
          this.getWebSocketForSubject(subject)?.unsubscribeLoroSync(subject);
        }
      },
    );
  }

  /** Broadcast a Loro document update to all peers via WebSocket.
   *  Non-persistent real-time; persistence is via commits. */
  public broadcastLoroSyncUpdate(subject: string, update: Uint8Array): void {
    if (!this._serverConnected) return;
    if (this.isLocalOnlySubject(subject)) return;
    this.getWebSocketForSubject(subject)?.sendLoroSyncUpdate(subject, update);
  }

  /** Subscribe to Loro ephemeral updates (cursors, presence). */
  public subscribeLoroEphemeral(
    subject: string,
    callback: LoroEphemeralCallback,
  ): () => void {
    return this.addLoroSubscriber(
      this.loroEphemeralSubscribers,
      subject,
      callback,
    );
  }

  /** Broadcast a Loro ephemeral update (cursors, presence) to peers. */
  public broadcastLoroEphemeralUpdate(
    subject: string,
    update: Uint8Array,
  ): void {
    if (!this._serverConnected) return;
    if (this.isLocalOnlySubject(subject)) return;
    this.getWebSocketForSubject(subject)?.sendLoroEphemeralUpdate(
      subject,
      update,
    );
  }

  // === Drive presence (ephemeral, issue #1229) ===

  /** Get (or lazily create) the presence manager for a drive. The manager
   *  owns the drive's shared Loro EphemeralStore and the `PRESENCE_*`
   *  websocket subscription. One instance per drive for the store's
   *  lifetime: consumers memoize it across renders, so replacing the
   *  instance would leave them writing to a dead manager (its transport
   *  still shuts down while unobserved — see `subscribe`). */
  public getPresence(drive: string): DrivePresenceManager {
    let manager = this.presenceManagers.get(drive);

    if (!manager) {
      manager = new DrivePresenceManager(this, drive);
      this.presenceManagers.set(drive, manager);
    }

    return manager;
  }

  /** Subscribe to raw presence payloads for a drive. Transport-level —
   *  use `getPresence(drive)` for the decoded presence list. */
  public subscribePresenceUpdates(
    drive: string,
    callback: PresenceCallback,
  ): () => void {
    return this.addLoroSubscriber(
      this.presenceSubscribers,
      drive,
      callback,
      () => {
        if (this._serverConnected && this.isLiveSyncedDrive(drive)) {
          this.presenceWebSocket(drive)?.subscribePresence(drive);
        }
      },
      () => {
        if (this._serverConnected && this.isLiveSyncedDrive(drive)) {
          this.presenceWebSocket(drive)?.unsubscribePresence(drive);
        }
      },
    );
  }

  /** Broadcast raw presence bytes (Loro EphemeralStore update) to a
   *  drive's presence subscribers. */
  public broadcastPresenceUpdate(drive: string, update: Uint8Array): void {
    if (!this._serverConnected) return;
    // Local-only drives and foreign-origin HTTP drives have no live
    // peers on the home websocket.
    if (!this.isLiveSyncedDrive(drive)) return;
    this.presenceWebSocket(drive)?.sendPresenceUpdate(drive, update);
  }

  private presenceWebSocket(drive: string): WSClient | undefined {
    return this.getDefaultWebSocket() ?? this.getWebSocketForSubject(drive);
  }

  public getPresenceSubjects(): string[] {
    return Array.from(this.presenceSubscribers.keys());
  }

  /** @internal An `EPHEMERAL` frame of kind `PRESENCE` for `drive`. */
  public __handlePresenceMessage(drive: string, update: Uint8Array): void {
    this.dispatchLoroMessage(this.presenceSubscribers, drive, update);
  }

  /** @internal Re-announce local presence after a websocket (re)connect:
   *  the new connection's server-side cache starts empty. */
  public __rebroadcastPresence(): void {
    for (const manager of this.presenceManagers.values()) {
      manager.rebroadcast();
    }
  }

  public getLoroSyncSubjects(): string[] {
    return Array.from(this.loroSyncSubscribers.keys());
  }

  public getLoroEphemeralSubjects(): string[] {
    return Array.from(this.loroEphemeralSubscribers.keys());
  }

  /** @internal An `EPHEMERAL` frame of kind `DOC`: an edit in progress. */
  public __handleLoroSyncMessage(subject: string, update: Uint8Array): void {
    this.dispatchLoroMessage(this.loroSyncSubscribers, subject, update);
  }

  /** @internal An `EPHEMERAL` frame of kind `LORO`: cursors. */
  public __handleLoroEphemeralMessage(
    subject: string,
    update: Uint8Array,
  ): void {
    this.dispatchLoroMessage(this.loroEphemeralSubscribers, subject, update);
  }

  /** Unregisters the callback (see `subscribe()`) */
  public unsubscribe(subject: string, callback: ResourceCallback): void {
    if (subject === undefined) return;
    const normalized = this.normalizeSubject(subject);
    const subs = this.subscribers.get(normalized);
    if (!subs) return;
    const filtered = subs.filter(cb => cb !== callback);
    if (filtered.length === 0) this.subscribers.delete(normalized);
    else this.subscribers.set(normalized, filtered);
  }

  /**
   * Notifies listeners registered with `on(StoreEvents.Indexing, drive, ...)`.
   * Used when a websocket `INDEX_STATUS` message is received.
   */
  public __notifyIndexingStatus(drive: string, indexing: boolean): void {
    const set = this.vectorIndexingSubscribers.get(drive);

    if (!set) {
      return;
    }

    for (const cb of set) {
      try {
        cb(indexing);
      } catch (e) {
        console.error(e);
      }
    }
  }

  public on(
    event: StoreEvents.Indexing,
    drive: string,
    callback: IndexingStatusCallback,
  ): () => void;
  public on<T extends Exclude<StoreEvents, StoreEvents.Indexing>>(
    event: T,
    callback: StoreEventHandlers[T],
  ): () => void;
  public on(
    event: StoreEvents,
    arg2: string | StoreEventHandlers[StoreEvents],
    arg3?: IndexingStatusCallback,
  ): () => void {
    if (event === StoreEvents.Indexing && typeof arg2 === 'string' && arg3) {
      const drive = arg2;
      const callback = arg3;
      let set = this.vectorIndexingSubscribers.get(drive);

      if (!set) {
        set = new Set();
        this.vectorIndexingSubscribers.set(drive, set);
      }

      set.add(callback);

      return () => {
        set!.delete(callback);

        if (set!.size === 0) {
          this.vectorIndexingSubscribers.delete(drive);
        }
      };
    }

    return this.eventManager.register(
      event as StoreEvents,
      arg2 as StoreEventHandlers[StoreEvents],
    );
  }

  private emitSyncStatus(): void {
    this.eventManager.emit(StoreEvents.SyncStatusChanged, this.getSyncStatus());
  }

  private pushCommitLog(entry: Omit<CommitLogEntry, 'id'>): void {
    // Dedup by commitId so a `pending` entry transitions in place to `sent` /
    // `failed` once the push resolves, rather than producing two rows for the
    // same commit. Incoming commits without an outgoing pending counterpart
    // simply prepend.
    const existingIdx = entry.commitId
      ? this._commitLog.findIndex(e => e.commitId === entry.commitId)
      : -1;

    if (existingIdx >= 0) {
      // Status transition for an already-logged commit. Two things
      // matter: (1) reuse the original \`propertySummaries\` —
      // \`summarizeCommitProperties\` is destructive on the second
      // call (it stored the snapshot as the prior baseline; the
      // second pass diffs the snapshot against itself → empty); (2)
      // move the merged entry to the top so users see fresh status
      // changes on the right side of the activity log.
      const prior = this._commitLog[existingIdx];
      const merged: CommitLogEntry = {
        ...prior,
        ...entry,
        propertySummaries: prior.propertySummaries,
      };
      this._commitLog = [
        merged,
        ...this._commitLog.slice(0, existingIdx),
        ...this._commitLog.slice(existingIdx + 1),
      ];
    } else {
      this._commitLog = [{ ...entry, id: ulid() }, ...this._commitLog].slice(
        0,
        50,
      );
    }

    this.eventManager.emit(StoreEvents.CommitLogChanged, this.getCommitLog());
  }

  /** Build a commit-log entry with the fields shared across every
   *  status / direction (subject, signer, prev, derived commitId,
   *  flags, summary). Per-status extras (server-supplied commitId,
   *  error message) come in via `extras`. */
  private buildCommitLogEntry(
    commit: Commit,
    direction: 'incoming' | 'outgoing',
    status: CommitLogEntry['status'],
    extras: { commitId?: string; error?: string } = {},
  ): Omit<CommitLogEntry, 'id'> {
    return {
      timestamp: Date.now(),
      direction,
      status,
      subject: commit.subject,
      signer: commit.signer,
      previousCommit: commit.previousCommit,
      commitId:
        extras.commitId ??
        (commit.signature ? `did:ad:commit:${commit.signature}` : undefined),
      hasLoroUpdate: !!commit.loroUpdate,
      destroy: !!commit.destroy,
      summary: this.summarizeCommit(commit),
      propertySummaries: this.summarizeCommitProperties(commit),
      ...(extras.error !== undefined ? { error: extras.error } : {}),
    };
  }

  /**
   * Records a locally-signed but not-yet-pushed commit as `pending` in the
   * commit log. When the push resolves, {@link postCommit} reuses the same
   * `commitId` so the entry transitions in place to `sent` or `failed`.
   */
  public logPendingCommit(commit: Commit): void {
    this.pushCommitLog(this.buildCommitLogEntry(commit, 'outgoing', 'pending'));
  }

  /** @internal Settle a commit that will never be POSTed (local-only
   *  drives sign locally). Transitions the `pending`
   *  entry `logPendingCommit` created so the Sync page doesn't show it
   *  as queued forever. */
  public logLocalOnlyCommitSettled(commit: Commit): void {
    this.pushCommitLog(this.buildCommitLogEntry(commit, 'outgoing', 'sent'));
  }

  private summarizeCommit(commit: Commit): string {
    const parts: string[] = [];

    if (commit.destroy) {
      parts.push('destroy');
    } else if (commit.isGenesis) {
      parts.push('created');
    } else {
      parts.push('updated');
    }

    if (commit.loroUpdate) {
      parts.push('(loro)');
    }

    return parts.join(' ');
  }

  /**
   * Diff this commit's loro snapshot against the previous one we logged for
   * the same subject. Only properties that differ — added, modified, removed
   * — are emitted. Genesis commits (no prior) treat every property as
   * `changed`. Returning an empty list is itself useful debug info: it means
   * the commit's snapshot has identical contents to the previous one, which
   * usually points to a duplicate-send or a UI that signed without a real
   * change.
   *
   * `pushCommitLog` is responsible for not stomping a real summary on a
   * status transition; this method always recomputes against the stored
   * baseline.
   */
  private summarizeCommitProperties(
    commit: Commit,
  ): CommitLogPropertySummary[] | undefined {
    if (!commit.loroUpdate) {
      return undefined;
    }

    try {
      const entriesOf = (resource: Resource): Map<string, JSONValue> => {
        const map = new Map<string, JSONValue>();

        for (const [prop, value] of resource.getEntries()) {
          if (
            prop === commits.properties.loroUpdate ||
            prop === commits.properties.lastCommit
          ) {
            continue;
          }

          map.set(prop, value as JSONValue);
        }

        return map;
      };

      // A non-genesis commit's `loroUpdate` is a DELTA, not full state. To show
      // what THIS commit changed we must diff against the accumulated state of
      // all prior commits — `_commitLogPriorSnapshots` holds that running
      // snapshot. Importing a bare delta into a fresh doc would drop the base
      // and make every untouched genesis property look "removed".
      const acc = new Resource(commit.subject);
      const priorBytes = this._commitLogPriorSnapshots.get(commit.subject);

      if (priorBytes) {
        try {
          acc.importLoroUpdate(priorBytes);
        } catch (e) {
          console.warn('[summarizeCommitProperties] prior decode failed:', e);
        }
      }

      const priorEntries = entriesOf(acc);

      // Apply this commit on top of the accumulated state.
      acc.importLoroUpdate(commit.loroUpdate);
      const currentEntries = entriesOf(acc);

      const summaries: CommitLogPropertySummary[] = [];

      for (const [prop, value] of currentEntries) {
        const before = priorEntries.get(prop);

        if (!commitLogValuesEqual(before, value)) {
          summaries.push({ property: prop, value, changeType: 'changed' });
        }
      }

      for (const [prop] of priorEntries) {
        if (!currentEntries.has(prop)) {
          summaries.push({
            property: prop,
            value: null as unknown as JSONValue,
            changeType: 'removed',
          });
        }
      }

      // Persist the ACCUMULATED snapshot (not this commit's delta) so the next
      // commit diffs against full state.
      const snapshot = acc.getLoroDoc?.()?.export({ mode: 'snapshot' });

      if (snapshot) {
        this._commitLogPriorSnapshots.set(commit.subject, snapshot);
      }

      return summaries.length > 0 ? summaries.slice(0, 20) : undefined;
    } catch (e) {
      console.warn('[summarizeCommitProperties] failed:', e);

      return undefined;
    }
  }

  /**
   * If the resource carries a `blob` reference, push the locally-stored bytes
   * to the server. Prefers the WS `BLOB_RESPONSE` fast path; falls back to
   * `PUT /blob/<hash>` over HTTP when the WS isn't open. Without the HTTP
   * fallback the server keeps the resource but never receives the bytes, so
   * `/download/files/<hash>` returns 404 — matching {@link postCommit}'s
   * transport (also HTTP) keeps both halves of an upload reliable.
   *
   * No-op if there's no clientDb (HTTP `/upload` already wrote the bytes
   * server-side) or no local copy of the bytes.
   *
   * Called from the outbox drain on every successful commit post, so the
   * bytes get sent both on initial save AND after `syncDirtyResources`
   * flushes commits that were queued while offline.
   */
  public async maybePushBlobForResource(resource: Resource): Promise<void> {
    if (!this.clientDb) return;

    const blobValue = resource.get(BLOB);
    if (typeof blobValue !== 'string') return;
    const prefix = 'did:ad:blob:';
    if (!blobValue.startsWith(prefix)) return;
    const hashHex = blobValue.slice(prefix.length);

    let hashBytes: Uint8Array;

    try {
      hashBytes = hexToBytes(hashHex);
    } catch {
      return;
    }

    if (hashBytes.length !== 32) return;

    let bytes: Uint8Array | null = null;

    try {
      bytes = await this.clientDb.getBlob(hashBytes);
    } catch {
      return;
    }

    if (!bytes) return;

    // HTTP PUT is the source of truth for blob delivery. Storage is content-
    // addressed and idempotent, so re-posting is a no-op. The WS BLOB_RESPONSE
    // path can drop frames when the connection closes mid-flight (e.g. server
    // heartbeat timeout right after `send()`), leaving the bytes "sent" from
    // the client's POV but never landing on the server. Subsequent commits
    // that depend on the blob (Plugin install reading the zip) then fail
    // server-side. Use the durable HTTP path; awaiting completion serializes
    // it with downstream commits.
    const url = `${this.getServerUrl()}/blob/${hashHex}`;
    // Honor `injectFetch` like every other network call on this class
    // (see `Client.fetch`'s identical fallback) — a bare global `fetch()`
    // here meant tests/embedders overriding the store's fetch couldn't
    // observe or intercept blob pushes at all.
    const fetchImpl = this.injectedFetch ?? fetch;
    await fetchImpl(url, {
      method: 'PUT',
      // Cast: TS lib.dom marks Uint8Array<SharedArrayBuffer> incompatible with
      // BodyInit/BlobPart; at runtime our bytes are ArrayBuffer-backed.
      body: bytes as unknown as BodyInit,
      headers: { 'Content-Type': 'application/octet-stream' },
    });
  }

  /**
   * Uploads files. The bytes are hashed (BLAKE3), stored in the local blob
   * store, and a `File` resource is created and committed through the normal
   * sync pipeline. The peer (server or another client) receives the resource
   * via Loro sync, sees the BLAKE3 hash, and pulls the bytes via the
   * BLOB_REQUEST/RESPONSE frames. Same path online or offline.
   */
  public async uploadFiles(
    files: FileOrFileLike[],
    parent: string,
  ): Promise<string[]> {
    const agent = this.getAgent();

    if (!agent) {
      throw Error('No agent set, cannot upload files');
    }

    // No local blob store — fall back to multipart POST `/upload`. The
    // server hashes, stores in Tree::Blobs, and creates the File resource
    // for us. Works in any browser (and Node) without WASM. The local-first
    // path below is preferable for offline support, but it's a hard
    // requirement only when ClientDb is attached.
    if (!this.clientDb) {
      const resources = await this.client.uploadFiles(
        files,
        this.getServerUrl(),
        agent,
        parent,
      );
      for (const r of resources) this.addResource(r);
      const subjects: string[] = [];

      for (const r of resources) {
        await this.notifyResourceManuallyCreated(r);
        subjects.push(r.subject);
      }

      return subjects;
    }

    const createdSubjects: string[] = [];
    const useDid =
      this.getAgent()!.subject?.startsWith('did:ad:agent:') ?? false;

    for (const file of files) {
      const blob = 'blob' in file ? file.blob : file;
      const name = file.name;
      const data = new Uint8Array(await blob.arrayBuffer());
      const hashBytes = await this.clientDb.blake3Hash(data);
      const hash = bytesToHex(hashBytes);

      await this.clientDb!.putBlob(hashBytes, data);

      const DRIVE_PROP = 'https://atomicdata.dev/properties/drive';
      const driveVal =
        (this.resources.get(parent)?.get(DRIVE_PROP) as string | undefined) ??
        parent;

      // Mint the cert-based DID up front (like `newResource`), so the upload
      // carries its real `did:ad:` from creation — no `_new:` placeholder.
      let genesisCertB64: string | undefined;
      let newSubject: string;

      if (useDid) {
        const minted = await this.mintCertDid(parent, driveVal);
        newSubject = minted.did;
        genesisCertB64 = minted.certB64;
      } else {
        newSubject = this.createHTTPSubject(parent);
      }

      const resource = this.getResourceLoading(newSubject, {
        newResource: true,
      });

      if (genesisCertB64) {
        await resource.set(
          'https://atomicdata.dev/properties/genesis',
          genesisCertB64,
          false,
        );
        await resource.set(DRIVE_PROP, driveVal, false);
      }

      // All values are produced from trusted code (hashes, fixed property
      // URLs). Skip validation — it would otherwise fetch each property's
      // definition over HTTP, which fails for new properties not yet on
      // atomicdata.dev (e.g. blob).
      await resource.set(core.properties.isA, [server.classes.file], false);
      await resource.set(core.properties.parent, parent, false);
      await resource.set(server.properties.filename, name, false);
      await resource.set(server.properties.filesize, blob.size, false);
      await resource.set(server.properties.mimetype, blob.type, false);
      await resource.set(INTERNAL_ID, hash, false);
      await resource.set(BLOB, `did:ad:blob:${hash}`, false);
      await resource.set(
        server.properties.downloadUrl,
        `${this.getServerUrl()}/download/files/${hash}`,
        false,
      );

      // Sign the genesis commit locally (its subject is already the cert DID,
      // so `signChanges` derives nothing), then STASH it on the resource —
      // mirrors `Store.newResource`. `save()` below moves the stashed genesis
      // into the outbox and drains it. (Stashing rather than enqueuing here
      // means a never-saved upload is never POSTed; here we always `save()`,
      // but the genesis MUST be stashed or `save()` has nothing to POST —
      // `signChanges` resets `commitBuilder.isGenesis`, so the genesis would
      // otherwise be silently dropped.)
      if (useDid) {
        const genesis = await resource.signChanges(this.getAgent()!);
        resource.stashGenesis(genesis);
      }

      await resource.save();
      // The blob bytes are pushed to the server from the outbox drain
      // (via `Store.maybePushBlobForResource`) — that path covers both the
      // online-save case here AND the offline → reconnect retry path, where
      // `syncDirtyResources` flushes the queued commits and the same hook
      // fires after the deferred push lands.
      await this.notifyResourceManuallyCreated(resource);
      createdSubjects.push(resource.subject);
    }

    return createdSubjects;
  }

  /** Posts a Commit to some endpoint. Returns the Commit created by the server. */
  public async postCommit(commit: Commit, endpoint: string): Promise<Commit> {
    const close = perfSpan('store.postCommit', {
      genesis: !!commit.isGenesis,
    });

    try {
      const created = await this.sendCommit(commit, endpoint);
      close('ok');
      this.pushCommitLog(
        this.buildCommitLogEntry(commit, 'outgoing', 'sent', {
          commitId: commitIdOf(created),
        }),
      );

      return created;
    } catch (e) {
      const errMsg = e instanceof Error ? e.message : String(e);
      close({ err: errMsg });
      // Pass the error through `extras.error`; the derived commitId in
      // `buildCommitLogEntry` matches the prior `pending` entry so it
      // transitions in place rather than producing a second row.
      this.pushCommitLog(
        this.buildCommitLogEntry(commit, 'outgoing', 'failed', {
          error: errMsg,
        }),
      );
      throw e;
    }
  }

  /**
   * Prefer the WebSocket transport when the matching origin's WS is open and
   * authenticated; fall back to HTTP `client.postCommit` otherwise. The WS
   * round-trip lets the server tag the resulting `DbEvent`s with the
   * originating connection id and suppress broadcasting them back — closes
   * the "client gets its own commit as a subscription push" echo. HTTP
   * commits still work; they just always reach every subscriber.
   */
  private async sendCommit(commit: Commit, endpoint: string): Promise<Commit> {
    const ws = this.getWebSocketForEndpoint(endpoint);

    if (ws && ws.readyState === WebSocket.OPEN) {
      try {
        return await ws.postCommit(commit);
      } catch (e) {
        // Fall through to HTTP — a broken WS shouldn't block saves while
        // the reconnect timer is still backing off. The WS error already
        // surfaced in console; the HTTP path will produce its own.
        console.warn('[Store.postCommit] WS path failed, using HTTP:', e);
      }
    }

    return this.client.postCommit(commit, endpoint);
  }

  private getWebSocketForEndpoint(endpoint: string): WSClient | undefined {
    try {
      const origin = new URL(endpoint).origin;

      return this.webSockets.get(origin);
    } catch {
      return this.getDefaultWebSocket();
    }
  }

  /**
   * Returns the ancestry of a resource, starting with the resource itself.
   */
  public async getResourceAncestry(resource: Resource): Promise<string[]> {
    const ancestry: string[] = [resource.subject];

    let lastAncestor: string = resource.get(core.properties.parent) as string;

    if (lastAncestor) {
      ancestry.push(lastAncestor);
    }

    while (lastAncestor) {
      const lastResource = await this.getResource(lastAncestor);

      if (lastResource) {
        lastAncestor = lastResource.get(core.properties.parent) as string;

        if (lastAncestor === undefined) {
          break;
        }

        if (ancestry.includes(lastAncestor)) {
          throw new Error(
            `Resource ${resource.subject} ancestry is cyclical. ${lastAncestor} is already in the ancestry}`,
          );
        }

        ancestry.push(lastAncestor);
      }
    }

    return ancestry;
  }

  /**
   * Returns a list of resources currently in the store which pass the given filter function.
   * This is a client-side filter, and does not query the server.
   */
  public clientSideQuery(filter: (resource: Resource) => boolean): Resource[] {
    return Array.from(this.resources.values()).filter(filter);
  }

  /**
   * @Internal
   * Add the resource to a batch that is saved when the parent is saved. Only gets saved when the parent is new.
   */
  public batchResource(subject: string) {
    const resource = this._resources.get(subject);

    if (!resource) {
      throw new Error(
        `Resource ${subject} can not be saved because it is not in the store.`,
      );
    }

    const parent = resource.get(core.properties.parent);

    if (parent === undefined) {
      throw new Error(
        `Resource ${subject} can not be added to a batch because it's missing a parent.`,
      );
    }

    if (!this.batchedResources.has(parent)) {
      this.batchedResources.set(parent, new Set([subject]));
    } else {
      this.batchedResources.get(parent)!.add(subject);
    }
  }

  /**
   * @Internal
   * Saves all resources that are in a batch for a parent.
   */
  public async saveBatchForParent(subject: string) {
    const subjects = this.batchedResources.get(subject);

    if (!subjects) return;

    for (const resourceSubject of subjects) {
      const resource = this._resources.get(resourceSubject);

      await resource?.save();
    }

    this.batchedResources.delete(subject);
  }

  public async importJsonAD(
    jsonADString: string,
    options: ImportJsonADOptions,
  ): Promise<void> {
    const url = new URL(endpoints.import, this.serverUrl);
    url.searchParams.set('parent', options.parent);
    url.searchParams.set(
      'overwrite-outside',
      options.overwriteOutside ? 'true' : 'false',
    );

    const result = await this.postToServer(url.toString(), jsonADString);

    if (result.error) {
      throw result.error;
    }
  }

  /**
   * Make sure the given tree of resources are available in the store.
   * This is useful in situations where you need certain resources to be available before rendering a page.
   * For example when rendering on a server that does not wait for resources to be fully available.
   *
   * **Example**:
   * ```ts
   * await store.preloadResourceTree('https://my-website.com', {
   *  [myWebsite.properties.projects]: {
   *    [myWebsite.properties.collaborators]: {
   *      [core.properties.image]: true,
   *    },
   *    [core.properties.image]: true,
   *  },
   * });
   * ```
   */
  public async preloadResourceTree(
    subject: string,
    treeTemplate: ResourceTreeTemplate,
  ): Promise<void> {
    const loadResourceTreeInner = async (
      resource: Resource,
      tree: ResourceTreeTemplate,
    ) => {
      const promises: Promise<unknown>[] = [];

      for (const [property, branch] of Object.entries(tree)) {
        await this.getResource(property);
        const values = normalizeToArray(resource.get(property));
        const resources = await Promise.all(
          values.map(value => this.getResource(value)),
        );

        if (typeof branch === 'boolean') {
          continue;
        }

        for (const res of resources) {
          promises.push(loadResourceTreeInner(res, branch));
        }
      }

      return Promise.allSettled(promises.flat());
    };

    const resource = await this.getResource(subject);

    await loadResourceTreeInner(resource, treeTemplate);
  }

  /** Creates a random HTTP subject under the given parent URL. */
  private createHTTPSubject(parentSubject: string): string {
    return `${parentSubject}/${this.randomPart()}`;
  }

  private randomPart(): string {
    return ulid().toLowerCase();
  }

  private async findAvailableSubject(
    path: string,
    parent: string,
    firstTry = true,
  ): Promise<string> {
    let url = new URL(`${parent}/${path}`).toString();

    if (!firstTry) {
      const randomPart = this.randomPart();
      url += `-${randomPart}`;
    }

    const taken = await this.checkSubjectTaken(url);

    if (taken) {
      return this.findAvailableSubject(path, parent, false);
    }

    return url;
  }

  /** Per-subject snapshot wrappers for `useSyncExternalStore`. Each
   * snapshot's `resource` field is a fresh Proxy of the cached
   * Resource, so `R.foo` reads stay reactive (Resource is mutated
   * in place, but the Proxy identity changes per notify). The
   * snapshot tuple identity changes too, which is what
   * `useSyncExternalStore` checks. */
  private snapshots = new Map<string, { resource: Resource }>();

  /** Subject → content stamp of the last state written to the local DB, so
   *  `addResource` can skip re-writing state that is already there. Entries are
   *  dropped by `removeResource` and by a failed write. */
  private lastPersistedStamp = new Map<string, number>();

  public getResourceSnapshot(
    subject: string,
    opts: FetchOpts = {},
  ): { resource: Resource } {
    const r = this.getResourceLoading(subject, opts);
    const key = this.normalizeSubject(r.subject);
    let snap = this.snapshots.get(key);

    if (!snap || snap.resource !== r.__internalObject) {
      snap = { resource: r.__internalObject };
      this.snapshots.set(key, snap);
    }

    return snap;
  }

  /**
   * Public re-notify for callers that mutated a Resource OUT OF BAND of a
   * commit / fetch and need `useSyncExternalStore` consumers to re-render —
   * specifically applying a buffered Loro snapshot once WASM finishes loading
   * (the snapshot arrived before Loro was ready). Bumps the snapshot tuple so
   * `useResource` / `useValue` re-render and observe `loading=false` + the
   * now-materialized props.
   */
  public notifyResourceUpdated(resource: Resource): void {
    void this.notify(resource);
  }

  /**
   * Resolves `true` as soon as the server WS is connected, or `false` if it
   * isn't within `timeoutMs`. Resolves immediately when already connected. Used
   * to avoid flashing an "offline" error during the brief disconnect→reconnect
   * window of a page reload.
   */
  /**
   * Resolve `true` once the store reports a live server connection, or
   * `false` after `timeoutMs`. The one implementation of a wait that used to
   * exist four times over (here, in `Collection`, and in two data-browser
   * helpers), each with its own timeout and return shape.
   */
  public waitForServerConnected(timeoutMs: number): Promise<boolean> {
    if (this._serverConnected) return Promise.resolve(true);

    return new Promise<boolean>(resolve => {
      let unsub: (() => void) | undefined;
      const timer = setTimeout(() => {
        unsub?.();
        resolve(false);
      }, timeoutMs);

      unsub = this.on(StoreEvents.ConnectionChanged, connected => {
        if (connected) {
          clearTimeout(timer);
          unsub?.();
          resolve(true);
        }
      });
    });
  }

  /** Lets subscribers know that a resource has been changed. */
  private async notify(resource: Resource): Promise<void> {
    // Bump snapshot tuple identity so `useSyncExternalStore` consumers
    // re-render. The Resource itself is mutated in place, but a fresh
    // outer `{resource}` object is `!== ` the previous one, which is
    // all `Object.is` needs.
    const key = this.normalizeSubject(resource.subject);
    this.snapshots.set(key, { resource: resource.__internalObject });

    this.eventManager.emit(StoreEvents.ResourceUpdated, resource);

    const callbacks = this.subscribers.get(key);
    if (!callbacks) return;
    Promise.allSettled(callbacks.map(async cb => cb(resource)));
  }
}

const normalizeToArray = (value: JSONValue): string[] => {
  if (typeof value === 'string') {
    return [value];
  }

  if (Array.isArray(value)) {
    return value as string[];
  }

  return [];
};

/**
 * A Property represents a relationship between a Subject and its Value.
 * https://atomicdata.dev/classes/Property
 */
export interface Property {
  subject: string;
  /** https://atomicdata.dev/properties/datatype */
  datatype: Datatype;
  /** https://atomicdata.dev/properties/shortname */
  shortname: string;
  /** https://atomicdata.dev/properties/description */
  description: string;
  /** https://atomicdata.dev/properties/classType */
  classType?: string;
  /** If the Property cannot be found or parsed, this will contain the error */
  error?: Error;
  /** https://atomicdata.dev/properties/isDynamic */
  isDynamic?: boolean;
  /** When the Property is still awaiting a server response */
  loading?: boolean;
  allowsOnly?: string[];
}

export interface FetchOpts {
  /**
   * If this is true, incomplete resources will not be automatically fetched.
   * Incomplete resources are faster to process server-side, but they need to be
   * fetched again when all properties are needed.
   */
  allowIncomplete?: boolean;
  /** Do not fetch over WebSockets, always fetch over HTTP(S) */
  noWebSocket?: boolean;
  /**
   * If true, will not send a request to a server - it will simply create a new
   * local resource.
   */
  newResource?: boolean;
}

/** Convert a Resource to a JSON-AD string for storage in the WASM DB. */
function resourceToJsonAd(resource: Resource): string | null {
  const obj = resource.toObject({ includeBinary: false });

  return obj ? JSON.stringify(obj) : null;
}

/**
 * Cheap 53-bit content stamp over exactly what a local-DB write persists: the
 * JSON-AD and the Loro snapshot. Used only to skip re-writing state identical
 * to the last write for that subject (see `addResource`), so the cost has to
 * stay far below the ~9ms write it saves — this is two xor-multiply passes over
 * a few KB, i.e. microseconds.
 *
 * Not a security hash. The failure mode of a collision is one skipped cache
 * write, repaired by the next real change or by re-fetching from the server.
 */
function hashPersistedState(jsonAd: string, snapshot?: Uint8Array): number {
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;

  for (let i = 0; i < jsonAd.length; i++) {
    const ch = jsonAd.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }

  if (snapshot) {
    // Length first, so two snapshots differing only in trailing bytes can't
    // land on the same stamp through the byte loop alone.
    h1 = Math.imul(h1 ^ snapshot.byteLength, 2654435761);

    for (let i = 0; i < snapshot.length; i++) {
      const b = snapshot[i];
      h1 = Math.imul(h1 ^ b, 2654435761);
      h2 = Math.imul(h2 ^ b, 1597334677);
    }
  }

  h1 =
    Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^
    Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 =
    Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^
    Math.imul(h1 ^ (h1 >>> 13), 3266489909);

  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}
