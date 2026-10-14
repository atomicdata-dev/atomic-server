import {
  serverOrigin as normalizeServerOrigin,
  parseDriveRoute,
  type DriveRoute,
} from './drive-routes.js';
import type { ScheduledSave, ResourceSaveState } from './scheduled-save.js';
import { SaveStatusCoordinator } from './save-status-coordinator.js';
import { verifyLocalDriveCopy } from './local-drive-copy.js';
import {
  encodeCommit as encodePeerCommit,
  encodeEphemeral as encodePeerEphemeral,
  decodeEphemeral as decodePeerEphemeral,
  EphemeralKind as PeerEphemeralKind,
} from './ws-v2.js';
import { serializeDeterministically as serializePeerCommit } from './commit.js';
import { taskSchema } from './task-schema.js';
import {
  mergeHistoryAttributions,
  parseHistoryAttribution,
  type HistoryAttribution,
} from './history-attribution.js';
import { ulid } from 'ulidx';
import type { Agent } from './agent.js';
import {
  canonicalDriveHash,
  canonicalDriveHashV2,
} from './canonical-drive-hash.js';
import {
  removeCookieAuthentication,
  setCookieAuthentication,
  signRequest,
} from './authentication.js';
import { Client, isOwnServerUrl, type FileOrFileLike } from './client.js';
import {
  CommitBuilder,
  commitIdOf,
  isCommitSubject,
  type Commit,
} from './commit.js';
import { datatypeFromUrl, type Datatype } from './datatypes.js';
import {
  AtomicError,
  RequestCancelledError,
  ServerRestartError,
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
import { notifications } from './ontologies/notifications.js';
import { conversations } from './ontologies/conversations.js';
import { forms } from './ontologies/forms.js';
import type { OptionalClass, UnknownClass } from './ontology.js';
import { JSONADParser } from './parse.js';
import {
  Resource,
  unknownSubject,
  type ResourceReadState,
} from './resource.js';
import {
  type SearchOpts,
  type SemanticSearchOpts,
  buildSearchSubject,
  buildSemanticSearchSubject,
} from './search.js';
import { stringToSlug } from './stringToSlug.js';
import { bytesToHex, hexToBytes, type JSONValue } from './value.js';
import { WSClient } from './websockets.js';
import { LoroLoader } from './loro-loader.js';
import { withDeadline } from './withDeadline.js';

/** How long a connected store waits on its local database before asking the server. */
const LOCAL_READ_DEADLINE_MS = 1_000;
/**
 * The same deadline while a drive sync runs. The sync keeps the local
 * database's worker busy writing what the server sends, so a read queues
 * behind those writes for most of the second above, and a device opening a
 * large drive painted each sidebar item a second late. The server answers in
 * tens of milliseconds, so it is asked almost at once.
 */
const LOCAL_READ_DEADLINE_DURING_SYNC_MS = 150;
import { BLOB, endpoints, INTERNAL_ID } from './urls.js';
import { SERVER_MANAGED_PROPS } from './server-managed-props.js';
import { initOntologies } from './ontologies/index.js';
import { decodeB64, encodeB64, encodeB64Url } from './base64.js';
import {
  canonicalizeScheme,
  isAgentSubject,
  agentPublicKey,
  isAtomicIdentifier,
  isBlobSubject,
  isLensSubject,
  isPropertySubject,
  commitSubject,
  blobSubject,
} from './subject.js';
import { propertyId } from './property-identity.js';
import {
  LensIndex,
  lensId,
  parseTransform,
  readTransformValue,
  verifyLensId,
} from './lens.js';
import {
  encodeGenesisCert,
  GENESIS_VERSION_V1,
  privateDriveCert,
  subjectForSignature,
  type GenesisCert,
} from './genesis.js';
import type {
  ClientDbWorker,
  ClientDbOutboxWrite,
  ClientDbQueryOpts,
  ClientDbQueryResult,
} from './client-db.js';
import { DrivePresenceManager } from './presence.js';
import { perfMark, perfSpan } from './perf-trace.js';
import {
  LocalOutbox,
  isPendingDepsCommitErrorMessage,
  isOutboxDatabase,
  isSettledDestroyErrorMessage,
  isTerminalCommitError,
  isUnrecoverableCommitError,
  isBenignTerminalCommitError,
  isMissingParentMessage,
  isNotEnrolledMessage,
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

/** The public key an agent subject names, whatever its spelling. */
function agentKeyOf(subject: string): string {
  return (agentPublicKey(subject) ?? subject)
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/** Callback called when the stores agent changes */
type AgentCallback = (agent: Agent | undefined) => void;
type ErrorCallback = (e: Error) => void;
type ConnectionStateCallback = (connected: boolean) => void;
type SyncStatusCallback = (status: StoreSyncStatus) => void;
type CommitLogCallback = (entries: CommitLogEntry[]) => void;

export interface RepeatedCommitFailure {
  subject: string;
  error: Error;
  failures: number;
  /** Origin the writes are sent to. */
  server: string;
  /** Drive the store was on when the write kept failing. */
  drive?: string;
  /** Milliseconds since the write first became dirty. */
  ageMs: number;
  /** Writes still waiting in the outbox, this one included. */
  outboxSize: number;
  /** Whether the websocket to the server was up. */
  connected: boolean;
  /** The write creates the resource, so it can fail for its parent. */
  isGenesis: boolean;
  /** A finished drive resync already re-armed this write once. */
  rearmedAfterResync: boolean;
}

type RepeatedCommitFailureCallback = (failure: RepeatedCommitFailure) => void;

/**
 * Lets the app deal with a drive the server refuses as "not enrolled" before
 * the store reports it. `drive` is the drive the refusal names. Resolve `true`
 * when the drive was handled (for instance switched to browser-only), so
 * there is nothing left to report. Resolve `false`, or reject, to leave the
 * report as it is. Called at most once per drive per session.
 */
export type RefusedDriveHandler = (
  drive: string,
  message: string,
) => boolean | Promise<boolean>;

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
  /** Known datatypes for propVals that should not fetch Property metadata. */
  propDatatypes?: Record<string, Datatype>;
  /** Set to true if the resource should have a DID as subject. Defaults to `true` for `did:ad` agents, otherwise `false`. */
  did?: boolean;
  /** When set, the resource is minted from this cert (deterministic DID)
   *  instead of a random-nonce certificate. */
  genesisCert?: GenesisCert;
  /** Seed a body or other state before the first save signs its genesis. */
  deferGenesis?: boolean;
  /**
   * Create a Property under its content-addressed ID, `atomic:prop:{blake3}`,
   * derived from `parent`, `propVals[shortname]` and `propVals[datatype]`
   * (see docs/src/schema/property-identity.md). No genesis cert is minted; the
   * resource is still signed as a genesis commit. Returns the existing Property
   * when the store already has it.
   *
   * This is an explicit opt-in rather than inferred from `isA`: the ID is
   * immutable and the three inputs must be known up front, so a caller that
   * builds a Property draft in steps must not silently get a hashed subject.
   */
  contentAddressedProperty?: boolean;
  /**
   * Create a Lens under its content-addressed ID, `atomic:lens:{blake3}`,
   * derived from `propVals[lensFrom]`, `propVals[lensTo]` and
   * `propVals[lensTransform]` (see docs/src/schema/lenses.md). Returns the
   * existing Lens when the store already has it.
   */
  contentAddressedLens?: boolean;
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
  /** Native shells have no ClientDb, so a disconnected node cannot save edits. */
  requireOnlineWrites?: boolean;
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
  /** subject → counter array (indexed by `peers`). Empty for a sparse state. */
  resources: Record<string, number[]>;
  /** Sparse form (`hashVersion` 2): subject → peer → counter, non-zero
   *  counters only. Set instead of `peers` and `resources`. */
  vvs?: Record<string, Record<string, number>>;
  /** Which drive hash `driveHash` is: 1 (dense) or 2 (sparse). */
  hashVersion?: 1 | 2;
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
  DriveRouteChanged = 'drive-route-changed',
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
  /**
   * A queued write has failed several drains in a row and is still being
   * retried. Meant for error reporting, not for the user.
   */
  CommitRepeatedlyFailing = 'commit-repeatedly-failing',
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
  /** Keep a newly created drive local until explicit hosting enrollment. */
  localOnly?: boolean;
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
  [StoreEvents.DriveRouteChanged]: DriveCallback;
  [StoreEvents.ConnectionChanged]: ConnectionStateCallback;
  [StoreEvents.SyncStatusChanged]: SyncStatusCallback;
  [StoreEvents.CommitLogChanged]: CommitLogCallback;
  [StoreEvents.ResourceUpdated]: ResourceCallback;
  [StoreEvents.Error]: ErrorCallback;
  [StoreEvents.CommitRepeatedlyFailing]: RepeatedCommitFailureCallback;
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
  | 'offline-replay'
  | 'peer-sync';

interface IncomingChangeContext {
  subject: string;
  /** `did:ad:commit:<sig>` — used for echo dedup on the loroBytes path. */
  commitId?: string;
  source: ChangeSource;
  receivedAt?: number;
  forceNotify?: boolean;
}

/** Exactly one representation. Bytes carry their own snapshot/update format;
 * transports cannot choose to discard an existing causal document. */
export type IncomingChange = IncomingChangeContext &
  (
    | {
        resource: Resource;
        loroBytes?: never;
        /** @deprecated Ingress derives replacement from local causal state. */
        replaceLoroDocsFromRemote?: boolean;
      }
    | {
        loroBytes: Uint8Array;
        resource?: never;
        /** @deprecated Binary ingress derives replacement from local causal state. */
        replaceLoroDocsFromRemote?: boolean;
      }
  );

/** Returns True if the client has WebSocket support */
const supportsWebSockets = () => typeof WebSocket !== 'undefined';
/** Subjects per GET_MANY frame; keeps one answer well under a single large frame. */
const GET_MANY_CHUNK = 200;
/** Subjects per local-database read. The worker walks the list serially and a
 *  follower tab's read also crosses a BroadcastChannel hop with a fixed
 *  timeout, so one very large batch is split instead of sent whole. */
const LOCAL_HYDRATION_CHUNK = GET_MANY_CHUNK;

/**
 * Whether a failed direct fetch of a foreign subject is worth retrying
 * through the own server's `/path` proxy: the origin could not be reached
 * (network, DNS, CORS) or failed itself (5xx). A 404 or 401 is an answer
 * about the resource, which the proxy would only repeat.
 */
function isProxyWorthyError(error?: Error): boolean {
  if (!error) return false;

  return (
    isTransportError(error) ||
    (error instanceof AtomicError && error.type === ErrorType.Server)
  );
}

/**
 * Subjects of the vocabulary every host carries in its own store.
 *
 * They are `atomicdata.dev` URLs that name a shape, not a deployment: a fixed,
 * tiny set that an installed server answers from its own data. Reaching them
 * over the public catalog would make an offline or firewalled install depend
 * on a website, so {@link Store.fetchResourceFromServer} routes them through
 * the host's `/path` proxy, and {@link Store.fetchResourceWithLocalFallback}
 * asks the host for them directly rather than local-first.
 */
export function isEmbeddedVocabulary(subject: string): boolean {
  return (
    embeddedVocabulary.has(subject) ||
    subject === 'https://atomicdata.dev/task/v1'
  );
}

const embeddedVocabulary = new Set<string>([
  ...Object.values(taskSchema.properties),
  ...Object.values(taskSchema.tags),
  // These classes ship in lib/defaults/plugins.json on every host. Their
  // public atomicdata.dev URLs are not published on the catalog yet.
  server.classes.plugin,
  server.classes.release,
  server.classes.installation,
  server.classes.listing,
  core.properties.importBaseline,
  core.properties.importResolution,
  core.properties.importReferenceReview,
  // lib/defaults/notifications.json, likewise not on the catalog yet.
  ...Object.values(notifications.classes),
  ...Object.values(notifications.properties),
  // lib/defaults/conversations.json, likewise.
  ...Object.values(conversations.classes),
  ...Object.values(conversations.properties),
  // lib/defaults/forms.json, likewise not on the catalog yet.
  ...Object.values(forms.classes),
  ...Object.values(forms.properties),
]);

/** One caller's pending local-database read; see `Store.hydrateFromLocalDb`. */
interface LocalHydrationRequest {
  promise: Promise<boolean | undefined>;
  resolve: (hydrated: boolean | undefined) => void;
  reject: (error: unknown) => void;
}

/**
 * How long resource fallback and collection reads wait for the app's
 * expected local database to attach. It is a boot-time event — `initClientDb` derives a
 * database name and unwraps a key first. Waiting avoids premature failures
 * and redundant server queries without blocking forever. Reads that time out
 * are reconsidered on attachment. Only announced databases are awaited (see
 * `Store.expectClientDb`).
 */
const CLIENT_DB_ATTACH_GRACE = 5000;

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
/** How many snapshots one slice of the version-vector read covers. The worker
 *  answers reads in order, so this is the longest a screen's read can wait
 *  behind the scan (about 40 ms at 500 on a laptop). */
const VV_SLICE = 500;

/** Reads a drive's version vectors in slices, so reads queued on the database
 *  worker run between them. One call for 10k resources held the worker for
 *  about 0.8 s and the screen's first reads waited that long. */
async function readDriveVersionVectors(
  db: ClientDbWorker,
  drive: string,
): Promise<Record<string, Record<string, number>>> {
  if (!db.getDriveSubjects || !db.getVersionVectorsForSubjects) {
    return db.getVersionVectorsForDrive(drive);
  }

  const subjects = await db.getDriveSubjects(drive);

  if (subjects.length <= VV_SLICE) {
    return db.getVersionVectorsForDrive(drive);
  }

  const all: Record<string, Record<string, number>> = {};

  for (let i = 0; i < subjects.length; i += VV_SLICE) {
    Object.assign(
      all,
      await db.getVersionVectorsForSubjects(subjects.slice(i, i + VV_SLICE)),
    );
  }

  return all;
}

export class Store {
  /** A list of all functions that need to be called when a certain resource is updated */
  public subscribers: Map<string, ResourceCallback[]>;
  /** Subjects held live on their own, not via the open drive: see
   *  {@link Store.subscribeLive}. Counted, so each holder can let go. */
  public liveSubjects: Map<string, number> = new Map();
  private loroSyncSubscribers: Map<string, LoroSyncCallback[]> = new Map();
  private loroEphemeralSubscribers: Map<string, LoroEphemeralCallback[]> =
    new Map();
  private presenceSubscribers: Map<string, PresenceCallback[]> = new Map();
  /** One presence manager per drive; managers remove themselves when
   *  their last subscriber leaves. */
  private presenceManagers: Map<string, DrivePresenceManager> = new Map();
  /** This tab's presence session, shared by every channel it announces in. */
  public readonly presenceSessionId: string = crypto.randomUUID();
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

  /** Foreign origins whose direct fetch failed while the own server's
   *  `/path` proxy answered. Later fetches from them go straight to the
   *  proxy for the rest of the session: one failed request per origin, not
   *  one per term. */
  private _proxiedOrigins: Set<string> = new Set();

  /** Subjects with a gap-recovery fetch in flight. A delta that cannot apply
   *  triggers one full-state fetch; this stops a burst of unappliable deltas
   *  for the same subject from firing one fetch each. */
  private _gapRecoveries: Set<string> = new Set();

  /** The updates that could not apply, per subject under recovery, to be
   *  replayed once a base is in place. */
  private _gapUpdates: Map<string, Uint8Array[]> = new Map();

  /**
   * Subjects whose in-memory Loro doc was rebuilt from JSON-AD alone, by a
   * local query that returns no snapshots. Such a doc holds the values but
   * none of the history: its ops are new, by a peer nobody else knows, so no
   * delta from the server or another tab can apply to it (#1905).
   *
   * Two consequences. It must not be written back to the local database,
   * where it would replace the real history the query read the values from.
   * And a delta that arrives for it is replayed on that local history before
   * anything asks the server.
   */
  private _withoutLoroHistory: Set<string> = new Set();

  /** Agent subjects already re-checked against the server this session — see
   *  the agent branch in {@link fetchResourceWithLocalFallback}. */
  private _revalidatedAgents: Set<string> = new Set();

  /**
   * Subjects this store has destroyed — the in-memory half of the tombstone
   * {@link removeResource} writes to the local database.
   *
   * A destroy is not instantaneous for everyone who can answer a query. The
   * server's `/query` races the local index in `Collection.fetchPage`, and an
   * answer computed before the destroy landed can arrive after it. Until this
   * set existed, "this subject is deleted" was only ever held by
   * {@link hasPendingDestroy} — an outbox entry that is dropped the moment the
   * server acks — so every consumer of a live query kept its own copy:
   * `Collection` had `_removedSubjects`, `useChildren` had a `removedRef`,
   * each scoped to one instance. A consumer created after the delete (a folder
   * re-expanded, a second view on the same query) had no memory of it and put
   * the row back, and rendering that row asks the store for the resource,
   * which re-creates the entry the destroy had just removed and renders it as
   * an error.
   *
   * One fact, in one place, that every one of those paths reads instead.
   * Insertion-ordered and capped: the oldest entries are the least likely to
   * still be contradicted by an answer in flight, and an unbounded set in a
   * long-lived tab is its own bug.
   */
  private _destroyed: Set<string> = new Set();

  /** How many destroyed subjects {@link _destroyed} keeps. */
  private static readonly DESTROYED_LIMIT = 10_000;

  /** Current Agent, used for signing commits. Is required for posting things. */
  private agent?: Agent;
  private identityGeneration = 0;
  private liveSubscriptionGeneration = 0;
  private routingGeneration = 0;

  /** Fences delayed route discovery, including drive/server A → B → A. */
  public getRoutingGeneration(): number {
    return this.routingGeneration;
  }

  /** Local session revision. Fences delayed work, including agent A → B → A. */
  public getIdentityGeneration(): number {
    return this.identityGeneration;
  }
  /** Mapped from origin to websocket */
  private webSockets: Map<string, WSClient>;

  /** Optional WASM-backed client-side database running in a Web Worker. */
  private clientDb?: ClientDbWorker;
  /** Whether one is on its way — see {@link expectClientDb}. */
  private clientDbExpected = false;
  /** Callbacks parked in {@link waitForClientDb} until the attach happens. */
  private clientDbWaiters = new Set<(attached: boolean) => void>();
  /** Reads whose attachment grace expired; retry against the eventual database. */
  private localReadsAwaitingAttach = new Map<string, Resource>();
  /**
   * Single durable queue replacing the old `dirtyForSync` Set +
   * `atomic.dirtyForSync` + `atomic.offline.<subject>` quartet.
   * Constructor callback re-emits `SyncStatusChanged` so subscribers
   * see queue-size changes without a manual `markDirtyForSync` call.
   */
  public readonly outbox: LocalOutbox = new LocalOutbox(
    () => {
      this.emitSyncStatus();
      this.scheduleOutboxDrain();
    },
    subject => this.pinSubjectRoute(subject),
  );
  /** Only restored queues need legacy genesis baseline repair. Online saves
   * must remain independent of local database readiness. */
  private restoredOutboxEntries = new WeakSet<OutboxEntry>();
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
    if (
      ![...this.serverConnections.values()].some(s => s.connected) &&
      !this._serverConnected
    )
      return;
    if (this.outbox.size === 0) return;
    if (!this.getAgent()) return;
    // Wake when the soonest entry is due (0 = due now), honoring per-entry
    // backoff. Always (re)schedule to the soonest time rather than bailing on
    // an existing timer: a fresh edit (due now) must not wait behind a failing
    // entry's backoff window, and a drain that skipped only-backing-off entries
    // must still re-arm so they retry when due.
    const dueAt = this.outbox.nextDueAt(entry =>
      this.isServerConnectedFor(entry.subject),
    );

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
      if (
        ![...this.serverConnections.values()].some(s => s.connected) &&
        !this._serverConnected
      )
        return;
      void this.syncDirtyResources().catch(() => undefined);
    }, delay);
  }
  /**
   * Whether the Store has an active connection to the server.
   * Driven by WebSocket open/close events. When false, commits are stored
   * locally and synced when the connection is restored.
   */
  /** Pages of unsynced drives' collections the server has answered. Its
   * members were written to the local DB as they loaded and live updates keep
   * it current while connected, so the local answer is whole from then on.
   * Cleared on reconnect, as what happened during a drop never arrived. Lives
   * here so `collection.ts` needs no runtime import of the store. */
  readonly collectionPagesAnsweredByServer = new Set<string>();
  private _serverConnected = false;
  private _serverConnectionError: string | undefined;
  private _driveSyncInProgress = false;
  private _driveSyncPulling = false;
  private activeDriveSyncs = new Map<string, boolean>();
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
   * Commit-log entry id → that commit's `loroUpdate`, kept only while the
   * entry is in the (capped) log, so {@link getCommitPropertySummaries} can
   * diff it when the Sync page asks.
   */
  private _commitLogUpdates = new Map<string, Uint8Array>();
  /** Entry id → property summaries already computed for it. */
  private _commitLogSummaries = new Map<
    string,
    CommitLogPropertySummary[] | undefined
  >();

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
  public readonly requireOnlineWrites: boolean;

  public constructor(opts: StoreOpts = {}) {
    this.requireOnlineWrites = opts.requireOnlineWrites ?? false;
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
          // Normalized on the way back in: an earlier build stored whatever
          // spelling the caller passed, and every reader looks with the
          // canonical form.
          this.localOnlyDrives = new Set(
            (JSON.parse(rawLocalOnly) as string[]).map(subject =>
              this.normalizeSubject(subject),
            ),
          );
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
    // The outbox lives in that database: until it attaches, the queue may be
    // missing entries only the database holds.
    this.outbox.expectDatabase();
    void this.bindOutboxDatabase();
  }

  /**
   * Move the current agent's outbox into the attached client database (see
   * `LocalOutbox.attachDatabase`), or settle for the localStorage queue when
   * none arrives or it cannot open. Safe to call repeatedly: the outbox
   * ignores a database it already holds, and a call that an identity change
   * or a newer database overtook stops.
   */
  private async bindOutboxDatabase(): Promise<void> {
    const agent = this.agent?.subject;
    const attached = await this.waitForClientDb(CLIENT_DB_ATTACH_GRACE);

    if (this.agent?.subject !== agent) return;

    const db = this.clientDb;

    if (!attached || !db || !isOutboxDatabase(db)) {
      // Nothing to move into (yet). A later `setClientDb` binds it then.
      if (!db) this.outbox.databaseUnavailable(agent);

      return;
    }

    const ready = await db.waitForInit();

    if (this.agent?.subject !== agent || this.clientDb !== db) return;

    if (!ready) {
      this.outbox.databaseUnavailable(agent);

      return;
    }

    const added = await this.outbox.attachDatabase(agent, db);

    for (const entry of added) this.hydrateCommitLogFromOutbox(entry);

    this.scheduleOutboxDrain();
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
  public waitForClientDb(
    timeoutMs: number = CLIENT_DB_ATTACH_GRACE,
  ): Promise<boolean> {
    if (this.clientDb) return Promise.resolve(true);
    if (!this.clientDbExpected) return Promise.resolve(false);

    return new Promise<boolean>(resolve => {
      const done = (attached: boolean) => {
        clearTimeout(timer);
        this.clientDbWaiters.delete(done);
        resolve(attached);
      };

      const timer = setTimeout(() => {
        this.clientDbWaiters.delete(done);
        resolve(false);
      }, timeoutMs);

      this.clientDbWaiters.add(done);
    });
  }

  /**
   * The local database announced with {@link expectClientDb} will not come
   * (its init failed). Stop treating a missing resource as possibly stored
   * locally: reads waiting for an attach are released and a real 404 no longer
   * waits out the attach grace period.
   */
  public clientDbUnavailable(): void {
    this.clientDbExpected = false;
    this.localReadsAwaitingAttach.clear();

    for (const waiter of [...this.clientDbWaiters]) waiter(false);
  }

  public setClientDb(clientDb: ClientDbWorker | undefined): void {
    // `initClientDb` calls this three times per page load (eager,
    // post-init, post-init-error) to refresh sync status. Only the
    // first call introduces a new worker; the others just want
    // `emitSyncStatus`.
    const attached = !!clientDb && clientDb !== this.clientDb;
    if (clientDb !== this.clientDb)
      this.collectionPagesAnsweredByServer.clear();
    this.clientDb = clientDb;

    if (isOutboxDatabase(clientDb)) this.outbox.expectDatabase();

    // Release fetches that started before the attach and would otherwise be
    // about to fail a resource this database can answer for.
    if (clientDb) {
      for (const waiter of [...this.clientDbWaiters]) waiter(true);
      void this.bindOutboxDatabase();
    }

    // Everything the server delivered while nothing was attached is in memory
    // only; this is the first moment it can be written.
    if (attached) {
      this.flushPendingClientDbWrites();
      const waiting = this.localReadsAwaitingAttach;
      this.localReadsAwaitingAttach = new Map();

      for (const [subject, resource] of waiting) {
        if (this.resources.get(subject) !== resource) continue;
        void this.hydrateFromLocalDb(subject).catch(error =>
          this.notifyError(error),
        );
      }
    }

    this.emitSyncStatus();
  }

  /**
   * The drive a resource belongs to — the root of its `parent` chain,
   * resolved against the in-memory store.
   */
  private driveOf(subject: string): string {
    let current = this.resolveSubject(subject);
    const seen = new Set<string>();

    for (let i = 0; i < 64; i++) {
      if (seen.has(current)) break;

      seen.add(current);
      const resource = this.resources.get(current);
      if (resource?.hasClasses(server.classes.drive)) return current;
      const declared = resource?.get('https://atomicdata.dev/properties/drive');
      if (typeof declared === 'string' && declared)
        return this.resolveSubject(declared);
      const parent = resource?.get(core.properties.parent);

      if (typeof parent !== 'string' || !parent || parent === current) {
        return this.resourceDrives.get(current) ?? current;
      }

      current = this.resolveSubject(parent);
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
   *  `save()` — registration is what routes saves away from the outbox.
   *
   *  Normalized on the way in, because every reader normalizes before it
   *  looks (`isLocalOnlyDrive`, `isLocalOnlySubject`): a caller's trailing
   *  slash or `did:ad:` spelling would otherwise store a key nothing finds. */
  public registerLocalOnlyDrive(drive: string): void {
    const normalized = this.normalizeSubject(drive);

    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(
        'atomic.localOnlyDrives',
        JSON.stringify([...new Set([...this.localOnlyDrives, normalized])]),
      );
    }

    this.localOnlyDrives.add(normalized);
  }

  private driveServers = new Map<string, string>();
  private routeRevisions = new Map<string, number>();
  private resourceOrigins = new Map<string, string>();
  private resourceDrives = new Map<string, string>();
  private serverConnections = new Map<
    string,
    { connected: boolean; error?: string }
  >();

  private routeStorageKey(): string {
    return `atomic.driveServers.${this.agent?.subject ?? '__anonymous__'}`;
  }

  private persistDriveServers(): void {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(
        this.routeStorageKey(),
        JSON.stringify([...this.driveServers]),
      );
    }
  }

  private loadDriveServers(): void {
    this.driveServers.clear();
    this.routeRevisions.clear();
    this.resourceOrigins.clear();
    this.resourceDrives.clear();
    this._syncedDrives.clear();
    this.activeDriveSyncs.clear();
    this.updateDriveSyncProgress();
    if (typeof localStorage === 'undefined') return;

    try {
      const entries: unknown = JSON.parse(
        localStorage.getItem(this.routeStorageKey()) ?? '[]',
      );
      if (!Array.isArray(entries)) return;

      for (const entry of entries) {
        if (!Array.isArray(entry)) continue;
        const route = parseDriveRoute({ drive: entry[0], server: entry[1] });
        if (route)
          this.driveServers.set(
            this.normalizeSubject(route.drive),
            route.server,
          );
      }
    } catch {
      /* A corrupt preference does not prevent local recovery. */
    }
  }

  /** Explicit placement, including a migration. Changing the default server
   * never moves a drive. The full origin is retained for vanity subdomains. */
  public setDriveServer(
    drive: string,
    url: string,
    { connect = true } = {},
  ): void {
    const key = this.resolveSubject(drive);
    const origin = normalizeServerOrigin(url);
    const previous = this.driveServers.get(key);

    if (previous !== origin) {
      this.driveServers.set(key, origin);
      this.routeRevisions.set(key, (this.routeRevisions.get(key) ?? 0) + 1);
      this.routingGeneration++;
      this._syncedDrives.delete(key);
      this.activeDriveSyncs.delete(key);
      this.updateDriveSyncProgress();
      this.collectionPagesAnsweredByServer.clear();

      // A receipt from the old destination cannot certify a migrated copy.
      if (previous) {
        for (const resource of this.resources.values()) {
          if (this.driveOf(resource.subject) === key) {
            this.rememberResourceOrigin(resource.subject, origin);
            resource.clearLoroSaveCursor();
          }
        }
      }

      this.persistDriveServers();

      // Old frames have no placement revision on the wire. Cancel that socket
      // at a migration boundary; other drives reconnect to their own origin.
      if (previous && this.webSockets.has(previous)) {
        this.webSockets.get(previous)!.close();
        this.webSockets.delete(previous);

        if (
          [...this.driveServers.values()].includes(previous) ||
          previous === this.serverUrl
        ) {
          this.openWebSocket(previous);
        }
      }

      this.eventManager.emit(StoreEvents.DriveRouteChanged, key);
    }

    if (
      connect &&
      supportsWebSockets() &&
      (typeof localStorage === 'undefined' ||
        localStorage.getItem('ws-disconnected') !== '1')
    ) {
      this.openWebSocket(origin);
    }

    this.emitSyncStatus();
    this.scheduleOutboxDrain();
  }

  /** An unset route uses the bootstrap server once, then keeps that choice.
   * Outbox entries carry it too, so a cold delete needs no surviving resource. */
  public routeForSubject(subject: string): DriveRoute {
    let key = this.resolveSubject(subject);

    if (/^https?:/.test(subject)) {
      const url = new URL(subject);
      const drive = url.searchParams.get('drive');
      if (drive) key = this.resolveSubject(drive);
    }

    const queued = this.outbox.getEntry(key)?.route;

    // Parentless Agent profiles are shared identities, not drive-owned rows.
    // Publish a fresh edit to the selected node; an already queued edit keeps
    // its captured destination. Access-key profiles with a parent stay scoped.
    if (
      isAgentSubject(key) &&
      !this.resources.get(key)?.get(core.properties.parent)
    ) {
      return {
        drive: key,
        server:
          queued?.server ??
          this.driveServers.get(
            this.normalizeSubject(this.getDrive() ?? this.serverUrl),
          ) ??
          this.serverUrl,
      };
    }

    const drive = this.normalizeSubject(queued?.drive ?? this.driveOf(key));
    const fallback = /^https?:/.test(subject)
      ? normalizeServerOrigin(subject)
      : this.serverUrl;
    // Query endpoints explicitly name their server. Their drive still supplies
    // the revision fence, including when a caller deliberately queries a replica.
    if (/^https?:/.test(subject) && new URL(subject).search)
      return { drive, server: fallback };

    return {
      drive,
      server:
        this.driveServers.get(drive) ??
        queued?.server ??
        this.resourceOrigins.get(key) ??
        fallback,
    };
  }

  public getServerUrlForSubject(subject?: string): string {
    return subject ? this.routeForSubject(subject).server : this.serverUrl;
  }

  /** Pure lookup used during Loro materialization, which cannot walk propvals
   * while those same propvals are being rebuilt. */
  public getResourceOrigin(subject: string): string | undefined {
    const key = this.normalizeSubject(subject);

    return (
      this.resourceOrigins.get(key) ??
      this.driveServers.get(key) ??
      (/^https?:/.test(subject)
        ? normalizeServerOrigin(subject)
        : this.serverUrl)
    );
  }

  public rememberResourceOrigin(subject: string, origin: string): void {
    this.resourceOrigins.set(
      this.normalizeSubject(subject),
      normalizeServerOrigin(origin),
    );
  }

  /** A scoped query establishes ownership even before a member is loaded. */
  public rememberResourceDrive(subject: string, drive: string): void {
    this.resourceDrives.set(
      this.resolveSubject(subject),
      this.resolveSubject(drive),
    );
  }

  public learnServerResource(
    resource: Resource,
    origin: string,
    alias?: string,
  ): void {
    if (resource.error) return;
    const subject = this.normalizeSubject(resource.subject);
    this.rememberResourceOrigin(subject, origin);
    if (alias && this.normalizeSubject(alias) !== subject)
      this.aliases.set(this.normalizeSubject(alias), subject);
    const declared = resource.get('https://atomicdata.dev/properties/drive');
    const drive = resource.hasClasses(server.classes.drive)
      ? subject
      : typeof declared === 'string'
        ? this.normalizeSubject(declared)
        : undefined;

    if (!resource.error && drive && !this.driveServers.has(drive)) {
      this.driveServers.set(drive, origin);
      this.persistDriveServers();
    }
  }

  public acceptsServerResource(
    subject: string,
    origin: string,
    bytes?: Uint8Array,
  ): boolean {
    let drive = this.driveOf(subject);
    let expected = this.driveServers.get(drive);

    if (!expected && bytes && LoroLoader.isLoaded()) {
      const doc = new LoroLoader.Loro.LoroDoc();

      try {
        doc.import(bytes);
        const declared = doc
          .getMap('properties')
          .get('https://atomicdata.dev/properties/drive');

        if (typeof declared === 'string') {
          drive = this.normalizeSubject(declared);
          expected = this.driveServers.get(drive);
        }
      } catch {
        /* A delta may need the cached document; normal ingress handles it. */
      } finally {
        doc.free();
      }
    }

    return !expected || expected === origin;
  }

  private pinSubjectRoute(subject: string): DriveRoute {
    const route = this.routeForSubject(subject);

    if (
      route.server &&
      !isAgentSubject(subject) &&
      !this.driveServers.has(route.drive)
    ) {
      this.driveServers.set(route.drive, route.server);
      this.persistDriveServers();
    }

    return route;
  }

  /** A continuation is owned by an identity and a placement revision, never by
   * whichever workspace happens to be selected when its response arrives. */
  public captureRoute(
    subject: string,
  ): DriveRoute & { current: () => boolean; key: string } {
    const route = this.routeForSubject(subject);
    const identity = this.identityGeneration;
    const revision = this.routeRevisions.get(route.drive) ?? 0;

    return {
      ...route,
      key: JSON.stringify([identity, route.drive, route.server, revision]),
      current: () =>
        identity === this.identityGeneration &&
        revision === (this.routeRevisions.get(route.drive) ?? 0) &&
        route.server === this.getServerUrlForSubject(subject),
    };
  }

  public isServerConnectedFor(subject?: string): boolean {
    const origin = this.getServerUrlForSubject(subject);

    return (
      this.serverConnections.get(origin)?.connected ??
      (origin === this.serverUrl && this._serverConnected)
    );
  }

  /** Report every origin independently. One failed tenant must not pause the
   * outbox or overwrite the status of another tenant. */
  public reportServerConnection(
    origin: string,
    connected: boolean,
    error?: string,
  ): void {
    this.serverConnections.set(origin, { connected, error });

    if (origin === this.serverUrl) this.setServerConnected(connected, error);
    else {
      this.eventManager.emit(
        StoreEvents.ConnectionChanged,
        this.serverConnected,
      );
      this.emitSyncStatus();
    }

    if (!connected) {
      for (const [drive, host] of this.driveServers) {
        if (host === origin) {
          this._syncedDrives.delete(this.normalizeSubject(drive));
          this.activeDriveSyncs.delete(drive);
        }
      }
    }

    this.updateDriveSyncProgress();
    this.emitSyncStatus();
    if (connected) this.scheduleOutboxDrain();
  }

  /** The drive a subject belongs to, for naming it to the person. */
  public driveOfSubject(subject: string): string {
    return this.driveOf(this.normalizeSubject(subject));
  }

  /**
   * Whether the server in use refuses `drive` outright because it does not
   * host it: a managed node answering "not enrolled" to our pushes, seen
   * either on the last drive sync or on a parked outbox entry of that drive.
   */
  public isDriveRefusedByServer(drive: string | undefined): boolean {
    if (!drive || this.isLocalOnlyDrive(drive)) return false;

    if (
      this._lastDriveSyncError?.drive === drive &&
      isNotEnrolledMessage(this._lastDriveSyncError.message)
    ) {
      return true;
    }

    const normalized = this.normalizeSubject(drive);

    return this.outbox
      .pending()
      .some(
        entry =>
          isNotEnrolledMessage(entry.lastAttemptError) &&
          this.driveOf(this.normalizeSubject(entry.subject)) === normalized,
      );
  }

  /** Switch this client to browser-only sync after verifying its local copy.
   * Does not delete data from the server or alter other devices' configuration.
   *
   * The three preconditions each get their own message. They used to share
   * "Open this drive with local storage available before disconnecting", which
   * is only true for one of them: someone signed out, or on a server this
   * client holds no socket for, was told to do something they had already done
   * and given nothing to act on.
   *
   * A drive the server refuses ({@link isDriveRefusedByServer}) skips the
   * verification: the server will not serve its copy, so this device's copy
   * is the only one there is, and waiting on its inventory or on the refused
   * writes would never end. Those writes are dropped from the outbox, since a
   * local-only drive is never pushed; turning sync on again resyncs the whole
   * drive rather than replaying them. */
  public async makeDriveLocal(drive: string): Promise<void> {
    const normalized = this.normalizeSubject(drive);
    const agent = this.getAgent();
    const generation = this.getIdentityGeneration();

    if (!agent) throw new Error('Sign in before disconnecting this workspace.');

    // The local database attaches a few hundred ms after boot and again after
    // every agent change, so a click inside that window found no database at
    // all. Wait for the attach rather than refusing. `waitForInit` and not
    // `isReady`, because the latter also demands the bootstrap seed and
    // nothing below reads a bootstrap resource.
    await this.waitForClientDb();
    const db = this.getClientDb();

    if (!db || !(await db.waitForInit()))
      // Reached from creating a drive and from sharing, not only from the
      // Sync page's disconnect: name the cause, not a step the reader never
      // took.
      throw new Error(
        db?.initError?.message ??
          'This needs local storage in this browser, which is not available right now. Reload the page and try again.',
      );

    if (this.isDriveRefusedByServer(drive)) {
      this.registerLocalOnlyDrive(drive);
      this.getWebSocketForSubject(drive)?.unsubscribeFromDrive(drive);

      for (const entry of this.outbox.pending()) {
        const subject = this.normalizeSubject(entry.subject);

        if (
          subject === normalized ||
          this.driveOf(subject) === normalized ||
          this.isLocalOnlySubject(entry.subject)
        ) {
          this.outbox.discard(entry.subject);
        }
      }

      if (this._lastDriveSyncError?.drive === drive) {
        this._lastDriveSyncError = undefined;
      }

      this.emitSyncStatus();

      return;
    }

    const route = this.captureRoute(drive);
    // Sockets are registered under whatever string opened them, which is not
    // always `serverUrl`, so fall back to the drive's origin exactly as
    // `promoteLocalDrive` does. An open one, at that: the inventory below is a
    // live request, and a socket that merely exists left `driveInventory` to fail
    // with "WebSocket is not open", which is not something a user can act on.
    const open = (candidate: WSClient | undefined) =>
      candidate?.readyState === WebSocket.OPEN ? candidate : undefined;
    const ws = open(this.getWebSocketForSubject(normalized));

    if (!ws)
      throw new AtomicError(
        'Connect to a server before disconnecting this workspace.',
        ErrorType.Server,
      );

    const current = (allowDriveSync = false) => {
      const status = this.getSyncStatus();
      if (
        this.getClientDb() !== db ||
        this.getAgent() !== agent ||
        this.getIdentityGeneration() !== generation ||
        !route.current() ||
        (status.syncInProgress &&
          !(allowDriveSync && this._driveSyncInProgress)) ||
        status.pendingDirtyCount ||
        status.blockedCount
      )
        throw new Error(
          'Wait for changes to finish syncing before disconnecting.',
        );
    };

    // Attaching the database can start reconciliation after the click. Let
    // that read complete before checking the local copy; identity changes,
    // pending writes and a stalled sync still prevent disconnection.
    const deadline = Date.now() + 15_000;

    const settled = async () => {
      if (this._driveSyncInProgress) {
        current(true);
        await new Promise<void>((resolve, reject) => {
          let unsubscribe = () => {};

          const finish = () => {
            clearTimeout(timer);
            unsubscribe();

            try {
              current();
              resolve();
            } catch (error) {
              reject(error);
            }
          };

          const timer = setTimeout(finish, Math.max(0, deadline - Date.now()));
          unsubscribe = this.on(StoreEvents.SyncStatusChanged, () => {
            if (!this._driveSyncInProgress || !route.current()) finish();
          });
          if (!this._driveSyncInProgress) finish();
        });
      }

      current();
    };

    await settled();
    // The caller's spelling goes to the socket and to the verification, not the
    // normalized one: `driveInventory` echoes the subjects it was asked about,
    // `verifyLocalDriveCopy` matches the drive against them, and the drive-wide
    // SUB this later drops was sent under `getDrive()`'s own spelling, which is
    // not normalized either. `registerLocalOnlyDrive` normalizes for itself.
    const inventory = await ws.driveInventory(drive, '');
    // A newly created child can still be missing the server's stamped ops:
    // its genesis POST succeeded before its subscription was installed.
    // Acquire missing revisions explicitly and await their local writes.
    // "Connected" and a drained outbox do not prove a complete local copy.
    await Promise.all(
      inventory.map(
        item =>
          this.lastPersisted.get(this.normalizeSubject(item.subject))?.done,
      ),
    );
    const local = await db.getVersionVectorsForDrive(drive);

    const missing = inventory.filter(item => {
      const vv = local[item.subject];

      return (
        !vv ||
        !Object.entries(item.vv).every(
          ([peer, counter]) => (vv[peer] ?? 0) >= counter,
        )
      );
    });

    // Bound pressure on HTTP and the local worker without serializing an
    // entire large workspace. Every continuation still checks its owner.
    for (let offset = 0; offset < missing.length; offset += 8) {
      await Promise.all(
        missing.slice(offset, offset + 8).map(async item => {
          await settled();
          const resource = await this.fetchResourceFromServer(item.subject, {
            noWebSocket: true,
            drive,
          });
          if (resource.error) throw resource.error;
          await settled();
          const jsonAd = resource.toClientDbJsonAd();
          const snapshot = resource.getLoroDoc()?.export({ mode: 'snapshot' });

          if (!jsonAd || !snapshot?.length) {
            throw new Error(
              'A resource is missing its local history. Keep the server connected.',
            );
          }

          await this.persistState(db, resource.subject, jsonAd, snapshot, {
            exact: true,
          });
        }),
      );
    }

    await verifyLocalDriveCopy(db, drive, inventory);
    // A second inventory catches changes made while attachment verification ran.
    await verifyLocalDriveCopy(db, drive, await ws.driveInventory(drive, ''));
    await settled();
    current();
    this.registerLocalOnlyDrive(drive);
    ws.unsubscribeFromDrive(drive);
    this.emitSyncStatus();
  }

  /** Forget a local-only drive (e.g. after deleting a demo workspace),
   *  keeping the persisted registration set bounded. */
  public unregisterLocalOnlyDrive(drive: string): void {
    // Normalized to match what `registerLocalOnlyDrive` stored.
    if (!this.localOnlyDrives.delete(this.normalizeSubject(drive))) return;

    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(
        'atomic.localOnlyDrives',
        JSON.stringify([...this.localOnlyDrives]),
      );
    }
  }

  public isLocalOnlyDrive(drive: string): boolean {
    // Normalized, like the write side: the set holds canonical keys, and a
    // caller may hold the `did:ad:` spelling or a trailing slash.
    return this.localOnlyDrives.has(this.normalizeSubject(drive));
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

    return (
      !this.isForeignOriginSubject(drive) ||
      this.driveServers.has(this.driveOf(drive))
    );
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

    if (!this.isServerConnectedFor(normalized)) {
      throw new AtomicError(
        'Connect to a server before syncing this workspace.',
        ErrorType.Server,
      );
    }

    // Order matters: unregister first so the subscribe/reconcile below is no
    // longer skipped by the local-only guards.
    this.unregisterLocalOnlyDrive(normalized);
    this.subscribeWebSocket(normalized);

    const ws = this.getWebSocketForSubject(normalized);
    await ws?.resyncDrive(normalized);
  }

  /**
   * Reconcile `drive` with the connected server and wait until that server's
   * inventory covers everything held locally (the drive root included).
   * Unlike `promoteLocalDrive`, which only kicks the reconcile off, this
   * resolves once the server provably has the drive, so a caller can report
   * "connected" honestly. Applies to a drive that was already synced
   * elsewhere too: switching servers alone never copies anything.
   * Throws when the server does not catch up within `timeoutMs`.
   */
  public async syncDriveToServerAndVerify(
    drive: string,
    timeoutMs = 60_000,
  ): Promise<void> {
    const normalized = this.normalizeSubject(drive);
    const route = this.captureRoute(drive);

    const assertCurrent = () => {
      if (!route.current())
        throw new RequestCancelledError(
          'Workspace destination changed during verification',
        );
    };

    const open = (candidate: WSClient | undefined) =>
      candidate?.readyState === WebSocket.OPEN ? candidate : undefined;
    const ws = open(this.getWebSocketForSubject(normalized));
    const db = this.getClientDb();

    if (!ws || !db) {
      throw new AtomicError(
        'Connect to a server before syncing this workspace.',
        ErrorType.Server,
      );
    }

    this.unregisterLocalOnlyDrive(normalized);
    this.subscribeWebSocket(normalized);

    const deadline = Date.now() + timeoutMs;
    let lastProblem = 'The server has not received this workspace yet.';

    while (Date.now() < deadline) {
      assertCurrent();
      await ws.resyncDrive(normalized);
      await db.flush();

      try {
        // A first upload's reconcile can still be sending its root. GET
        // has a correlated, quiet NotFound response; inventory requires a
        // readable root and would otherwise be refused and time out.
        await ws.fetch(drive);
        const remote = await ws.driveInventory(drive, '');
        const local = await db.getVersionVectorsForDrive(drive);
        const remoteBySubject = new Map(remote.map(i => [i.subject, i.vv]));

        if (!remoteBySubject.has(drive)) {
          lastProblem = 'The server is still missing this workspace root.';
        } else {
          const missing = Object.entries(local).filter(([subject, vv]) => {
            const have = remoteBySubject.get(subject);

            return (
              !have ||
              Object.entries(vv).some(
                ([peer, counter]) => (have[peer] ?? 0) < counter,
              )
            );
          });

          assertCurrent();
          if (missing.length === 0) return;

          lastProblem = `The server is still missing ${missing.length} item(s).`;
        }
      } catch (e) {
        assertCurrent();
        lastProblem = e instanceof Error ? e.message : String(e);
      }

      await new Promise(resolve => setTimeout(resolve, 2_000));
    }

    throw new AtomicError(
      `Cloud Server did not finish receiving this workspace. ${lastProblem}`,
      ErrorType.Server,
    );
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

    // Normalized, because the set holds normalized keys and a propval is
    // whatever the server wrote: a `did:ad:` spelling of an `atomic:` drive
    // would otherwise miss here and let a local-only resource try a POST.
    if (
      typeof drive === 'string' &&
      this.localOnlyDrives.has(this.normalizeSubject(drive))
    ) {
      return true;
    }

    // `driveOf` returns a raw `parent` propval, so normalize that too.
    return this.localOnlyDrives.has(
      this.normalizeSubject(this.driveOf(normalized)),
    );
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
    this.restoredOutboxEntries.add(entry);

    if (entry.signedGenesis) {
      this.pushCommitLog(
        this.buildCommitLogEntry(entry.signedGenesis, 'outgoing', 'pending'),
        entry.signedGenesis.loroUpdate,
      );
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
    // Entries still in the database are invisible until it attaches. The
    // reconnect sequence refetches and reconciles after this resolves, and
    // must not do so over an offline edit the queue has not loaded yet.
    if (!this.getAgent()) return;
    await this.outbox.whenHydrated();

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
          const code = e instanceof AtomicError ? e.code : undefined;

          // A redundant genesis (the resource already exists on the server)
          // or a write aimed at an immutable Commit is a benign bookkeeping
          // drop, not a lost write — see `isBenignTerminalCommitError`. Other
          // terminal drops may mean a genuinely lost edit, so those still
          // surface — silent discards are worse than visible recoveries there.
          if (isBenignTerminalCommitError(msg, code)) {
            console.debug(
              `Dropped unsyncable commit for ${entry.subject}: ${msg}`,
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
          // subscription). Commit subjects are skipped for the same reason in
          // reverse: the Commit on the server is already what it will always
          // be, so there is nothing to align, and the legacy `/commits/<sig>`
          // form carries unescaped signature characters that only produce a
          // failed fetch.
          if (
            !entry.subject.startsWith('_new:') &&
            !entry.subject.startsWith('_local:') &&
            !isCommitSubject(entry.subject)
          ) {
            this.fetchResourceFromServer(entry.subject).catch(() => undefined);
          }
        },
        isBlockingError: (_entry, e) => {
          const msg = e instanceof Error ? e.message : String(e);
          const code = e instanceof AtomicError ? e.code : undefined;

          return isUnrecoverableCommitError(msg, code);
        },
        onRepeatedFailure: (entry, e) => {
          const error = e instanceof Error ? e : new Error(String(e));
          const report = () =>
            this.eventManager.emit(StoreEvents.CommitRepeatedlyFailing, {
              subject: entry.subject,
              error,
              failures: entry.failures ?? 0,
              server: this.getServerUrlForSubject(entry.subject),
              drive: this.driveOfSubject(entry.subject),
              ageMs: Math.max(0, Date.now() - entry.enqueuedAt),
              outboxSize: this.outbox.size,
              connected: this.isServerConnectedFor(entry.subject),
              isGenesis: entry.signedGenesis !== undefined,
              rearmedAfterResync: entry.rearmedAfterResync === true,
            });
          const refused = this.refusedDriveOf(error.message);

          // A refusal the app resolves (the drive moves to browser-only) is
          // not a failure worth reporting: nothing keeps failing afterwards.
          if (refused && this.refusedDriveHandler) {
            void this.healRefusedDrive(refused, error.message).then(healed => {
              if (!healed) report();
            });

            return;
          }

          report();
        },
        onBlocked: (entry, e) => {
          this.notifyBlockedSync(
            entry.subject,
            e instanceof Error ? e.message : String(e),
          );
        },
      });

      // Children may call syncDirtyResources themselves. Start them only after
      // the parent's drain has completed, never from inside its drain callback.
      for (const parent of [...this.batchedResources.keys()]) {
        if (this.resources.get(parent)?.getLastCommitForChain()) {
          await this.saveBatchForParent(parent);
        }
      }
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
   * must exist on the server before their commits validate (except an
   * agent whose parent is queued too: see `hasQueuedParent`); the
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
    if (isAgentSubject(subject) && !this.hasQueuedParent(subject)) priority = 0;
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

  /**
   * Whether `subject`'s parent is itself still waiting in the outbox. An
   * agent created under a parent — an app's agent in the drive's App
   * identities folder — is admitted through that parent's append right; sent
   * ahead of it, the server finds no parent and answers that only the agent
   * itself may create its Agent resource. Such an agent drains in the depth
   * order below, after its parent, instead of first.
   */
  private hasQueuedParent(subject: string): boolean {
    const parent = this.resources.get(subject)?.get(core.properties.parent);

    return (
      typeof parent === 'string' &&
      parent !== subject &&
      this.outbox.hasPending(parent)
    );
  }

  /**
   * Whether signing `resource` as `agent` would put another agent's name on a
   * parentless Agent resource. Compared by key, not spelling: the same key
   * appears as `atomic:agent:`, `did:ad:agent:`, base64url or padded base64.
   * An Agent resource with a parent (an access key's profile, filed under
   * its issuer's folder) is rightly written by someone else.
   */
  private signsForeignAgentResource(resource: Resource, agent: Agent): boolean {
    if (!isAgentSubject(resource.subject) || !agent.subject) return false;
    if (resource.get(core.properties.parent)) return false;

    return agentKeyOf(resource.subject) !== agentKeyOf(agent.subject);
  }

  /** Subjects of Agent resources with edits waiting for their own agent, by
   *  agent key. In memory: the resource itself still holds the ops. */
  private heldForOwner = new Map<string, Set<string>>();

  private holdForOwner(subject: string): void {
    const key = agentKeyOf(subject);
    const held = this.heldForOwner.get(key) ?? new Set<string>();
    held.add(subject);
    this.heldForOwner.set(key, held);
  }

  private releaseHeldFor(agent: Agent | undefined): void {
    const key = agent?.subject ? agentKeyOf(agent.subject) : undefined;
    const held = key ? this.heldForOwner.get(key) : undefined;

    if (!key || !held) return;

    this.heldForOwner.delete(key);

    for (const subject of held) this.outbox.markDirty(subject);
  }

  private outboxTierOf = (entry: OutboxEntry): string => {
    const [priority, depth] = this.outboxTier(entry.subject);

    return `${priority}:${depth}`;
  };

  /**
   * Drain one subject's outbox entry under sign-at-drain. Steps:
   *
   *  0. If a `signedDestroy` envelope is queued (`Resource.destroy()`
   *     while the POST could not be made or acked), POST it verbatim and
   *     drop the entry — there is no Loro delta to sign for a subject
   *     that is going away, so steps 1-2 are skipped. If the entry ALSO
   *     still holds an unposted `signedGenesis`, the resource never
   *     existed on the server: nothing is POSTed and the entry is dropped.
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
    // (which renames it to `did:ad:<sig>`) before it can be POSTed. The
    // current UI no longer creates these, but an outbox written by an older
    // build may still hold one. Reaching the drain with one means: the server
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

    // Queues from before per-drive routing have no captured route. Recover
    // their ownership from local metadata before choosing a connection, without
    // fetching a deleted resource or sending anything to the bootstrap server.
    if (!entry.route && this.clientDb) {
      const identity = this.identityGeneration;
      let ancestor = this.normalizeSubject(subject);
      const seen = new Set<string>();

      for (let depth = 0; depth < 64 && !seen.has(ancestor); depth++) {
        seen.add(ancestor);

        if (this.driveServers.has(ancestor)) {
          this.rememberResourceDrive(subject, ancestor);
          break;
        }

        const row = await this.clientDb.getResourceWithSnapshot(ancestor);
        if (
          identity !== this.identityGeneration ||
          this.outbox.getEntry(subject) !== entry
        )
          throw new RequestCancelledError('Outbox identity changed');
        if (!row.jsonAd) break;
        const values = JSON.parse(row.jsonAd);
        const parent =
          values['https://atomicdata.dev/properties/drive'] ??
          values[core.properties.parent];
        if (typeof parent !== 'string') break;
        ancestor = this.normalizeSubject(parent);
      }
    }

    if (!this.isServerConnectedFor(subject)) return;
    const route = this.captureRoute(subject);
    const owner = entry;

    const assertCurrent = () => {
      if (!route.current() || this.outbox.getEntry(subject) !== owner) {
        throw new RequestCancelledError(
          'Commit destination or identity changed',
        );
      }
    };

    const endpoint = new URL('/commit', route.server).toString();

    // Step 0: a queued destroy supersedes everything else for this subject.
    // Handled BEFORE the cold-drain `getResource` below, which would refetch
    // the (server-side still existing) resource and resurrect it locally.
    if (entry.signedDestroy) {
      await this.drainDestroy(subject, entry.signedDestroy, endpoint, {
        neverSynced: !!entry.signedGenesis,
        assertCurrent,
      });

      return;
    }

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

      // Older queues omitted the baseline whenever genesis was unposted,
      // including when the durable snapshot contained subsequent edits.
      // Retain the envelope's version before clearing it so a reload can
      // never mistake those edits for server-accepted state.
      if (
        this.restoredOutboxEntries.has(entry) &&
        this.clientDb &&
        !this.clientDb.unsupportedEnvironment &&
        !entry.baseVersion &&
        genesis.loroUpdate
      ) {
        this.outbox.setBaseVersion(
          subject,
          encodeB64(
            LoroLoader.Loro.decodeImportBlobMeta(
              genesis.loroUpdate,
              false,
            ).partialEndVersionVector.encode(),
          ),
        );
      }

      // Ours, from before the POST: the echo can land before the ack and
      // must be recognised either way (see `applyIncoming`).
      if (genesis.signature) {
        this.resources
          .get(subject)
          ?.appliedCommitSignatures.add(genesis.signature);
      }

      assertCurrent();
      const created = await this.postCommit(genesis, endpoint);
      assertCurrent();
      // Acceptance owns queue cleanup. Receipt bookkeeping must never turn
      // a successful POST into a retry of the accepted genesis.
      this.outbox.clearGenesis(subject);

      try {
        this.resources
          .get(subject)
          ?.recordServerAcceptance(
            endpoint,
            created,
            LoroLoader.Loro.decodeImportBlobMeta(genesis.loroUpdate!, false)
              .partialEndVersionVector,
          );
      } catch (error) {
        console.warn('Could not record the accepted genesis receipt', error);
      }

      const commitId = commitIdOf(created);
      const resource = this.resources.get(subject);

      if (resource && commitId) {
        resource.setLastCommitValue(commitId);
        resource.applyToStore('local-acked', { commitId });
        resource.markSynced();
        await this.maybePushBlobForResource(resource).catch(() => undefined);
        // wasNew pipeline — first-time subscribe + save batched children
        this.subscribeWebSocket(subject);
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
      // restored from storage after a page load, and nothing on the
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
    // restored offline edit before its real state has
    // a chance to land.
    const hasLoroState =
      resource.hasLoroDoc() && !!resource.getLoroDoc()?.oplogVersion();

    if (resource.loading && !hasLoroState) {
      this.emitSyncStatus();

      return;
    }

    const agent = this.getAgent();
    if (!agent) return;

    // An Agent resource is created and written by that agent alone (the
    // server rejects any other signer). The signer is picked here, at drain
    // time, so an identity swap between the edit and this point would send
    // agent A's profile signed as agent B. Hold the edit for its owner
    // instead: it stays dirty on the resource, is not an error, and is
    // re-queued when that agent is current again (see `setAgent`).
    if (this.signsForeignAgentResource(resource, agent)) {
      this.holdForOwner(resource.subject);
      this.outbox.clearDirty(subject);
      this.emitSyncStatus();

      return;
    }

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
    let offlineSnapshotLoaded = false;

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
            this.hydrateResourceFromJson(
              subject,
              JSON.parse(jsonAd),
              snapshot ?? undefined,
            );
          }

          const refreshed = this.resources.get(subject);

          if (refreshed && snapshot && snapshot.length > 0) {
            // A stored snapshot can predate current edits. It supplies missing
            // history, not permission to replace the live document. This also
            // preserves edits made after an online genesis was cached.
            offlineSnapshotLoaded =
              refreshed.importLoroUpdate(snapshot).complete;
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
      if (
        entry.baseVersion &&
        (postedGenesis ||
          (offlineSnapshotLoaded &&
            resource.hasLoroDoc() &&
            !resource.hasOpsPastSaveCursor()))
      ) {
        // A complete local snapshot equal to the last synced baseline has
        // nothing left to send. Idempotent offline saves (e.g. re-linking an
        // existing personal drive) still enqueue a baseline. Clear them only
        // after reading that snapshot, never from a possibly stale server copy.
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
    assertCurrent();
    const commit = await builder.sign(agent);
    assertCurrent();

    // Registered before the POST, not after the ack: the server echoes the
    // commit to this connection too, and under load that echo lands before
    // `COMMIT_OK`. `applyIncoming` recognises it by signature and imports it
    // without a notify, so an own save never re-renders the page mid-edit.
    if (commit.signature) {
      resource.appliedCommitSignatures.add(commit.signature);
    }

    let created: Commit;

    try {
      created = await this.postCommit(commit, endpoint);
      assertCurrent();
    } catch (e) {
      // Pending-deps rejection: the delta we just sent starts past ops the
      // server never received (an earlier commit was lost after the save
      // cursor advanced). Retrying the same delta can never succeed — the
      // missing base won't appear server-side. Drop the cursor so the next
      // drain attempt (scheduled by the outbox backoff) exports a
      // self-contained snapshot, which the server can always merge; that
      // re-delivers the lost range too.
      if (e instanceof Error && isPendingDepsCommitErrorMessage(e.message)) {
        resource.clearLoroSaveCursor();
      }

      throw e;
    }

    const commitId = commitIdOf(created);

    if (commitId) {
      resource.setLastCommitValue(commitId);
      resource.applyToStore('local-acked', { commitId });
    }

    // Advance the cursor to the version that was IN this commit, not
    // to current oplog version — any local ops added during the
    // `await postCommit` round-trip are post-commit and must remain
    // dirty until the next drain pass.
    resource.markLoroSavedAt(versionAfterExport);
    resource.recordServerAcceptance(endpoint, created, versionAfterExport);

    // The offline baseline (if any) has now been exported and acked — the
    // cursor sits at or past it, so drop it. Any still-dirty ops past the
    // cursor are online edits with the live cursor as their baseline.
    this.outbox.clearBaseVersion(subject);

    // Did this commit capture everything, or did the user type more
    // during the `await postCommit` round-trip? Compute BEFORE firing
    // `notifyResourceSaved` so the `_dirty` flag is already cleared
    // when a ResourceSaved listener re-reads `hasUnsavedChanges()` or
    // `getSaveState()`; otherwise it reads a stale `true`.
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
   * Drain a queued destroy (step 0 of {@link drainOutboxSubject}).
   *
   * `neverSynced`: the entry still carries an unposted `signedGenesis`, so
   * the resource was created AND deleted before either write reached the
   * server. A destroy of a subject the server has never seen would only be
   * refused, and a never-synced resource needs no tombstone — POST neither,
   * drop the entry, make sure the local copy is gone.
   *
   * A server answer that says the resource is already gone (see
   * {@link isSettledDestroyErrorMessage}) counts as an ack: the goal of the
   * delete is met. Every other failure is rethrown so the outbox applies
   * its usual backoff / terminal / blocking classification and
   * `Resource.destroy()` can surface it to the caller.
   */
  private async drainDestroy(
    subject: string,
    destroy: Commit,
    endpoint: string,
    opts: { neverSynced: boolean; assertCurrent: () => void },
  ): Promise<void> {
    if (!opts.neverSynced) {
      // Registered before the POST like every own commit: should the server
      // echo anything for this subject before the ack, it is ours.
      if (destroy.signature) {
        this.resources
          .get(subject)
          ?.appliedCommitSignatures.add(destroy.signature);
      }

      try {
        await this.postCommit(destroy, endpoint);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);

        if (!isSettledDestroyErrorMessage(msg)) throw e;

        console.debug(
          `[Outbox] destroy of ${subject} already settled on the server: ${msg}`,
        );
      }
    }

    // Drops the whole entry: nothing else about this subject is worth
    // syncing. Then make sure the resource is gone locally too — `destroy()`
    // already removed it optimistically, but a cold drain after a reload
    // (or a fetch that raced the delete) may have brought it back.
    opts.assertCurrent();
    this.outbox.clearDestroy(subject);
    this.removeResource(subject);
    this.emitSyncStatus();
  }

  /**
   * Compute the drive sync state: a hash summarizing all resources' Loro
   * version vectors, plus the individual VV data for diff computation.
   * Used by the sync protocol to determine what needs syncing.
   */
  public async computeDriveSyncState(
    drive: string,
    { sparse = false }: { sparse?: boolean } = {},
  ): Promise<DriveSyncState> {
    // Collect VVs from WASM DB (persisted snapshots)
    let allVVs: Record<string, Record<string, number>> = {};

    // The state is what the server compares against: built from memory alone
    // (the database not attached yet, or not answering) it claims the client
    // holds a handful of resources, and the server answers by sending the
    // whole drive again. Wait for the database, and fail the sync attempt
    // rather than describe a partial state.
    if (!this.clientDb && !(await this.waitForClientDb())) {
      if (this.clientDbExpected) {
        throw new Error('Local database not attached yet');
      }
    }

    if (this.clientDb) {
      try {
        if (!this.clientDb.isReady && !(await this.clientDb.waitForReady())) {
          throw new Error('Local database is not ready');
        }

        // Scoped to THIS drive via the same parent-index walk the server uses
        // (`collect_drive_subjects`): O(this drive) instead of O(every resource
        // in every drive). It also keeps foreign-drive subjects out of the VV
        // we send — the server treats a client-known subject it doesn't have in
        // the drive as a pull/remove candidate, so an unscoped VV made every
        // single-drive sync reason about unrelated drives' resources.
        const endVV = perfSpan('clientdb.getVersionVectorsForDrive');
        allVVs = await readDriveVersionVectors(this.clientDb, drive);
        endVV({ count: Object.keys(allVVs).length });
      } catch (e) {
        throw new Error(`Local database unavailable for sync: ${e}`);
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

    if (sparse) {
      // Per-resource counters as they are: no peer table, no matrix. Each
      // resource has a peer of its own, so the dense form below is resources
      // times peers, and the hash and frame built from it dominated opening a
      // large drive.
      const vvs: Record<string, Record<string, number>> = {};

      for (const [subject, vv] of Object.entries(allVVs)) {
        vvs[subject] = Object.fromEntries(
          Object.entries(vv).filter(([, counter]) => counter !== 0),
        );
      }

      return {
        drive,
        driveHash: await canonicalDriveHashV2(vvs),
        peers: [],
        resources: {},
        vvs,
        hashVersion: 2,
      };
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
      const { jsonAd, snapshot } =
        await this.clientDb.getResourceWithSnapshot(subject);
      if (!jsonAd) return null;

      return (
        this.hydrateOfflineReplay(
          subject,
          JSON.parse(jsonAd),
          snapshot ?? undefined,
        ) ?? null
      );
    } catch {
      return null;
    }
  }

  /** Build a Resource from a parsed JSON-AD object, hydrate Loro,
   *  and route through the unified ingress with `offline-replay`
   *  source. Used by both the OPFS-cold-load path and the
   *  per-page-reload outbox restore path.
   *
   *  Returns the store's own copy, or `undefined` when the ingress refused
   *  the state (the subject was destroyed in this session). Never the
   *  Resource built here when it was refused: that one has no store, so a
   *  caller that edits and saves it fails with "Resource has no store". */
  private hydrateOfflineReplay(
    subject: string,
    parsed: Record<string, unknown>,
    snapshot?: Uint8Array,
  ): Resource | undefined {
    const existing = this.getResolved(subject);
    const resource = new Resource(subject);
    resource.applyHydratedValues(
      Object.entries(parsed).filter(([key]) => key !== '@id') as [
        string,
        JSONValue,
      ][],
    );

    // JSON is a read cache, not a replacement for the document's causal
    // history. Reconstructing it as fresh ops makes later edits lose LWW
    // against the existing server document (notably agent profile renames).
    if (snapshot?.length) {
      resource.importLoroUpdate(snapshot, true);
      this._withoutLoroHistory.delete(this.normalizeSubject(subject));
    } else {
      resource.getLoroDoc();

      // Only when nothing with real history is here to merge into: a
      // placeholder, or nothing at all.
      if (!existing || existing.loading) {
        this._withoutLoroHistory.add(this.normalizeSubject(subject));
      }
    }

    resource.loading = false;
    const outcome = this.applyIncoming({
      subject: resource.subject,
      resource,
      source: 'offline-replay',
    });

    return outcome === 'applied' ? this.getResolved(subject) : undefined;
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
   * @deprecated The app no longer creates `_new:` placeholders. Create drafts
   * with `store.newResource({ deferGenesis: true })`: they keep their subject
   * when saved, so there is nothing to alias. Kept for backward compatibility.
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
    if (isCommitSubject(subject)) return false;
    if (isAtomicIdentifier(subject)) return true;
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

        return (
          url.origin === new URL(this.serverUrl).origin ||
          [...this.driveServers.values()].includes(url.origin)
        );
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

    // Atomic identifiers — new URL() would mangle base64 characters.
    // Canonicalize `did:ad:` → `atomic:` so both spellings share one Map key.
    if (isAtomicIdentifier(subject)) {
      return canonicalizeScheme(subject);
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
   * Repair a document that has fallen behind by importing the missing causal
   * history from a local or remote snapshot.
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
  private recoverFromIncompleteImport(
    subject: string,
    source: string | undefined,
    update: Uint8Array,
  ): void {
    const updates = this._gapUpdates.get(subject) ?? [];
    updates.push(update);
    this._gapUpdates.set(subject, updates);

    if (this._gapRecoveries.has(subject)) return;

    this._gapRecoveries.add(subject);
    this.getResolved(subject)?.setRecovering(true);
    console.info(
      `[Store] incomplete Loro import for ${subject.slice(0, 60)} ` +
        `(source: ${source ?? 'unknown'}) — missing base state, catching up ` +
        `from the local database, else from the server.`,
    );

    // Destroyed while the repair ran (a cascade from its parent's delete,
    // say): "not found" is then the right answer, not a failure, and the
    // resource must not come back as an errored copy. The local-base replay
    // (#1905) waits on the local database first, which widened this window
    // enough for the delete e2e to hit it.
    const gone = () =>
      this.isDestroyed(subject) || this.hasPendingDestroy(subject);
    const fromServer = () =>
      gone()
        ? undefined
        : this.fetchResourceFromServer(subject, { forceOverride: true });
    const repair: Promise<unknown> = this.clientDb
      ? this.replayOnLocalBase(subject).then(done =>
          done ? undefined : fromServer(),
        )
      : Promise.resolve(fromServer());

    repair
      .catch(error => {
        if (gone()) {
          console.info(
            `[Store] ${subject.slice(0, 60)} was deleted while its missing state was being recovered.`,
          );

          return;
        }

        console.warn(
          `[Store] failed to recover missing state for ${subject}:`,
          error,
        );

        if (!this.resources.get(subject)?.get(core.properties.isA)) {
          this.failResource(
            subject,
            error instanceof Error ? error : new Error(String(error)),
          );
        }
      })
      .finally(() => {
        this._gapRecoveries.delete(subject);
        this._gapUpdates.delete(subject);
        const resource = this.getResolved(subject);

        if (resource) {
          resource.setRecovering(false);
          this.notify(resource);
        }
      });
  }

  /**
   * Put the history an update was built on under `subject`'s doc, from the
   * local database, then replay the updates that could not apply. True when
   * they all applied.
   *
   * The server sends a drive sync as deltas from the version vectors this
   * client reported, and those come from the local database. So the base a
   * sync delta needs is, by construction, the snapshot stored locally, one
   * worker round trip away. The doc in memory lacks it only because it was
   * built from something else: a local query's JSON-AD, or nothing at all
   * when the update is the first this page hears of the subject.
   *
   * Asking the server instead worked too, but only as fast as the server
   * answered, and meanwhile the resource sat under repair: `getResource`
   * waited on it and whatever was listed from it (the apps a table offers,
   * #1846) went stale.
   */
  private async replayOnLocalBase(subject: string): Promise<boolean> {
    const clientDb = this.clientDb;

    if (!clientDb) return false;
    if (!clientDb.isReady && !(await clientDb.waitForReady())) return false;

    let snapshot: Uint8Array | null;

    try {
      ({ snapshot } = await clientDb.getResourceWithSnapshot(subject));
    } catch {
      return false;
    }

    const resource = this.getResolved(subject);

    if (!snapshot?.length || !resource) return false;

    if (this.isDestroyed(subject) || this.hasPendingDestroy(subject)) {
      return false;
    }

    // A doc with no history of its own gains nothing from a merge but new
    // ops that can outvote the real ones, so it is replaced, unless it
    // carries an edit that has not reached the server.
    const replace =
      (this._withoutLoroHistory.has(subject) ||
        !this.hasRenderableContent(resource)) &&
      !resource.hasUnsavedChanges() &&
      !this.outbox.mayHavePending(subject);

    if (!resource.importLoroUpdate(snapshot, replace).complete) return false;

    this._withoutLoroHistory.delete(subject);

    for (const update of this._gapUpdates.get(subject) ?? []) {
      if (!resource.importLoroUpdate(update).complete) return false;
    }

    resource.error = undefined;
    resource.loading = false;
    this.addResource(resource, { skipCommitCompare: true });

    return true;
  }

  /**
   * Materialize an incoming revision and notify observers. `applied` describes
   * the in-memory view; its asynchronous local mirror is not a durability receipt.
   */
  public applyIncoming(
    change: IncomingChange,
  ): 'applied' | 'deduped' | 'invalid' {
    // JavaScript callers do not have the TypeScript union's protection.
    if (!!change.resource === !!change.loroBytes) return 'invalid';
    // A destroyed resource must not come back. Before the drain POSTs the
    // envelope the server still holds it, and after the ack an answer that
    // was computed before the destroy landed can still be in flight, so a SUB
    // push, a reconnect SYNC or a fetch that raced the delete can all deliver
    // its state at either moment. Treat that state as already superseded.
    if (
      this.isDestroyed(change.subject) ||
      this.hasPendingDestroy(change.subject)
    )
      return 'deduped';

    // Computed query and search answers have no shared edit history. Classify the
    // subject before branching on payload format so HTTP and binary GETs
    // cannot disagree about whether an earlier answer should be replaced.
    // Nested editable members of an HTTP response retain their own history.
    const computedProjection =
      change.source === 'ws-query-update' ||
      ((change.source === 'http-fetch' || change.source === 'ws-pending-get') &&
        /^https?:/.test(change.subject) &&
        ['/query', '/search', '/vector_search'].includes(
          new URL(change.subject).pathname,
        ) &&
        (!change.resource || change.resource.subject === change.subject));

    // Resource-direct path: caller is the authoritative producer.
    if (change.resource) {
      if (
        change.source === 'local-acked' &&
        change.commitId &&
        change.resource.error instanceof AtomicError &&
        change.resource.error.type === ErrorType.NotFound
      ) {
        // A pre-genesis lookup may fail while the creation is in flight.
        // The server acknowledgement proves that this resource now exists.
        change.resource.error = undefined;
        change.resource.loading = false;
      }

      const alias =
        change.subject !== change.resource.subject ? change.subject : undefined;

      const existing = this.resources.get(
        this.normalizeSubject(change.subject),
      );
      const replaceProjection =
        (change.source === 'http-fetch' || computedProjection) &&
        existing !== change.resource.__internalObject &&
        (computedProjection ||
          this._withoutLoroHistory.has(
            this.normalizeSubject(change.subject),
          )) &&
        !existing?.hasUnsavedChanges() &&
        !this.outbox.mayHavePending(change.subject);

      // The server's copy brings the real history with it.
      if (change.source === 'http-fetch') {
        this._withoutLoroHistory.delete(this.normalizeSubject(change.subject));
      }

      this.addResource(change.resource, {
        skipCommitCompare: true,
        alias,
        replaceLoroDocsFromRemote: replaceProjection,
      });

      return 'applied';
    }

    if (!change.loroBytes) return 'invalid';

    const subject = this.normalizeSubject(change.subject);
    const existing = this.resources.get(this.aliases.get(subject) ?? subject);

    // Echo dedup ⇒ no notify. Two ways to recognise our own commit: the
    // cached `lastCommit` matches (the ack already landed), or the id's
    // signature is one this client signed (`appliedCommitSignatures`, added
    // before the POST — the echo can arrive before the ack). The bytes are
    // still imported: the echo carries the `lastCommit` stamp the server
    // wrote under its own peer, and the next edit by anyone who loaded the
    // stored snapshot depends on that op. Without it that edit parks as
    // pending and the document stops being live for its author. Importing
    // our own ops again is a no-op for Loro.
    //
    // Not notifying matters as much as importing: a notify re-renders the
    // page, and an own save's echo lands right as the user opens the next
    // cell's picker (tables e2e "create and fill" on a loaded runner).
    const ownSignature = isCommitSubject(change.commitId ?? '')
      ? change.commitId!.replace(/^(atomic:commit:|did:ad:commit:)/, '')
      : undefined;
    const isOwnCommit =
      !!existing &&
      !!change.commitId &&
      (existing.get(commits.properties.lastCommit) === change.commitId ||
        (!!ownSignature && existing.appliedCommitSignatures.has(ownSignature)));

    if (
      !change.forceNotify &&
      existing &&
      !existing.loading &&
      !existing.error &&
      isOwnCommit
    ) {
      if (!isCommitSubject(subject)) {
        existing.importLoroUpdate(change.loroBytes);
      }

      return 'deduped';
    }

    // Receiving state must not initiate another read of that same state.
    // getResourceLoading starts an OPFS/server lookup whose delayed fallback
    // can refetch a snapshot we have already applied. Only pending offline
    // edits need that local hydration to merge their durable copy back in.
    const resource =
      existing ??
      (this.outbox.mayHavePending(subject)
        ? this.getResourceLoading(subject, { newResource: false })
        : new Resource(subject));
    resource.setStore(this);
    // Preserve pending edits in memory and on disk. A cold local outbox can
    // contain edits that this Resource has not hydrated yet.
    // A full snapshot is not permission to discard another replica's history.
    // A computed query or a projection rebuilt from JSON has no shared
    // causal base worth merging.
    // Inspect the payload here so every transport applies the same policy.
    let snapshot = false;

    // Cold clients buffer bytes until Loro is ready. They have no live Loro
    // history to replace yet, and an unavailable decoder is not invalid data.
    if (
      LoroLoader.isLoaded() &&
      (computedProjection || this._withoutLoroHistory.has(subject))
    ) {
      try {
        snapshot = LoroLoader.Loro.decodeImportBlobMeta(
          change.loroBytes,
          false,
        ).mode.includes('snapshot');
      } catch {
        return 'invalid';
      }
    }

    const replace =
      snapshot &&
      (computedProjection || this._withoutLoroHistory.has(subject)) &&
      !isCommitSubject(subject) &&
      !resource.hasUnsavedChanges() &&
      !this.outbox.mayHavePending(subject);
    const { complete } = resource.importLoroUpdate(change.loroBytes, replace);

    // A complete import supplies real causal history, including a SYNC_PUSH
    // snapshot which has no GET-response replacement flag. Keeping a resource
    // marked JSON-only here makes writeToClientDb skip the received edit:
    // mounted views show the new value, while reload still reads the old one.
    if (complete) {
      this._withoutLoroHistory.delete(subject);
    }

    // Commit-detail resources (`did:ad:commit:<sig>`) carry a single
    // commit's `loroUpdate`, which is a DELTA by design — importing it
    // into a fresh doc legitimately leaves "pending" ops (the base it
    // builds on lives in the committed-to resource, not here). They are
    // exempt from the incomplete-import guard below; otherwise every
    // commit fetched on refresh (e.g. <CommitDetail> in a chatroom)
    // would be failed and vanish.
    const isCommitDetail = isCommitSubject(subject);

    // Incomplete import: the bytes couldn't fully apply (missing base
    // ops left pending). The resource has whatever it had before plus
    // `lastCommit` — but NOT the real Loro-backed props. Without this
    // guard it would flip to `loading=false` and render as an empty
    // "loaded" resource (only `subject` + `lastCommit` showing), with
    // no error anywhere. Surface it instead. Skip the failure if the
    // resource already had usable content from a prior good import
    // (a late/partial live push shouldn't blow away a good state).
    if (!complete && !isCommitDetail) {
      // The resource already has usable content, so failing it would throw
      // away good state for the sake of an update we couldn't apply. The old
      // code took the other extreme and fell through to `return 'applied'`,
      // which is how a collaborator's text went missing in silence: one
      // delta arrives whose base ops we never saw, Loro parks it as pending,
      // and every later delta parks behind it. No error, no indicator — the
      // document simply stops being live until someone reloads.
      //
      // Ask for full state to supply the missing base. Ingress merges causal
      // history and preserves unsaved local edits and pending outbox work.
      //
      // Deliberately NOT stamping `lastCommit` here. We did not apply that
      // commit, and claiming it would make the echo-dedup at the top of this
      // method drop the very fetch being issued to repair the gap.
      resource.loading = !this.hasRenderableContent(resource);
      this.addResource(resource, { skipCommitCompare: true });
      this.recoverFromIncompleteImport(
        subject,
        change.source,
        change.loroBytes,
      );

      return 'invalid';
    }

    if (change.commitId) resource.setLastCommitValue(change.commitId);
    // A successful read/update supersedes an earlier failed lookup (including
    // a pre-genesis read that arrived after this resource was created).
    resource.error = undefined;
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
      try {
        storeResource.merge(resource.__internalObject, {
          replaceLoroDocs: replaceLoroDocsFromRemote,
        });
      } catch (error) {
        // Preserve the existing history, but surface failed ingress even for
        // fire-and-forget callers. They must not silently replace local edits.
        this.notifyError(
          error instanceof Error ? error : new Error(String(error)),
        );
        throw error;
      }
    } else {
      this.resources.set(subject, resource.__internalObject);
    }

    const emitResource = storeResource ?? resource.__internalObject;

    // Persist the canonical merged resource, not the incoming snapshot. An
    // older response may contribute valid CRDT history without replacing a
    // newer local edit; writing the incoming object would roll back OPFS while
    // mounted readers continue to show the merged (correct) state.
    // Atomic put queued BEFORE notify. The worker's serialised
    // queue means a follow-up `queryLocalDb` (e.g. from
    // Collection.refresh in a notify listener) sees the new
    // resource. Skip for new/loading/incomplete/unsynced — those are
    // persisted by the save path once they are real, or are
    // placeholders.
    if (this.clientDb) {
      this.writeToClientDb(emitResource);
    } else if (this.clientDbExpected && isPersistableState(emitResource)) {
      // No local database attached YET. `initClientDb` detaches synchronously
      // when the identity changes and re-attaches only once that agent's own
      // database has been opened, which spans seconds on a cold load — so a
      // sign-in has a window where every resource the server delivers is held
      // in memory and written nowhere.
      //
      // Nothing re-adds a resource that was applied once, so that used to be
      // permanent: a drive sync landing in the window left the resources in
      // memory and out of the local index, `finishDriveSync` vouched for the
      // drive anyway, and `Collection.finishLocalDbPage` then treated the empty
      // index as authoritative and never asked the server. A second device
      // could open a drive and show none of its contents for the whole
      // session. Remember them and write them when the database arrives.
      this.pendingClientDbWrites.add(emitResource.subject);
    }

    this.notify(emitResource);
  }

  /** Subjects whose state arrived while no local database was attached, to be
   *  written once one is. Bounded by the attach window, which is one cold load
   *  or one identity change. */
  private pendingClientDbWrites = new Set<string>();

  /** Write what arrived while the local database was detached. A different
   *  worker is a different database file, so what {@link lastPersisted}
   *  says was already written does not apply to it. */
  private flushPendingClientDbWrites(): void {
    if (this.pendingClientDbWrites.size === 0) return;

    const subjects = [...this.pendingClientDbWrites];
    this.pendingClientDbWrites.clear();

    for (const subject of subjects) {
      this.lastPersisted.delete(subject);
      const resource = this._resources.get(
        this.aliases.get(subject) ?? subject,
      );

      if (resource) this.writeToClientDb(resource);
    }
  }

  /** Persist a resource's current state to the local database, if there is one
   *  and this state is worth writing. */
  private writeToClientDb(resource: Resource): void {
    if (
      // Skip persisting when the worker has a known init failure (e.g.
      // OPFS leader-election couldn't steal the lock — Firefox doesn't
      // support `navigator.locks.request({ steal: true })`). Without this
      // gate every single `addResource` would queue a `putResourceWithSnapshot`
      // that fails with the same error, flooding the console with one
      // stack trace per resource. The worker itself has already warned
      // once when init failed — that single line is the actionable signal.
      !this.clientDb ||
      this.clientDb.initError ||
      !isPersistableState(resource) ||
      // Rebuilt from the local database's own JSON-AD: writing it back would
      // replace the history stored there with ops that have none (#1905).
      // An edit on it is still written, by the save.
      (this._withoutLoroHistory.has(this.normalizeSubject(resource.subject)) &&
        !resource.hasUnsavedChanges())
    ) {
      return;
    }

    // Captured, because the write is reported asynchronously and the worker
    // can be swapped out from under it by an identity change.
    const clientDb = this.clientDb;

    try {
      const jsonAd = resource.toClientDbJsonAd();

      if (!jsonAd) return;

      const doc = resource.getLoroDoc?.();
      // A snapshot export commits pending ops, untagged; keep a mid-edit
      // persist from stripping the edit's history token.
      resource.sealPendingEdits();
      const snapshot = doc?.export({ mode: 'snapshot' });

      // Skipped when this exact state is already written there: a table
      // built from a template used to do 64 writes for 15 resources.
      this.persistState(clientDb, resource.subject, jsonAd, snapshot).catch(
        e => {
          // A follower's in-flight write is deliberately cancelled on leader
          // handoff; the next attempt retries it. That is not a storage fault
          // to report as an error.
          if (!(e instanceof RequestCancelledError)) {
            console.error(
              `[ClientDb] put failed for ${resource.subject.slice(0, 60)}:`,
              e,
            );
          }
        },
      );
    } catch (e) {
      console.error(
        `[ClientDb] put serialization threw for ${resource.subject.slice(0, 60)}:`,
        e,
      );
    }
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
    propDatatypes,
    noParent,
    did,
    genesisCert,
    deferGenesis,
    contentAddressedProperty,
    contentAddressedLens,
  }: CreateResourceOptions = {}): Promise<Resource<C>> {
    const agentSubject = this.getAgent()?.subject;
    const shouldUseDid =
      did ?? !!(agentSubject && isAgentSubject(agentSubject));
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

    if (contentAddressedProperty) {
      const shortname = propVals?.[core.properties.shortname];
      const datatype = propVals?.[core.properties.datatype];

      if (
        noParent ||
        !parent ||
        typeof shortname !== 'string' ||
        typeof datatype !== 'string'
      ) {
        throw new Error(
          'contentAddressedProperty needs parent, shortname and datatype',
        );
      }

      newSubject = propertyId(normalizedParent, shortname, datatype);

      // Two devices can mint the same Property. Reuse it instead of failing.
      const existing = this.resources.get(newSubject);

      if (existing && !existing.new) {
        return existing as Resource<C>;
      }
    } else if (contentAddressedLens) {
      const from = propVals?.[core.properties.lensFrom];
      const to = propVals?.[core.properties.lensTo];

      if (
        noParent ||
        !parent ||
        typeof from !== 'string' ||
        typeof to !== 'string'
      ) {
        throw new Error(
          'contentAddressedLens needs parent, lensFrom, lensTo and lensTransform',
        );
      }

      newSubject = lensId(from, to, propVals?.[core.properties.lensTransform]);

      // Two devices can mint the same Lens. Reuse it instead of failing.
      const existing = this.resources.get(newSubject);

      if (existing && !existing.new) {
        return existing as Resource<C>;
      }
    } else if (genesisCert) {
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

    // Creating a resource under a subject this store destroyed earlier is the
    // one thing that legitimately undoes a tombstone. Minted DIDs never
    // collide, so in practice this is a caller-supplied subject: a local-only
    // drive rebuilt in place, or a test fixture.
    this.clearDestroyed(newSubject);

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
        const datatype = propDatatypes?.[key];
        await resource.set(key, value, datatype === undefined, datatype);
      }
    }

    // Sign the genesis commit locally now — its subject is already the cert DID,
    // so `signChanges` derives nothing and renames nothing — then STASH it ON
    // THE RESOURCE (not the outbox). Creating a resource must not persist it;
    // only `save()` does (it moves the stash into the outbox). So a
    // created-but-never-saved resource (e.g. an unfilled `TableNewRow`) is never
    // POSTed. This is the only remaining `signChanges` call site.
    if (
      !deferGenesis &&
      ((shouldUseDid && !subject) ||
        genesisCert ||
        contentAddressedProperty ||
        contentAddressedLens)
    ) {
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
      let existing = this._resources.get(existingDid);

      // An empty memory cache after a reload is not evidence that this home
      // is new. Read the durable copy before writing default properties to
      // its deterministic subject. Unlike a display lookup, a failed read
      // here must stop creation rather than become a cache miss.
      if (
        !existing?.isReady() &&
        this.clientDb &&
        !this.clientDb.unsupportedEnvironment
      ) {
        const db = this.clientDb;
        const generation = this.getIdentityGeneration();
        await db.waitForInit();
        const { jsonAd, snapshot } =
          await db.getResourceWithSnapshot(existingDid);

        if (
          this.getAgent() !== agent ||
          this.getIdentityGeneration() !== generation ||
          this.clientDb !== db
        ) {
          throw new Error(
            'The active identity or local database changed while opening the personal drive.',
          );
        }

        if (jsonAd) {
          existing = this.hydrateOfflineReplay(
            existingDid,
            JSON.parse(jsonAd),
            snapshot ?? undefined,
          );

          if (!existing?.hasClasses(server.classes.drive)) {
            throw new Error(
              'The stored personal drive is incomplete. Recover it before creating another drive.',
            );
          }
        }
      }

      if (
        existing?.isReady() &&
        !existing.new &&
        !existing.error &&
        existing.hasClasses(server.classes.drive)
      ) {
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

    if (opts.localOnly) this.registerLocalOnlyDrive(drive.subject);
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
    // genesis commit is signed before this value exists, so it can't be part
    // of the creation commit.
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
    let agentResource: Resource | undefined = prior?.isReady()
      ? prior
      : undefined;

    if (
      this.serverUrlWithoutSocket !== this.serverUrl &&
      !this.isLocalOnlySubject(agentSubject)
    ) {
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

    // The fetch above can outlast a sign-in as another identity. The pointer
    // is only a cache for older clients, so leave it rather than write
    // agent A's resource while another agent is signed in.
    const current = this.getAgent()?.subject;

    if (!current || agentKeyOf(current) !== agentKeyOf(agentSubject)) {
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

  /** Authoritative import/setup identity lookup; never infer absence from an incomplete cache. */
  public async findByLocalId(
    drive: string,
    parent: string,
    localId: string,
  ): Promise<Resource | undefined> {
    const { readConnectionSubjects } = await import('./plugin-connection.js');
    const subjects = await readConnectionSubjects(
      this,
      drive,
      core.properties.localId,
      localId,
    );
    const matches: Resource[] = [];

    for (const subject of subjects) {
      const resource = await this.fetchResourceFromServer(subject, {
        noWebSocket: true,
        drive,
      });
      if (resource.error) throw resource.error;
      const actualParent = resource.get(core.properties.parent);
      if (
        typeof actualParent === 'string' &&
        actualParent.split('?')[0] === parent.split('?')[0]
      )
        matches.push(resource);
    }

    if (!matches.length) return undefined;
    const { resolvedImportSubject } = await import('./import-resolution.js');
    const chosen = resolvedImportSubject(
      Object.fromEntries(matches.map(r => [r.subject, r.getPropVals()])),
    );
    if (!chosen)
      throw new Error('Ambiguous destination/localId; review all copies again');

    return matches.find(r => r.subject === chosen);
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
    const offline =
      !this.isServerConnectedFor(parentScope ?? this.drive) && !opts.serverOnly;
    const limit = opts.limit ?? 30;

    // The local OPFS search can take a while on a large drive, so it must not
    // delay the hosted request: both start now and run concurrently.
    const localSearch: Promise<string[]> =
      !opts.serverOnly &&
      clientDb?.isReady &&
      typeof clientDb.search === 'function'
        ? Promise.resolve()
            .then(() =>
              clientDb.search(query, {
                limit,
                parents: parentScope,
                filters: opts.filters,
              }),
            )
            .then(hits => {
              if (hits.length > 0) {
                searchDebug('[search] local kv →', hits.length, hits);
                opts.onPartial?.(this.withoutDestroyed(hits));
              }

              return hits;
            })
            .catch(e => {
              // When the server can still answer, a broken local index must
              // not take the whole search down.
              if (offline) throw e;

              searchDebug('[search] local kv failed', e);

              return [] as string[];
            })
        : Promise.resolve([]);

    // Offline: hosted `/search` is unreachable. Return whatever the local
    // index has (empty if ClientDb is down).
    if (offline) {
      const kvResults = await localSearch;
      searchDebug('[search] OFFLINE kv →', kvResults.length, kvResults);

      return this.withoutDestroyed(kvResults);
    }

    // Merge with hosted `/search` (same KV engine) so OPFS lag still
    // picks up hits the server already indexed.
    const searchSubject = buildSearchSubject(
      this.getServerUrlForSubject(parentScope ?? this.drive),
      query,
      opts,
    );
    searchDebug('[search] server search →', searchSubject);
    // Search URLs are dynamic query resources without commit identities. Keeping
    // one in the normal resource cache makes a later retry merge against the
    // previous response and discard it as "unchanged", even when `/search` now
    // returns new matches. Evict only the in-memory synthetic resource so every
    // retry observes the server's current result set.
    this._resources.delete(this.resolveSubject(searchSubject));
    const serverSearch = this.fetchResourceFromServer(searchSubject, {
      noWebSocket: true,
    });
    // Avoid an unhandled rejection if the server fails while we still await
    // the local search.
    serverSearch.catch(() => undefined);

    const kvResults = await localSearch;
    const searchResource = await serverSearch;
    const results = searchResource.get(server.properties.results) ?? [];
    searchDebug('[search] server search returned', results.length);

    return this.withoutDestroyed([
      ...new Set([...kvResults, ...results]),
    ]).slice(0, limit);
  }

  /**
   * Search answers come from two indexes (local and hosted) that can both lag
   * a destroy: the hosted one until the outbox delivered it, the local one
   * until a stale push re-wrote the row. A subject this store knows was
   * destroyed would only render as a "was destroyed" error row, so it never
   * reaches the caller.
   */
  private withoutDestroyed(subjects: string[]): string[] {
    return subjects.filter(subject => !this.isDestroyed(subject));
  }

  public async semanticSearch(
    query: string,
    opts: SemanticSearchOpts = {},
  ): Promise<{ subject: string; chunk: string }[]> {
    const parent = Array.isArray(opts.parents) ? opts.parents[0] : opts.parents;
    const vectorSearchSubject = buildSemanticSearchSubject(
      this.getServerUrlForSubject(parent ?? this.drive),
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
        ? { agent: this.agent, serverURL: this.getServerUrlForSubject(subject) }
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
   * replaced with the real `did:ad:...` on first save. Otherwise builds a
   * random HTTP subject under `parent` or the server root.
   *
   * @deprecated Use `store.newResource({ parent, isA, deferGenesis: true })`
   * and read `resource.subject`: the resource gets its final subject up front
   * and is never renamed. Kept for backward compatibility; nothing in the
   * library or app calls it any more.
   */
  public createSubject(parent?: string): string {
    const agentSubject = this.getAgent()?.subject;

    if (!!agentSubject && isAgentSubject(agentSubject)) {
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
      version: GENESIS_VERSION_V1,
      signerPubkey: decodeB64(await agent.getPublicKey()),
      createdAt: Date.now(),
      nonce: crypto.getRandomValues(new Uint8Array(16)),
      parent: canonicalizeScheme(parent),
      drive: canonicalizeScheme(drive),
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
    // A cold cache reads the local database first. Remote recovery still
    // belongs to sign-in: callers must establish backup/server absence before
    // materializing a home this device has never held.
    return this.createDrive(name, {
      ...opts,
      personal: true,
    });
  }

  /**
   * True when the resource carries enough state to stand on its own: a
   * class, or any property beyond the server-managed skeleton
   * (`SERVER_MANAGED_PROPS`) that `rebuildCacheFromLoro` preserves. A
   * resource that passes this is worth more than a failed
   * fetch — it renders, and the alternative is showing the user nothing.
   */
  private hasRenderableContent(resource: Resource | undefined): boolean {
    if (!resource) return false;

    if (resource.get(core.properties.isA)) return true;

    return resource
      .getEntries()
      .some(([prop]) => !SERVER_MANAGED_PROPS.has(prop));
  }

  /** Local-database reads asked for since the last flush, one entry per
   *  subject. A subject asked for twice before the flush shares the entry. */
  private _pendingLocalHydration = new Map<string, LocalHydrationRequest>();

  /** Subject → promise of a flushed read that still awaits the worker. */
  private _inFlightLocalHydration = new Map<
    string,
    Promise<boolean | undefined>
  >();

  /** Set from the first request of a batch until that batch is handed to the
   *  worker, so one flush is queued per batch and no more. */
  private _localHydrationFlushQueued = false;

  /**
   * Try the local WASM DB (OPFS) for a persisted copy of `subject` and hydrate
   * the store from it.
   *
   * Every `useResource` that misses the in-memory cache lands here, from
   * inside React's render. One worker round trip per subject made a cold page
   * with many resources slow: each `postMessage` costs milliseconds, queues
   * behind sync traffic, and in a follower tab crosses a BroadcastChannel
   * hop as well. So a call does not read at once. It joins the pending batch
   * and the batch is read in one {@link hydrateManyFromLocalDb} call from a
   * microtask — after the synchronous render pass that issued it. React
   * renders a default-lane update in one task, so a whole cold mount is one
   * round trip; a time-sliced (transition) render becomes one round trip per
   * slice rather than per resource. A microtask beats `setTimeout(0)` here:
   * that would put a timer clamp on every cold read, and `notify` already
   * relies on a microtask being enough to leave the render phase.
   *
   * A subject that is pending or in flight reuses the existing read.
   *
   * @returns `true` when a local copy hydrated into something renderable,
   *   `false` when the database was asked and does not have it, and
   *   `undefined` when there was no database to ask — callers must not read
   *   that silence as "not stored locally".
   */
  private hydrateFromLocalDb(subject: string): Promise<boolean | undefined> {
    const inFlight = this._inFlightLocalHydration.get(subject);
    if (inFlight) return inFlight;

    const pending = this._pendingLocalHydration.get(subject);
    if (pending) return pending.promise;

    let resolve!: LocalHydrationRequest['resolve'];
    let reject!: LocalHydrationRequest['reject'];
    const promise = new Promise<boolean | undefined>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    this._pendingLocalHydration.set(subject, { promise, resolve, reject });

    if (!this._localHydrationFlushQueued) {
      this._localHydrationFlushQueued = true;
      queueMicrotask(() => void this.flushLocalHydration());
    }

    return promise;
  }

  /**
   * Hand the pending batch to the worker and settle each caller's promise
   * with its own answer. A worker failure resolves every subject of the
   * chunk to `false` inside `hydrateManyFromLocalDb`, exactly as the
   * single-subject read did; only an unexpected throw rejects the callers.
   */
  private async flushLocalHydration(): Promise<void> {
    // Hold the batch open while the database initializes. A reload mounts its
    // resources before the worker is ready, and everything asked for in that
    // window should ride the one round trip that follows.
    if (this.clientDb) await this.clientDb.waitForInit();

    const batch = this._pendingLocalHydration;
    this._pendingLocalHydration = new Map();
    this._localHydrationFlushQueued = false;

    for (const [subject, request] of batch) {
      this._inFlightLocalHydration.set(subject, request.promise);
    }

    const subjects = [...batch.keys()];
    const chunks: string[][] = [];

    for (let i = 0; i < subjects.length; i += LOCAL_HYDRATION_CHUNK) {
      chunks.push(subjects.slice(i, i + LOCAL_HYDRATION_CHUNK));
    }

    await Promise.all(
      chunks.map(async chunk => {
        try {
          const hydrated = await this.hydrateManyFromLocalDb(chunk);

          chunk.forEach((subject, index) =>
            batch.get(subject)!.resolve(hydrated?.[index]),
          );
        } catch (e) {
          for (const subject of chunk) batch.get(subject)!.reject(e);
        } finally {
          // Before any caller resumes (their continuations are microtasks),
          // so a re-ask after this answer is a fresh read, not this one.
          for (const subject of chunk) {
            if (
              this._inFlightLocalHydration.get(subject) ===
              batch.get(subject)!.promise
            ) {
              this._inFlightLocalHydration.delete(subject);
            }
          }
        }
      }),
    );
  }

  /**
   * Hydrate a list of subjects from the embedded database in one worker round
   * trip. One boolean per subject: `true` when a renderable copy is now in
   * memory. `undefined` when there is no database to ask, which is a different
   * answer from "not there" (offline they lead to opposite conclusions).
   */
  private async hydrateManyFromLocalDb(
    subjects: string[],
  ): Promise<boolean[] | undefined> {
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

    // JSON-AD and Loro snapshot for every subject in a single worker
    // round trip. Each postMessage costs milliseconds and queues behind
    // whatever sync traffic the worker is busy with, so per-subject calls
    // were what made a cold page with many resources slow.
    let rows: Array<{ jsonAd: string | null; snapshot: Uint8Array | null }>;

    try {
      // Older database adapters (and test fakes) only have the single read.
      rows = this.clientDb.getResourcesWithSnapshots
        ? await this.clientDb.getResourcesWithSnapshots(subjects)
        : await Promise.all(
            subjects.map(s => this.clientDb!.getResourceWithSnapshot(s)),
          );
    } catch (e) {
      console.warn(`[ClientDb] OPFS lookup failed:`, e);

      return subjects.map(() => false);
    }

    return subjects.map((subject, index) => {
      const { jsonAd, snapshot } = rows[index] ?? {};

      if (!jsonAd) return false;

      let hasLocalData = false;

      try {
        hasLocalData = this.hydrateResourceFromJson(
          subject,
          JSON.parse(jsonAd),
          snapshot ?? undefined,
        );
      } catch (e) {
        console.warn(`[ClientDb] OPFS lookup failed for "${subject}":`, e);

        return false;
      }

      // Hydration publishes JSON and causal state together. A skeleton-only
      // record still needs a server fetch; commit-detail resources may carry
      // a partial delta but remain renderable from their class metadata.
      if (hasLocalData) {
        const resource = this.resources.get(subject);
        const hasClass = !!resource?.get(core.properties.isA);
        const renderable =
          !!resource && (hasClass || this.hasRenderableContent(resource));

        if (!renderable) {
          hasLocalData = false;

          if (resource) {
            resource.loading = true;
          }
        }
      }

      return hasLocalData;
    });
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
    const readAgent = this.agent?.subject;

    // Foreign HTTP identities are served by their own authority. A local
    // database attachment/lock must not delay that read (in particular the
    // bounded legacy-account lookup during sign-in). Keep OPFS as an offline
    // fallback, but do not make it a prerequisite for contacting the server.
    if (
      /^https?:\/\//.test(subject) &&
      new URL(subject).origin !== new URL(this.serverUrl).origin &&
      !isEmbeddedVocabulary(subject) &&
      !this.isLocalOnlySubject(subject)
    ) {
      // Show the cached copy while the authority answers. Without this a
      // legacy `https://` drive (every profile, avatar and table on it) came
      // up as `loading` after each reload even though OPFS held it, because
      // the only thing that read OPFS was the offline fallback below. Not
      // awaited: the server read must not wait for the database. Hydration
      // merges the stored Loro state, so a late local answer cannot undo the
      // server's.
      void this.hydrateFromLocalDb(subject).catch(() => undefined);

      try {
        const remote = await this.fetchResourceFromServer(subject, opts);
        if (!isTransportError(remote.error)) return;
      } catch (e) {
        if (e instanceof RequestCancelledError) throw e;
        if (!isTransportError(e)) throw e;
      }
    }

    // Embedded vocabulary skips the local-first detour while there is a server
    // to ask. It is about twenty fixed, tiny resources that the installed host
    // serves from its own store, so the client database can only ever hold a
    // copy of what the host would return — while the read that fetches that
    // copy is a WASM worker round trip, measured at 3965 ms under four local
    // Playwright workers where the host answered the same subjects in 1.5 to
    // 2.1 ms. Nothing here can ask the server until that read comes back, so a
    // busy worker left a kanban board rendering `useTitle`'s `...` placeholder
    // for its column headings well past 45 seconds, with the answer two
    // milliseconds away. A failed fetch falls through to the path below, which
    // is what keeps an offline install working.
    if (this._serverConnected && isEmbeddedVocabulary(subject)) {
      try {
        await this.fetchResourceFromServer(subject, opts);

        return;
      } catch (e) {
        if (e instanceof RequestCancelledError) throw e;
      }
    }

    // With a server to ask, a local read that has not answered in a
    // second (a busy worker, a leader tab that stopped answering) is treated
    // as no database: the server is asked instead of the page sitting on a
    // placeholder. Offline, the local database is the only source, so it is
    // awaited as long as it takes.
    let local = this.isServerConnectedFor(subject)
      ? await withDeadline<boolean | undefined>(
          this.hydrateFromLocalDb(subject),
          this.localReadDeadlineMs(),
          undefined,
        )
      : await this.hydrateFromLocalDb(subject);
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

      if (!(await this.waitForClientDb(CLIENT_DB_ATTACH_GRACE))) {
        // A timeout bounds the loading state; it does not prove the local
        // copy is absent. Revisit this read when a slow attachment completes.
        const resource = this.resources.get(subject);

        if (
          this.clientDbExpected &&
          resource &&
          this.agent?.subject === readAgent
        ) {
          this.localReadsAwaitingAttach.set(subject, resource);
        }

        return;
      }

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
      // Disconnected. Wait for the socket only where one is coming: a DID
      // subject needs it, and a browser opening its socket at boot should not
      // fall back to an HTTP 404 in the meantime. A store that never opened a
      // socket (a Node client, a unit test) fetches over HTTP right away.
      if (
        !this.isServerConnectedFor(subject) &&
        (isAtomicIdentifier(subject) || this.getWebSocketForSubject(subject))
      ) {
        // Offline — use whatever local data we found. If there IS no local
        // data, surface the offline state to the caller rather than leaving
        // the resource stuck in `loading`.
        if (!hasLocalData) {
          // BUT: a page reload starts with the WS disconnected and reconnects
          // within a few hundred ms. Failing the resource as "offline" during
          // that handshake flashes an ErrorPage before the real load (the
          // user-visible "error state" flicker). Wait briefly for the WS; if it
          // connects, fetch from the server. Only fail if it stays down.
          const connected = await this.waitForServerConnected(5000, subject);

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
        if (isAgentSubject(subject) && !this._revalidatedAgents.has(subject)) {
          this._revalidatedAgents.add(subject);
          await this.fetchResourceFromServer(subject, opts);
        }
      } else {
        // Online, no local data — server is our only source.
        await this.fetchResourceFromServer(subject, opts);
      }

      // HTTP and WebSocket reads can resolve to an errored Resource rather
      // than reject. A server miss does not settle a local read which had no
      // database yet (or hit its deadline). Otherwise opening a Vault-only
      // child directly at boot leaves a permanent 404 over its OPFS copy.
      if (!hasLocalData && this.resources.get(subject)?.error) {
        await askOnceAttached();
      }
    } catch (e) {
      // A cancelled fetch (the page is leaving) settles nothing: the caller
      // awaiting it must see the cancellation, a fire-and-forget one ignores it.
      if (e instanceof RequestCancelledError) throw e;

      // Server fetch failed with no local data. Surface the actual server
      // error (e.g. 401 Unauthorized) so callers (ErrorPage, GettingStartedFlow)
      // can react correctly. Only fall back to a generic offline message when
      // we have no other signal.
      await askOnceAttached();

      // The request may predate a local creation or restore. Its initial
      // cache miss is not evidence that the resource is still missing now.
      const current = this.resources.get(subject);
      if (current?.isReady() && this.hasRenderableContent(current)) return;

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

  /** Publish a completed local import into live resources using their causal history.
   * Reads are fenced to the database and identity that owned the import. */
  public async refreshRestoredResources(
    subjects: string[],
    deleted: string[],
  ): Promise<void> {
    const db = this.clientDb;
    const generation = this.getIdentityGeneration();
    const current = () =>
      this.clientDb === db && this.getIdentityGeneration() === generation;

    const check = () => {
      if (!current())
        throw new RequestCancelledError('Recovery session changed');
    };

    if (db) {
      await db.waitForInit();
      check();
      const rows = await db.getResourcesWithSnapshots(subjects);
      check();
      subjects.forEach((subject, index) => {
        const row = rows[index];
        if (!row?.jsonAd)
          throw new Error(`Restored resource is missing: ${subject}`);
        this.hydrateResourceFromJson(
          this.normalizeSubject(subject),
          JSON.parse(row.jsonAd),
          row.snapshot ?? undefined,
        );
      });
    } else {
      // Native imports write the embedded node, whose normal fetch path
      // already fences route changes and merges snapshots into open editors.
      for (const subject of subjects) {
        check();
        await this.reloadResource(subject);
        check();
        const resource = this.getResolved(subject);
        if (resource?.error) throw resource.error;
      }
    }

    check();

    for (const subject of deleted) {
      this.markDestroyed(this.resolveSubject(subject));
      // The importer already durably deleted it. Do not enqueue a second
      // database delete that could race a subsequent recreation.
      this.evictResource(subject);
    }
  }

  private hydrateResourceFromJson(
    subject: string,
    parsed: Record<string, unknown>,
    snapshot?: Uint8Array,
  ): boolean {
    // `removeResource` tombstoned this subject in OPFS, but the worker may
    // not have processed that yet when a read races the delete. Whatever is
    // still on disk is the pre-delete state; do not bring it back into
    // memory. Report "handled" so the caller does not fall back to a server
    // fetch that would resurrect it either.
    if (this.hasPendingDestroy(subject)) return true;

    const existing = this.getResolved(subject);

    // Don't overwrite a resource that has a Loro snapshot with one that doesn't.
    if (
      existing &&
      existing.get(commits.properties.loroUpdate) &&
      !parsed[commits.properties.loroUpdate] &&
      !snapshot?.length
    ) {
      return true;
    }

    // A JSON-only cache has no causal history, so do not turn it into fresh
    // competing operations over an unsynced edit. A stored Loro snapshot does
    // have history: merge it through hydrateOfflineReplay without replacing
    // the local document. This matters after Vault import, when an automatic
    // profile edit may already be queued in memory. Skipping the snapshot then
    // lets that partial profile overwrite the restored name on the next save.
    if (
      existing?.hasUnsavedChanges() &&
      !snapshot?.length &&
      !parsed[commits.properties.loroUpdate]
    ) {
      return true;
    }

    this.hydrateOfflineReplay(subject, parsed, snapshot);

    // If the outbox holds a dirty bit for this subject (offline edit
    // restored after a reload), kick a drain now that the resource
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

  /** Read authoritative server values without merging optimistic local edits.
   * Use when confirming a reviewed operation, not for ordinary cached reads. */
  public async readServerSnapshot(
    subject: string,
  ): Promise<Readonly<ReturnType<Resource['getPropVals']>>> {
    const agent = this.getAgent();
    const route = this.captureRoute(subject);
    const { resource } = await this.client.fetchResourceHTTP(subject, {
      signInfo: agent
        ? { agent, serverURL: this.getServerUrlForSubject(subject) }
        : undefined,
      serverURL: this.getServerUrlForSubject(subject),
    });
    if (!route.current())
      throw new RequestCancelledError(
        'Server destination changed while reading',
      );
    if (resource.error) throw resource.error;

    return resource.getPropVals();
  }

  /** Refresh a cached resource from its server. Local-only resources and
   * creations still awaiting acknowledgement retain their local state. Use
   * readServerSnapshot when the caller must prove a value exists remotely. */
  public async fetchResourceFromServer<C extends OptionalClass = UnknownClass>(
    /** The resource URL to be fetched */
    subject: string,
    opts: {
      /** Ownership hint for a cold DID outside the selected drive. */
      drive?: string;
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
    if (opts.drive)
      this.resourceDrives.set(
        this.resolveSubject(subject),
        this.resolveSubject(opts.drive),
      );

    // Embedded pilot vocabulary must resolve through the installed host, not
    // depend on a public catalog deployment being available.
    if (isEmbeddedVocabulary(subject)) {
      opts = { ...opts, fromProxy: true, noWebSocket: true };
    }

    const normalizedSubject = this.normalizeSubject(subject);

    // A server cannot refresh a browser-only resource. In particular, explicit
    // refresh callers must not turn a valid local drive into a server 404.
    if (this.isLocalOnlySubject(normalizedSubject)) {
      const local = this.resources.get(normalizedSubject);
      if (local?.isReady()) return local as Resource<C>;
      const stored = await this.fetchResourceFromClientDb(normalizedSubject);
      if (stored) return stored as Resource<C>;
      throw new AtomicError(LOCAL_ONLY_NOT_FOUND_MESSAGE, ErrorType.Transport);
    }

    // A freshly signed DID already has its final identity, but no remote
    // representation yet. Preserve its local handle while creation is queued;
    // a speculative GET/404 must not replace the draft or its save state.
    // Remote durability is established by a save receipt/readServerSnapshot,
    // never by this cache-refresh helper returning a ready Resource.
    const authored = this.resources.get(normalizedSubject);

    if (opts.method !== 'POST' && authored?.awaitingCreation) {
      return authored as Resource<C>;
    }

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

    const route = this.captureRoute(subject);
    const fetchKey = `${normalizedSubject}:${route.key}`;

    if (canDedup) {
      const inflight = this._inFlightFetches.get(fetchKey);
      if (inflight) return inflight as Promise<Resource<C>>;
    }

    const work = this._fetchResourceFromServerImpl<C>(subject, opts);

    if (canDedup) {
      const tracked = work.finally(() => {
        // Only clear if we're still the owner of the slot — a
        // re-entrant fetch that took the slot after us shouldn't be
        // wiped by our completion.
        if (this._inFlightFetches.get(fetchKey) === tracked) {
          this._inFlightFetches.delete(fetchKey);
        }
      });
      this._inFlightFetches.set(fetchKey, tracked);

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
    const route = this.captureRoute(subject);

    const assertCurrent = () => {
      if (!route.current())
        throw new RequestCancelledError(`Resource route changed: ${subject}`);
    };

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

    const resolvedSubject = this.resolveSubject(subject);
    const fetchSubject = isAtomicIdentifier(resolvedSubject)
      ? resolvedSubject
      : subject.startsWith('http') || isAtomicIdentifier(subject)
        ? subject
        : new URL(subject, route.server).toString();

    // Serving JSON-AD over HTTP does not prove this origin speaks our socket
    // protocol. Reuse a socket opened by a selected drive or live holder, but
    // do not start one just because a vocabulary response declared a drive.
    const ws =
      !opts.fromProxy && !opts.noWebSocket
        ? this.getWebSocketForSubject(
            fetchSubject,
            !this.foreignHttpOrigin(fetchSubject),
          )
        : undefined;

    if (
      !opts.fromProxy &&
      !opts.noWebSocket &&
      supportsWebSockets() &&
      ws?.readyState === WebSocket.OPEN
    ) {
      try {
        await ws.fetch(fetchSubject);
      } catch (error) {
        assertCurrent();
        // A hook may already have installed a loading placeholder. Settle it
        // so concurrent getResource callers receive the failure, not a timeout.
        const pending = this.getResolved(subject);

        if (pending && !this.hasRenderableContent(pending)) {
          this.failResource(
            subject,
            error instanceof Error ? error : new Error(String(error)),
          );

          return pending as Resource<C>;
        }

        throw error;
      }
    } else {
      const signInfo = this.agent
        ? {
            agent: this.agent,
            serverURL: this.driveServers.has(route.drive)
              ? route.server
              : this.serverUrl,
          }
        : undefined;

      const fetchVia = (fromProxy: boolean) =>
        this.client.fetchResourceHTTP(fetchSubject, {
          from: fromProxy ? this.serverUrl : undefined,
          method: opts.method,
          body: opts.body,
          signInfo:
            fromProxy && this.agent
              ? { agent: this.agent, serverURL: this.serverUrl }
              : signInfo,
          serverURL: fromProxy ? this.serverUrl : route.server,
        });

      // Only plain documents, the shape of a vocabulary term. A query or
      // collection URL is an endpoint on that server, whose errors mean
      // something to the caller (an old server refusing `drive`, say).
      const foreignOrigin =
        !opts.fromProxy && opts.method !== 'POST' && !fetchSubject.includes('?')
          ? this.foreignHttpOrigin(fetchSubject)
          : undefined;
      const proxyFirst =
        foreignOrigin !== undefined && this._proxiedOrigins.has(foreignOrigin);

      let result = await fetchVia(!!opts.fromProxy || proxyFirst);

      // A foreign origin that could not answer (down, blocked by CORS, 5xx):
      // ask the own server, which fetches external vocabulary on first use
      // and keeps it. When the proxy was tried first (it served this origin
      // before) and failed, try the origin itself instead. Either way one
      // extra attempt, never a loop. The result then takes the same path
      // below as a direct answer, so it is stored and cached the same way.
      if (
        foreignOrigin !== undefined &&
        !result.cancelled &&
        isProxyWorthyError(result.resource.error)
      ) {
        const retried = await fetchVia(!proxyFirst);

        if (!retried.cancelled && !retried.resource.error) {
          if (proxyFirst) {
            this._proxiedOrigins.delete(foreignOrigin);
          } else {
            this._proxiedOrigins.add(foreignOrigin);
          }

          result = retried;
        }
      }

      assertCurrent();
      const { resource, createdResources, cancelled } = result;

      if (cancelled) {
        const cached = this.resources.get(normalizedSubject);
        if (cached?.isReady()) return cached as Resource<C>;

        throw new RequestCancelledError(`Resource fetch cancelled: ${subject}`);
      }

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
      if (!resource.error)
        this.rememberResourceOrigin(resource.subject, route.server);
      this.applyIncoming({
        subject,
        resource,
        source: 'http-fetch',
        replaceLoroDocsFromRemote: !!opts.forceOverride,
      });

      this.learnServerResource(resource, route.server, subject);
      const primarySubject = this.normalizeSubject(resource.subject);
      createdResources.forEach(r => {
        if (this.normalizeSubject(r.subject) !== primarySubject) {
          if (!r.error) this.rememberResourceOrigin(r.subject, route.server);
          this.applyIncoming({
            subject: r.subject,
            resource: r,
            source: 'http-fetch',
            replaceLoroDocsFromRemote: !!opts.forceOverride,
          });
        }
      });
    }

    // Resolve HTTP aliases of a DID (`https://host/did:ad:…` → `did:ad:…`)
    // so a fetch by the address-bar URL returns the resource stored under
    // its canonical `@id`.
    return this.resources.get(this.resolveSubject(normalizedSubject))!;
  }

  /** The origin of an http(s) `subject` that the own server does not serve,
   *  or undefined for the own server, DIDs and anything unparseable. */
  private foreignHttpOrigin(subject: string): string | undefined {
    if (!this.getServerUrl() || !/^https?:\/\//.test(subject)) {
      return undefined;
    }

    if (isOwnServerUrl(subject, this.getServerUrl())) return undefined;

    try {
      return new URL(subject).origin;
    } catch {
      return undefined;
    }
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

  private warnedSchemeMismatch = new Set<string>();

  /** Opens a Websocket for some subject URL, or returns the existing one. */
  public getWebSocketForSubject(
    subject: string,
    connect = true,
  ): WSClient | undefined {
    try {
      const origin = this.getServerUrlForSubject(subject);

      if (
        connect &&
        !this.webSockets.has(origin) &&
        this.driveServers.has(this.driveOf(subject)) &&
        !this.isLocalOnlySubject(subject) &&
        origin !== this.serverUrlWithoutSocket &&
        supportsWebSockets() &&
        (typeof localStorage === 'undefined' ||
          localStorage.getItem('ws-disconnected') !== '1')
      ) {
        this.openWebSocket(origin);
      }

      const ws = this.webSockets.get(origin);

      if (ws) return ws;

      // The same host under another scheme (`http://` subject, `https://`
      // server) is this server, not a missing one: a proxy-terminated
      // deployment whose server still names itself `http://`. Returning
      // undefined here silently turns off subscriptions and live sync.
      const serverOrigin = this.serverUrl
        ? new URL(this.serverUrl).origin
        : undefined;

      if (
        serverOrigin &&
        origin !== serverOrigin &&
        new URL(origin).host === new URL(serverOrigin).host
      ) {
        if (!this.warnedSchemeMismatch.has(origin)) {
          this.warnedSchemeMismatch.add(origin);
          console.warn(
            `Subject origin ${origin} differs from the server URL ${serverOrigin} only by scheme; using the server's WebSocket. Set ATOMIC_SERVER_URL on the server to its public https URL.`,
          );
        }

        return this.webSockets.get(serverOrigin) ?? this.getDefaultWebSocket();
      }

      return undefined;
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
      const url = new URL(
        '/history-attribution',
        this.getServerUrlForSubject(subject),
      );
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
    // The empty string is the same class of non-subject: `useResource(x ?? '')`
    // and `useResource(drive)` before the drive setting hydrates both land
    // here, and `normalizeSubject('')` resolves them to the server's root —
    // a URL that holds no resource on a DID drive, so every such render fired
    // a fetch that 404s and logs two console errors.
    if (
      subjectRaw === unknownSubject ||
      subjectRaw === null ||
      subjectRaw === ''
    ) {
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
    const resolved = isCommitSubject(normalized)
      ? normalized
      : (this.aliases.get(normalized) ?? normalized);
    const isNew =
      !!opts.newResource ||
      normalized.startsWith('_new:') ||
      normalized.startsWith('_local:');

    let resource = this.resources.get(resolved);

    if (!resource) {
      resource = new Resource<C>(normalized, isNew);

      // A view still holding a destroyed subject (a row a stale query answer
      // put back, a link in a page that has not re-rendered yet) asks for it
      // here. Answer from what the store already knows instead of fetching:
      // the request can only 404, and the round-trip is what turned a row
      // that should have gone away into a "Resource with error" that stays.
      if (!isNew && this.isDestroyed(normalized)) {
        resource.loading = false;
        resource.setError(
          new AtomicError(
            `Resource ${normalized} was destroyed`,
            ErrorType.NotFound,
          ),
        );
        this.addResource(resource, { alias: normalized });

        return resource;
      }

      if (!isNew) resource.loading = true;
      this.addResource(resource, { alias: normalized });
      if (!isNew)
        this.fetchResourceWithLocalFallback(normalized, opts).catch(
          () => undefined,
        );

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
        if (isAgentSubject(resolved)) {
          this.fetchResourceWithLocalFallback(resolved, opts).catch(
            () => undefined,
          );
        } else {
          this.fetchResourceFromServer(resolved, opts).catch(error => {
            if (!(error instanceof RequestCancelledError)) {
              this.failResource(resolved, error);
            }
          });
        }
      }
    }

    return resource;
  }

  /**
   * Gets many resources at once, in the order asked. Nearest source first:
   * whatever is already in memory (or in flight) is reused, then the embedded
   * database is asked for the rest in parallel, and only what neither has
   * goes to the server, as one `GET_MANY` per chunk over the WebSocket (or as
   * parallel single fetches where that is impossible: no socket, local-only
   * subjects). Each entry is what `getResource` would have produced, so a
   * missing subject comes back as a resource carrying `error` rather than as
   * an exception.
   */
  public async getResources<C extends OptionalClass = UnknownClass>(
    subjects: string[],
  ): Promise<Resource<C>[]> {
    const close = perfSpan('store.getResources', { count: subjects.length });
    const pending = new Map<string, Promise<Resource<C>>>();
    const batches = new Map<WSClient, string[]>();
    const misses: string[] = [];

    for (const subject of new Set(subjects)) {
      const resolved = this.resolveSubject(subject);
      const found = this.resources.get(resolved);

      if (found && (found.isReady() || found.error)) {
        pending.set(subject, Promise.resolve(found as Resource<C>));
        continue;
      }

      const inflight = this._inFlightFetches.get(
        `${this.normalizeSubject(subject)}:${this.captureRoute(subject).key}`,
      );

      if (inflight) {
        pending.set(subject, inflight as Promise<Resource<C>>);
        continue;
      }

      misses.push(subject);
    }

    // The embedded database holds everything this device has synced; one
    // worker round trip hydrates every hit into memory without the server.
    const hits =
      (await this.hydrateManyFromLocalDb(
        misses.map(subject => this.resolveSubject(subject)),
      )) ?? [];
    const local = misses.map((subject, index) => {
      const resource = this.resources.get(this.resolveSubject(subject));

      return hits[index] && resource?.isReady()
        ? (resource as Resource<C>)
        : undefined;
    });

    for (const [index, subject] of misses.entries()) {
      const resolved = this.resolveSubject(subject);
      const fromDb = local[index];

      if (fromDb) {
        pending.set(subject, Promise.resolve(fromDb));
        continue;
      }

      const ws =
        supportsWebSockets() &&
        !this.isLocalOnlySubject(resolved) &&
        !resolved.startsWith('_new:') &&
        !resolved.startsWith('_local:')
          ? this.getWebSocketForSubject(resolved)
          : undefined;

      if (ws?.readyState !== WebSocket.OPEN) {
        pending.set(subject, this.getResource<C>(subject));
        continue;
      }

      batches.set(ws, [...(batches.get(ws) ?? []), subject]);
    }

    for (const [ws, wanted] of batches) {
      for (let i = 0; i < wanted.length; i += GET_MANY_CHUNK) {
        const chunk = wanted.slice(i, i + GET_MANY_CHUNK);
        const batch = ws.fetchMany(chunk);

        chunk.forEach((subject, index) => {
          const route = this.captureRoute(subject);
          const normalized = `${this.normalizeSubject(subject)}:${route.key}`;
          const one = batch.then(entries => {
            const entry = entries[index];

            if (!route.current() || entry instanceof RequestCancelledError)
              throw new RequestCancelledError('Batch resource route changed');
            if (!(entry instanceof Error)) return entry as Resource<C>;

            // Same shape as a failed single fetch: the placeholder (created
            // here if nothing asked for it yet) carries the error.
            const existing = this.getResolved(subject);

            if (!existing) {
              const placeholder = new Resource<C>(this.resolveSubject(subject));
              this.addResource(placeholder, { skipCommitCompare: true });
            }

            this.failResource(subject, entry);

            return this.getResolved(subject) as Resource<C>;
          });
          const tracked = one.finally(() => {
            if (this._inFlightFetches.get(normalized) === tracked) {
              this._inFlightFetches.delete(normalized);
            }
          });
          this._inFlightFetches.set(normalized, tracked);
          pending.set(subject, tracked);
        });
      }
    }

    const results = await Promise.all(
      subjects.map(subject => pending.get(subject)!),
    );
    close({ misses: misses.length });

    return results;
  }

  /**
   * Gets a resource by URL, waiting until it is loaded. The read policy is the
   * one `useResource` follows (`getResourceLoading`): memory, then the
   * embedded database, then the server. A subject that cannot be loaded
   * resolves to a resource carrying `error` rather than throwing.
   */
  public async getResource<C extends OptionalClass = UnknownClass>(
    subjectRaw: string,
    opts: { drive?: string } = {},
  ): Promise<Resource<C>> {
    if (opts.drive)
      this.resourceDrives.set(
        this.resolveSubject(subjectRaw),
        this.resolveSubject(opts.drive),
      );
    const normalized = this.normalizeSubject(subjectRaw);
    const resolved = this.resolveSubject(subjectRaw);
    let found = this.resources.get(resolved) as Resource<C> | undefined;

    if (!found) {
      // Temporary subjects are never fetched; `getResourceLoading` knows.
      // Neither is the empty string, which normalization would otherwise turn
      // into the server's root.
      if (
        subjectRaw === '' ||
        normalized.startsWith('_new:') ||
        normalized.startsWith('_local:')
      ) {
        return this.getResourceLoading<C>(subjectRaw);
      }

      found = new Resource<C>(normalized);
      found.loading = true;
      this.addResource(found, { alias: normalized });
      // Awaited here so a cancelled fetch rejects instead of hanging.
      await this.fetchResourceWithLocalFallback(normalized);
      found =
        (this.resources.get(resolved) as Resource<C> | undefined) ?? found;
    }

    if (found.isReady() || found.error) {
      return found;
    }

    // Someone else is loading it, or recovery of missing history is still in
    // flight: wait for the resource to settle.
    const resource = await new Promise<Resource<C>>((resolve, reject) => {
      const defaultTimeout = 10000;
      let timer: ReturnType<typeof setTimeout> | undefined;

      const cb: ResourceCallback<C> = res => {
        // Snapshot notifications can precede hydration. Keep waiting for
        // data, but let terminal errors reach the caller.
        if (res.loading && !res.error) return;
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

    // Follow live changes so a later read is not stale. Commits are
    // immutable, so they need no subscription.
    if (!resource.error && !resource.hasClasses(commits.classes.commit)) {
      this.subscribeWebSocket(resource.subject);
    }

    return resource;
  }

  /**
   * Read from memory or the local database, without contacting a server.
   * Use with queryLocalDb so a locally indexed identity is resolved against
   * the same authority, even while online or before its commits have synced.
   * Missing/unavailable local state is an error, never permission to recreate it.
   */
  public async getLocalResource(subjectRaw: string): Promise<Resource> {
    const subject = this.resolveSubject(subjectRaw);
    const cached = this.resources.get(subject);
    if (cached?.isReady()) return cached;

    const found = await this.hydrateFromLocalDb(subject);
    const resource = this.resources.get(subject);
    if (found && resource?.isReady()) return resource;

    throw new Error(
      found === undefined
        ? 'Local resource database is unavailable'
        : `Resource ${subjectRaw} is not available locally`,
    );
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

  /** Drives whose "not enrolled" refusal was already reported this session. */
  private _notifiedRefusedDrives = new Set<string>();

  /** Drives whose "server lacks the parent" refusal was already reported. */
  private _notifiedMissingParentDrives = new Set<string>();

  private refusedDriveHandler: RefusedDriveHandler | undefined;

  /** One attempt per drive per session, so a failing drive is not looked up
   *  again by every entry that fails for it. */
  private _refusedDriveAttempts = new Map<string, Promise<boolean>>();

  /**
   * Register how the app resolves a drive the server refuses as "not
   * enrolled" ({@link RefusedDriveHandler}). Without one, or when it does not
   * resolve the drive, the person is told as before. Returns a function that
   * removes the handler.
   */
  public setRefusedDriveHandler(
    handler: RefusedDriveHandler | undefined,
  ): () => void {
    this.refusedDriveHandler = handler;

    return () => {
      if (this.refusedDriveHandler === handler) {
        this.refusedDriveHandler = undefined;
      }
    };
  }

  /** The drive a "not enrolled" refusal names, if `message` is one. The
   *  refusal names the drive it refuses; that is the same for every resource
   *  in it, where a resource's own drive may not be known yet. */
  private refusedDriveOf(message: string): string | undefined {
    if (!isNotEnrolledMessage(message)) return undefined;

    return /Drive (\S+) is not enrolled/.exec(message)?.[1];
  }

  /** Ask the registered handler about a refused drive, once per drive. A
   *  handler that throws counts as not resolved. */
  private healRefusedDrive(drive: string, message: string): Promise<boolean> {
    const key = this.normalizeSubject(drive);
    const existing = this._refusedDriveAttempts.get(key);

    if (existing) return existing;

    const handler = this.refusedDriveHandler;
    const attempt = (async () => {
      try {
        return !!(await handler?.(drive, message));
      } catch (e) {
        console.warn('[Store] refused drive handler failed:', e);

        return false;
      }
    })();
    this._refusedDriveAttempts.set(key, attempt);

    return attempt;
  }

  /**
   * Tell the person a write stopped syncing. The entry stays queued and
   * visible, and a fresh edit re-arms it.
   *
   * A node refusing a whole drive as "not enrolled" is one condition, not one
   * per resource: every create and every comment in that drive is refused the
   * same way, and a toast for each buried the person under errors that name
   * resources they never see. Say it once per drive, in terms of the drive,
   * and say what happens to their edits.
   */
  private notifyBlockedSync(subject: string, message: string): void {
    if (isNotEnrolledMessage(message)) {
      const named = this.refusedDriveOf(message);
      const drive =
        named ?? this.driveOf(this.normalizeSubject(subject)) ?? subject;

      if (this._notifiedRefusedDrives.has(drive)) return;

      this._notifiedRefusedDrives.add(drive);

      const toast = () =>
        this.notifyError(
          new Error(
            `This server does not host this workspace (${message.trim()}) ` +
              `Your changes are kept on this device and are not being sent. ` +
              `Ask the server's operator to enrol the workspace, or turn on ` +
              `browser-only sync for it in the sync settings.`,
          ),
        );

      // The app may resolve the drive first (it moves to browser-only); only
      // a drive it leaves alone is reported.
      if (named && this.refusedDriveHandler) {
        void this.healRefusedDrive(named, message)
          .then(healed => {
            if (!healed) toast();
          })
          .catch(e => console.warn('[Store] could not report refusal:', e));

        return;
      }

      toast();

      return;
    }

    if (isMissingParentMessage(message)) {
      // Every write under a workspace the server does not hold is refused the
      // same way, and each one used to toast on every page load. Say it once
      // per workspace, in terms of the workspace, and say what to do.
      const drive = this.driveOf(this.normalizeSubject(subject)) ?? subject;

      if (this._notifiedMissingParentDrives.has(drive)) return;

      this._notifiedMissingParentDrives.add(drive);
      this.notifyError(
        new Error(
          `Some changes could not be sent: the server does not have the ` +
            `workspace they belong to (${drive.slice(0, 40)}…). They are ` +
            `kept on this device and are not being retried. Once the workspace ` +
            `is back on the server, syncing it sends them; if it is gone, ` +
            `discard them on the Sync page.`,
        ),
      );

      return;
    }

    this.notifyError(
      new Error(
        `Could not sync ${subject.slice(0, 60)}… — ${message} ` +
          `Not retrying; edit again once you have access.`,
      ),
    );
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
    return this.isServerConnectedFor(this.drive);
  }

  /** Called by WebSocket client when connection state changes. */
  public setServerConnected(connected: boolean, error?: string): void {
    const nextError = connected ? undefined : error;
    this.serverConnections.set(this.serverUrl, { connected, error: nextError });

    if (
      this._serverConnected === connected &&
      this._serverConnectionError === nextError
    ) {
      return;
    }

    this._serverConnected = connected;
    this._serverConnectionError = nextError;

    if (connected) {
      this.collectionPagesAnsweredByServer.clear();
    }

    if (!connected) {
      this._driveSyncInProgress = false;
      this._driveSyncPulling = false;
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

    await this.fetchResourceWithLocalFallback(resolved).catch(e => {
      if (!(e instanceof RequestCancelledError)) throw e;
    });
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

  private saveStatus = new SaveStatusCoordinator({
    getOutboxEntry: subject => this.outbox.getEntry(subject),
    isConnected: subject => this.isServerConnectedFor(subject),
    changePending: delta => {
      this._scheduledSaves += delta;
      this.emitSyncStatus();
    },
    subscribeSync: callback => this.on(StoreEvents.SyncStatusChanged, callback),
    onError: error => this.notifyError(error),
  });

  /** One owner per debounce slot. Resource identity survives genesis renaming. */
  public createSaveScheduler(
    resource: Resource,
    options: {
      shouldSave?: () => boolean;
      onError?: (error: Error) => void;
    } = {},
  ): ScheduledSave {
    return this.saveStatus.createScheduler(resource, options);
  }

  /** Read status is separate: a queued offline edit can still be fully readable. */
  public getSaveState(resource: Resource): ResourceSaveState {
    return this.saveStatus.getState(resource);
  }

  public subscribeSaveState(
    resource: Resource,
    callback: () => void,
  ): () => void {
    return this.saveStatus.subscribe(resource, callback);
  }

  private updateDriveSyncProgress(): void {
    this._driveSyncInProgress = this.activeDriveSyncs.size > 0;
    this._driveSyncPulling = [...this.activeDriveSyncs.values()].some(Boolean);
  }

  public startDriveSync(drive = this.drive ?? ''): void {
    this.activeDriveSyncs.set(drive ? this.normalizeSubject(drive) : '', false);
    this.updateDriveSyncProgress();
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
    this.activeDriveSyncs.delete(this.normalizeSubject(drive));
    this.activeDriveSyncs.delete('');
    this.updateDriveSyncProgress();
    this._lastDriveSync = { drive, count, timestamp };

    if (drive) {
      this._syncedDrives.add(this.normalizeSubject(drive));

      if (this._lastDriveSyncError?.drive === drive) {
        this._lastDriveSyncError = undefined;
      }

      // Writes the server refused for a missing parent (a drive root it never
      // received) were parked after their retries. This resync is what offers
      // that parent, so try them once more.
      const syncedDrive = this.normalizeSubject(drive);
      const rearmed = this.outbox.rearmParentBlocked(
        subject =>
          this.normalizeSubject(
            this.driveOf(this.normalizeSubject(subject)),
          ) === syncedDrive,
      );

      if (rearmed > 0) this.scheduleOutboxDrain();
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
    this.activeDriveSyncs.delete(this.normalizeSubject(drive));
    this.activeDriveSyncs.delete('');
    this.updateDriveSyncProgress();
    this._lastDriveSyncError = { drive, message, timestamp: Date.now() };

    if (drive) {
      this._syncedDrives.delete(this.normalizeSubject(drive));
    }

    this.emitSyncStatus();
  }

  /** How long a read waits for the local database before asking the
   *  connected server instead. */
  public localReadDeadlineMs(): number {
    return this._driveSyncInProgress
      ? LOCAL_READ_DEADLINE_DURING_SYNC_MS
      : LOCAL_READ_DEADLINE_MS;
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
  /** True while the server is sending a drive's resources and they are not all
   *  saved locally yet: the local database may hold only part of the drive. */
  public isDriveSyncPulling(): boolean {
    return this._driveSyncPulling;
  }

  /** The server started sending resources for a drive sync. */
  public startDriveSyncPull(drive = this.drive ?? ''): void {
    this.activeDriveSyncs.set(drive ? this.normalizeSubject(drive) : '', true);
    this.updateDriveSyncProgress();
  }

  public hasCompletedDriveSyncFor(drive: string | undefined): boolean {
    if (!drive) return false;

    return this._syncedDrives.has(this.normalizeSubject(drive));
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
      serverConnected: this.serverConnected,
      serverConnectionError: this.serverConnections.get(
        this.getServerUrlForSubject(this.drive),
      )?.error,
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
      serverUrl: this.getServerUrlForSubject(this.drive),
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

  /** True while `Resource.destroy()` has removed `subject` locally but the
   *  signed destroy commit is still queued in the outbox (offline, or the
   *  POST has not acked yet). Incoming state for such a subject is stale by
   *  definition and must not resurrect it. */
  public hasPendingDestroy(subjectRaw: string): boolean {
    const subject = this.normalizeSubject(subjectRaw);

    return !!this.outbox.getEntry(this.aliases.get(subject) ?? subject)
      ?.signedDestroy;
  }

  /**
   * True when this store has destroyed `subject`.
   *
   * The one answer every consumer of a live query asks before admitting a
   * member: the query it is reading may have been answered before the destroy
   * landed. Broader than {@link hasPendingDestroy}, which only covers the
   * window before the server acks — the stale answer usually arrives after it.
   */
  public isDestroyed(subjectRaw: string): boolean {
    return this._destroyed.has(this.resolveSubject(subjectRaw));
  }

  /**
   * Forget that `subject` was destroyed, for the rare case where one is
   * legitimately created again under the same subject (a local-only drive
   * rebuilt in place, a test fixture). Called by {@link newResource}; a
   * resource arriving from a query or a push never clears a tombstone,
   * because that is the resurrection this set exists to stop.
   */
  public clearDestroyed(subjectRaw: string): void {
    this._destroyed.delete(this.resolveSubject(subjectRaw));
  }

  /** Records the tombstone, evicting the oldest once the cap is reached. */
  private markDestroyed(subject: string): void {
    // Re-inserting moves the subject to the end of the iteration order, so a
    // subject destroyed twice is treated as the more recent of the two.
    this._destroyed.delete(subject);
    this._destroyed.add(subject);

    while (this._destroyed.size > Store.DESTROYED_LIMIT) {
      const oldest = this._destroyed.values().next().value;

      if (oldest === undefined) break;
      this._destroyed.delete(oldest);
    }
  }

  /** Removes resource from this store, does not delete it from the server, use `resource.destroy()` to delete it from the server. */
  public removeResource(subjectRaw: string, shouldNotify = true): void {
    const resolved = this.resolveSubject(subjectRaw);

    // The in-memory half of the tombstone below. Recorded before the eviction
    // notifies, so a listener that reacts by re-reading a query already sees
    // the subject as destroyed and drops it from the answer.
    this.markDestroyed(resolved);

    if (isLensSubject(resolved)) {
      const lens = this.lenses.get(resolved);

      this.lenses.remove(resolved);

      if (lens) this.rematerializeLensed(lens.from, lens.to);
    }

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

    this.evictResource(subjectRaw, shouldNotify);
  }

  /** Forget an in-memory cache entry without deleting or tombstoning its data. */
  public evictResource(subjectRaw: string, shouldNotify = true): void {
    const resolved = this.resolveSubject(subjectRaw);
    // A subsequently loaded resource must not inherit the old cache stamp.
    this.lastPersisted.delete(resolved);
    this._withoutLoroHistory.delete(resolved);

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
    const identityChanged = this.agent?.subject !== agent?.subject;
    if (this.agent !== agent) this.identityGeneration++;

    if (this.agent?.subject !== agent?.subject) {
      this.localReadsAwaitingAttach.clear();
      this.collectionPagesAnsweredByServer.clear();

      // Anonymous holders are public views; keep them through first login.
      // An existing account's holders must be reacquired by the new owner.
      if (this.agent) {
        this.liveSubscriptionGeneration++;
        const subjects = [...this.liveSubjects.keys()];
        this.liveSubjects.clear();

        for (const subject of subjects) {
          this.getWebSocketForSubject(subject)?.unsubscribeResource(subject);
        }
      }
    }

    // The current drive is an account context, not a server preference. Clear
    // it before reauthenticating, so the next identity never subscribes or
    // reconciles the previous identity's private workspace.
    const replaceConnections = !!this.agent && identityChanged;

    if (replaceConnections) {
      this.setDrive('');
      for (const socket of this.webSockets.values()) socket.close();
      this.webSockets.clear();
    }

    this.agent = agent;
    if (identityChanged) this.loadDriveServers();

    if (
      replaceConnections &&
      this.serverUrl !== this.serverUrlWithoutSocket &&
      supportsWebSockets() &&
      (typeof localStorage === 'undefined' ||
        localStorage.getItem('ws-disconnected') !== '1')
    ) {
      this.openWebSocket(this.serverUrl);
    }

    // The outbox is identity-scoped: rebind to this agent's own queue so a new
    // identity never drains a previous agent's commits (whose `did:ad:<sig>`
    // subjects can't be re-signed by anyone else — they'd 401 forever).
    this.outbox.rebind(agent?.subject);
    this.releaseHeldFor(agent);
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
          if (e instanceof RequestCancelledError) return;
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

    // After the event: an app that keeps one database per agent detaches the
    // previous agent's on it, and this must not bind that one.
    void this.bindOutboxDatabase();
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
    if (isAtomicIdentifier(subject)) return true;

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

    const agentName = legacy.get(core.properties.name) as string | undefined;
    // A home is titled after whoever owns it, so a migrated account keeps its
    // own name here too. No literal for the nameless case: `ensurePrivateDrive`
    // has the default, and a copy of it here is a copy that can drift.
    const privateDrive = await this.ensurePrivateDrive(
      agentName?.trim() ? `${agentName.trim()}'s Drive` : undefined,
      { agentName },
    );

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
    url = normalizeServerOrigin(url);

    const previous = this.serverUrl;

    if (previous !== url) {
      this.routingGeneration++;
      this.collectionPagesAnsweredByServer.clear();
    }

    this.serverUrl = url;

    if (previous && previous !== url) {
      const state = this.serverConnections.get(url);
      this.setServerConnected(state?.connected ?? false, state?.error);
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
    const resolved = drive ? this.resolveSubject(drive) : drive;
    if (Client.isBareHttpOrigin(drive) && isAtomicIdentifier(resolved))
      drive = resolved;
    if ((this.drive ?? '') !== drive) this.routingGeneration++;

    if (!drive) {
      this.drive = undefined;
    } else if (Client.isBareHttpOrigin(drive)) {
      this.setServerUrl(new URL(drive).origin);
    } else {
      this.drive = drive;
      if (!this.isForeignOriginSubject(drive)) this.pinSubjectRoute(drive);
      const origin = this.getServerUrlForSubject(drive);
      if (
        this.isLiveSyncedDrive(drive) &&
        supportsWebSockets() &&
        (typeof localStorage === 'undefined' ||
          localStorage.getItem('ws-disconnected') !== '1') &&
        origin !== this.serverUrlWithoutSocket
      )
        this.openWebSocket(origin);
    }

    if (typeof window !== 'undefined') {
      localStorage.setItem('drive', JSON.stringify(drive));
    }

    this.eventManager.emit(StoreEvents.DriveChanged, drive);
  }

  /** Opens a WebSocket for this Atomic Server URL */
  public openWebSocket(url: string) {
    url = normalizeServerOrigin(url);

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
  public reconnect(timeoutMs = 15000, subject = this.drive): Promise<void> {
    const url = this.getServerUrlForSubject(subject);

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

      unsub = this.on(StoreEvents.ConnectionChanged, () => {
        const state = this.serverConnections.get(url);

        if (state?.connected) {
          clearTimeout(timer);
          unsub?.();
          resolve();
        } else if (state?.error) {
          // A disconnect without an error message is the synchronous
          // teardown step below — keep waiting for the real outcome.
          clearTimeout(timer);
          unsub?.();
          reject(new Error(state.error));
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

      this.reportServerConnection(url, false);
      this.openWebSocket(url);
    });
  }

  /** Close the WebSocket connection. Persists across refresh until reconnect(). */
  public disconnect(): void {
    for (const socket of this.webSockets.values()) socket.close();
    this.webSockets.clear();

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

    return this.addLoroSubscriber(
      this.subscribers,
      normalized,
      callback,
      () => this.subscribeWebSocket(normalized),
      () => {
        if (isAgentSubject(normalized))
          this.getWebSocketForSubject(normalized)?.unsubscribeAgentProfile(
            normalized,
          );
      },
    );
  }

  /**
   * Keep changes to `subject`, and to its children, arriving while the app
   * runs. The open drive's subscription covers everything in it; this is for
   * what lives elsewhere and was shared with you on its own, like a chatroom
   * in someone else's drive, which that subscription can never reach.
   * Survives reconnects. Returns a function that lets go.
   */
  public subscribeLive(subject: string): () => void {
    const normalized = this.normalizeSubject(subject);
    const generation = this.liveSubscriptionGeneration;
    let released = false;
    const count = this.liveSubjects.get(normalized) ?? 0;
    this.liveSubjects.set(normalized, count + 1);

    if (count === 0) {
      this.getWebSocketForSubject(normalized)?.subscribeResource(normalized);
    }

    return () => {
      if (released || generation !== this.liveSubscriptionGeneration) return;
      released = true;
      const left = (this.liveSubjects.get(normalized) ?? 1) - 1;

      if (left > 0) {
        this.liveSubjects.set(normalized, left);

        return;
      }

      this.liveSubjects.delete(normalized);
      this.getWebSocketForSubject(normalized)?.unsubscribeResource(normalized);
    };
  }

  /** Drive resources use drive-wide fan-out. Mounted agent profiles also need
   * a targeted subscription: another user's profile is outside our drive. */
  public subscribeWebSocket(subject: string): void {
    if (!isAgentSubject(subject) || !this.isServerConnectedFor(subject)) return;
    const normalized = this.normalizeSubject(subject);

    if (
      normalized === unknownSubject ||
      normalized.includes('/commits/') ||
      isCommitSubject(normalized) ||
      this.isLocalOnlySubject(normalized)
    ) {
      return;
    }

    try {
      const ws = this.getWebSocketForSubject(subject);
      if (this.subscribers.has(normalized))
        ws?.subscribeAgentProfile(normalized);
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
      const ws = this.getWebSocketForSubject(driveSubject);
      ws?.subscribeIndexStatus(driveSubject);
    } catch (e) {
      console.error(e);
    }

    return () => {
      unsubEvent();

      try {
        const ws = this.getWebSocketForSubject(driveSubject);
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
        if (
          this.isServerConnectedFor(subject) &&
          !this.isLocalOnlySubject(subject)
        ) {
          this.getWebSocketForSubject(subject)?.subscribeLoroSync(subject);
        }
      },
      () => {
        if (
          this.isServerConnectedFor(subject) &&
          !this.isLocalOnlySubject(subject)
        ) {
          this.getWebSocketForSubject(subject)?.unsubscribeLoroSync(subject);
        }
      },
    );
  }

  /** Broadcast a Loro document update to all peers via WebSocket.
   *  Non-persistent real-time; persistence is via commits. */
  public broadcastLoroSyncUpdate(subject: string, update: Uint8Array): void {
    this.publishPeerEphemeral(subject, update, PeerEphemeralKind.DOC);
    if (!this.isServerConnectedFor(subject)) return;
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
    this.publishPeerEphemeral(subject, update, PeerEphemeralKind.LORO);
    if (!this.isServerConnectedFor(subject)) return;
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

  /**
   * The presence channel for viewing `subject`, when it isn't the drive's:
   * the nearest resource at or above it that carries its own `read` list.
   * That is what an invite or a share writes to, so it is where someone given
   * this one thing out of a drive they can't open can meet the people who
   * can. Host and guest compute it from the same resource data, so they land
   * in the same channel. `undefined` means the drive's channel covers it.
   * Only walks resources already loaded; a parent that isn't is the top.
   */
  public presenceScope(subject: string): string | undefined {
    let current = this.resources.get(this.normalizeSubject(subject));

    for (let depth = 0; current && depth < 32; depth++) {
      if (current.error || current.loading) return undefined;
      if (current.hasClasses(server.classes.drive)) return undefined;

      const readers = current.get(core.properties.read);

      if (Array.isArray(readers) && readers.length > 0) {
        return current.subject;
      }

      const parent = current.get(core.properties.parent);

      if (typeof parent !== 'string') return undefined;

      current = this.resources.get(this.normalizeSubject(parent));
    }

    return undefined;
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
        if (this.isServerConnectedFor(drive) && this.isLiveSyncedDrive(drive)) {
          this.presenceWebSocket(drive)?.subscribePresence(drive);
        }
      },
      () => {
        if (this.isServerConnectedFor(drive) && this.isLiveSyncedDrive(drive)) {
          this.presenceWebSocket(drive)?.unsubscribePresence(drive);
        }
      },
    );
  }

  /** Broadcast raw presence bytes (Loro EphemeralStore update) to a
   *  drive's presence subscribers. */
  public broadcastPresenceUpdate(drive: string, update: Uint8Array): void {
    this.publishPeerEphemeral(drive, update, PeerEphemeralKind.PRESENCE);
    if (!this.isServerConnectedFor(drive)) return;
    // Local-only drives and foreign-origin HTTP drives have no live
    // peers on the home websocket.
    if (!this.isLiveSyncedDrive(drive)) return;
    this.presenceWebSocket(drive)?.sendPresenceUpdate(drive, update);
  }

  private presenceWebSocket(drive: string): WSClient | undefined {
    return this.getWebSocketForSubject(drive);
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
    if (filtered.length === 0) {
      this.subscribers.delete(normalized);
      if (isAgentSubject(normalized))
        this.getWebSocketForSubject(normalized)?.unsubscribeAgentProfile(
          normalized,
        );
    } else this.subscribers.set(normalized, filtered);
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

  private pushCommitLog(
    entry: Omit<CommitLogEntry, 'id'>,
    loroUpdate?: Uint8Array,
  ): void {
    // Dedup by commitId so a `pending` entry transitions in place to `sent` /
    // `failed` once the push resolves, rather than producing two rows for the
    // same commit. Incoming commits without an outgoing pending counterpart
    // simply prepend.
    const existingIdx = entry.commitId
      ? this._commitLog.findIndex(e => e.commitId === entry.commitId)
      : -1;

    if (existingIdx >= 0) {
      // Status transition for an already-logged commit: keep its id (and so
      // its update bytes) and move it to the top so users see fresh status
      // changes first.
      const prior = this._commitLog[existingIdx];
      const merged: CommitLogEntry = { ...prior, ...entry };
      this._commitLog = [
        merged,
        ...this._commitLog.slice(0, existingIdx),
        ...this._commitLog.slice(existingIdx + 1),
      ];
    } else {
      const id = ulid();
      if (loroUpdate) this._commitLogUpdates.set(id, loroUpdate);
      this._commitLog = [{ ...entry, id }, ...this._commitLog];

      for (const dropped of this._commitLog.splice(50)) {
        this._commitLogUpdates.delete(dropped.id);
        this._commitLogSummaries.delete(dropped.id);
      }
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
        (commit.signature ? commitSubject(commit.signature) : undefined),
      hasLoroUpdate: !!commit.loroUpdate,
      destroy: !!commit.destroy,
      summary: this.summarizeCommit(commit),
      ...(extras.error !== undefined ? { error: extras.error } : {}),
    };
  }

  /**
   * Records a locally-signed but not-yet-pushed commit as `pending` in the
   * commit log. When the push resolves, {@link postCommit} reuses the same
   * `commitId` so the entry transitions in place to `sent` or `failed`.
   */
  public logPendingCommit(commit: Commit): void {
    this.pushCommitLog(
      this.buildCommitLogEntry(commit, 'outgoing', 'pending'),
      commit.loroUpdate,
    );
  }

  /** @internal Settle a commit that will never be POSTed (local-only
   *  drives sign locally). Transitions the `pending`
   *  entry `logPendingCommit` created so the Sync page doesn't show it
   *  as queued forever. */
  private peerListeners = new Set<
    (subject: string, frame: Uint8Array) => void
  >();

  public subscribePeerFrames(
    listener: (subject: string, frame: Uint8Array) => void,
  ): () => void {
    this.peerListeners.add(listener);

    return () => {
      this.peerListeners.delete(listener);
    };
  }

  public async destroyLocalResource(commit: Commit): Promise<void> {
    if (!this.clientDb)
      throw new Error('Local storage is required to delete this resource');
    await this.clientDb.applyPeerCommit(
      serializePeerCommit({ ...commit }, true),
    );
    this.publishPeerCommit(commit);
    this.removeResource(commit.subject);
  }

  public publishPeerCommit(commit: Commit): void {
    const frame = encodePeerCommit(0, serializePeerCommit({ ...commit }, true));
    for (const listener of this.peerListeners) listener(commit.subject, frame);
  }

  public receivePeerEphemeral(frame: Uint8Array): void {
    const message = decodePeerEphemeral(frame.subarray(1));
    if (!message) return;
    const map =
      message.kind === PeerEphemeralKind.DOC
        ? this.loroSyncSubscribers
        : message.kind === PeerEphemeralKind.PRESENCE
          ? this.presenceSubscribers
          : this.loroEphemeralSubscribers;
    this.dispatchLoroMessage(map, message.subject, message.payload);
  }

  private publishPeerEphemeral(
    subject: string,
    update: Uint8Array,
    kind: number,
  ): void {
    const agent = this.getAgent()?.subject;
    if (!agent) return;
    const frame = encodePeerEphemeral(kind, subject, agent, update);
    for (const listener of this.peerListeners) listener(subject, frame);
  }

  public logLocalOnlyCommitSettled(commit: Commit): void {
    this.pushCommitLog(
      this.buildCommitLogEntry(commit, 'outgoing', 'sent'),
      commit.loroUpdate,
    );
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
   * The properties a logged commit changed, computed when asked (the Sync
   * page) rather than on every save. The commit's `loroUpdate` is a delta, so
   * it is applied on top of the resource's own state at the version the delta
   * starts from (a fork of the live Loro doc), and the two are compared. A
   * genesis starts from an empty doc, so every property shows as `changed`.
   * Returns `undefined` when there is nothing to diff: no update bytes, the
   * resource is no longer loaded, or its history no longer reaches back that
   * far.
   */
  public getCommitPropertySummaries(
    entry: CommitLogEntry,
  ): CommitLogPropertySummary[] | undefined {
    if (this._commitLogSummaries.has(entry.id)) {
      return this._commitLogSummaries.get(entry.id);
    }

    const update = this._commitLogUpdates.get(entry.id);
    if (!update) return undefined;

    // A restored log can render before the lazy WASM module is ready.
    // Retry when it loads; do not cache "no properties" for this commit.
    if (!LoroLoader.isLoaded()) {
      LoroLoader.onReady(this.notifyCommitSummariesReady);

      return undefined;
    }

    const summaries = this.diffCommitProperties(entry.subject, update);
    this._commitLogSummaries.set(entry.id, summaries);

    return summaries;
  }

  private notifyCommitSummariesReady = (): void => {
    this.eventManager.emit(StoreEvents.CommitLogChanged, this.getCommitLog());
  };

  private diffCommitProperties(
    subject: string,
    update: Uint8Array,
  ): CommitLogPropertySummary[] | undefined {
    try {
      const start = LoroLoader.Loro.decodeImportBlobMeta(
        update,
        false,
      ).partialStartVersionVector;
      let prior: Uint8Array | undefined;

      if (start.length() > 0) {
        const doc = this.resources.get(subject)?.getLoroDoc();
        if (!doc) return undefined;
        prior = doc
          .forkAt(doc.vvToFrontiers(start))
          .export({ mode: 'snapshot' });
      }

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

      const acc = new Resource(subject);
      if (prior) acc.importLoroUpdate(prior);
      const priorEntries = entriesOf(acc);
      acc.importLoroUpdate(update);
      const currentEntries = entriesOf(acc);
      const summaries: CommitLogPropertySummary[] = [];

      for (const [prop, value] of currentEntries) {
        if (!commitLogValuesEqual(priorEntries.get(prop), value)) {
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

      return summaries.length > 0 ? summaries.slice(0, 20) : undefined;
    } catch (e) {
      console.warn('[getCommitPropertySummaries] failed:', e);

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
    if (!isBlobSubject(blobValue)) return;
    const hashHex = blobValue.replace(/^(atomic:blob:|did:ad:blob:)/, '');

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
    const url = `${this.getServerUrlForSubject(resource.subject)}/blob/${hashHex}`;
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
        this.getServerUrlForSubject(parent),
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
    const agentForDid = this.getAgent()!.subject;
    const useDid = !!agentForDid && isAgentSubject(agentForDid);

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
      await resource.set(BLOB, blobSubject(hash), false);
      await resource.set(
        server.properties.downloadUrl,
        `${this.getServerUrlForSubject(parent)}/download/files/${hash}`,
        false,
      );

      // Sign the genesis commit locally (its subject is already the cert DID,
      // so `signChanges` derives nothing), then STASH it on the resource —
      // mirrors `Store.newResource`. `save()` below moves the stashed genesis
      // into the outbox and drains it. (Stashing rather than enqueuing here
      // means a never-saved upload is never POSTed; here we always `save()`,
      // but the genesis MUST be stashed or `save()` has nothing to POST —
      // `signChanges` builds the genesis flag into the returned commit only,
      // so the genesis would otherwise be silently dropped.)
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
        commit.loroUpdate,
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
        commit.loroUpdate,
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
    const route = this.captureRoute(commit.subject);
    const ws = this.getWebSocketForEndpoint(endpoint);

    if (ws && ws.readyState === WebSocket.OPEN) {
      try {
        return await ws.postCommit(commit);
      } catch (e) {
        if (e instanceof RequestCancelledError) throw e;
        // A server refusal is an answer, not a broken transport. Retrying the
        // same rejected commit over HTTP only duplicates the failed write.
        const message = e instanceof Error ? e.message : String(e);
        const code = e instanceof AtomicError ? e.code : undefined;

        if (
          isUnrecoverableCommitError(message, code) ||
          isTerminalCommitError(message, code)
        ) {
          throw e;
        }

        // Fall through to HTTP — a broken WS shouldn't block saves while
        // the reconnect timer is still backing off. The WS error already
        // surfaced in console; the HTTP path will produce its own.
        if (!(e instanceof ServerRestartError)) {
          console.warn('[Store.postCommit] WS path failed, using HTTP:', e);
        }
      }
    }

    if (!route.current())
      throw new RequestCancelledError('Commit destination changed');

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

    // Claim the batch before children recursively drain their own saves.
    this.batchedResources.delete(subject);

    try {
      for (const resourceSubject of subjects) {
        const resource = this._resources.get(resourceSubject);
        await resource?.save();
        subjects.delete(resourceSubject);
      }
    } catch (error) {
      this.batchedResources.set(
        subject,
        new Set([...subjects, ...(this.batchedResources.get(subject) ?? [])]),
      );
      throw error;
    }
  }

  public async importJsonAD(
    jsonADString: string,
    options: ImportJsonADOptions,
  ): Promise<void> {
    const url = new URL(
      endpoints.import,
      this.getServerUrlForSubject(options.parent),
    );
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

    try {
      const resource = await this.getResource(subject);
      await loadResourceTreeInner(resource, treeTemplate);
    } catch (error) {
      // Preloading is optional work for a page that may already be leaving.
      // Keep real fetch failures visible, but stop a cancelled traversal.
      if (!(error instanceof RequestCancelledError)) throw error;
    }
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

  /** Immutable read status and a stable mutation handle, replaced on notify. */
  private snapshots = new Map<string, ResourceSnapshot>();

  /** Subject → the last state written to the local DB: which database, a
   *  content stamp, and the write itself. While the write is in flight it also
   *  holds the exact bytes, so a durable caller can match on content rather
   *  than on the stamp. Entries are dropped by `removeResource` and by a
   *  failed write. */
  private lastPersisted = new Map<string, PersistedState>();

  /**
   * Write `jsonAd` + `snapshot` for `subject` to `db`, unless that state is
   * already written or being written there, in which case this returns that
   * write. `addResource` and `Resource.persistToClientDb` both go through
   * here, so an online save that the drain already persisted does not write
   * the same row (an index rebuild plus an fsync, ~9ms) a second time.
   *
   * Deliberately a content stamp rather than `lastCommit`: local edits and
   * merges change state without advancing it, and the stamp covers the Loro
   * snapshot so a CRDT-only change still writes. A stamp collision would skip
   * one cache write, which the server copy repairs. `exact` callers cannot
   * afford that (an offline edit has no server copy), so they only reuse a
   * write that is still in flight with byte-identical content.
   *
   * @internal
   */
  public persistState(
    db: ClientDbWorker,
    subject: string,
    jsonAd: string,
    snapshot?: Uint8Array,
    {
      exact = false,
      outbox,
    }: {
      exact?: boolean;
      /** Outbox rows to write in the same worker message and flush. A write
       *  carrying them is never skipped as a duplicate. */
      outbox?: ClientDbOutboxWrite;
    } = {},
  ): Promise<void> {
    const stamp = hashPersistedState(jsonAd, snapshot);
    const last = this.lastPersisted.get(subject);

    if (!outbox && last && last.db === db && last.stamp === stamp) {
      if (!exact) return last.done;

      if (
        last.inFlight &&
        last.inFlight.jsonAd === jsonAd &&
        bytesEqual(last.inFlight.snapshot, snapshot)
      ) {
        return last.done;
      }
    }

    const entry: PersistedState = {
      db,
      stamp,
      done: Promise.resolve(),
      inFlight: { jsonAd, snapshot },
    };
    entry.done = db
      .putResourceWithSnapshot(subject, jsonAd, snapshot, outbox)
      .then(
        () => {
          entry.inFlight = undefined;
        },
        e => {
          // Failed write: forget it so the next attempt is not skipped as a
          // duplicate of a write that never landed.
          if (this.lastPersisted.get(subject) === entry) {
            this.lastPersisted.delete(subject);
          }

          throw e;
        },
      );
    this.lastPersisted.set(subject, entry);

    return entry.done;
  }

  private snapshotReadDepth = 0;

  public getResourceSnapshot(
    subject: string,
    opts: FetchOpts = {},
  ): ResourceSnapshot {
    let r: Resource;
    this.snapshotReadDepth++;

    try {
      r = this.getResourceLoading(subject, opts);
    } finally {
      this.snapshotReadDepth--;
    }

    const key = this.normalizeSubject(r.subject);
    let snap = this.snapshots.get(key);

    if (!snap || snap.resource !== r.__internalObject) {
      snap = captureResourceSnapshot(r);
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
  public waitForServerConnected(
    timeoutMs: number,
    subject = this.drive,
  ): Promise<boolean> {
    if (this.isServerConnectedFor(subject)) return Promise.resolve(true);

    return new Promise<boolean>(resolve => {
      let unsub: (() => void) | undefined;
      const timer = setTimeout(() => {
        unsub?.();
        resolve(false);
      }, timeoutMs);

      unsub = this.on(StoreEvents.ConnectionChanged, () => {
        if (this.isServerConnectedFor(subject)) {
          clearTimeout(timer);
          unsub?.();
          resolve(true);
        }
      });
    });
  }

  private bulkRefreshables = new Set<WeakRef<{ refresh(): Promise<void> }>>();

  /** Collections register here so that a bulk pull, which stores resources in
   *  the database worker without announcing each one, can tell them to ask the
   *  local database again. Held weakly: a collection nobody uses is not kept
   *  alive for it. */
  public registerBulkRefreshable(collection: {
    refresh(): Promise<void>;
  }): void {
    this.bulkRefreshables.add(new WeakRef(collection));
  }

  /** Resources were stored without a notification each (see
   *  `WSClient.applyPulledStates`): re-run the queries that are still alive. */
  public notifyBulkApplied(): void {
    for (const ref of this.bulkRefreshables) {
      const collection = ref.deref();

      if (!collection) {
        this.bulkRefreshables.delete(ref);
        continue;
      }

      collection.refresh().catch(() => undefined);
    }
  }

  /**
   * The lenses this store knows, by the properties they touch. Resources
   * derive values through them when their Loro doc is materialized (see
   * `lens.ts`). Filled as Lens resources load; `loadLenses` brings in a
   * drive's lenses.
   */
  public readonly lenses = new LensIndex();

  /**
   * Make a loaded Lens active and re-materialize the loaded resources that
   * hold one of its properties.
   *
   * It applies only when its ID matches its content and its `parent` is the
   * parent of the property it writes (`lensTo`): a lens never applies across an
   * ontology it does not own. Anything wrong just means the lens is not
   * applied; it never fails a load.
   */
  public async activateLens(resource: Resource): Promise<void> {
    try {
      const from = resource.get(core.properties.lensFrom);
      const to = resource.get(core.properties.lensTo);
      const parent = resource.get(core.properties.parent);
      const transform = readTransformValue(
        resource.get(core.properties.lensTransform),
      );

      if (
        typeof from !== 'string' ||
        typeof to !== 'string' ||
        typeof parent !== 'string' ||
        !verifyLensId(resource.subject, from, to, transform)
      ) {
        return;
      }

      const canonical = canonicalizeScheme(resource.subject);
      const existing = this.lenses.get(canonical);

      if (existing) return;

      // `lensTo` must be known to read its parent. Only content-addressed
      // properties are fetched: a lens must not make the store fetch any URL.
      const target = isPropertySubject(to)
        ? await this.getResource(to)
        : this.resources.get(canonicalizeScheme(to));
      const targetParent = target?.get(core.properties.parent);

      if (
        typeof targetParent !== 'string' ||
        canonicalizeScheme(targetParent) !== canonicalizeScheme(parent)
      ) {
        return;
      }

      this.lenses.insert({
        id: canonical,
        from: canonicalizeScheme(from),
        to: canonicalizeScheme(to),
        transform: parseTransform(transform),
        parent: canonicalizeScheme(parent),
      });

      this.rematerializeLensed(
        canonicalizeScheme(from),
        canonicalizeScheme(to),
      );
    } catch {
      // An inactive lens derives nothing; reading is unaffected.
    }
  }

  /** Re-derive the loaded resources that hold one of these properties. */
  private rematerializeLensed(...props: string[]): void {
    for (const resource of this.resources.values()) {
      if (resource.refreshDerivedValues(props)) {
        void this.notify(resource);
      }
    }
  }

  /** Lets subscribers know that a resource has been changed. */
  private async notify(resource: Resource): Promise<void> {
    // A React snapshot read may initialize a missing resource. Other mounted
    // readers must not receive a state update inside that render.
    if (this.snapshotReadDepth > 0) {
      queueMicrotask(() => void this.notify(resource));

      return;
    }

    // Bump snapshot tuple identity so `useSyncExternalStore` consumers
    // re-render. The Resource itself is mutated in place, but a fresh
    // outer `{resource}` object is `!== ` the previous one, which is
    // all `Object.is` needs.
    const key = this.normalizeSubject(resource.subject);
    this.snapshots.set(key, captureResourceSnapshot(resource));

    if (isLensSubject(key)) {
      void this.activateLens(resource);
    }

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

interface PersistedState {
  db: ClientDbWorker;
  stamp: number;
  done: Promise<void>;
  inFlight?: { jsonAd: string; snapshot?: Uint8Array };
}

function bytesEqual(a?: Uint8Array, b?: Uint8Array): boolean {
  if (a === b) return true;
  if (!a || !b || a.length !== b.length) return false;

  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }

  return true;
}

/** Whether a resource's current state belongs in the local database at all.
 *
 *  A Collection is a derived query result, not a record: a page is either
 *  assembled from `queryLocalDb` over the index or fetched from the server, and
 *  neither ever reads it back out of the local database. Writing it there costs
 *  a full index rebuild and an fsync for something nothing reads — and because
 *  collections are deliberately exempt from `addResource`'s `lastCommit` skip,
 *  they are re-added (and so re-written) on every refresh. Building one table
 *  from a template wrote a single collection page seven times.
 *
 *  The rest are placeholders or half-formed state: those are persisted by the
 *  save path once they are real. */
function isPersistableState(resource: Resource): boolean {
  return (
    !resource.hasClasses(collections.classes.collection) &&
    !resource.loading &&
    !resource.new &&
    !resource.hasPendingCommits &&
    !resource.get(core.properties.incomplete)
  );
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

/** Captured scalar read state; `resource` remains the live mutation handle. */
export interface ResourceSnapshot<C extends OptionalClass = UnknownClass> {
  readonly resource: Resource<C>;
  readonly readState: ResourceReadState;
  readonly ready: boolean;
  readonly loading: boolean;
  readonly error: Error | undefined;
}

function captureResourceSnapshot(resource: Resource): ResourceSnapshot {
  return Object.freeze({
    resource: resource.__internalObject,
    readState: resource.readState,
    ready: resource.isReady(),
    loading: resource.loading,
    error: resource.error,
  });
}
