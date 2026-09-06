import type {
  LoroDoc,
  LoroList,
  UndoManager as LoroUndoManager,
  VersionVector,
} from 'loro-crdt';
import { enableLoro, LoroLoader } from './loro-loader.js';
import { decodeB64, encodeB64 } from './base64.js';
import { EventManager } from './EventManager.js';
import { decodeGenesisCert, genesisSignerDid } from './genesis.js';
import type { Agent } from './agent.js';
import { Client } from './client.js';
import type { Collection } from './collection.js';
import { CollectionBuilder } from './collectionBuilder.js';
import { CommitBuilder, Commit } from './commit.js';
import { perfSpan } from './perf-trace.js';
import { validateDatatype, datatypeTag, Datatype } from './datatypes.js';
import { isUnauthorized } from './error.js';
import { commits } from './ontologies/commits.js';
import { core } from './ontologies/core.js';
import { server } from './ontologies/server.js';

import {
  getKnownClassDefBySubject,
  getKnownNameBySubject,
  type InferTypeOfValueInTriple,
  type OptionalClass,
  type QuickAccessPropType,
} from './ontology.js';
import type { ChangeSource, Store } from './store.js';
import {
  copyResource,
  forkResource,
  isFork,
  mergeFork,
  type MergeForkOptions,
} from './forks.js';
import { GENESIS, properties, instances } from './urls.js';
import { isCommitSubject } from './local-outbox.js';
import {
  valToArray,
  type JSONValue,
  type JSONArray,
  type JSONObject,
  type AtomicValue,
} from './value.js';

/** Contains the PropertyURL / Value combinations */
export type PropVals = Map<string, AtomicValue>;

/**
 * Propvals the server derives and ships alongside a resource, which must never
 * be written into its CRDT.
 *
 * They all have another source of truth: `lastCommit` is commit metadata,
 * `createdAt` and `createdBy` come from the genesis certificate (see
 * {@link Resource.getCreatedBy}). Writing one into Loro produces a LOCAL
 * operation, and a local operation means a dirty subject and a commit — for a
 * value the client never authored. On a resource you may write that is a
 * redundant commit per hydration; on one you may only READ, the server refuses
 * it forever, which is how an invitee who had written nothing ended up with a
 * blocked outbox entry and a permanent "changes pending".
 *
 * They stay in the read cache, so `resource.get()` and JSON-AD round-trips are
 * unaffected — which is why every `serverManaged` preservation list below has
 * to include them.
 */
const DERIVED_BY_SERVER: ReadonlySet<string> = new Set<string>([
  properties.commit.lastCommit,
  commits.properties.createdAt,
  properties.createdBy,
]);

/** True for a propval the server derives — see {@link DERIVED_BY_SERVER}. */
const isDerivedByServer = (prop: string): boolean =>
  DERIVED_BY_SERVER.has(prop);

export interface MergeOptions {
  replaceLoroDocs?: boolean;
  /**
   * Property keys to skip when merging: keep local values and do not delete them
   * when missing from the remote resource.
   */
  omitKeysFromMerge?: string[];
}
/**
 * If a resource has no subject, it will have this subject. This means that the
 * Resource is not saved or fetched.
 */
export const unknownSubject = 'unknown-subject';

/**
 * Outcome of {@link Resource.save}:
 *  - `'persisted'` — the server acknowledged the commit.
 *  - `'offline'`   — server unreachable; saved locally, drain retries
 *                    on reconnect (also returned for a child queued
 *                    behind an unsaved parent).
 *  - `'noop'`      — nothing to save.
 */
export type SaveResult = 'persisted' | 'offline' | 'noop';

/**
 * Origin tag attached to Loro commits the runtime writes for housekeeping
 * (datatype-tag mirroring, post-save bookkeeping, etc.). Commits with this
 * origin are excluded from the `UndoManager` so they don't consume the
 * user's undo presses — see {@link Resource.ensureUndoManager}.
 *
 * `atomic:` is reserved as the namespace; pick further-specific origins
 * (e.g. `atomic:system:datatypes`) if/when undo behavior needs to
 * differentiate them.
 */
export const SYSTEM_COMMIT_ORIGIN = 'atomic:system';

/**
 * True for the runtime's internal Loro change-message tokens: `c-<ulid>`
 * (per-Atomic-commit, written at drain-time export) and `e-<ulid>`
 * (per-logical-edit, written by the list/undo mutation methods). These
 * exist purely so `getLoroHistory` can bucket ops into versions — they
 * must never be surfaced as human-facing metadata (e.g. `getCreatedBy`
 * reads the genesis change message as the creator-agent carrier).
 */
export function isInternalCommitToken(message: string): boolean {
  return /^[ce]-/.test(message);
}

let editTokenCounter = 0;

/**
 * Unique-within-oplog token for a locally-authored logical edit. Wall-clock
 * base36 plus a monotonic counter: unique across reloads (a rehydrated doc
 * carries its old tokens) without pulling in a ulid dependency here.
 */
function nextEditToken(): string {
  editTokenCounter += 1;

  return `e-${Date.now().toString(36)}-${editTokenCounter.toString(36)}`;
}

export enum ResourceEvents {
  LocalChange = 'local-change',
  LoadingChange = 'loading-change',
}

type ResourceEventHandlers = {
  [ResourceEvents.LocalChange]: (prop: string, value: JSONValue) => void;
  [ResourceEvents.LoadingChange]: (loading: boolean) => void;
};

/**
 * Loro OpLog change timestamps are Unix **seconds** (see loro-crdt `Change.timestamp`).
 * The history UI uses milliseconds. Some older snapshots may incorrectly carry ms in the
 * oplog; treat values >= 1e12 as already ms.
 */
export function normalizeLoroChangeTimestampMs(timestamp: number): number {
  if (timestamp <= 0) {
    return timestamp;
  }

  return timestamp >= 1_000_000_000_000 ? timestamp : timestamp * 1000;
}

/**
 * Describes an Atomic Resource, which has a Subject URL and a bunch of Property
 * / Value combinations.
 *
 * Create new resources using `store.createResource()`.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export class Resource<C extends OptionalClass = any> {
  // WARNING: WHEN ADDING A PROPERTY, ALSO ADD IT TO THE CLONE METHOD

  /** If the resource could not be fetched, we put that info here. */
  public error?: Error;
  /** If the commit could not be saved, we put that info here. */
  public commitError?: Error;
  /** Is true for locally created, unsaved resources */
  public new: boolean;
  /**
   * Every commit that has been applied should be stored here, which prevents
   * applying the same commit twice
   */
  public appliedCommitSignatures: Set<string> = new Set();

  private _loading = false;
  private _dirty = false;

  #commitBuilder: CommitBuilder;
  private _subject: string;
  /** Memoized read cache derived from Loro. Rebuilt lazily when #cacheDirty. */
  #cache: Record<string, JSONValue> = Object.create(null);
  /** True when Loro has been modified but #cache hasn't been rebuilt yet. */
  #cacheDirty = false;
  private _auxValues: Map<string, AtomicValue> = new Map();
  /** Raw Loro snapshot bytes, kept separate from properties. Not a propval. */
  private _loroSnapshotBytes?: Uint8Array | string;

  /** A genesis commit signed by `store.newResource` to derive the DID
   *  subject, held HERE (not in the outbox) until the first `save()`.
   *  Keeping it off the outbox means a created-but-never-saved resource
   *  — e.g. an unfilled table placeholder row, which `TableNewRow`
   *  creates on mount — is never POSTed: it's just GC'd when discarded.
   *  `save()` moves it into the outbox to drain. See sign-at-drain. */
  private _pendingGenesis?: Commit;

  /** Loro CRDT document backing this resource. Lazily initialized. */
  private _loroDoc?: LoroDoc;
  /** The "properties" map inside the LoroDoc. Typed as any because the LoroMap generic causes issues with set(). */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private _loroMap?: any;
  /** Loro UndoManager for undo/redo support. Lazily initialized. */
  private _loroUndoManager?: LoroUndoManager;
  /** Version vector at the time of last save, used to export deltas */
  private _loroVersionAtLastSave?: VersionVector;

  /**
   * The id of the most recently applied commit (`did:ad:commit:{sig}`).
   * Stamp for genesis detection and echo-dedup; not a fetchable resource.
   * Protected from being clobbered by remote merges.
   */
  private _lastCommit: string | undefined;

  /** Refcount of in-flight `save()` calls. Bumped in `save()` entry
   * and dropped in the matching `finally`. */
  private _saveDepth = 0;

  /** True while at least one `save()` is in flight. Lets the store
   * report this in `pendingDirtyCount` so editor exit paths
   * (Escape/blur) don't return before the commit lands. */
  public get isSaving(): boolean {
    return this._saveDepth > 0;
  }

  private _store?: Store;
  private eventManager = new EventManager<
    ResourceEvents,
    ResourceEventHandlers
  >();

  public constructor(subject: string, newResource?: boolean) {
    if (typeof subject !== 'string') {
      // Check if the subject is an object with an @id property
      if (subject && typeof subject === 'object' && '@id' in subject) {
        throw new Error(
          'Found named nested resource instead of subjects, this probably means your server is outdated.',
        );
      }

      throw new Error(
        'Invalid subject given to resource, must be a string, found ' +
          typeof subject,
      );
    }

    this.new = !!newResource;
    this._subject = subject;
    this.#commitBuilder = new CommitBuilder(subject);
  }

  public get __internalObject(): Resource<C> {
    return this;
  }

  /**
   * Is true when the Resource is currently being fetched, awaiting a response
   * from the Server.
   * Use `resource.on(ResourceEvents.LoadingChange, (loading) => {})` to listen for changes.
   */
  public get loading(): boolean {
    if (this._loading) return true;

    // A resource with buffered Loro snapshot bytes but no doc CAN be readable
    // if the cache has propvals already (typical post-`parseMetaTags`: the
    // JSON-AD-initial meta tag flattens propvals into `#cache` and the
    // `loroUpdate` field — if present — lands in `_loroSnapshotBytes`).
    // Only treat the buffered-without-doc state as "loading" when there's
    // genuinely nothing to render — empty cache means `get(prop)` would
    // return undefined for every prop until Loro hydrates the buffer.
    if (!this._loroDoc) {
      const buf = this._loroSnapshotBytes;
      const hasBuffered =
        (buf instanceof Uint8Array && buf.length > 0) ||
        (typeof buf === 'string' && buf.length > 0);

      // Buffered bytes only count as "still loading" while Loro WASM ISN'T
      // ready — that's the only time they can't materialize. Once Loro IS
      // loaded, the very next `get()`/`getEntries()` builds the doc and applies
      // the buffer, so the resource is effectively renderable; reporting
      // `loading` then sticks a spinner on top of real data (observed: a Drive
      // with `isA` + 6 entries rendering a spinner). So: only buffered AND
      // Loro-not-loaded AND a non-renderable (skeleton-only) cache is loading.
      // A WS UPDATE stamps `lastCommit` from the frame's commit-id while the
      // snapshot is still buffered, so a lone `lastCommit` is NOT renderable;
      // treating it as loaded renders the bare subject ("flash of wrong state")
      // and makes consumers that gate on `isReady()` (the sidebar) show empty.
      if (hasBuffered && !LoroLoader.isLoaded()) {
        // Object.create(null) #cache → Object.keys is the cheap own-prop scan.
        const hasRenderable = Object.keys(this.#cache).some(
          k =>
            !isDerivedByServer(k) &&
            k !== core.properties.parent &&
            k !== 'https://atomicdata.dev/properties/drive',
        );
        if (!hasRenderable) return true;
      }
    }

    return false;
  }

  /** The subject URL of the resource */
  public get subject(): string {
    return this._subject;
  }

  /** Stable reference to the resource, even when the resource is proxied, for example when using @tomic/react or @tomic/svelte. */
  public get stable(): Resource<C> {
    return this.__internalObject;
  }

  /** A human readable title for the resource, returns first of either: name, shortname, filename or subject */
  public get title(): string {
    return (this.get(core.properties.name) ??
      this.get(core.properties.shortname) ??
      this.get(server.properties.filename) ??
      this.get(core.properties.description) ??
      this.subject) as string;
  }

  /**
   * Dynamic prop accessor, only works for known properties registered via an ontology.
   * @example const description = resource.props.description
   */
  public get props(): QuickAccessPropType<C> {
    const defaultProps = {
      parent: core.properties.parent,
      isA: core.properties.isA,
      write: core.properties.write,
      read: core.properties.read,
    };

    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const innerThis = this;

    const defs = this.getClasses()
      .map(c => getKnownClassDefBySubject(c))
      .filter(def => def !== undefined);

    const getPropSubject = (name: string) => {
      // Check if the property is a default property
      if (name in defaultProps) {
        return defaultProps[name as keyof typeof defaultProps];
      }

      // Check if the property is defined in any of the classes
      for (const def of defs) {
        const value = def[name];

        if (value !== undefined) {
          return value;
        }
      }

      // Check if any known property on the resource matches the requested name.
      for (const [key] of this.getEntries()) {
        const propName = getKnownNameBySubject(key);

        if (propName === name) {
          return key;
        }
      }
    };

    return new Proxy({} as QuickAccessPropType<C>, {
      get(_target, propName) {
        const propSubject = getPropSubject(propName as string);

        return innerThis.get(propSubject ?? '');
      },

      set(_target, propName, value) {
        const propSubject = getPropSubject(propName as string);

        if (!propSubject) {
          throw new Error(
            `Unable to set property: ${propName.toString()} on ${innerThis.subject}. The property's subject could not be found.`,
          );
        }

        innerThis.set(propSubject, value, false);

        return true;
      },
    });
  }

  /** Returns `true` when there are locally-signed commits waiting to be pushed. */
  public get hasPendingCommits(): boolean {
    return this._store?.outbox.hasPending(this.subject) ?? false;
  }

  private get store(): Store {
    if (!this._store) {
      console.error(`Resource ${this.subject} has no store`);
      throw new Error('Resource has no store');
    }

    return this._store;
  }

  public set loading(loading: boolean) {
    if (this._loading === loading) return;

    this._loading = loading;
    this.eventManager.emit(ResourceEvents.LoadingChange, loading);
  }
  public on<T extends ResourceEvents>(
    event: T,
    callback: ResourceEventHandlers[T],
  ) {
    return this.eventManager.register(event, callback);
  }

  /** @internal */
  public setStore(store: Store): void {
    this._store = store;
  }

  /** Funnel `this` through the store's unified ingress.
   *  Defaults `subject` to `this.subject`; pass an override only
   *  for the post-genesis subject-rename case. */
  public applyToStore(
    source: ChangeSource,
    opts: { subject?: string; commitId?: string } = {},
  ): void {
    this.store.applyIncoming({
      subject: opts.subject ?? this.subject,
      resource: this,
      source,
      ...(opts.commitId !== undefined ? { commitId: opts.commitId } : {}),
    });
  }

  /** Returns true if a LoroDoc has been initialized for this resource. */
  public hasLoroDoc(): boolean {
    return this._loroDoc !== undefined;
  }

  /**
   * Returns the LoroDoc backing this resource, creating one if needed.
   * Returns undefined if Loro is not loaded.
   */
  public getLoroDoc(): LoroDoc | undefined {
    if (!LoroLoader.isLoaded()) {
      return undefined;
    }

    if (!this._loroDoc) {
      const { LoroDoc: LoroDocClass } = LoroLoader.Loro;
      this._loroDoc = new LoroDocClass();
      // Match the server (`lib/src/loro.rs`): record per-change Unix seconds on commit.
      this._loroDoc.setRecordTimestamp(true);
      this._loroMap = this._loroDoc.getMap('properties');

      // If the resource has a persisted Loro snapshot, import it.
      const stored = Resource.decodeStoredSnapshot(this._loroSnapshotBytes);
      const initializedFromSnapshot = !!stored;

      if (stored) {
        this._loroDoc.import(stored);
      } else {
        for (const [key, value] of Object.entries(this.#cache)) {
          if (!isDerivedByServer(key)) {
            this.loroSetProperty(key, value);
          }
        }
      }

      // Heal: a Loro snapshot may be stale relative to the JSON-AD propvals
      // that arrived alongside it (the server's index can include properties
      // — e.g. `parent`, `isA` — that the resource's own snapshot was
      // produced before, or that the snapshot author never wrote into Loro).
      // Without this pass, those propvals get silently dropped when
      // `rebuildCacheFromLoro` below overwrites `#cache` with the snapshot's
      // contents only, and consumers see `resource.get(parent)` as
      // `undefined` for resources whose hierarchy is fully discoverable from
      // the JSON-AD payload. Write any cache key absent from the imported
      // doc into Loro before the cache rebuild — only when we actually
      // initialised from a snapshot, so the no-snapshot path's prior
      // behaviour is unchanged.
      if (initializedFromSnapshot && this._loroMap) {
        for (const [key, value] of Object.entries(this.#cache)) {
          if (!isDerivedByServer(key) && this._loroMap.get(key) === undefined) {
            this.loroSetProperty(key, value);
          }
        }

        // The heal writes above are HYDRATION, not user edits — they copy
        // propvals the server already sent alongside this very snapshot.
        // Flush them now, tagged with the system origin, for two reasons:
        // the dirty-marking subscriber below ignores that origin (so merely
        // OPENING someone else's resource can't enqueue a write we have no
        // rights to make), and committing before the save cursor is read
        // keeps them out of the next delta export. Guarded on pending ops
        // because `setRecordTimestamp(true)` makes even an empty commit
        // write a commit-point op and advance `oplogVersion`.
        if (this._loroDoc.getPendingTxnLength() > 0) {
          this._loroDoc.commit({ origin: SYSTEM_COMMIT_ORIGIN });
        }
      }

      this.rebuildCacheFromLoro();
      this.#cacheDirty = false;
      // Initialize the export cursor:
      //   - If the outbox holds a dirty bit for this subject, the
      //     ops in the loaded snapshot weren't all server-acked yet
      //     (offline-edit-then-reload case). Leave the cursor
      //     undefined so the next drain exports a full snapshot —
      //     server idempotently replays the ops it already has.
      //   - Otherwise (clean hydrate from clientDb, or an existing
      //     resource that wasn't dirty), set the cursor to current
      //     oplogVersion so subsequent edits export as deltas from
      //     this point.
      const outboxKnowsThisSubjectIsDirty =
        this._store?.outbox.hasPending(this.subject) ?? false;
      this._loroVersionAtLastSave =
        !outboxKnowsThisSubjectIsDirty &&
        (initializedFromSnapshot || (!this.new && !this._dirty))
          ? this._loroDoc.oplogVersion()
          : undefined;

      // Drained the buffer — `loading` getter now returns false (assuming
      // `_loading` was false). Emit `LoadingChange(false)` so subscribers
      // (useResource → useTitle, etc.) re-render and pick up the
      // freshly-materialized data. Without this, a resource that arrived
      // via SYNC_PUSH before Loro was ready would stay stuck on its
      // loading indicator until some other event happens to fire.
      if (initializedFromSnapshot) {
        // Materialized from a snapshot → the content is now available. If it's
        // RENDERABLE (has a class), clear any `_loading` flag that was set
        // before the buffer could apply — a snapshot buffered before Loro WASM
        // was ready leaves `getResourceLoading`'s `_loading=true` in place, and
        // the top-of-getter `if (this._loading)` would otherwise keep reporting
        // loading and stick a spinner on top of the real data (observed: a
        // Drive with isA + 6 entries). Gate on the class so an INCOMPLETE
        // snapshot (no isA) stays loading for the store's refetch guard.
        if (this._loading && this.#cache[core.properties.isA] !== undefined) {
          this._loading = false;
        }

        this.eventManager.emit(ResourceEvents.LoadingChange, this.loading);
      }

      // Sign-at-drain: a local Loro op marks the subject dirty in the
      // outbox. Provenance decides what counts as "local": a peer's ops
      // arrive as `by: 'import'` and the runtime's own housekeeping
      // writes carry `SYSTEM_COMMIT_ORIGIN`, so only user-driven `set()`
      // calls get through.
      //
      // Skip subjects we don't own:
      // - `did:ad:commit:*` are commit-detail resources materialized
      //   locally for the Sync page; the server creates them on apply
      //   and there's nothing to POST.
      // - External HTTP subjects (atomicdata.dev/* etc.) belong to
      //   another domain. POSTing them returns "Subject of commit
      //   should be sent to other domain."
      this._loroDoc.subscribe(batch => {
        // Only genuine local edits enqueue. `import` (a peer's ops) and
        // `checkout` (history scrub) are not writes of ours, and anything
        // tagged with the system origin is runtime housekeeping —
        // hydration, heal, datatype tags, post-ack bookkeeping — which
        // replays state the server already has.
        if (batch.by !== 'local') return;
        if (batch.origin?.startsWith(SYSTEM_COMMIT_ORIGIN)) return;
        if (!this._store) return;
        if (isCommitSubject(this.subject)) return;
        // A resource still under construction (created, not yet `save()`d):
        // its property writes belong to the genesis commit, which is signed and
        // stashed at creation and drained by `save()`. Marking it dirty here
        // would enqueue a phantom incremental commit alongside the genesis.
        // Keyed on `new` (cleared once the genesis is signed), NOT on a subject
        // scheme — the resource carries its real `did:ad:` from birth.
        if (this.new) return;
        // `_new:` placeholders (the interactive New-Resource form / any
        // `store.createSubject()` caller, as opposed to `store.newResource()`
        // which mints a real DID up front) can only be synced by first
        // deriving their real subject via `signChanges` — that's what
        // `_saveInner`'s explicit-save path does. `this.new` is supposed to
        // gate that window, but it can be reset by unrelated reconciliation
        // (e.g. `applyToStore` merging in a fetch response) before the
        // resource is actually complete. Without this, a `_new:` subject
        // reaches the plain incremental-commit path, the server rejects it
        // (it was never genesis'd — often missing required properties too),
        // the terminal-drop handler refetches it, that refetch can reset
        // `new` again, and the next local edit repeats the cycle.
        if (this.subject.startsWith('_new:')) return;
        if (!this._store.isOwnedSubject(this.subject)) return;
        // Local-only drives never drain — their saves persist to
        // clientDb directly (see `saveLocalOnly`). Marking dirty here
        // would strand an entry the drain can only fail on.
        if (this._store.isLocalOnlySubject(this.subject)) return;
        // Skip when offline: `pendingDirtyCount > 0` is the canonical
        // "edit is durable" signal. Marking dirty here while offline
        // would race the async `saveOffline` clientDb write — a
        // page reload between this synchronous `markDirty` and the
        // OPFS persist landing would lose the edit. `_saveInner`'s
        // offline branch awaits `saveOffline` and only then calls
        // `markDirty`, so the count rising correctly implies the
        // edit is in clientDb.
        if (!this._store.serverConnected) return;
        this._store.outbox.markDirty(this.subject);
      });
    }

    return this._loroDoc;
  }

  /** Returns the Loro properties map, or undefined if Loro isn't loaded */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private getLoroMap(): any {
    if (!this._loroMap) {
      this.getLoroDoc();
    }

    return this._loroMap;
  }

  private applyRawValue(prop: string, val: AtomicValue): void {
    if (isDerivedByServer(prop)) {
      if (val === undefined) {
        delete this.#cache[prop];
      } else {
        this.#cache[prop] = val as JSONValue;
      }

      return;
    }

    if (prop === commits.properties.loroUpdate) {
      // For a Commit resource (`did:ad:commit:<sig>`), `loroUpdate` is a
      // BINARY PROPERTY OF THE COMMIT — the snapshot bytes for the
      // *committed* resource, not the commit's own Loro state. Importing
      // those bytes into the commit's Loro doc would overwrite the
      // commit's propvals (isA=Commit, signature, signer, etc.) with the
      // committed resource's propvals (e.g. isA=Message, parent, …),
      // which is exactly what `did:ad:commit:` pages showed before.
      //
      // Keep the bytes in `_auxValues` so they round-trip on `toObject`
      // and `getEntries`, but don't touch `_loroSnapshotBytes`.
      if (this._subject.startsWith('did:ad:commit:')) {
        if (val === undefined) {
          this._auxValues.delete(prop);
        } else if (val instanceof Uint8Array) {
          this._auxValues.set(prop, val);
        } else if (typeof val === 'string') {
          this._auxValues.set(prop, decodeB64(val));
        }

        return;
      }

      if (val === undefined) {
        this._loroSnapshotBytes = undefined;
        this.resetLoroState();

        return;
      }

      if (!(val instanceof Uint8Array) && typeof val !== 'string') {
        throw new Error('loroUpdate must be a Uint8Array or base64 string');
      }

      this._loroSnapshotBytes = val;

      // If a Loro doc already exists, merge the incoming snapshot INTO it.
      // Tearing the doc down and rebuilding would allocate a fresh peer on
      // the next getLoroDoc(), making subsequent local ops concurrent with
      // stored state (silent LWW drop). If no doc exists yet, do nothing —
      // getLoroDoc() will build one from _loroSnapshotBytes on first access.
      if (this._loroDoc) {
        const bytes =
          val instanceof Uint8Array ? val : decodeB64(val as string);

        try {
          this._loroDoc.import(bytes);
          this.rebuildCacheFromLoro();
          this.#cacheDirty = false;
          this.initLoroSaveCursorIfFresh();
        } catch (e) {
          console.warn(
            `[Resource] Loro import on hydration failed for ${this.subject}:`,
            e,
          );
        }
      }

      return;
    }

    // Binary values go to auxValues (Loro can't store raw Uint8Array)
    if (val instanceof Uint8Array) {
      this._auxValues.set(prop, val);

      return;
    }

    // If Loro doc exists, write through it (canonical path)
    if (this._loroDoc) {
      if (val === undefined) {
        this.loroDeleteProperty(prop);
      } else {
        this.loroSetProperty(prop, val as JSONValue);
      }

      this.#cacheDirty = true;

      return;
    }

    // No Loro doc yet (hydration) — write to cache as temporary buffer.
    // getLoroDoc() will seed Loro from cache when it's first called.
    if (val === undefined) {
      delete this.#cache[prop];
    } else {
      this.#cache[prop] = val as JSONValue;
    }
  }

  /** Returns all property entries (cache + binary aux values) as a flat array. */
  public getEntries(): [string, AtomicValue][] {
    if (this.#cacheDirty && this._loroDoc) {
      this.rebuildCacheFromLoro();
      this.#cacheDirty = false;
    }

    return [
      ...Object.entries(this.#cache),
      ...Array.from(this._auxValues.entries()),
    ];
  }

  private rebuildCacheFromLoro(): void {
    const propsMap = this.getLoroMap();
    const json = propsMap?.toJSON();
    const nextCache: Record<string, JSONValue> = Object.create(null);
    // The sibling `datatypes` map tags load-bearing properties (see
    // `writeDatatypeTags`/`datatypeTag`) — `'resourceArray'` or `'json'`
    // here means the stored string is legacy JSON-stringified content, not
    // coincidentally JSON-looking text in a plain string/markdown property.
    const datatypesJson = this._loroDoc?.getMap('datatypes').toJSON() as
      | Record<string, string>
      | undefined;

    // Loro snapshots arrive with their subject-valued props still in the
    // server's `internal:` storage form — see `localizeInternalSubject`. This
    // is the single point where doc values become propvals, so it is the one
    // place that has to resolve them.
    // The `store` getter throws when unset (a bare `new Resource()` in tests,
    // or a resource built before it's attached), so read the field directly.
    const origin = this._store?.getServerUrl();

    if (json && typeof json === 'object') {
      for (const [key, value] of Object.entries(json)) {
        const normalized = normalizeLoroValue(datatypesJson?.[key], value);
        nextCache[key] = origin
          ? localizeInternalSubjects(normalized, origin)
          : normalized;
      }
    }

    // Preserve server-managed / genesis-immutable properties in the cache.
    // These are set once (at genesis or by the server) and are NOT necessarily
    // re-encoded into a later Loro delta — so a rebuild from a delta-only doc
    // would otherwise drop them. `drive` and `parent` matter especially for a
    // GUEST who loaded a shared resource: losing the parent's `drive` here
    // leaves a reply unstamped, so the drive-scoped commit fan-out never
    // delivers it to the owner. See planning/commit-fanout-drive-isolation.md.
    const serverManaged = [
      properties.commit.lastCommit,
      commits.properties.createdAt,
      properties.createdBy,
      'https://atomicdata.dev/properties/drive',
      // The inline genesis certificate: set once at creation, immutable, and
      // must not be dropped when the cache is rebuilt from a delta-only doc —
      // it's what verifies the resource's DID.
      'https://atomicdata.dev/properties/genesis',
      core.properties.parent,
    ];

    for (const key of serverManaged) {
      if (this.#cache[key] !== undefined && nextCache[key] === undefined) {
        nextCache[key] = this.#cache[key];
      }
    }

    this.#cache = nextCache;
  }

  /**
   * Populate the sibling `datatypes` Loro map
   * so the server recovers reference / array `Value` variants exactly instead
   * of guessing. The map is sparse — only load-bearing datatypes get a tag;
   * see {@link datatypeTag}. Idempotent: re-signing rewrites nothing.
   *
   * Cache-only — never triggers a fetch. A property whose definition is not
   * already cached is left untagged; the server then falls back to its
   * materialization heuristic, exactly as before this map existed. Properties
   * edited via `set()` with validation are always cached by the time we sign.
   */
  private writeDatatypeTags(
    commitOptions: { origin?: string; timestamp?: number; message?: string } = {
      origin: SYSTEM_COMMIT_ORIGIN,
    },
  ): void {
    const doc = this._loroDoc;

    if (!doc) {
      return;
    }

    const props = doc.getMap('properties').toJSON() as Record<string, unknown>;
    const datatypesMap = doc.getMap('datatypes');

    let wroteAnything = false;

    for (const [prop, loroValue] of Object.entries(props)) {
      const datatype = this.store?.resources
        .get(prop)
        ?.get(core.properties.datatype)
        ?.toString();

      if (datatype === undefined) {
        // The Property isn't loaded in this store, so we can't tag it here.
        // This is best-effort: the server is the authoritative enforcement
        // point — it resolves an untagged property's datatype from its
        // registered Property (and rejects genuinely-untypeable ones), so a
        // value is never silently dropped on materialize.
        continue;
      }

      const tag = datatypeTag(datatype, loroValue);

      if (tag !== undefined && datatypesMap.get(prop) !== tag) {
        datatypesMap.set(prop, tag);
        wroteAnything = true;
      }
    }

    // Flush these writes in their own commit, tagged with the system
    // origin so the UndoManager (configured with `excludeOriginPrefixes:
    // ['atomic:system']` in {@link ensureUndoManager}) doesn't record them
    // as undo steps. Without this, every first save after a user edit
    // pushes a phantom checkpoint and the user's next undo silently reverts
    // the datatype-tag rewrite instead of their stroke / property change.
    if (wroteAnything) {
      // For a genesis sign, `signChanges` passes the agent + ms timestamp here:
      // this is the FIRST commit on the doc, so it creates the genesis change,
      // and the creation metadata (createdBy/createdAt) must ride on it. A later
      // `commit()` would be a no-op (no pending ops) and never attach them.
      doc.commit(commitOptions);
    }
  }

  private resetLoroState(): void {
    this._loroDoc = undefined;
    this._loroMap = undefined;
    this._loroUndoManager = undefined;
    this._loroVersionAtLastSave = undefined;
  }

  /**
   * Write a value to the Loro map. This is called internally by set().
   * Converts JSON values to Loro-compatible types.
   */
  private loroSetProperty(prop: string, value: JSONValue): void {
    const map = this.getLoroMap();

    if (!map) {
      // Loro not loaded yet — write to cache as fallback.
      // getLoroDoc() will seed Loro from cache when it initializes.
      if (value === undefined || value === null) {
        delete this.#cache[prop];
      } else {
        this.#cache[prop] = value;
      }

      return;
    }

    if (value === undefined || value === null) {
      map.delete(prop);

      return;
    }

    // Loro accepts primitives and containers directly
    if (
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'boolean'
    ) {
      map.set(prop, value);
    } else if (this.isLocalizedTextProp(prop, value)) {
      // LocalizedText: a native LoroMap keyed by language tag, so each
      // language is its own LWW register and concurrent edits to different
      // languages merge instead of clobbering. Mutate an existing container
      // in place — replacing it resets its identity and drops cross-device
      // merges targeting the old one (same reasoning as `replaceListItems`).
      const { LoroMap: LoroMapClass } = LoroLoader.Loro;
      const existing = map.get(prop);
      const translations = value as Record<string, string>;

      let langMap;

      if (
        existing &&
        typeof existing === 'object' &&
        'set' in existing &&
        !('push' in existing)
      ) {
        langMap = existing;

        for (const key of langMap.keys()) {
          if (translations[key] === undefined) {
            langMap.delete(key);
          }
        }
      } else {
        langMap = map.setContainer(prop, new LoroMapClass());
      }

      for (const [tag, translation] of Object.entries(translations)) {
        if (langMap.get(tag) !== translation) {
          langMap.set(tag, translation);
        }
      }
    } else if (Array.isArray(value)) {
      // Use native LoroList for arrays — enables per-element CRDT merge.
      // Object/array elements must become nested containers (LoroMap /
      // LoroList), the same as `writeJsonToLoroList`/`pushListItem` do — a
      // list seeded here with plain objects would later confuse the
      // append/replace paths (they expect container elements) and, for a
      // canvas, breaks the first `pushListItem` stroke.
      //
      // Drain in-place rather than `setContainer(new LoroList())`. Replacing
      // the container resets its identity, so a later snapshot import of the
      // original list (OPFS cold-load, WS GET) merges two concurrent lists
      // and the array order flashes — table columns (`requires`/`recommends`)
      // and sidebar `isA` were the visible cases.
      this.writeLoroListInPlace(map, prop, value);
    } else {
      // Objects: serialize to JSON string.
      map.set(prop, JSON.stringify(value));
    }
  }

  /**
   * True when `prop` is a LocalizedText property (cache-only datatype
   * lookup, same best-effort contract as `writeDatatypeTags`) holding a
   * flat object of language tag -> string.
   */
  private isLocalizedTextProp(prop: string, value: JSONValue): boolean {
    if (
      value === null ||
      typeof value !== 'object' ||
      Array.isArray(value) ||
      Object.values(value).some(v => typeof v !== 'string')
    ) {
      return false;
    }

    const datatype = this._store?.resources
      .get(prop)
      ?.get(core.properties.datatype)
      ?.toString();

    return datatype === Datatype.LOCALIZEDTEXT;
  }

  /**
   * Remove a property from the Loro map.
   */
  private loroDeleteProperty(prop: string): void {
    const map = this.getLoroMap();

    if (!map) {
      delete this.#cache[prop];

      return;
    }

    map.delete(prop);
  }

  /**
   * Export the Loro state to attach to the next outgoing commit.
   *
   * We export a delta (incremental update) if a previous baseline version exists,
   * otherwise we export a full snapshot (e.g. for genesis commits).
   * Loro merges both snapshots and deltas seamlessly.
   *
   * Returns undefined if there are no Loro changes since the last save.
   */
  /**
   * Export Loro bytes for WS drive-sync pull responses.
   * Prefers incremental updates since `serverVv`; falls back to a full
   * snapshot when the delta is empty (e.g. blob-only pull).
   */
  static exportLoroBytesForSync(
    doc: LoroDoc,
    serverVersionVector?: Record<string, number>,
  ): Uint8Array | undefined {
    if (!LoroLoader.isLoaded()) {
      return undefined;
    }

    let bytes: Uint8Array | undefined;

    if (serverVersionVector && Object.keys(serverVersionVector).length > 0) {
      const { VersionVector } = LoroLoader.Loro;
      const map = new Map<string, number>();

      for (const [peer, counter] of Object.entries(serverVersionVector)) {
        map.set(peer, counter);
      }

      try {
        const from = VersionVector.parseJSON(map as Map<`${number}`, number>);
        bytes = doc.export({ mode: 'update', from });
      } catch {
        // Fall through to snapshot.
      }
    }

    if (!bytes || bytes.length <= 4) {
      try {
        bytes = doc.export({ mode: 'snapshot' });
      } catch {
        return undefined;
      }
    }

    return bytes.length > 4 ? bytes : undefined;
  }

  /**
   * Sign-at-drain export helper. Returns the Loro delta from the
   * last-saved cursor (or a full snapshot on first sign), along with
   * the version vector AT the moment of export. The drain must
   * advance `_loroVersionAtLastSave` to *that* version after the
   * commit POSTs — not to the current `oplogVersion`, because the
   * user can type more characters during the POST round-trip and
   * those new ops are NOT in the signed commit. Advancing to current
   * would silently drop them on the next drain pass.
   *
   * @internal store-level drain only — not part of the public API.
   */
  public exportLoroDeltaForDrain(
    isFirstCommit: boolean,
    commitMessage?: string,
  ): { bytes: Uint8Array; versionAfterExport: VersionVector } | undefined {
    const bytes = this.exportLoroDeltaInternal(isFirstCommit, commitMessage);
    if (!bytes) return undefined;
    if (!this._loroDoc) return undefined;

    return { bytes, versionAfterExport: this._loroDoc.oplogVersion() };
  }

  /**
   * Legacy export helper — used by `signChanges` to fold the Loro
   * delta into a CommitBuilder before sign. Same bytes as
   * `exportLoroDeltaForDrain` returns, just without the version
   * capture (signChanges advances the cursor itself with a direct
   * `_loroVersionAtLastSave = oplogVersion()` assignment).
   *
   * @internal used by `signChanges` only — not part of the public API.
   */
  public exportLoroDelta(
    isFirstCommit: boolean,
    commitMessage?: string,
  ): Uint8Array | undefined {
    return this.exportLoroDeltaInternal(isFirstCommit, commitMessage);
  }

  /**
   * Advance the Loro save cursor to a specific version (typically the
   * version captured at drain-time export, not the current oplog
   * version — see `exportLoroDeltaForDrain` above for why).
   *
   * @internal store-level drain only — not part of the public API.
   */
  public markLoroSavedAt(version: VersionVector): void {
    if (this._loroDoc) {
      this._loroVersionAtLastSave = version;
    }
  }

  /** Base64-encode the current save cursor (last-synced Loro version) for
   *  durable storage. Returns undefined when nothing has synced yet (the
   *  cursor is the resource's whole history → handled as a first commit).
   *  @internal offline-persistence only. */
  public getEncodedSaveCursor(): string | undefined {
    if (!this._loroVersionAtLastSave) return undefined;

    try {
      return encodeB64(this._loroVersionAtLastSave.encode());
    } catch {
      return undefined;
    }
  }

  /** Restore the save cursor from a base64-encoded `VersionVector` (see
   *  `getEncodedSaveCursor`). Used on reload to point the cursor back at
   *  the last-synced version so the reconnect drain exports the offline
   *  delta rather than an empty one.
   *  @internal store-level drain only. */
  public restoreSaveCursor(encoded: string): void {
    if (!this._loroDoc || !LoroLoader.isLoaded()) return;

    try {
      const { VersionVector } = LoroLoader.Loro;
      this._loroVersionAtLastSave = VersionVector.decode(decodeB64(encoded));
    } catch (e) {
      console.warn(
        `[Resource] failed to restore save cursor for ${this.subject}:`,
        e,
      );
    }
  }

  /** True when the Loro doc has ops past the current save cursor —
   *  i.e. local edits not yet exported into a signed commit. Used by
   *  the drain to decide whether to clear the outbox dirty bit after
   *  a successful POST: if the user typed more during the round-trip,
   *  those ops are past the just-advanced cursor and the subject must
   *  stay dirty so the next drain pass picks them up.
   *  @internal store-level drain only — not part of the public API. */
  public hasOpsPastSaveCursor(): boolean {
    if (!this._loroDoc) return false;
    if (!this._loroVersionAtLastSave) return false;

    return !this.versionVectorsEqual(
      this._loroDoc.oplogVersion(),
      this._loroVersionAtLastSave,
    );
  }

  /** The resource's last applied commit id (`did:ad:commit:{sig}`).
   *  Stamp for genesis detection and echo-dedup — not a fetchable resource.
   *  @internal store-level drain only — not part of the public API. */
  public getLastCommitForChain(): string | undefined {
    return (
      this._lastCommit ?? this.get(properties.commit.lastCommit)?.toString()
    );
  }

  /** Compare two Loro VersionVectors by their JSON representation. */
  private versionVectorsEqual(a: VersionVector, b: VersionVector): boolean {
    const aj = a.toJSON();
    const bj = b.toJSON();
    if (aj.size !== bj.size) return false;

    for (const [peer, counter] of aj) {
      if (bj.get(peer) !== counter) return false;
    }

    return true;
  }

  private exportLoroDeltaInternal(
    isFirstCommit: boolean,
    commitMessage?: string,
  ): Uint8Array | undefined {
    if (!this._loroDoc) {
      return undefined;
    }

    // Pre-check: if oplogVersion matches the cursor exactly, no new
    // local ops since the last sign. `doc.commit()` below would
    // otherwise emit a fresh "commit-point" op (because
    // `setRecordTimestamp(true)` writes a timestamp on every commit
    // boundary), advancing oplogVersion past the cursor and producing
    // a non-empty delta with no real content. Skipping the
    // doc.commit() also avoids re-firing the local-change subscriber
    // which would re-mark the subject dirty in the outbox.
    if (!isFirstCommit && this._loroVersionAtLastSave) {
      const currentVV = this._loroDoc.oplogVersion();

      if (this.versionVectorsEqual(currentVV, this._loroVersionAtLastSave)) {
        return undefined;
      }
    }

    // Force commit any pending transaction in Loro so that oplog version is
    // advanced. Tag the change with `commitMessage` when the caller (the
    // drain) provides one: a distinct message per Atomic commit makes Loro
    // start a NEW Change rather than merging these ops into the previous
    // one. That per-commit Change boundary is what `getLoroHistory` buckets
    // by to reconstruct one version per commit — without it, every edit
    // collapses into a single Change (same peer, same second) and history
    // shows only the latest state. Set synchronously here, before any
    // `await`, so it never races user input or the save cursor.
    // Stamp every commit with millisecond precision. Loro's auto-record is
    // second-resolution, which collapses the ordering of resources created in
    // the same second (e.g. chat messages sorted by `createdAt`, which is read
    // from the genesis change's timestamp). Loro orders changes by lamport,
    // not timestamp, so a finer timestamp is safe metadata; readers normalise
    // mixed-unit oplogs via `normalizeLoroChangeTimestampMs`.
    this._loroDoc.commit({
      timestamp: Date.now(),
      ...(commitMessage ? { message: commitMessage } : {}),
    });

    // If it's the first commit, we must export a full snapshot.
    if (isFirstCommit || !this._loroVersionAtLastSave) {
      const snapshot = this._loroDoc.export({ mode: 'snapshot' });

      // A header-only snapshot (no ops) means "no changes worth sending".
      if (snapshot.length <= 4) {
        return undefined;
      }

      return snapshot;
    }

    // Otherwise, export the incremental updates since the last save (the delta).
    const delta = this._loroDoc.export({
      mode: 'update',
      from: this._loroVersionAtLastSave,
    });

    if (delta.length <= 4) {
      return undefined;
    }

    return delta;
  }

  /**
   * Initialize the Loro save cursor on first-time hydration only.
   *
   * Called from import/merge paths after the doc has been seeded from
   * external bytes. Subsequent advances belong to `signChanges` — the
   * only caller that actually knows "I just exported everything up to
   * here". If we let merge/import advance the cursor, it captures the
   * doc's CURRENT version, which by then may include local pending
   * edits the user typed while a previous sign was in flight. The next
   * sign would then export from that advanced cursor and emit an empty
   * delta, silently dropping the user's edits on the wire.
   */
  private initLoroSaveCursorIfFresh(): void {
    if (this._loroDoc && this._loroVersionAtLastSave === undefined) {
      this._loroVersionAtLastSave = this._loroDoc.oplogVersion();
    }
  }

  /** Decode the dual-typed `_loroSnapshotBytes` field: Uint8Array
   *  passes through, base64 string is decoded. Returns undefined
   *  if the bytes are missing or empty. */
  private static decodeStoredSnapshot(
    bytes: Uint8Array | string | undefined,
  ): Uint8Array | undefined {
    if (bytes instanceof Uint8Array && bytes.length > 0) return bytes;
    if (typeof bytes === 'string' && bytes.length > 0) return decodeB64(bytes);

    return undefined;
  }

  /** Snapshot bytes from a source Resource: prefer the live Loro
   *  doc, fall back to stored bytes. Used by `merge` and
   *  `cloneLoroStateFrom`. */
  private static extractLoroSnapshot(
    resource: Resource,
  ): Uint8Array | undefined {
    return resource._loroDoc
      ? resource._loroDoc.export({ mode: 'snapshot' })
      : Resource.decodeStoredSnapshot(resource._loroSnapshotBytes);
  }

  private cloneLoroStateFrom(resource: Resource): void {
    this.resetLoroState();
    if (!LoroLoader.isLoaded()) return;

    const snapshot = Resource.extractLoroSnapshot(resource);
    if (!snapshot || snapshot.length === 0) return;

    const { LoroDoc: LoroDocClass } = LoroLoader.Loro;
    this._loroDoc = new LoroDocClass();
    this._loroDoc.import(snapshot);
    this._loroMap = this._loroDoc.getMap('properties');

    this._loroVersionAtLastSave = resource._loroVersionAtLastSave
      ? this._loroDoc.oplogVersion()
      : undefined;
  }

  /** Checks if the content of two Resource instances is equal */
  public equals(resourceB: Resource): boolean {
    if (this === resourceB.__internalObject) {
      return true;
    }

    if (this.subject !== resourceB.subject) {
      return false;
    }

    if (this.new !== resourceB.new) {
      return false;
    }

    if (this.error !== resourceB.error) {
      return false;
    }

    if (this.loading !== resourceB.loading) {
      return false;
    }

    if (
      JSON.stringify(this.getEntries()) !==
      JSON.stringify(resourceB.getEntries())
    ) {
      return false;
    }

    return true;
  }

  /** Checks if the agent has write rights by traversing the graph. Recursive function. */
  public async canWrite(
    agent?: string,
    /**
     * @internal Recursion accumulator: subjects already visited in this
     * permission chain. Catches multi-step parent cycles (A→B→C→A) which
     * the previous immediate-parent check missed — leading to infinite
     * recursion under accidentally-cyclical drives.
     */
    seen?: Set<string>,
  ): Promise<[boolean, string | undefined]> {
    if (!agent) {
      return [false, 'No agent given'];
    }

    // Agents can always edit their own resource (e.g. their profile)
    if (agent === this.subject) {
      return [true, undefined];
    }

    const writeArray = this.get(core.properties.write);

    if (writeArray && valToArray(writeArray).includes(agent)) {
      return [true, undefined];
    }

    if (writeArray && valToArray(writeArray).includes(instances.publicAgent)) {
      return [true, undefined];
    }

    const parentSubject = this.get(properties.parent) as string;

    if (!parentSubject) {
      return [false, `No write right or parent in ${this.subject}`];
    }

    // Agents can always edit themselves
    if (parentSubject === agent) {
      return [true, undefined];
    }

    // Cycle detection: any ancestor we've already visited in this chain.
    // Catches both immediate (A↔B) and longer (A→B→C→A) cycles.
    const visited = seen ?? new Set<string>();

    if (visited.has(parentSubject)) {
      console.warn(
        'Circular parent chain at',
        this.subject,
        '→',
        parentSubject,
      );

      return [true, `Circular parent chain at ${this.subject}`];
    }

    visited.add(this.subject);

    const parent: Resource = await this.store.getResource(parentSubject);

    // The recursive part
    return await parent.canWrite(agent, visited);
  }

  /**
   * Creates a clone of the Resource, which makes sure the reference is
   * different from the previous one. This can be useful when doing reference compares.
   */
  public clone(): Resource<C> {
    const res = new Resource(this.subject);

    res.#cache = structuredClone(this.#cache);
    res._auxValues = new Map(
      structuredClone(Array.from(this._auxValues.entries())),
    );
    res._loroSnapshotBytes = this._loroSnapshotBytes;

    res.loading = this.loading;
    res.new = this.new;
    res.error = structuredClone(this.error);
    res.commitError = this.commitError;
    res.#commitBuilder = this.#commitBuilder.clone();
    res._dirty = this._dirty;
    res.appliedCommitSignatures = this.appliedCommitSignatures;

    res.cloneLoroStateFrom(this);

    return res as Resource<C>;
  }

  /**
   * Merges a resource into this resource using Loro CRDT merge.
   *
   * Both sides' Loro state is imported into a single doc. Loro handles
   * conflict resolution automatically — both local offline edits and
   * remote server edits survive. The cache is then rebuilt from the
   * merged Loro state.
   * @param options.replaceLoroDocs When true, each local Loro.Doc is updated to match the remote document state (authoritative replace).
   * @param options.omitKeysFromMerge Keys to skip so local values are kept (including when absent on the remote resource).
   */
  public merge(resourceB: Resource, options: MergeOptions = {}): void {
    const omitKeysFromMerge = options.omitKeysFromMerge ?? [];

    if (this.subject !== resourceB.subject) {
      throw new Error('Cannot merge resources with different subjects');
    }

    const incomingSnapshot = Resource.extractLoroSnapshot(resourceB);

    if (
      incomingSnapshot &&
      incomingSnapshot.length > 0 &&
      LoroLoader.isLoaded()
    ) {
      // Ensure we have a local Loro doc
      const localDoc = this.getLoroDoc();

      if (localDoc) {
        // Read local values for omitted keys
        const savedOmittedValues: Record<string, AtomicValue> = {};

        for (const key of omitKeysFromMerge) {
          const val = this.get(key);

          if (val !== undefined) {
            savedOmittedValues[key] = val;
          }
        }

        if (options.replaceLoroDocs) {
          this.cloneLoroStateFrom(resourceB);
          this._loroSnapshotBytes = resourceB._loroSnapshotBytes;
          this.#cache = structuredClone(resourceB.#cache);
          this._auxValues = new Map(
            structuredClone(Array.from(resourceB._auxValues.entries())),
          );
        } else {
          // Import the incoming state — Loro merges via CRDT
          try {
            localDoc.import(incomingSnapshot);
          } catch (e) {
            // Import can fail if the snapshot is from an incompatible version.
            // Fall back to replacing state entirely.
            console.warn(
              `[Resource] Loro merge failed for ${this.subject}, replacing:`,
              e,
            );
            this.resetLoroState();
            this._loroSnapshotBytes = resourceB._loroSnapshotBytes;
            this.#cache = structuredClone(resourceB.#cache);
            this._auxValues = new Map(
              structuredClone(Array.from(resourceB._auxValues.entries())),
            );
          }
        }

        // Restore local values for omitted keys
        for (const key of omitKeysFromMerge) {
          if (savedOmittedValues[key] !== undefined) {
            this.set(key, savedOmittedValues[key]);
          }
        }

        // Copy housekeeping properties from resourceB.#cache to this.#cache
        // before rebuilding cache so they are preserved
        const serverManaged = [
          properties.commit.lastCommit,
          commits.properties.createdAt,
          properties.createdBy,
        ];

        for (const key of serverManaged) {
          if (resourceB.#cache[key] !== undefined) {
            this.#cache[key] = resourceB.#cache[key];
          }
        }

        // Rebuild the read cache from the merged Loro doc
        this.rebuildCacheFromLoro();
        this.#cacheDirty = false;
        this.initLoroSaveCursorIfFresh();
      } else {
        // No local Loro doc — just take the incoming state. `resourceB` is
        // discarded after merge (the store keeps `this`), so we can take
        // ownership of its cache and auxValues directly instead of paying
        // a `structuredClone` deep copy on every WS UPDATE. The shallow
        // Map copy keeps callers from accidentally mutating the source's
        // entries, which is the only invariant `structuredClone` was
        // protecting here.
        this.#cache = resourceB.#cache;
        this._auxValues = new Map(resourceB._auxValues);
        this._loroSnapshotBytes = resourceB._loroSnapshotBytes;
      }
    } else {
      // No incoming Loro snapshot (e.g. metadata-only update or non-crdt resource)
      // Copy housekeeping properties first
      const serverManaged = [
        properties.commit.lastCommit,
        commits.properties.createdAt,
        properties.createdBy,
      ];

      for (const key of serverManaged) {
        if (resourceB.#cache[key] !== undefined) {
          this.#cache[key] = resourceB.#cache[key];
        }
      }

      // Shallow copy other fields if no loro doc exists at all
      if (!this._loroDoc) {
        this.#cache = resourceB.#cache;
        this._auxValues = new Map(resourceB._auxValues);
      }
    }

    this.new = resourceB.new;
    this.error = resourceB.error;
    this.commitError = resourceB.commitError;

    // Only update _lastCommit if the remote version has one and we don't have one,
    // or if they are different (assuming the remote one is newer if it comes from the store).
    const remoteLastCommit = resourceB
      .get(properties.commit.lastCommit)
      ?.toString();

    if (remoteLastCommit && remoteLastCommit !== this._lastCommit) {
      this.setLastCommitValue(remoteLastCommit);
    }

    const remoteCreatedAt = resourceB.get(commits.properties.createdAt);

    if (typeof remoteCreatedAt === 'number') {
      this.setCreatedAtValue(remoteCreatedAt);
    }

    // A bootstrapped stub carries an `incomplete` marker so that visiting its
    // subject triggers a real fetch. That marker lives in the stub's own Loro
    // ops, and a CRDT merge UNIONS the two docs — so merging in the fetched
    // full copy left the marker standing and `getResourceLoading` refetched
    // the subject forever. The incoming copy is what decides: if it is not
    // itself marked incomplete, the staleness the marker recorded is resolved.
    //
    // `removeUnsafe`, not `remove`: this is reconciliation, not an edit, and
    // must not leave a pending change for the drain to commit.
    if (
      resourceB.get(core.properties.incomplete) === undefined &&
      this.get(core.properties.incomplete) !== undefined
    ) {
      this.removeUnsafe(core.properties.incomplete);
    }

    // We set this last because it will trigger a loading change event.
    this.loading = resourceB.loading;
  }

  /** Checks if the resource is both loaded and free from errors */
  public isReady(): boolean {
    return !this.loading && this.error === undefined;
  }

  /** Get a Value by its property
   * @param propUrl The subject of the property
   * @example
   * import { core } from '@tomic/lib'
   * const description = resource.get(core.properties.description)
   * const publishedAt = resource.get('https://my-atomicserver.dev/properties/published-at')
   */
  public get<Prop extends string, Returns = InferTypeOfValueInTriple<C, Prop>>(
    propUrl: Prop,
  ): Returns {
    if (this.#cacheDirty && this._loroDoc) {
      this.rebuildCacheFromLoro();
      this.#cacheDirty = false;
    }

    return (this._auxValues.get(propUrl) ?? this.#cache[propUrl]) as Returns;
  }

  /**
   * Every property URL this resource has a value for, mapped to that value.
   *
   * The returned object is a copy; mutating it does not change the resource.
   */
  public getPropVals(): Record<string, AtomicValue> {
    if (this.#cacheDirty && this._loroDoc) {
      this.rebuildCacheFromLoro();
      this.#cacheDirty = false;
    }

    return {
      ...this.#cache,
      ...Object.fromEntries(this._auxValues.entries()),
    };
  }

  /**
   * Get a Value by its property, returns as Array with subjects instead of the
   * full resource or throws error. Returns empty array if there is no value
   */
  public getSubjects(propUrl: string): string[] {
    return this.getArray(propUrl).map(item => {
      if (typeof item === 'string') return item;

      return (item as JSONObject)['@id'] as string;
    });
  }

  /**
   * Get a Value by its property, returns as Array or throws error. Returns
   * empty array if there is no value
   */
  public getArray(propUrl: string): JSONArray {
    const result = this.get(propUrl) ?? [];

    return valToArray(result);
  }

  /** Returns a list of classes of this resource */
  public getClasses(): string[] {
    return this.getSubjects(core.properties.isA);
  }

  /** Checks if the resource is all of the given classes */
  public hasClasses(...classSubjects: string[]): boolean {
    return classSubjects.every(classSubject =>
      this.getClasses().includes(classSubject),
    );
  }

  /**
   * `.matchClass()` takes an object that maps class subjects to values.
   * If the resource has a class that is a key in the object, the corresponding value is returned.
   * An optional fallback value can be provided as the second argument.
   * The order of the classes in the object is important, as the first match is returned.
   */
  public matchClass<T>(obj: Record<string, T>): T | undefined;
  public matchClass<T>(obj: Record<string, T>, fallback: T): T;
  public matchClass<T>(obj: Record<string, T>, fallback?: T): T | undefined {
    for (const [classSubject, value] of Object.entries(obj)) {
      if (this.hasClasses(classSubject)) {
        return value;
      }
    }

    return fallback;
  }

  /** Remove the given classes from the resource */
  public removeClasses(...classSubjects: string[]): void {
    // Using .set on this somehow has other typescript rules than using resource.set. Casting to Resource seems to fix this.
    (this as Resource).set(
      core.properties.isA,
      this.getClasses().filter(
        classSubject => !classSubjects.includes(classSubject),
      ),
      false,
    );
  }

  /** Adds the given classes to the resource */
  public addClasses(...classSubject: string[]): Promise<void> {
    const classesSet = new Set([...this.getClasses(), ...classSubject]);

    // Using .set on this somehow has other typescript rules than using resource.set. Casting to Resource seems to fix this.
    return (this as Resource).set(
      core.properties.isA as string,
      Array.from(classesSet),
    );
  }

  /** Returns true if the resource has unsaved local changes. */
  public hasUnsavedChanges(): boolean {
    return this.#commitBuilder.hasUnsavedChanges() || this._dirty;
  }

  /** Clear the dirty flag after a successful drain has signed + POSTed
   *  the accumulated Loro delta. The store-level drain
   *  (`drainOutboxSubject`) calls this once the resource is caught up
   *  (no ops past the save cursor) — without it, `_dirty` stays `true`
   *  forever after the very first edit and the editable-title `*`
   *  indicator never clears (rename-regression e2e). Distinct from the
   *  Loro save cursor (`markLoroSavedAt`): the cursor tracks WHICH ops
   *  are signed; this flag is the coarse "are there any unsynced
   *  edits" signal that `hasUnsavedChanges` / `UnsavedIndicator` read.
   *  @internal store-level drain only. */
  public markSynced(): void {
    this._dirty = false;
  }

  /** Mark the resource as having unsaved local changes.
   *  Use this when external code (e.g. Loro editor plugins) modifies the
   *  resource's LoroDoc directly without going through `set()`. */
  public markDirty(): void {
    this._dirty = true;
    this.eventManager.emit(ResourceEvents.LocalChange, '', undefined);
  }

  public getCommitsCollectionSubject(): string {
    // For DID subjects (or other non-HTTP URIs) we can't derive the server
    // origin from the subject itself — use the store's server URL instead.
    const base =
      this.subject.startsWith('did:') || this.subject.startsWith('_')
        ? this.store.getServerUrl()
        : this.subject;
    const url = new URL('/query', base);
    url.searchParams.append('property', commits.properties.subject);
    url.searchParams.append('value', this.subject);
    url.searchParams.append('sort_by', commits.properties.createdAt);
    url.searchParams.append('include_nested', 'true');
    url.searchParams.append('page_size', '9999');

    return url.toString();
  }

  /** Returns a Collection with all children of this resource
   * @param pageSize The amount of children per page (default: 100)
   */
  public async getChildrenCollection(pageSize = 100): Promise<Collection> {
    return await new CollectionBuilder(this.store)
      .setPageSize(pageSize)
      .setProperty(core.properties.parent)
      .setValue(this.subject)
      .buildAndFetch();
  }

  /**
   * The founding (genesis) change in the Loro oplog: the earliest change by
   * timestamp, then by op counter (offline edits record timestamp 0, so the
   * counter tiebreak keeps genesis first). Creation metadata is derived from
   * it — and because it lives inside the resource's own Loro doc, no separate
   * commit fetch is needed and it survives a refresh.
   */
  private getGenesisChange():
    | { timestamp: number; message: string | undefined }
    | undefined {
    const doc = this.getLoroDoc();

    if (!doc) {
      return undefined;
    }

    let genesis:
      | { timestamp: number; lamport: number; message: string | undefined }
      | undefined;

    for (const [, changes] of doc.getAllChanges().entries()) {
      for (const change of changes) {
        // Select by Lamport (causal order) — the founding change is the
        // minimum. NOT by timestamp: a server-authored follow-up (e.g.
        // `lastCommit` after apply) can carry a second-resolution timestamp
        // that sorts before the client's millisecond-precise genesis within
        // the same second, mis-picking a later, message-less change.
        if (!genesis || change.lamport < genesis.lamport) {
          genesis = {
            timestamp: change.timestamp,
            lamport: change.lamport,
            message: change.message,
          };
        }
      }
    }

    return (
      genesis && { timestamp: genesis.timestamp, message: genesis.message }
    );
  }

  /**
   * Creation timestamp (Unix **ms**) from the inline genesis certificate.
   * Materialized propvals and the founding Loro change remain fallbacks for
   * resources created before certificates. No commit fetch is required.
   */
  public getCreatedAt(): number | undefined {
    // The inline certificate is the source of truth for DID resources. The
    // materialized propval exists for queries / JSON-AD compatibility; the
    // Loro change remains a fallback for resources created before certs.
    const cert = this.getGenesisCertificate();

    if (cert && cert.createdAt > 0) {
      return cert.createdAt;
    }

    const fromPropval = this.get(properties.commit.createdAt);

    if (typeof fromPropval === 'number') {
      return normalizeLoroChangeTimestampMs(fromPropval);
    }

    const genesis = this.getGenesisChange();

    if (!genesis || genesis.timestamp <= 0) {
      return undefined;
    }

    return normalizeLoroChangeTimestampMs(genesis.timestamp);
  }

  /**
   * Creator from the inline genesis certificate's signing key. Materialized
   * propvals and the founding Loro change message remain legacy fallbacks.
   */
  public getCreatedBy(): string | undefined {
    const cert = this.getGenesisCertificate();

    if (cert) {
      return genesisSignerDid(cert);
    }

    // Materialized propvals and the Loro message are compatibility paths for
    // legacy resources without a genesis certificate.
    const fromPropval = this.get(properties.createdBy);

    if (typeof fromPropval === 'string' && fromPropval.length > 0) {
      return fromPropval;
    }

    const message = this.getGenesisChange()?.message;

    // An internal bucketing token (`c-`/`e-`) means the earliest change was
    // a runtime-tagged edit, not the signed genesis — there's no creator
    // metadata to read.
    return message && message.length > 0 && !isInternalCommitToken(message)
      ? message
      : undefined;
  }

  private getGenesisCertificate():
    | ReturnType<typeof decodeGenesisCert>
    | undefined {
    const encoded = this.get(GENESIS);

    if (typeof encoded !== 'string' || encoded.length === 0) {
      return undefined;
    }

    try {
      return decodeGenesisCert(decodeB64(encoded));
    } catch {
      return undefined;
    }
  }

  /**
   * Whether the OpLog holds any state older than the current one — i.e.
   * whether `getLoroHistory()` would return more than just "now".
   *
   * Counts version buckets the same way `getLoroHistory` groups them, but
   * without materializing any of them: no `checkout()`, no `toJSON()`. Use
   * this for "is there anything to undo?" and leave the (far more expensive)
   * materialization until something actually reads a historical state.
   */
  public hasPriorLoroVersions(): boolean {
    const doc = this.getLoroDoc();

    if (!doc) {
      return false;
    }

    const buckets = new Set<string>();

    for (const changes of doc.getAllChanges().values()) {
      for (const change of changes) {
        buckets.add(change.message ?? '');

        // The newest bucket is the current state, so two distinct buckets is
        // already enough — no reason to walk the rest of the oplog.
        if (buckets.size > 1) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Get the history of this resource from its Loro OpLog.
   * Returns an array of Versions, each with materialized property values
   * at that point in time. Uses Loro's `checkout()` for instant time-travel
   * — no network round-trips needed.
   */
  public getLoroHistory(): Version[] {
    const liveDoc = this.getLoroDoc();

    if (!liveDoc) {
      return [];
    }

    // Time-travel on a fork. `doc.checkout()` mutates the doc's state and
    // fires events on every subscriber — including loro-prosemirror's plugin,
    // whose docSubscription leaks across editor unmount (its plugin destroy
    // only clears the init timeout, never unsubscribes). Calling checkout on
    // the live doc would fire that stale subscription with a historical state
    // where containers tracked in the plugin's mapping may not yet have a
    // `children` field, crashing in `absolutePositionToCursor`. The fork has
    // its own state and no subscribers, so checkouts here are isolated.
    const doc = liveDoc.fork();

    // Loro merges sequential same-peer ops into a single Change whose
    // `length` is the operation count. Iterating only over Changes therefore
    // collapses every edit between commits into one version. To recover one
    // version per *commit* we enumerate every op counter inside each Change
    // and group by the change message (see the bucketing below). The state
    // captured for each bucket is the **last** op counter that carried its
    // message — the snapshot that was actually saved under that commit.
    //
    // Enumerating steps is cheap; *materializing* one is not (a checkout plus
    // a whole-document toJSON). Since only the last step of each bucket is
    // ever read, we resolve the winners first and materialize only those.
    // Materializing every step instead made this O(total ops) — a canvas
    // stores one op per stroke point, so opening a small drawing spent
    // seconds doing 6000+ checkouts to produce 10 versions.
    type Step = {
      peer: string;
      counter: number;
      lamport: number;
      timestamp: number;
      message: string | undefined;
    };
    const steps: Step[] = [];

    for (const [peer, changes] of doc.getAllChanges().entries()) {
      for (const change of changes) {
        for (let i = 0; i < change.length; i++) {
          steps.push({
            peer,
            counter: change.counter + i,
            lamport: change.lamport + i,
            timestamp: change.timestamp,
            message: change.message,
          });
        }
      }
    }

    // Sort by Lamport clock: causal order, unlike wall-clock timestamps.
    // Loro often reports timestamp=0 for offline edits, second-resolution
    // stamps tie for every edit within the same second, and cross-peer
    // counter comparison is meaningless — sorting on (timestamp, counter)
    // used to interleave peers arbitrarily, which could even place the
    // genesis state *after* the latest one. Lamport order is guaranteed to
    // respect happened-before; genuinely concurrent ops tie and get a
    // stable peer-id tiebreak.
    steps.sort(
      (a, b) =>
        a.lamport - b.lamport ||
        (a.peer < b.peer ? -1 : a.peer > b.peer ? 1 : 0) ||
        a.counter - b.counter,
    );

    const lastCommitProp = 'https://atomicdata.dev/properties/lastCommit';
    type GroupedVersion = {
      contentKey: string;
      step: Step;
      propvals: Map<string, JSONValue>;
      containers: Map<string, JSONValue>;
    };
    const grouped: GroupedVersion[] = [];

    /** Stable signature of propvals (minus `lastCommit`) plus other top-level
     *  containers, used to detect versions that represent the same observable
     *  state arrived at from different peers (e.g. the same snapshot
     *  reimported during sync). Including containers is what lets body-only
     *  edits register as distinct versions instead of collapsing into the
     *  previous propvals-identical bucket.
     *
     *  Nested object keys are sorted, because `doc.toJSON()` emits map keys in
     *  an order that depends on how the doc reached that version: jumping
     *  straight to a version can yield `{color, path, width}` where arriving
     *  by replaying every op yields `{width, path, color}`. Same state, and a
     *  plain `JSON.stringify` would call them different — which made dedup
     *  depend on the checkout path taken to get there. */
    const canonicalize = (_key: string, value: JSONValue): JSONValue => {
      if (!value || typeof value !== 'object' || Array.isArray(value)) {
        return value;
      }

      const record = value as Record<string, JSONValue>;

      return Object.fromEntries(
        Object.keys(record)
          .sort()
          .map(k => [k, record[k]]),
      );
    };

    const contentSignature = (
      pv: Map<string, JSONValue>,
      ct: Map<string, JSONValue>,
    ): string => {
      const propEntries = Array.from(pv.entries())
        .filter(([k]) => k !== lastCommitProp)
        .sort(([a], [b]) => a.localeCompare(b));
      const containerEntries = Array.from(ct.entries()).sort(([a], [b]) =>
        a.localeCompare(b),
      );

      return JSON.stringify([propEntries, containerEntries], canonicalize);
    };

    // Bucket by the Loro Change message. Two token families exist:
    // `e-<token>` written by the logical-edit mutation methods
    // (pushListItem / replaceListItems / removeListItem / undo / redo —
    // see `commitLoroEdit`), and `c-<ulid>` written by the drain for
    // ops that were still pending at export time (property `set()`s).
    // All ops of one edit/commit share a message and form one version.
    // Ops with no message (the genesis/base change, and body edits made
    // outside the runtime, e.g. loro-prosemirror) bucket under '' as the
    // base version — intentionally collapsed so document typing doesn't
    // spam a version per keystroke batch. The latest step per bucket
    // wins — the final saved state under that commit.
    //
    // (Earlier this bucketed by the `lastCommit` propval, but under
    // sign-at-drain `lastCommit` is server-assigned and never written into
    // the Loro doc, so every op collapsed into the '' bucket and history
    // showed only the latest state.)
    //
    // `steps` is in causal order, so the last write per key is the winner.
    // Bucket order follows first appearance, which is what orders the
    // resulting versions.
    const bucketOrder: string[] = [];
    const winners = new Map<string, Step>();

    for (const step of steps) {
      const bucketKey = step.message ?? '';

      if (!winners.has(bucketKey)) {
        bucketOrder.push(bucketKey);
      }

      winners.set(bucketKey, step);
    }

    for (const bucketKey of bucketOrder) {
      const step = winners.get(bucketKey)!;
      const frontiers = [
        { peer: step.peer as `${number}`, counter: step.counter },
      ];

      try {
        doc.checkout(frontiers);
      } catch {
        continue;
      }

      // Materialize *the whole doc* at this version, not just `properties`.
      // The `properties` root holds Atomic propvals; loro-prosemirror writes
      // a Document's body into a separate top-level `doc` root container.
      // Reading only `properties` is why the history page silently dropped
      // every document-body edit, surfacing only title/metadata changes.
      const fullJson = doc.toJSON() as
        | Record<string, JSONValue>
        | null
        | undefined;
      const propvals = new Map<string, JSONValue>();
      const containers = new Map<string, JSONValue>();

      if (fullJson && typeof fullJson === 'object') {
        for (const [key, value] of Object.entries(fullJson)) {
          if (key === 'properties') {
            if (value && typeof value === 'object' && !Array.isArray(value)) {
              for (const [pk, pv] of Object.entries(
                value as Record<string, JSONValue>,
              )) {
                propvals.set(pk, pv);
              }
            }
          } else if (key !== 'datatypes') {
            // `datatypes` is internal property-type metadata, not content
            // anyone should see in a history view.
            containers.set(key, value);
          }
        }
      }

      grouped.push({
        contentKey: contentSignature(propvals, containers),
        step,
        propvals,
        containers,
      });
    }

    // Drop earlier buckets whose content signature matches a later one — they
    // represent the same observable state, just under a different lastCommit
    // (e.g. a snapshot reimported from a peer). Keeping only the freshest
    // entry per content gives one version per real saved state.
    const seenContent = new Set<string>();
    const dedupedReverse: GroupedVersion[] = [];

    for (let i = grouped.length - 1; i >= 0; i--) {
      const g = grouped[i];

      if (seenContent.has(g.contentKey)) continue;
      seenContent.add(g.contentKey);
      dedupedReverse.push(g);
    }

    const deduped = dedupedReverse.reverse();

    const versions: Version[] = deduped.map(g => ({
      peer: g.step.peer,
      timestamp: normalizeLoroChangeTimestampMs(g.step.timestamp),
      frontiers: [
        { peer: g.step.peer as `${number}`, counter: g.step.counter },
      ],
      // `step.message` is the internal per-commit bucketing token
      // (`c-<ulid>`), not a human-authored message — don't surface it in the
      // history UI. Left undefined until real commit messages exist.
      message: undefined,
      // The raw token, for matching this version to the signed envelope
      // that introduced it (`attributionForVersion`).
      token: g.step.message,
      propvals: g.propvals,
      containers: g.containers,
    }));

    return versions;
  }

  /**
   * Sets the resource to the specified version and saves it.
   * @param version The version to set the resource to, you can get this using `resource.getHistory()`
   *
   * NOTE: restores **propvals only**. Top-level Loro containers in
   * `version.containers` (most importantly the `doc` body for Documents) are
   * not replayed back into the live doc, so restoring a historical version
   * leaves the body at its current state. A complete restore needs to
   * either checkout the historical frontiers and re-export, or import a
   * targeted snapshot of each container — distinct work from this view-side
   * fix.
   */
  public async setVersion(version: Version): Promise<void> {
    // Remove any prop that doesn't exist in this version
    for (const [prop] of this.getEntries()) {
      if (!version.propvals.has(prop)) {
        this.remove(prop);
      }
    }

    // Set all properties from the version
    for (const [key, value] of version.propvals.entries()) {
      if (value === undefined) continue;
      await this.set(key, value);
    }

    // TODO: We should let the user save, this is what we usually do.
    await this.save();
  }

  /** Returns the subject URL of the Resource */
  public getSubjectNoParams(): string {
    // DID subjects (did:ad:...) don't have meaningful origin/pathname.
    if (this.subject.startsWith('did:') || this.subject.startsWith('_')) {
      return this.subject;
    }

    const url = new URL(this.subject);

    return url.origin + url.pathname;
  }

  /** Applies a batch of non-validating values during hydration or derived updates. */
  public applyHydratedValues(values: Iterable<[string, AtomicValue]>): void {
    // Close out any UNCOMMITTED user edit under its own origin first.
    // `set()` leaves its ops in an open Loro transaction, so a server
    // response landing between a keystroke and the next commit boundary
    // would otherwise be flushed by the system-origin commit below —
    // folding the user's edit into a change the outbox is told to ignore,
    // which loses it silently.
    if (this._loroDoc && this._loroDoc.getPendingTxnLength() > 0) {
      this._loroDoc.commit({ timestamp: Date.now() });
    }

    for (const [key, value] of values) {
      this.applyRawValue(key, value);
    }

    // These values came FROM a server response. When a Loro doc already
    // exists they were written through it as local ops; commit them under
    // the system origin so the dirty-marking subscriber skips them.
    // Otherwise re-fetching a resource we can read but not write (anything
    // on someone else's drive) queues an "updated (loro)" commit that the
    // server rejects as unauthorized, forever.
    // Re-read `_loroDoc`: a `loroUpdate: undefined` value above resets it.
    if (this._loroDoc && this._loroDoc.getPendingTxnLength() > 0) {
      this._loroDoc.commit({ origin: SYSTEM_COMMIT_ORIGIN });
    }
  }

  /** Returns a JSON-safe object view for storage and diagnostics. */
  public toObject(
    opts: { includeBinary?: boolean } = {},
  ): Record<string, unknown> | null {
    const { includeBinary = false } = opts;
    const obj: Record<string, unknown> = { '@id': this.subject };
    let count = 0;

    for (const [key, value] of this.getEntries()) {
      if (!includeBinary && value instanceof Uint8Array) {
        continue;
      }

      obj[key] = value;
      count++;
    }

    return count === 0 ? null : obj;
  }

  /** Compact debug representation for error messages. */
  public debugValueSummary(): string {
    const objectView = this.toObject({ includeBinary: false });

    return objectView ? JSON.stringify(objectView) : '{}';
  }

  /**
   * Updates the cached `lastCommit` metadata without treating it as a user
   * edit. Called after the server acks a commit. The doc write is committed
   * under the system origin so the `UndoManager` (excluding that prefix)
   * doesn't count it as an undo step — otherwise the user's next undo press
   * would silently rewind the `lastCommit` pointer instead of the visible
   * edit they actually want to reverse.
   */
  public setLastCommitValue(lastCommit: string): void {
    this._lastCommit = lastCommit;
    this.applyRawValue(properties.commit.lastCommit, lastCommit);
  }

  /** Same system-origin treatment as `setLastCommitValue` for `createdAt`. */
  public setCreatedAtValue(createdAt: number): void {
    this.applyRawValue(commits.properties.createdAt, createdAt);
  }

  /**
   * Iterates over the parents of the resource, returns who has read / write
   * rights for this resource
   */
  public async getRights(): Promise<Right[]> {
    const rights: Right[] = [];

    const collect = (prop: string, type: RightType) => {
      for (const subject of this.getSubjects(prop)) {
        rights.push({ for: subject, type, setIn: this.subject });
      }
    };

    collect(properties.write, RightType.WRITE);
    collect(properties.read, RightType.READ);

    const parentSubject = this.get(properties.parent) as string;

    if (parentSubject) {
      if (parentSubject === this.subject) {
        console.warn('Circular parent', parentSubject);

        return rights;
      }

      const parent = await this.store.getResource(parentSubject);
      rights.push(...(await parent.getRights()));
    }

    return rights;
  }

  /** Returns true is the resource had an `Unauthorized` 401 response. */
  public isUnauthorized(): boolean {
    return !!this.error && isUnauthorized(this.error);
  }

  /** Removes the resource form both the server and locally */
  public async destroy(agent?: Agent): Promise<void> {
    if (this.new) {
      this.store.removeResource(this.subject);

      return;
    }

    const newCommitBuilder = new CommitBuilder(this.subject);
    newCommitBuilder.setDestroy(true);

    // If a fetch is in flight, wait for it so we destroy the current
    // resource rather than a stale in-memory copy.
    if (this.loading) {
      await this.store.getResource(this.subject).catch(() => undefined);
    }

    if (agent === undefined) {
      agent = this.store.getAgent();
    }

    if (agent?.subject === undefined) {
      throw new Error(
        'No agent has been set or passed, you cannot delete this.',
      );
    }

    const commit = await newCommitBuilder.sign(agent);
    await this.store.postCommit(commit, this.getCommitEndpoint());
    this.store.removeResource(this.subject);
  }

  /** Appends a Resource to a ResourceArray */
  public push(propUrl: string, values: JSONArray, unique?: boolean): void {
    const propVal = (this.get(propUrl) as JSONArray) ?? [];

    if (unique) {
      values = values
        .filter(value => !propVal.includes(value))
        .filter((value, index, self) => self.indexOf(value) === index);
    }

    // Build a new array so that the reference changes. This is needed in most UI frameworks.
    const newArray = [...propVal, ...values];
    this.loroSetProperty(propUrl, newArray);
    this.#cacheDirty = true;
    this._dirty = true;
  }

  /**
   * Commit the pending Loro transaction as ONE logical edit, tagged with a
   * unique `e-<token>` message and a millisecond timestamp.
   *
   * The message is load-bearing for history: Loro merges consecutive
   * same-peer commits into a single Change unless the message (or
   * timestamp) differs, and `getLoroHistory` buckets ops by message. A
   * bare `commit()` here would fold every list edit between drains into
   * the unmessaged base bucket, so history and the canvas scrub gesture
   * would only ever see the latest state. (The drain's own `c-<ulid>`
   * token can't help — it tags the transaction pending at export time,
   * and these methods have already committed theirs by then.)
   */
  private commitLoroEdit(): void {
    this._loroDoc?.commit({
      timestamp: Date.now(),
      message: nextEditToken(),
    });
  }

  /**
   * Append one item to a JSON array property using the native Loro list (CRDT-friendly).
   * Used for canvas strokes and other list fields that merge per element across peers.
   */
  public pushListItem(propUrl: string, item: JSONValue): void {
    const propVal = (this.get(propUrl) as JSONArray) ?? [];
    this.#cache[propUrl] = [...propVal, item];
    this.#cacheDirty = true;
    this._dirty = true;

    const map = this.getLoroMap();

    if (!map) {
      return;
    }

    const { LoroList, LoroMap } = LoroLoader.Loro;
    const existing = map.get(propUrl);

    const append = (list: LoroList, value: JSONValue) => {
      if (
        value !== null &&
        typeof value === 'object' &&
        !Array.isArray(value)
      ) {
        const itemMap = list.pushContainer(new LoroMap());
        this.writeJsonToLoroMap(itemMap, value as JSONObject);
      } else {
        list.push(value);
      }
    };

    // A real LoroList container exposes `pushContainer`; a plain-array VALUE
    // (e.g. strokes seeded via `.set()` rather than appended incrementally)
    // only has `push`. Appending to the latter as if it were a container
    // throws "pushContainer is not a function". Promote it to a fresh
    // container seeded with its existing items, then append.
    if (
      existing &&
      typeof existing === 'object' &&
      'pushContainer' in existing
    ) {
      append(existing as LoroList, item);
    } else {
      const list = map.setContainer(propUrl, new LoroList());

      for (const el of propVal) {
        append(list, el);
      }

      append(list, item);
    }

    this.commitLoroEdit();
    this.eventManager.emit(
      ResourceEvents.LocalChange,
      propUrl,
      this.#cache[propUrl],
    );
  }

  /**
   * Replace every item in a Loro list property atomically.
   *
   * Deletes all current items and pushes the new ones in a single
   * `LoroDoc.commit()`, so the `UndoManager` records the replacement as
   * **one** undo checkpoint (not N). Used by the canvas history-scrub
   * gesture: on release we want one undo to take the user back to the
   * pre-scrub state, not N undos for N strokes.
   *
   * Object items become `LoroMap` containers (per-field CRDT merging on
   * future edits); primitives are pushed directly — same semantics as
   * `pushListItem`, just batched.
   */
  public replaceListItems(propUrl: string, items: JSONArray): void {
    this.#cache[propUrl] = [...items];
    this.#cacheDirty = true;
    this._dirty = true;

    const map = this.getLoroMap();

    if (!map) {
      return;
    }

    this.writeLoroListInPlace(map, propUrl, items);

    // Single commit at end → single UndoManager checkpoint for the whole
    // replacement.
    this.commitLoroEdit();
    this.eventManager.emit(
      ResourceEvents.LocalChange,
      propUrl,
      this.#cache[propUrl],
    );
  }

  /** Remove an item from a Loro list property by index. Used for canvas stroke deletion. */
  public removeListItem(propUrl: string, index: number): void {
    const map = this.getLoroMap();
    if (!map) return;

    const existing = map.get(propUrl);

    if (!existing || typeof existing !== 'object' || !('delete' in existing)) {
      // A plain-array value (seeded via `.set()`, not yet a container) has no
      // `delete`. Promote it to a container minus the item so erasing a
      // baked-in stroke actually persists.
      if (Array.isArray(existing)) {
        const next = existing.slice();
        next.splice(index, 1);
        this.replaceListItems(propUrl, next as JSONArray);
      }

      return;
    }

    const list = existing as LoroList;
    list.delete(index, 1);
    this.commitLoroEdit();
    this.rebuildCacheFromLoro();
    this.#cacheDirty = false;
    this._dirty = true;
    this.eventManager.emit(
      ResourceEvents.LocalChange,
      propUrl,
      this.#cache[propUrl],
    );
  }

  private writeJsonToLoroMap(
    map: InstanceType<typeof LoroLoader.Loro.LoroMap>,
    obj: JSONObject,
  ): void {
    const { LoroList, LoroMap } = LoroLoader.Loro;

    for (const [key, value] of Object.entries(obj)) {
      if (
        typeof value === 'string' ||
        typeof value === 'number' ||
        typeof value === 'boolean'
      ) {
        map.set(key, value);
      } else if (Array.isArray(value)) {
        const list = map.setContainer(key, new LoroList());
        this.writeJsonToLoroList(list, value);
      } else if (value && typeof value === 'object') {
        const nested = map.setContainer(key, new LoroMap());
        this.writeJsonToLoroMap(nested, value as JSONObject);
      }
    }
  }

  /**
   * Write `value` into the property's LoroList, keeping the existing
   * container when one is already there. Minting a new list on every
   * `set()` made OPFS/WS snapshot imports concurrent with the seed and
   * shuffled array order on open.
   */
  private writeLoroListInPlace(
    map: {
      get: (key: string) => unknown;
      setContainer: (key: string, container: LoroList) => LoroList;
    },
    prop: string,
    value: JSONValue[],
  ): void {
    const { LoroList: LoroListClass } = LoroLoader.Loro;
    const existing = map.get(prop);

    let list: LoroList;

    if (existing && typeof existing === 'object' && 'delete' in existing) {
      list = existing as LoroList;

      if (list.length > 0) {
        list.delete(0, list.length);
      }
    } else {
      list = map.setContainer(prop, new LoroListClass());
    }

    this.writeJsonToLoroList(list, value);
  }

  private writeJsonToLoroList(list: LoroList, arr: JSONValue[]): void {
    const { LoroList, LoroMap } = LoroLoader.Loro;

    for (const item of arr) {
      if (Array.isArray(item)) {
        const nested = list.pushContainer(new LoroList());
        this.writeJsonToLoroList(nested, item);
      } else if (item && typeof item === 'object') {
        const nested = list.pushContainer(new LoroMap());
        this.writeJsonToLoroMap(nested, item as JSONObject);
      } else if (
        typeof item === 'string' ||
        typeof item === 'number' ||
        typeof item === 'boolean'
      ) {
        list.push(item);
      }
    }
  }

  /**
   * Initialize the Loro UndoManager for undo/redo support. Call after the
   * doc is ready.
   *
   * `excludeOriginPrefixes: ['atomic:system']` is load-bearing. Internal
   * housekeeping commits (`writeDatatypeTags`, `markLoroSaved`, future
   * `adoptResourceState` etc.) tag their commits with that origin —
   * without the exclude, every save inserts a phantom undo step (the
   * datatype-tag rewrite), and the user's first undo press silently
   * reverts *that* instead of their last visible edit, exactly matching
   * the canvas bug: "Saving… shown, but the stroke doesn't disappear".
   * See {@link SYSTEM_COMMIT_ORIGIN}.
   */
  public ensureUndoManager(): void {
    const doc = this.getLoroDoc();
    if (!doc || this._loroUndoManager) return;
    const { UndoManager } = LoroLoader.Loro;
    const um = new UndoManager(doc, {
      maxUndoSteps: 200,
      mergeInterval: 0,
      excludeOriginPrefixes: [SYSTEM_COMMIT_ORIGIN],
    });
    this._loroUndoManager = um;
  }

  /** Undo last local operation. Returns true if something was undone. */
  public undo(): boolean {
    if (!this._loroUndoManager) return false;
    if (!this._loroUndoManager.canUndo()) return false;
    this._loroUndoManager.undo();
    this.commitLoroEdit();
    this.rebuildCacheFromLoro();
    this.#cacheDirty = false;
    this._dirty = true;
    // Reset saved version so next save exports full snapshot
    this._loroVersionAtLastSave = undefined;
    // Undo can change any number of properties; emit a wildcard
    // `LocalChange` so consumers (canvas page, useValue hooks, etc.) know
    // to re-read the cache. Without this the Loro state is correct but
    // React UI keeps painting the pre-undo strokes — the symptom is
    // "tapping undo shows Saving… but nothing visually changes".
    this.eventManager.emit(ResourceEvents.LocalChange, '', undefined);

    return true;
  }

  /** Redo last undone operation. Returns true if something was redone. */
  public redo(): boolean {
    if (!this._loroUndoManager) return false;
    if (!this._loroUndoManager.canRedo()) return false;
    this._loroUndoManager.redo();
    this.commitLoroEdit();
    this.rebuildCacheFromLoro();
    this.#cacheDirty = false;
    this._dirty = true;
    // Reset saved version so next save exports full snapshot
    this._loroVersionAtLastSave = undefined;
    // See `undo()` — wildcard `LocalChange` so React consumers reload.
    this.eventManager.emit(ResourceEvents.LocalChange, '', undefined);

    return true;
  }

  /** Whether undo is available. */
  public canUndo(): boolean {
    return this._loroUndoManager?.canUndo() ?? false;
  }

  /** Whether redo is available. */
  public canRedo(): boolean {
    return this._loroUndoManager?.canRedo() ?? false;
  }

  /** Removes a property value combination from the resource */
  public remove(propertyUrl: string): void {
    this.removeUnsafe(propertyUrl);
    this._dirty = true;
  }

  /**
   * Sign pending changes into a {@link Commit}.
   *
   * For DID genesis commits the subject is replaced with `did:ad:<signature>`.
   *
   * @returns The signed {@link Commit}.
   *
   * @internal Called only by `Store.newResource` (genesis) and the
   * store-level drain. Application code uses `store.newResource(...)`
   * + `resource.save()`, never this directly.
   */
  public async signChanges(differentAgent?: Agent): Promise<Commit> {
    const agent = this.store.getAgent() ?? differentAgent;

    if (!agent) {
      throw new Error('No agent has been set or passed, you cannot sign.');
    }

    // Loro is required: commits ride on `loroUpdate` bytes. If the app
    // deferred the WASM download (first paint optimization), trigger it
    // here on demand. Subsequent calls are no-ops — `enableLoro` is
    // idempotent and resolves immediately once the module is cached.
    if (!LoroLoader.isLoaded()) {
      await enableLoro();
    }

    // Ensure all cached properties are in the Loro doc before signing.
    // This catches properties set via cache hydration that haven't been
    // written to Loro yet (e.g. write/read permissions during creation).
    this.getLoroDoc();
    this.rebuildCacheFromLoro();
    this.#cacheDirty = false;

    // Genesis detection uses the lastCommit stamp (server-acked). Under
    // sign-at-drain there's at most one signed-but-unposted commit
    // per subject (the optional `signedGenesis` in the outbox).
    const lastCommit =
      this._lastCommit ?? this.get(properties.commit.lastCommit)?.toString();
    const isFirstCommit = !lastCommit;

    // Stamp the resource's `drive` at genesis (mirrors
    // `lib/src/commit.rs::create_did`). This is the genesis chokepoint that
    // EVERY creation path flows through — including table rows, which set their
    // parent directly and bypass `store.newResource`. The server's
    // `check_rights` resolves via this stable drive grant instead of walking a
    // parent that may not be materialized yet under concurrent creation (the
    // parent-before-child 401 cascade), and the WS commit fan-out routes by it
    // (planning/commit-fanout-drive-isolation.md).
    const DRIVE_PROP = 'https://atomicdata.dev/properties/drive';

    if (isFirstCommit && !this.get(DRIVE_PROP)) {
      const parentSubject = this.get(core.properties.parent) as
        | string
        | undefined;

      // A resource lives in its PARENT's drive — which is NOT necessarily the
      // creating agent's active drive. They coincide when you create in your
      // own drive, but diverge when a guest writes into a drive shared with
      // them (e.g. replying in someone else's chatroom): the resource belongs
      // to the OWNER's drive. Stamping the guest's own drive (or nothing) would
      // misroute the commit — the drive-scoped fan-out delivers only to the
      // owning drive's subscribers, so the owner never sees it. So the parent's
      // drive is authoritative: walk the LOCAL parent chain first (sync — the
      // chain is cached while you're viewing it, and `rebuildCacheFromLoro` now
      // preserves `drive`/`parent`), and only fall back to the active drive for
      // a top-level resource or a parent not yet materialized.
      const DRIVE_CLASS = 'https://atomicdata.dev/classes/Drive';
      let drive: string | undefined;

      if (parentSubject) {
        let cursor: string | undefined = parentSubject;
        const seen = new Set<string>();

        while (cursor && !seen.has(cursor)) {
          seen.add(cursor);
          const ancestor = this.store.getResourceLoading(cursor);
          const ancestorDrive = ancestor?.get(DRIVE_PROP) as string | undefined;

          if (ancestorDrive) {
            drive = ancestorDrive; // ancestor knows its drive (common path)
            break;
          }

          const classes =
            (ancestor?.get(core.properties.isA) as string[] | undefined) ?? [];

          if (classes.includes(DRIVE_CLASS)) {
            drive = cursor; // the chain reached the Drive root itself
            break;
          }

          const grandparent = ancestor?.get(core.properties.parent) as
            | string
            | undefined;

          if (!grandparent) {
            // Inconclusive: a genuine top-level root, or an ancestor not
            // materialized yet. Don't guess a non-drive ancestor — fall back
            // to the active drive below.
            break;
          }

          cursor = grandparent;
        }
      }

      if (!drive) {
        // A Drive IS its own drive. Its authoritative drive is its own subject
        // (a DID derived from the genesis signature — unknown here, before
        // signing), resolved by children walking the parent chain and by the
        // server. Do NOT fall back to the *active* drive: `createDrive` sets
        // the new drive active only AFTER creating it, so the active drive at
        // this point is the PREVIOUS one — stamping it makes every drive (and,
        // via inheritance, its children) point at the wrong drive. Leave it
        // unset; children resolve correctly from the parent chain.
        const isADrive = (
          (this.get(core.properties.isA) as string[] | undefined) ?? []
        ).includes(DRIVE_CLASS);

        if (!isADrive) {
          drive = this.store.getDrive();
        }
      }

      if (drive) {
        // `validate: false` — don't trigger a (possibly networked) Property
        // fetch on the hot creation path. The server resolves `drive`'s
        // datatype from its registered Property when materializing.
        await this.set(DRIVE_PROP, drive, false);
      }
    }

    // Stamp the sibling `datatypes` map so the server materializes
    // references/arrays exactly. Runs here — after
    // every property is in the doc, before the snapshot export below — so it
    // covers props set via `set()` and via cache hydration alike.
    //
    // On a genesis sign this is the FIRST commit on the doc, so it creates the
    // genesis change — tag it with the signing agent's subject (→ `createdBy`)
    // and a millisecond timestamp (→ `createdAt`). The oplog records only a
    // random peer id, never the agent, so this commit message is what carries
    // authorship inside the doc, readable without fetching the commit (which is
    // no longer refetchable under sign-at-drain).
    this.writeDatatypeTags(
      isFirstCommit
        ? {
            origin: SYSTEM_COMMIT_ORIGIN,
            timestamp: Date.now(),
            message: agent.subject,
          }
        : undefined,
    );

    // Export Loro delta — the sole carrier of property changes. Pass the agent
    // again as a fallback: if `writeDatatypeTags` had nothing to commit, this
    // export's commit is the one that creates the genesis change.
    const loroDelta = this.exportLoroDelta(
      isFirstCommit,
      isFirstCommit ? agent.subject : undefined,
    );

    if (!this.#commitBuilder.hasUnsavedChanges() && !loroDelta) {
      this._dirty = false;
      throw new Error(`No changes to sign for ${this.subject}`);
    }

    if (loroDelta) {
      this.#commitBuilder.setLoroUpdate(loroDelta);
    }

    // Auto-detect genesis: no lastCommit stamp means this is a new resource.
    // The server requires is_genesis=true for DID resources that do not
    // yet exist. Only for DID-eligible subjects (_new: or did:ad:) —
    // HTTP URLs use server-assigned subjects.
    // Agents are excluded: their identity is fixed by their public key
    // (did:ad:agent:<pubkey>), not derived from a genesis-commit signature.
    // Marking an agent commit as genesis triggers `delete subject` below,
    // which makes the server's parser derive the resource subject as
    // `did:ad:<signature>` and silently store the agent's data under a
    // commit-id key instead of the agent DID — subsequent fetches of the
    // agent then 404 in `get_propvals` and fall through to a synthetic
    // 4-property view (createdAt, isA, publicKey, read).
    const isDIDEligible =
      this.subject.startsWith('_new:') || this.subject.startsWith('did:ad:');
    const isAgent = this.subject.startsWith('did:ad:agent:');

    if (isDIDEligible && !isAgent && isFirstCommit) {
      this.#commitBuilder.setIsGenesis(true);
    }

    // Clone the builder so new changes after this call go into a fresh one.
    const builder = this.#commitBuilder.clone();
    this.#commitBuilder = new CommitBuilder(this.subject);
    this._dirty = false;

    // Advance the save cursor: everything in the doc up to here is now
    // captured in the signed commit. The next exportLoroDelta will start
    // from this version. Must be a direct assignment — `markLoroSaved`-
    // style "init only" helpers would no-op here.
    if (this._loroDoc) {
      this._loroVersionAtLastSave = this._loroDoc.oplogVersion();
    }

    const commit = await builder.sign(agent);

    // DID genesis: the real subject is derived from the signature.
    if (commit.subject !== this.subject) {
      const oldSubject = this.subject;
      this._subject = commit.subject;
      // Update the fresh #commitBuilder to use the real subject.
      this.#commitBuilder = new CommitBuilder(commit.subject);

      if (this._store) {
        // Silently move the resource in the store map — don't use removeResource()
        // which emits events that trigger cascading fetches (sideBarHandler etc.)
        this.store.resources.delete(oldSubject);
        // Keep an alias so children that reference the old _new: subject can still find it.
        this.applyToStore('local-pre-push', { subject: oldSubject });
      }
    }

    this.appliedCommitSignatures.add(commit.signature);
    this.loading = false;
    this.new = false;

    // Under sign-at-drain, the caller (`store.newResource` for the
    // genesis path) decides how to enqueue the envelope — typically
    // via `outbox.setGenesisCommit` for DID-derived subjects. Drain
    // POSTs the genesis; subsequent Loro ops mark dirty + drain
    // signs incremental commits directly without going through
    // `signChanges`.

    // Surface the queued commit in the Sync page's commit log immediately,
    // so users can see what's pending without waiting for the push. The same
    // log entry transitions in place to `sent` / `failed` when the outbox
    // drain posts it.
    this.store.logPendingCommit(commit);

    return commit;
  }

  /**
   * Commits the changes and sends the Commit to the resource's `/commit`
   * endpoint. Returns the Url of the created Commit. If you don't pass an Agent
   * explicitly, the default Agent of the Store is used.
   * When there are no changes no commit is made and the function returns Promise<undefined>.
   *
   * The commit is signed at drain time by the outbox, not here.
   */
  /**
   * Persist this resource. Resolves once the change is durable:
   *
   *  - `'persisted'` — the server acknowledged the commit.
   *  - `'offline'`   — server unreachable; saved to clientDb, the drain
   *                    retries on reconnect.
   *  - `'noop'`      — nothing to save (no unsaved changes, nothing
   *                    pending).
   *
   * Always uses the store's agent. Genesis (DID derivation) is decided
   * internally by `store.newResource`, not by callers — there is no
   * public "mark this as genesis" step.
   */
  /** @internal — set by `store.newResource` to hand off the
   *  DID-derivation genesis commit. Held until the first `save()`. */
  public stashGenesis(commit: Commit): void {
    this._pendingGenesis = commit;
  }

  /**
   * Fork this resource into a Fork under `parent`, and save it.
   *
   * The fork is only as private as `parent` is — see {@link forkResource}.
   */
  public fork(parent: string): Promise<Resource> {
    return forkResource(this.store, this, parent);
  }

  /**
   * Duplicate this resource into a new, independent resource under `parent`,
   * carrying its content but not its identity, ACL, or history. Unlike
   * {@link fork}, the copy has no link back and cannot be merged in. See
   * {@link copyResource}.
   */
  public copyTo(parent: string): Promise<Resource> {
    return copyResource(this.store, this, parent);
  }

  /**
   * Merge this Fork onto the resource it forked, as a single commit signed by
   * the current agent. Throws if this is not a Fork. See {@link mergeFork}.
   *
   * Named for its target rather than `merge`, which already means something
   * else here: folding another Resource's propvals into this one.
   */
  public mergeIntoOriginal(options?: MergeForkOptions): Promise<Resource> {
    return mergeFork(this.store, this, options);
  }

  /** Whether this resource proposes a change to another one. */
  public get isFork(): boolean {
    return isFork(this);
  }

  /**
   * Whether this resource carries Loro-container content — a rich-text `doc`
   * body (DocumentV2) — beyond its plain propvals. Such content can't be forked
   * or merged by copying propvals; it needs the CRDT body path below.
   */
  public hasLoroBody(): boolean {
    const doc = this.getLoroDoc();

    if (!doc) return false;

    try {
      return doc.getMap('doc').keys().length > 0;
    } catch {
      return false;
    }
  }

  /**
   * Seed this resource's Loro body from `source` by importing its snapshot, so
   * the two bodies share causal history and can later merge as a CRDT. Returns
   * `source`'s Loro version at this point, base64-encoded — persist it (as
   * `forkVersion`) and pass it to {@link mergeLoroBodyFrom} at merge time.
   *
   * The import also overwrites this resource's propvals with `source`'s; the
   * caller MUST re-assert this resource's own identity/propvals afterward.
   * @internal fork/merge only.
   */
  public seedLoroBodyFrom(source: Resource): string | undefined {
    const src = source.getLoroDoc();
    const dst = this.getLoroDoc();

    if (!src || !dst) return undefined;

    const forkVersion = src.oplogVersion();
    dst.import(src.export({ mode: 'snapshot' }));
    dst.commit();

    return encodeB64(forkVersion.encode());
  }

  /**
   * Merge `fork`'s body edits since `forkVersionB64` into this resource's live
   * Loro doc. Because the fork's body shares this resource's pre-fork history
   * (see {@link seedLoroBodyFrom}), only the fork's new body ops are imported,
   * and they merge with any concurrent edits to this resource as a CRDT — no
   * side loses its work.
   *
   * The import also overwrites this resource's propvals with the fork's; the
   * caller MUST restore this resource's own propvals afterward.
   * @internal fork/merge only.
   */
  public mergeLoroBodyFrom(fork: Resource, forkVersionB64: string): void {
    const src = fork.getLoroDoc();
    const dst = this.getLoroDoc();

    if (!src || !dst) return;

    const { VersionVector } = LoroLoader.Loro;
    const from = VersionVector.decode(decodeB64(forkVersionB64));
    const delta = src.export({ mode: 'update', from });

    if (delta.length === 0) return;

    dst.import(delta);
    dst.commit();
  }

  public async save(): Promise<SaveResult> {
    const hasChanges = this.hasUnsavedChanges();

    if (
      !hasChanges &&
      !this._pendingGenesis &&
      !this.store.outbox.hasPending(this.subject)
    ) {
      // Save called on a clean resource (typical on blur with no edits) — not
      // an error worth surfacing to the console.
      return 'noop';
    }

    this._saveDepth++;
    const closeSave = perfSpan('resource.save');

    try {
      return await this._saveInner(hasChanges);
    } finally {
      closeSave();
      this._saveDepth--;
    }
  }

  private async _saveInner(hasChanges: boolean): Promise<SaveResult> {
    const agent = this.store.getAgent();

    if (!agent) {
      throw new Error('No agent has been set, you cannot save.');
    }

    if (!this._lastCommit) {
      this._lastCommit = this.get(properties.commit.lastCommit)?.toString();
    }

    // If the parent of this resource is new we can't save yet so we add it to a batched that gets saved when the parent does.
    if (this.isParentNew()) {
      this.store.batchResource(this.subject);

      return 'offline';
    }

    // Local-only drives: sign-at-save. Same signing pipeline as the
    // drain (so history, attribution, and the Loro save cursor behave
    // identically), but the commit is materialized locally instead of
    // POSTed — these subjects never reach a server.
    if (this.store.isLocalOnlySubject(this.subject)) {
      return this.saveLocalOnly(agent, hasChanges);
    }

    // True when this save creates the resource for the first time (a genesis
    // commit). Newly-created online resources are not otherwise written to the
    // local clientDb — `addResource` skips OPFS puts for `_new:`/unsynced
    // resources, and the `_new:`→`did:ad:` rename doesn't re-persist. Without a
    // clientDb write the resource is on the server but absent from OPFS, so the
    // OPFS-first collection queries (`parent=…`) miss it after a reload until a
    // full drive re-sync happens to pull it back. We persist it below.
    let wasGenesis = false;

    try {
      // A genesis signed at creation time by `store.newResource` is held
      // on the resource (`_pendingGenesis`) — NOT the outbox — so an
      // unsaved placeholder (e.g. a table row created on mount but never
      // filled) is never POSTed. Now that the user is explicitly
      // saving, move it into the outbox to drain.
      if (this._pendingGenesis) {
        wasGenesis = true;
        this.store.outbox.setGenesisCommit(this.subject, this._pendingGenesis);
        this._pendingGenesis = undefined;
      } else if (
        hasChanges &&
        (this.#commitBuilder.isGenesis || this.subject.startsWith('_new:'))
      ) {
        wasGenesis = true;

        // Genesis path for resources NOT created via `store.newResource` —
        // the new-resource form / `NewInstanceButton`, which mint a
        // transient `_new:` subject via `store.createSubject()` and then
        // `set()` + `save()` with no explicit genesis step. The real
        // `did:ad:<sig>`
        // subject only exists after signing, so sign now: `signChanges`
        // auto-detects genesis (no lastCommit stamp + DID-eligible), derives
        // the DID, and renames this resource in place; we enqueue the
        // signed genesis under the NEW subject. Without this a `_new:`
        // subject would be marked dirty and the drain would POST a commit
        // with `subject: "_new:…"`, which the server rejects ("Unable to
        // parse string as URL") and retries forever.
        try {
          const genesis = await this.signChanges(agent);
          this.store.outbox.setGenesisCommit(this.subject, genesis);
        } catch (e) {
          if (
            e instanceof Error &&
            e.message.startsWith('No changes to sign')
          ) {
            return 'noop';
          }

          throw e;
        }
      }

      if (!this.store.serverConnected) {
        // Offline: persist the Loro snapshot to clientDb BEFORE
        // marking the outbox dirty. `pendingDirtyCount > 0` is the
        // canonical "edit landed durably" signal; bumping it via
        // `markDirty` before `saveOffline` finishes would leave a
        // window where a reload loses the OPFS snapshot while the
        // localStorage dirty bit survives.
        await this.saveOffline();

        if (hasChanges && !this.#commitBuilder.isGenesis) {
          this.store.outbox.markDirty(this.subject);
        }

        return 'offline';
      }

      if (hasChanges && !this.#commitBuilder.isGenesis) {
        // Online non-genesis: mark dirty. The store-level drain
        // exports the accumulated Loro delta, signs ONE commit, sends.
        this.store.outbox.markDirty(this.subject);
      }

      // Await the drain so `save()` resolves only once the server has
      // acked. The keystroke path is unaffected — `useValue` debounces
      // 100 ms before calling `save()`, and the drain coalesces; the
      // await matters for explicit saves (blur, Enter, programmatic)
      // that need "is it safe to leave?" before proceeding.
      await this.store.syncDirtyResources();

      // Mirror just-created resources into clientDb so the OPFS-first cold
      // path (collection `parent=` queries after a reload) sees them locally
      // instead of returning a stale empty result. Covers two cases:
      //  - Agents: the server returns a synthetic just-in-time view (no
      //    `drives`/`privateDrive`) until the commit durably persists, so a
      //    refetch under load loses the user's saved drives.
      //  - Any genesis (e.g. table rows materialized from a virtual `_new:`
      //    placeholder): the resource is on the server but was never put in
      //    OPFS, so its parent-indexed membership is invisible after reload.
      //
      // This write is on the critical path of every create, and against a
      // RELEASE server it is the dominant one: ~33 ms here versus ~5 ms for the
      // commit round-trip it follows. Measure against a debug server and you
      // conclude the opposite — that build verifies signatures ~7× slower,
      // which buries this. Worker-side split of the ~33 ms, on sub-2KB
      // payloads: ~13 ms `putResource` (parse + a redb write transaction per
      // resource), ~2.5 ms snapshot, ~3.5 ms fsync, the rest postMessage and
      // queue wait. The Loro export before it is 0 ms.
      //
      // It stays awaited AND durable regardless. Callers read the local
      // database back straight away (a table's rows come from a `parent=`
      // query); dropping either loses freshly-typed rows in `tables.spec.ts`,
      // measured on a healthy store. Making a burst of creates faster means
      // making fewer, larger writes — one transaction over N resources — not
      // making each one lazier.
      if (wasGenesis || this.subject.startsWith('did:ad:agent:')) {
        await this.persistToClientDb();
      }

      return 'persisted';
    } catch (e) {
      if (isNetworkError(e)) {
        this.store.setServerConnected(false);
        await this.saveOffline();

        return 'offline';
      }

      this.commitError = e;
      this.applyToStore('local-pre-push');
      throw e;
    }
  }

  /**
   * Persist a resource that belongs to a local-only drive (never
   * synced to any server). Mirrors the online path's contract
   * ('persisted' = durable) without a POST: sign the accumulated
   * changes through the same pipeline as the drain — advancing the
   * Loro save cursor and chaining `lastCommit` identically — then
   * materialize each commit for the local history log and write the
   * full state to clientDb (OPFS).
   */
  private async saveLocalOnly(
    agent: Agent,
    hasChanges: boolean,
  ): Promise<SaveResult> {
    const settled: Commit[] = [];
    const genesis = this._pendingGenesis;
    this._pendingGenesis = undefined;

    if (genesis) {
      settled.push(genesis);
      // The delta sign below uses lastCommit as the "already exists"
      // stamp — point it at the genesis first.
      this.setLastCommitValue(`did:ad:commit:${genesis.signature}`);
    }

    if (hasChanges) {
      try {
        settled.push(await this.signChanges(agent));
      } catch (e) {
        if (e instanceof Error && e.message.startsWith('No changes to sign')) {
          if (settled.length === 0) return 'noop';
        } else {
          throw e;
        }
      }
    }

    // Server sets `createdAt` on apply; local-only resources need it
    // locally for sorting (mirrors `saveOffline`).
    if (this.get(commits.properties.createdAt) === undefined) {
      this.setCreatedAtValue(Date.now());
    }

    for (const commit of settled) {
      this.setLastCommitValue(`did:ad:commit:${commit.signature}`);
      this.store.logLocalOnlyCommitSettled(commit);
    }

    await this.persistToClientDb();

    this.commitError = undefined;
    this.loading = false;
    this.applyToStore('local-acked');
    this.store.notifyResourceSaved(this);

    return 'persisted';
  }

  /**
   * Save when the server is unreachable. Under sign-at-drain the
   * outbox holds a dirty bit (and optionally a pre-signed genesis
   * envelope) but no incremental signed commits — those are signed
   * fresh from the Loro delta at drain time. So the offline path:
   *
   *  - Persists this resource atomically (JSON-AD + Loro snapshot) to
   *    clientDb so a reload can hydrate the Loro state before the WS
   *    reconnect drain re-signs from the same `_loroVersionAtLastSave`
   *    cursor.
   */
  private async saveOffline(): Promise<void> {
    // Server sets createdAt on apply; we need it locally for sort.
    if (this.get(commits.properties.createdAt) === undefined) {
      this.setCreatedAtValue(Date.now());
    }

    const signedGenesis = this.store.outbox.getEntry(
      this.subject,
    )?.signedGenesis;

    if (signedGenesis) {
      this.setLastCommitValue(`did:ad:commit:${signedGenesis.signature}`);
    }

    // Capture the last-synced Loro version so a reload can rewind the save
    // cursor here and re-emit this offline delta. `_loroVersionAtLastSave`
    // still points at the last server-acked version (the offline ops are
    // past it — that's why the subject is dirty), so this is exactly the
    // baseline the reconnect drain must export from. `setBaseVersion` keeps
    // only the first offline baseline, so a run of offline edits all rebase
    // on the same synced version.
    //
    // Skip when the only commit is an unposted genesis. `signChanges` already
    // advanced the local cursor to that snapshot; treating it as a rewind
    // baseline makes the post-genesis empty export look like "OPFS not ready"
    // and the drain retries forever (`offline-create-then-online`).
    if (!signedGenesis) {
      const baseVersion = this.getEncodedSaveCursor();

      if (baseVersion) {
        this.store.outbox.setBaseVersion(this.subject, baseVersion);
      }
    }

    await this.persistToClientDb();

    this.commitError = undefined;
    this.loading = false;
    this.applyToStore('offline-replay');
    this.store.notifyResourceSaved(this);
  }

  /**
   * Mirror this resource's full state (JSON-AD propvals + Loro snapshot)
   * into clientDb (OPFS) so a reload can read it locally. `saveOffline`
   * uses it for offline durability. The online save path uses it for
   * `did:ad:agent:` subjects: the server returns a synthetic just-in-time
   * agent view (only publicKey/read/createdAt/isA — NO `drives`) whenever
   * the agent's commit hasn't durably persisted yet, so under load a
   * reload would refetch that view and lose the user's saved drives.
   * Mirroring the agent locally means the cold-load path
   * (`fetchResourceWithLocalFallback`) reads it from clientDb and never
   * consults the racy server view.
   *
   * @internal store-level / offline-persistence only.
   */
  public async persistToClientDb(): Promise<void> {
    const clientDb = this.store.getClientDb();
    if (!clientDb) return;

    const obj: Record<string, unknown> = { '@id': this.subject };

    for (const [k, v] of this.getEntries()) {
      if (!(v instanceof Uint8Array)) obj[k] = v;
    }

    const snapshot = this._loroDoc?.export({ mode: 'snapshot' });

    // Await the OPFS write — when `save()` resolves the edit MUST survive a
    // reload. A non-awaited write left a reload reading OPFS before the
    // write landed and silently losing the edit.
    const closePersist = perfSpan('resource.persistToClientDb');

    try {
      await clientDb.putResourceWithSnapshot(
        this.subject,
        JSON.stringify(obj),
        snapshot,
      );
      closePersist();
    } catch (e) {
      closePersist({ err: e instanceof Error ? e.message : String(e) });
      console.error('[persistToClientDb] failed:', e);
    }
  }

  /**
   * Set a Property, Value combination and perform a validation. Will throw if
   * property is not valid for the datatype. Will fetch the datatype if it's not
   * available. Updates the cache and Loro doc.
   *
   * When undefined is passed as value, the property is removed from the resource.
   */
  public async set<
    Prop extends string,
    Value extends InferTypeOfValueInTriple<C, Prop>,
  >(
    prop: Prop,
    value: Value,
    /**
     * Disable validation if you don't need it. It might cause a fetch if the
     * Property is not present when set is called
     */
    validate = true,
  ): Promise<void> {
    if (value instanceof Uint8Array) {
      throw new Error('Binary values (Uint8Array) cannot be set via set().');
    }

    if (validate) {
      let fullProp;

      try {
        fullProp = await this.store.getProperty(prop);
      } catch (e) {
        // Property fetch failed (offline, server 5xx, property doesn't
        // exist yet on a fresh server). Skipping validation here lets
        // the edit land in Loro — the server will reject the resulting
        // commit later if the datatype is genuinely wrong. Dropping the
        // user's keystroke in this case is the worse outcome.
        console.warn(
          `[Resource.set] Skipping validation for ${prop} on ${this.subject} — property fetch failed:`,
          e,
        );
        fullProp = undefined;
      }

      if (fullProp) {
        try {
          validateDatatype(value, fullProp.datatype);
        } catch (e) {
          if (e instanceof Error) {
            e.message = `Error validating ${fullProp.shortname} with value ${value} for ${this.subject}: ${e.message}`;
          }

          throw e;
        }
      }
    }

    if (value === undefined) {
      this.remove(prop);
      this.eventManager.emit(ResourceEvents.LocalChange, prop, value);

      return;
    }

    // Write to Loro only — cache is rebuilt lazily on next get()
    this.loroSetProperty(prop, value as JSONValue);
    this.#cacheDirty = true;

    this._dirty = true;
    this.eventManager.emit(
      ResourceEvents.LocalChange,
      prop,
      value as JSONValue,
    );
  }

  public removeUnsafe(prop: string): void {
    if (prop === commits.properties.loroUpdate) {
      this._loroSnapshotBytes = undefined;
      this.resetLoroState();

      return;
    }

    if (isDerivedByServer(prop)) {
      delete this.#cache[prop];

      return;
    }

    this.loroDeleteProperty(prop);
    this._auxValues.delete(prop);
    this.#cacheDirty = true;
  }

  public clearUnsafe(): void {
    this.#cache = Object.create(null);
    this.#cacheDirty = false;
    this._auxValues.clear();
    this._loroSnapshotBytes = undefined;
    this.resetLoroState();
  }

  /** Import committed Loro bytes (snapshot or update) into the doc.
   *  Returns `{ complete }` — `false` when the bytes couldn't fully
   *  apply (threw, or left pending ops awaiting base deps we don't
   *  have). Callers persisting / displaying the result should treat
   *  `complete: false` as "this state is unusable," not "loaded." */
  public importLoroUpdate(
    loroUpdate: Uint8Array,
    /**
     * Replace the local Loro doc with these bytes instead of merging. Use ONLY
     * for authoritative FULL snapshots (e.g. a WS GET response carrying the
     * SNAPSHOT flag): merging a full snapshot into a doc that was previously
     * seeded with PARTIAL state (a SUB push delivering only some props) can
     * surface only the seed's props, leaving the resource class-less. A clean
     * replace makes the authoritative state win. Never pass `true` for a delta.
     */
    replace = false,
  ): { complete: boolean } {
    // Drop any seeded/partial state so the incoming snapshot is authoritative.
    if (replace) {
      this.resetLoroState();
      // Point `getLoroDoc()` at these bytes so it imports the snapshot
      // instead of seeding a *new* LoroList per array from `#cache`.
      // Seeding-then-merging was the OPFS cold-load flash: two concurrent
      // lists for `requires`/`recommends` concatenated or LWW-swapped.
      this._loroSnapshotBytes = loroUpdate;
    }

    // Ensure the LoroDoc exists, then import the update into it.
    const doc = this.getLoroDoc();

    if (!doc) {
      // Loro WASM not loaded — buffer the bytes for `getLoroDoc()` to
      // import once Loro initializes. The `loading` getter sees the
      // buffered bytes and keeps reporting `true` until then, so
      // consumers don't fall back to the truncated DID.
      this._loroSnapshotBytes = loroUpdate;

      // RACE FIX: a WS GET/SUB snapshot can arrive BEFORE Loro WASM finishes
      // loading. We buffer it above, but nothing guarantees the buffer is ever
      // applied — the React hooks that re-render `onReady` only materialize the
      // doc if they happen to read a prop, and the Compiler can memoize the
      // (empty) render so they don't. Apply the buffer ourselves the moment
      // Loro is ready and re-notify so consumers re-render (`getLoroDoc` clears
      // `_loading` when it materializes renderable content — see its
      // `initializedFromSnapshot` branch). Without this, the resource is stuck
      // showing its bare subject until something else pokes it — the flaky "dev
      // drive sometimes doesn't show" bug.
      LoroLoader.onReady(() => {
        if (!this._loroDoc && this._loroSnapshotBytes) {
          this.getLoroDoc();
          // Re-notify THROUGH THE STORE — `useResource`/`useValue` re-render
          // only on `store.notify` (snapshot-tuple bump), NOT on the Resource's
          // own eventManager.
          this._store?.notifyResourceUpdated(this);
        }
      });

      // Not applied yet, but not a failure — `getLoroDoc()` will
      // import the buffer and the `loading` getter keeps it gated.
      return { complete: true };
    }

    try {
      // `replace` already pointed `getLoroDoc()` at these bytes, so the
      // snapshot is in the doc. Importing it a second time merged it with
      // the JSON-AD heal commit and could drop `isA` (stuck `loading`, no
      // title after reload) or duplicate array items.
      if (replace) {
        this._loroSnapshotBytes = undefined;
        this.eventManager.emit(ResourceEvents.LocalChange, '', undefined);

        return { complete: true };
      }

      const status = doc.import(loroUpdate);
      this.rebuildCacheFromLoro();
      this.#cacheDirty = false;
      this.initLoroSaveCursorIfFresh();

      // Mirror what `markDirty` / `undo` / `redo` already do: when the
      // resource's Loro state changes out-of-band of `set` / `pushListItem`,
      // emit a wildcard `LocalChange` so React consumers (canvas page,
      // `useValue`, etc.) re-read the cache. Without this, an incoming
      // WS `UPDATE` quietly mutates the doc and the UI keeps painting the
      // pre-import state until the user navigates away and back.
      this.eventManager.emit(ResourceEvents.LocalChange, '', undefined);

      // `pending` is non-null when the update referenced base ops we
      // don't have — Loro buffers those ops and applies *nothing*
      // visible until the missing deps arrive (which, for a GET /
      // sync-push response, they never will). This is how a 14 KB
      // delta sent to a client that lacks the base snapshot lands as
      // a resource with only `subject` + `lastCommit` and no real
      // properties — and used to do so silently. Surface it so the
      // store can decide whether to error the resource. See
      // `lib/src/sync/engine.rs` `export_updates_since` — the server
      // sends a delta whenever the client reports any VV for the
      // subject, so a client whose in-memory doc doesn't actually
      // hold that base (e.g. an OPFS-leadership-failed tab reporting
      // the leader's VVs) gets an unappliable delta.
      // `pending` is non-null when the update referenced base ops we
      // don't have — Loro buffers those and applies nothing visible.
      // We DON'T warn here: importing a delta into a fresh
      // commit-detail resource (materialization) legitimately leaves
      // pending ops. The caller decides whether pending is a problem —
      // `applyIncoming` treats it as a sync error (full state expected),
      // materialization ignores it (delta expected).
      const pending = status?.pending;
      const hasPending = !!pending && pending.size > 0;

      return { complete: !hasPending };
    } catch (e) {
      console.warn(
        `[Resource] importLoroUpdate failed for ${this.subject}:`,
        e,
      );

      return { complete: false };
    }
  }

  /** Sets the error on the Resource. Does not Throw. */
  public setError(e: Error): void {
    this.error = e;
  }

  /** Set the Subject / ID URL of the Resource. Does not update the Store. */
  public setSubject(subject: string): void {
    const normalized = this._store?.normalizeSubject(subject) ?? subject;
    Client.tryValidSubject(normalized);
    this.#commitBuilder.setSubject(normalized);
    this._subject = normalized;
  }

  /** Refetches the resource from the server. Will reset all changes to the latest saved version */
  public async refresh(): Promise<void> {
    // Reset the commit builder so our changes don't get merged with the server version.
    this.#commitBuilder = new CommitBuilder(this.subject);

    await this.store.fetchResourceFromServer(this.subject, {
      noWebSocket: true,
    });
  }

  /** Resolves the `/commit` endpoint for this resource. */
  private getCommitEndpoint(): string {
    const serverUrl = this.store.getServerUrl();

    if (!serverUrl || serverUrl === 'null') {
      console.warn(
        `Resource ${this.subject} has an invalid server URL: ${serverUrl}. Falling back to origin.`,
      );
    }

    const base = !serverUrl || serverUrl === 'null' ? '' : serverUrl;
    const fallbackBase = base || window.location.origin;

    if (
      this.subject.startsWith('did:') ||
      this.subject.startsWith('internal:')
    ) {
      return new URL('/commit', fallbackBase).toString();
    }

    try {
      const url = new URL(this.subject);

      if (url.origin && url.origin !== 'null') {
        return url.origin + `/commit`;
      }
    } catch {
      // ignore
    }

    return new URL('/commit', fallbackBase).toString();
  }

  private isParentNew() {
    const parentSubject = this.get(core.properties.parent) as string;

    if (!parentSubject) {
      return false;
    }

    const parent = this.store.getResourceLoading(parentSubject);

    return parent.new;
  }
}

/**
 * A subject that is `internal:` and nothing else — no whitespace, and either
 * `internal:/path` (server root) or `internal:tenant:/path` (subdomain drive).
 *
 * Deliberately strict so a prose propval that merely begins with the word
 * "internal:" is never rewritten. Any real subject matches; a sentence does
 * not, because it contains a space.
 */
const INTERNAL_SUBJECT = /^internal:(?:\/|[A-Za-z0-9-]+:\/)\S*$/;

/**
 * Resolves an `internal:` subject against this server's origin — the client
 * side of what {@link https://docs.atomicdata.dev | serialize.rs} does for
 * HTTP responses.
 *
 * `internal:` is the server's *storage* scheme. It reaches the browser only
 * through Loro snapshots: a WebSocket frame carries the CRDT bytes verbatim,
 * and while the frame's subject header is resolved server-side, the AtomicUrl
 * values *inside* the document are not. (They can't be — the snapshot is
 * covered by the commit signature, so the server must not rewrite it.)
 *
 * Left raw, such a value is unusable: the browser has no host to send a
 * request to, so `useResource` on it issues no request at all and hangs in
 * `loading` forever, with nothing in the console. That is why a migrated
 * drive's tables render no rows — the table dereferences its `classtype`,
 * which arrives as `internal:/…` — and why the same resource ends up in the
 * store under two keys at once.
 *
 * Resolving unconditionally is safe here in a way it would not be on the
 * server: the client never mints an `internal:` subject of its own. Its
 * temporary subjects are `_new:`/`_local:` and its local-only drives are
 * DIDs, so an `internal:` string in the browser is always a leaked storage
 * subject.
 */
export function localizeInternalSubject(value: string, origin: string): string {
  if (!INTERNAL_SUBJECT.test(value)) return value;

  const rest = value.slice('internal:'.length);
  const base = origin.replace(/\/+$/, '');

  // `internal:/path` → `<origin>/path`. Root (`internal:/`) keeps its slash,
  // matching the subject the server serves for a root drive.
  if (rest.startsWith('/')) return `${base}${rest}`;

  // `internal:tenant:/path` → `<proto>tenant.<host>/path`
  const separator = rest.indexOf(':/');

  if (separator === -1) return value;

  const subdomain = rest.slice(0, separator);
  const path = rest.slice(separator + 1);
  const withProtocol = /^(\w+:\/\/)(.*)$/.exec(base);

  return withProtocol
    ? `${withProtocol[1]}${subdomain}.${withProtocol[2]}${path}`
    : `${subdomain}.${base}${path}`;
}

/** Applies {@link localizeInternalSubject} to a propval, including arrays. */
function localizeInternalSubjects(value: JSONValue, origin: string): JSONValue {
  if (typeof value === 'string') {
    return localizeInternalSubject(value, origin);
  }

  if (Array.isArray(value)) {
    let changed = false;
    const next = value.map(item => {
      if (typeof item !== 'string') return item;

      const localized = localizeInternalSubject(item, origin);

      if (localized !== item) changed = true;

      return localized;
    });

    return changed ? (next as JSONValue) : value;
  }

  return value;
}

function normalizeLoroValue(
  loroDatatypeTag: string | undefined,
  value: unknown,
): JSONValue {
  // LoroList.toJSON() returns a native JS array — pass through directly.
  if (Array.isArray(value)) {
    return value as JSONValue;
  }

  // Legacy: arrays/objects were JSON-stringified before Loro arrays became
  // native `LoroList`s (see `loroSetProperty`) and before the `json`
  // datatype existed as such. The sibling `datatypes` map (`datatypeTag`,
  // `writeDatatypeTags`) tags exactly which properties actually hold
  // array/JSON content, so only THOSE strings get JSON.parsed — a plain
  // string/markdown propval (a chat title, a resource description) that
  // merely starts with `{` or `[` is never misread as JSON.
  if (
    (loroDatatypeTag === 'resourceArray' ||
      loroDatatypeTag === 'json' ||
      loroDatatypeTag === 'localizedText') &&
    typeof value === 'string' &&
    (value.startsWith('[') || value.startsWith('{'))
  ) {
    try {
      const parsed = JSON.parse(value) as JSONValue;

      if (loroDatatypeTag === 'resourceArray' && !Array.isArray(parsed)) {
        return value;
      }

      return parsed;
    } catch {
      return value;
    }
  }

  return value as JSONValue;
}

/** Type of Rights (e.g. read or write) */
export enum RightType {
  /** Open a resource or its children */
  READ = 'read',
  /** Edit or delete a resource or its children */
  WRITE = 'write',
}

/** A grant / permission that is set somewhere */
export interface Right {
  /** Subject of the Agent who the right is for */
  for: string;
  /** The resource that has set the Right */
  setIn: string;
  /** Type of right (e.g. read / write) */
  type: RightType;
}

/** A point in the resource's history, derived from the Loro OpLog. */
export interface Version {
  /** Peer that authored this change */
  peer: string;
  /** Timestamp in milliseconds */
  timestamp: number;
  /** Loro frontiers — pass to doc.checkout() to materialize this version */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  frontiers: any[];
  /** Human-readable commit message, if set */
  message?: string;
  /**
   * The Loro change message this version was bucketed by: the drain's
   * `c-<ulid>` commit token or, at genesis, the creator's agent subject.
   * Not for display; it is what a signed envelope's `tokens` name.
   */
  token?: string;
  /** Materialized property values at this version */
  propvals: Map<string, JSONValue>;
  /** Top-level Loro containers besides `properties` at this version — most
   *  notably `doc`, the loro-prosemirror rich-text root that holds a
   *  Document's body. Empty when the resource has no extra containers. */
  containers: Map<string, JSONValue>;
}

/** Returns true if the error is a network/fetch failure (server unreachable). */
function isNetworkError(e: unknown): boolean {
  if (e instanceof TypeError && e.message.includes('Failed to fetch')) {
    return true;
  }

  if (e instanceof Error && e.message.includes('Failed to fetch')) {
    return true;
  }

  // AtomicError wrapping a fetch failure
  if (
    e instanceof Error &&
    e.message.includes('Posting Commit') &&
    e.message.includes('Failed to fetch')
  ) {
    return true;
  }

  return false;
}
