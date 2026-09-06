import stringify from 'fast-json-stable-stringify';
// https://github.com/paulmillr/noble-ed25519/issues/38

import { Client } from './client.js';
import { Resource } from './resource.js';
import type { Store } from './store.js';
import { type JSONValue, type JSONArray } from './value.js';
import { decodeB64, encodeB64 } from './base64.js';
import { commits } from './ontologies/commits.js';
import { core } from './ontologies/core.js';
import type { Agent } from './agent.js';
import { perfSpan } from './perf-trace.js';

/** A {@link Commit} without its signature, signer and timestamp */
export interface CommitBuilderI {
  /** The resource being edited */
  subject: string;
  /** The property-value combinations being edited https://atomicdata.dev/properties/set */
  set?: Record<string, JSONValue>;
  /**
   * The property-value combinations for which one or more ResourceArrays will
   * be appended. https://atomicdata.dev/properties/push
   */
  push?: Record<string, JSONArray>;
  /** Loro CRDT binary update for the entire resource */
  loroUpdate?: Uint8Array;
  /** The properties that need to be removed. https://atomicdata.dev/properties/remove */
  remove?: string[];
  /** If true, the resource must be deleted. https://atomicdata.dev/properties/destroy */
  destroy?: boolean;
  /**
   * URL of an earlier envelope, optional audit metadata. Not a causal gate.
   */
  previousCommit?: string;
  /** Whether this is the first commit for a Resource. */
  isGenesis?: boolean;
}

interface CommitBuilderBase {
  set?: Map<string, JSONValue>;
  push?: Map<string, Set<JSONValue>>;
  loroUpdate?: Uint8Array;
  remove?: Set<string>;
  destroy?: boolean;
  previousCommit?: string;
  isGenesis?: boolean;
}

type JSONADObject = Record<string, JSONValue>;

/** Return the current time as Atomic Data timestamp. Milliseconds since unix epoch. */
/** Resolve the commitId (the `did:ad:commit:<sig>` URL or
 *  whatever the server stored) for a freshly-acked Commit. */
export function commitIdOf(commit: Commit): string | undefined {
  return (
    (commit.id as string | undefined) ??
    (commit.signature ? `did:ad:commit:${commit.signature}` : undefined)
  );
}

export function getTimestampNow(): number {
  return Math.round(new Date().getTime());
}

/** A {@link Commit} without its signature, signer and timestamp */
export class CommitBuilder {
  // WARNING
  // If you add stuff here, add it to `.clone()!` too!
  private _subject: string;
  private _set: Map<string, JSONValue>;
  private _push: Map<string, Set<JSONValue>>;
  private _loroUpdate?: Uint8Array;
  private _remove: Set<string>;
  private _destroy?: boolean;
  private _previousCommit?: string;
  private _isGenesis?: boolean;

  /** Removes any query parameters from the Subject */
  public constructor(subject: string, base: CommitBuilderBase = {}) {
    this._subject = Client.removeQueryParamsFromURL(subject);
    this._set = base.set ?? new Map();
    this._push = base.push ?? new Map();
    this._loroUpdate = base.loroUpdate;
    this._remove = base.remove ?? new Set();
    this._destroy = base.destroy;
    this._previousCommit = base.previousCommit;
    this._isGenesis = base.isGenesis;
  }

  public get subject(): string {
    return this._subject;
  }

  public get set() {
    return this._set;
  }

  public get push() {
    return this._push;
  }

  public get loroUpdate() {
    return this._loroUpdate;
  }

  public get remove() {
    return this._remove;
  }

  public get destroy() {
    return this._destroy;
  }

  public get previousCommit() {
    return this._previousCommit;
  }

  public get isGenesis() {
    return this._isGenesis;
  }

  /** Set a Loro CRDT binary update for this commit. */
  public setLoroUpdate(update: Uint8Array): CommitBuilder {
    this._loroUpdate = update;

    return this;
  }

  public setDestroy(destroy: boolean): CommitBuilder {
    this._destroy = destroy;

    return this;
  }

  /**
   * Optional audit pointer at an earlier envelope. Not a causal gate.
   */
  public setPreviousCommit(prev: string): CommitBuilder {
    this._previousCommit = prev;

    return this;
  }

  public setIsGenesis(isGenesis: boolean): CommitBuilder {
    this._isGenesis = isGenesis;

    return this;
  }

  public setSubject(subject: string): CommitBuilder {
    this._subject = subject;

    return this;
  }

  /**
   * Signs the commit using the privateKey of the Agent, and returns a full
   * Commit which is ready to be sent to an Atomic-Server `/commit` endpoint.
   */
  public sign(agent: Agent): Promise<Commit> {
    return this.signAt(agent, getTimestampNow());
  }

  /** Returns true if the CommitBuilder has non-empty changes (set, remove, destroy) */
  public hasUnsavedChanges(): boolean {
    return (
      this.set.size > 0 ||
      this.push.size > 0 ||
      this.destroy ||
      this.remove.size > 0 ||
      this.loroUpdate !== undefined
    );
  }

  /**
   * Creates a clone of the CommitBuilder. This is required, because I want to
   * prevent any adjustments to the CommitBuilder while signing, as this could
   * cause race conditions with wrong signatures
   */
  // Warning: I'm not sure whether this actually solves the issue. Might be a good idea to remove this.
  public clone(): CommitBuilder {
    const base = {
      set: this.set,
      push: this.push,
      loroUpdate: this.loroUpdate,
      remove: this.remove,
      destroy: this.destroy,
      previousCommit: this.previousCommit,
      isGenesis: this.isGenesis,
    };

    return new CommitBuilder(this.subject, structuredClone(base));
  }

  public toPlainObject(): CommitBuilderI {
    return {
      subject: this.subject,
      set: Object.fromEntries(this.set.entries()),
      push: Object.fromEntries(
        Array.from(this.push.entries()).map(([k, v]) => [k, Array.from(v)]),
      ),
      remove: Array.from(this.remove),
      destroy: this.destroy,
      previousCommit: this.previousCommit,
      isGenesis: this.isGenesis,
      loroUpdate: this.loroUpdate,
    };
  }

  /** Creates a signature for a Commit using the private Key of some Agent. */
  public async signAt(
    /** The agent signing the commit */
    agent: Agent,
    /** Time of signing in millisecons since unix epoch */
    createdAt: number,
  ): Promise<Commit> {
    if (agent.subject === undefined) {
      throw new Error('Cannot sign commit if the agent has no subject');
    }

    if (!this.hasUnsavedChanges()) {
      throw new Error(`No changes to commit in ${this.subject}`);
    }

    const commitPreSigned: UnsignedCommit = {
      ...this.clone().toPlainObject(),
      createdAt,
      signer: agent.subject,
    };

    // Genesis must be set explicitly via CommitBuilder.setIsGenesis(true).
    // We never infer genesis from the subject pattern — that was the source of
    // accidental genesis commits when a stale `_new:` subject ended up on an
    // edit commit.
    const isExplicitGenesis = this._isGenesis === true;

    if (isExplicitGenesis) {
      commitPreSigned.isGenesis = true;
    }

    const closeSign = perfSpan('commit.signAt');
    const serializedCommit = serializeDeterministically({ ...commitPreSigned });
    const signature = await agent.sign(serializedCommit);
    closeSign();

    let subject = commitPreSigned.subject;

    // DID-genesis substitution: only needed for placeholder subjects where
    // the real DID isn't known until after signing. Two accepted forms:
    //   - `_new:…`         — the client's random placeholder (store.newResource)
    //   - `did:ad:genesis` — the server's and legacy-client convention
    // Any OTHER `did:ad:…` subject (agent, or a pre-derived drive/resource
    // DID) already has its canonical identity — substituting it would rename
    // the resource mid-flight and break downstream references (signer,
    // privateDrive, invite target, …).
    const subjectIsPlaceholder =
      commitPreSigned.subject.startsWith('_new:') ||
      commitPreSigned.subject === 'did:ad:genesis';

    if (isExplicitGenesis && subjectIsPlaceholder) {
      subject = `did:ad:${signature}`;
    }

    const commitPostSigned: Commit = {
      ...commitPreSigned,
      subject,
      signature,
    };

    return commitPostSigned;
  }
}

/** A {@link Commit} without its signature, but with a signer and timestamp */
interface UnsignedCommit extends CommitBuilderI {
  /** https://atomicdata.dev/properties/signer */
  signer: string;
  /** Unix timestamp in milliseconds, see https://atomicdata.dev/properties/createdAt */
  createdAt: number;
}

/**
 * A Commit represents a (set of) changes to one specific Resource. See
 * https://atomicdata.dev/classes/Commit If you want to create a Commit, you
 * should probably use the {@link CommitBuilder} and call `.sign()` on it.
 */
export interface Commit extends UnsignedCommit {
  /** https://atomicdata.dev/properties/signature */
  signature: string;
  /**
   * Subject of created Commit. Will only be present after it was accepted and
   * applied by the Server.
   */
  id?: string;
}

const serializeMap = {
  subject: commits.properties.subject,
  set: commits.properties.set,
  push: commits.properties.push,
  remove: commits.properties.remove,
  destroy: commits.properties.destroy,
  previousCommit: commits.properties.previousCommit,
  isGenesis: commits.properties.isGenesis,
  createdAt: commits.properties.createdAt,
  signer: commits.properties.signer,
  signature: commits.properties.signature,
  loroUpdate: commits.properties.loroUpdate,
  id: 'id',
};

/** Replaces the keys of a Commit object with their respective json-ad key */
export function commitToJsonADObject(
  commit: UnsignedCommit | Commit,
  origin?: string,
): JSONADObject {
  const jsonAdObj: JSONADObject = {
    [core.properties.isA]: [commits.classes.commit],
  };

  for (const kv of Object.entries(commit)) {
    const [key, value] = kv as [keyof Commit, Commit[keyof Commit]];
    const serializedKey = serializeMap[key];

    if (serializedKey) {
      jsonAdObj[serializedKey] = serializeCommitValue(key, value);
    }
  }

  if (origin && commit.subject) {
    jsonAdObj['@id'] = commit.subject;
  }

  return jsonAdObj;
}

function serializeCommitValue<K extends keyof Commit>(
  key: K,
  value: Commit[K],
): JSONValue {
  // loroUpdate is a binary blob, serialized as a plain base64 string
  if (key === 'loroUpdate') {
    const castValue = value as Commit['loroUpdate'];

    if (castValue !== undefined) {
      return encodeB64(castValue);
    }

    return undefined;
  }

  // The rest of the values can just be returned as is
  return value as JSONValue;
}

/**
 * Takes a commit and serializes it deterministically (canonicilaization). Is
 * used both for signing Commits as well as serializing them.
 * https://docs.atomicdata.dev/core/json-ad.html#canonicalized-json-ad
 *
 * For DID genesis commits the `subject` field is excluded from the signed
 * bytes because the subject is derived from the signature itself (circular
 * dependency). `isGenesis` is kept in the bytes so both sides sign/verify the
 * same content.
 */
export function serializeDeterministically(
  commit: UnsignedCommit | Commit,
  /**
   * Keep the genesis `subject` in the output. Off for SIGNING (the subject is
   * derived from the signature, so it can't be in the signed bytes). On for the
   * NETWORK body: a cert-minted DID (`did:ad:<cert-signature>`) is NOT the
   * commit signature, so the server can't re-derive it — it must be told. The
   * server still verifies the content signature over the subject-less bytes, so
   * including it here is safe (and, for a legacy DID, it equals the signature
   * the server would derive anyway).
   */
  includeGenesisSubject = false,
): string {
  // Remove empty arrays, objects, false values from root
  if (commit.remove && Object.keys(commit.remove).length === 0) {
    delete commit.remove;
  }

  if (commit.set && Object.keys(commit.set).length === 0) {
    delete commit.set;
  }

  if (commit.push && Object.keys(commit.push).length === 0) {
    delete commit.push;
  }

  if (commit.destroy === false) {
    delete commit.destroy;
  }

  if (commit.loroUpdate === undefined) {
    delete commit.loroUpdate;
  }

  const jsonadCommit = commitToJsonADObject(commit);

  // For DID genesis commits the subject is excluded from the SIGNED bytes — it
  // is derived from the signature so it cannot be part of them (circular dep).
  // The network body keeps it (see `includeGenesisSubject`) so the server can
  // use the real cert DID instead of re-deriving `did:ad:<commit-signature>`.
  // isGenesis always stays so the server can read and verify it.
  if (commit.isGenesis === true && !includeGenesisSubject) {
    delete jsonadCommit[commits.properties.subject];
  }

  // Canonical serialization should never include @id for commits
  delete jsonadCommit['@id'];

  return stringify(jsonadCommit);
}

export function parseCommitJSON(str: string): Commit {
  try {
    const jsonAdObj = JSON.parse(str);

    // Check if it's an object
    if (typeof jsonAdObj !== 'object') {
      throw new Error(`Commit is not an object`);
    }

    const subject = jsonAdObj[commits.properties.subject];
    const set = jsonAdObj[commits.properties.set];
    const push = jsonAdObj[commits.properties.push];
    const loroUpdate = parseLoroUpdateValue(
      jsonAdObj[commits.properties.loroUpdate],
    );
    const signer = jsonAdObj[commits.properties.signer];
    const createdAt = jsonAdObj[commits.properties.createdAt];
    const remove: string[] | undefined = jsonAdObj[commits.properties.remove];
    const destroy: boolean | undefined = jsonAdObj[commits.properties.destroy];
    const signature: string = jsonAdObj[commits.properties.signature];
    const id: undefined | string = jsonAdObj['@id'];
    const previousCommit: undefined | string =
      jsonAdObj[commits.properties.previousCommit];
    const isGenesis: undefined | boolean =
      jsonAdObj[commits.properties.isGenesis];

    if (!signature) {
      throw new Error(`Commit has no signature`);
    }

    return {
      subject,
      set,
      push,
      loroUpdate,
      signer,
      createdAt,
      remove,
      destroy,
      signature,
      id,
      previousCommit,
      isGenesis,
    };
  } catch (e) {
    throw new Error(`Could not parse commit: ${e}, Commit: ${str}`);
  }
}

/** Applies a commit, but does not modify the store */
export function applyCommitToResource(
  resource: Resource,
  commit: Commit,
): Resource {
  const { destroy, loroUpdate } = commit;

  if (loroUpdate) {
    execLoroUpdateCommit(loroUpdate, resource);
  }

  if (destroy) {
    resource.clearUnsafe();
  }

  return resource;
}

/** Parses a JSON-AD Commit, applies it and adds it (and nested resources) to the store. */
export function parseAndApplyCommit(jsonAdObjStr: string, store: Store) {
  const commit = parseCommitJSON(jsonAdObjStr);
  const { subject, id, destroy, signature } = commit;

  let resource = store.resources.get(subject) as Resource;

  // If the resource doesn't exist in the store, create the resource
  if (!resource) {
    resource = new Resource(subject);
  } else {
    // Commit has already been applied here, ignore the commit
    if (resource.appliedCommitSignatures.has(signature)) {
      return;
    }
  }

  resource = applyCommitToResource(resource, commit);

  if (id) {
    // This is something that the server does, too.
    resource.setLastCommitValue(id);
  }

  if (destroy) {
    store.removeResource(subject);

    return;
  } else {
    resource.appliedCommitSignatures.add(signature);

    store.applyIncoming({
      subject: resource.subject,
      resource,
      source: 'ws-sub-push',
    });
  }
}

function parseLoroUpdateValue(value: JSONValue): Uint8Array | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value === 'string') {
    return decodeB64(value);
  }

  throw new Error(
    `Invalid loroUpdate value, expected base64 string: ${JSON.stringify(value)}`,
  );
}

/**
 * Imports a Loro CRDT update into the resource's LoroDoc and materializes
 * the changed properties into the resource's propvals so the UI updates.
 */
function execLoroUpdateCommit(loroUpdate: Uint8Array, resource: Resource) {
  resource.importLoroUpdate(loroUpdate);
}
