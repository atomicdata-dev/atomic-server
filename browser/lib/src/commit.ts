import { sign, getPublicKey, utils } from '@noble/ed25519';
import stringify from 'fast-json-stable-stringify';
import { decode as decodeB64, encode as encodeB64 } from 'base64-arraybuffer';

// https://github.com/paulmillr/noble-ed25519/issues/38
import { sha512 } from '@noble/hashes/sha512';
utils.sha512 = msg => Promise.resolve(sha512(msg));

import {
  isArray,
  JSONArray,
  JSONValue,
  Resource,
  properties,
  urls,
  Store,
  Client,
  JSONADParser,
} from './index.js';

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
  /** The properties that need to be removed. https://atomicdata.dev/properties/remove */
  remove?: string[];
  /** If true, the resource must be deleted. https://atomicdata.dev/properties/destroy */
  destroy?: boolean;
  /**
   * URL of the previous Commit, used by the receiver to make sure that we're
   * having the same current version.
   */
  previousCommit?: string;
}

interface CommitBuilderBase {
  set?: Map<string, JSONValue>;
  push?: Map<string, Set<JSONValue>>;
  remove?: Set<string>;
  destroy?: boolean;
  previousCommit?: string;
}

/** Return the current time as Atomic Data timestamp. Milliseconds since unix epoch. */
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
  private _remove: Set<string>;
  private _destroy?: boolean;
  private _previousCommit?: string;

  /** Removes any query parameters from the Subject */
  public constructor(subject: string, base: CommitBuilderBase = {}) {
    this._subject = Client.removeQueryParamsFromURL(subject);
    this._set = base.set ?? new Map();
    this._push = base.push ?? new Map();
    this._remove = base.remove ?? new Set();
    this._destroy = base.destroy;
    this._previousCommit = base.previousCommit;
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

  public get remove() {
    return this._remove;
  }

  public get destroy() {
    return this._destroy;
  }

  public get previousCommit() {
    return this._previousCommit;
  }

  public addSetAction(property: string, value: JSONValue): CommitBuilder {
    this.removeRemoveAction(property);
    this._set.set(property, value);

    return this;
  }

  public addPushAction(property: string, ...values: JSONArray): CommitBuilder {
    const pushSet = this._push.get(property) ?? new Set();

    for (const value of values) {
      pushSet.add(value);
    }

    this._push.set(property, pushSet);

    return this;
  }

  public addRemoveAction(property: string): CommitBuilder {
    this._set.delete(property);
    this._push.delete(property);

    this._remove.add(property);

    return this;
  }

  public removeRemoveAction(property: string): CommitBuilder {
    this._remove.delete(property);

    return this;
  }

  public setDestroy(destroy: boolean): CommitBuilder {
    this._destroy = destroy;

    return this;
  }

  /**
   * Set the URL of the Commit that was previously (last) applied. The value of
   * this should probably be the `lastCommit` of the Resource.
   */
  public setPreviousCommit(prev: string): CommitBuilder {
    this._previousCommit = prev;

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
  public async sign(privateKey: string, agentSubject: string): Promise<Commit> {
    const commit = await this.signAt(
      agentSubject,
      privateKey,
      getTimestampNow(),
    );

    return commit;
  }

  /** Returns true if the CommitBuilder has non-empty changes (set, remove, destroy) */
  public hasUnsavedChanges(): boolean {
    return (
      this.set.size > 0 ||
      this.push.size > 0 ||
      this.destroy ||
      this.remove.size > 0
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
      remove: this.remove,
      destroy: this.destroy,
      previousCommit: this.previousCommit,
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
    };
  }

  /** Creates a signature for a Commit using the private Key of some Agent. */
  public async signAt(
    /** Subject URL of the Agent signing the Commit */
    agent: string,
    /** Base64 serialized private key matching the public key of the agent */
    privateKey: string,
    /** Time of signing in millisecons since unix epoch */
    createdAt: number,
  ): Promise<Commit> {
    if (agent === undefined) {
      throw new Error('No agent passed to sign commit');
    }

    if (!this.hasUnsavedChanges()) {
      throw new Error(`No changes to commit in ${this.subject}`);
    }

    const commitPreSigned: CommitPreSigned = {
      ...this.clone().toPlainObject(),
      createdAt,
      signer: agent,
    };
    const serializedCommit = serializeDeterministically({ ...commitPreSigned });
    const signature = await signToBase64(serializedCommit, privateKey);
    const commitPostSigned: Commit = {
      ...commitPreSigned,
      signature,
    };

    return commitPostSigned;
  }
}

/** A {@link Commit} without its signature, but with a signer and timestamp */
interface CommitPreSigned extends CommitBuilderI {
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
export interface Commit extends CommitPreSigned {
  /** https://atomicdata.dev/properties/signature */
  signature: string;
  /**
   * Subject of created Commit. Will only be present after it was accepted and
   * applied by the Server.
   */
  id?: string;
}

/** Replaces a key in a Commit. Ignores it if it's not there */
function replaceKey(
  o: Commit | CommitPreSigned,
  oldKey: string,
  newKey: string,
) {
  if (oldKey in o && oldKey !== newKey) {
    Object.defineProperty(
      o,
      newKey,
      Object.getOwnPropertyDescriptor(o, oldKey)!,
    );
    delete o[oldKey];
  }
}

/**
 * Takes a commit and serializes it deterministically (canonicilaization). Is
 * used both for signing Commits as well as serializing them.
 * https://docs.atomicdata.dev/core/json-ad.html#canonicalized-json-ad
 */
export function serializeDeterministically(
  commit: CommitPreSigned | Commit,
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

  replaceKey(commit, 'createdAt', urls.properties.commit.createdAt);
  replaceKey(commit, 'subject', urls.properties.commit.subject);
  replaceKey(commit, 'set', urls.properties.commit.set);
  replaceKey(commit, 'push', urls.properties.commit.push);
  replaceKey(commit, 'signer', urls.properties.commit.signer);
  replaceKey(commit, 'signature', urls.properties.commit.signature);
  replaceKey(commit, 'remove', urls.properties.commit.remove);
  replaceKey(commit, 'destroy', urls.properties.commit.destroy);
  replaceKey(commit, 'previousCommit', urls.properties.commit.previousCommit);
  commit[urls.properties.isA] = [urls.classes.commit];

  return stringify(commit);
}

// /** Checks whether the commit signature is correct */
// function verifyCommit(commit: Commit, publicKey: string): boolean {
//   delete commit.signature;
//   const serializedCommit = serializeDeterministically(commit);
//   verify();
// }

/**
 * Signs a string using a base64 encoded ed25519 private key. Outputs a base64
 * encoded ed25519 signature
 */
export const signToBase64 = async (
  message: string,
  privateKeyBase64: string,
): Promise<string> => {
  const privateKeyArrayBuffer = decodeB64(privateKeyBase64);
  const privateKeyBytes: Uint8Array = new Uint8Array(privateKeyArrayBuffer);
  const utf8Encode = new TextEncoder();
  const messageBytes: Uint8Array = utf8Encode.encode(message);
  const signatureHex = await sign(messageBytes, privateKeyBytes);
  const signatureBase64 = encodeB64(signatureHex);

  return signatureBase64;
};

/** From base64 encoded private key */
export const generatePublicKeyFromPrivate = async (
  privateKey: string,
): Promise<string> => {
  const privateKeyArrayBuffer = decodeB64(privateKey);
  const privateKeyBytes: Uint8Array = new Uint8Array(privateKeyArrayBuffer);
  const publickey = await getPublicKey(privateKeyBytes);
  const publicBase64 = encodeB64(publickey);

  return publicBase64;
};

interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export async function generateKeyPair(): Promise<KeyPair> {
  const privateBytes = utils.randomPrivateKey();
  const publicBytes = await getPublicKey(privateBytes);
  const privateKey = encodeB64(privateBytes);
  const publicKey = encodeB64(publicBytes);

  return {
    publicKey,
    privateKey,
  };
}

export function parseCommitResource(resource: Resource): Commit {
  const commit: Commit = {
    id: resource.getSubject(),
    subject: resource.get(urls.properties.commit.subject) as string,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    set: resource.get(urls.properties.commit.set) as Record<string, any>,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    push: resource.get(urls.properties.commit.push) as Record<string, any>,
    signer: resource.get(urls.properties.commit.signer) as string,
    createdAt: resource.get(urls.properties.commit.createdAt) as number,
    remove: resource.get(urls.properties.commit.remove) as string[],
    destroy: resource.get(urls.properties.commit.destroy) as boolean,
    signature: resource.get(urls.properties.commit.signature) as string,
  };

  return commit;
}

export function parseCommitJSON(str: string): Commit {
  try {
    const jsonAdObj = JSON.parse(str);

    // Check if it's an object
    if (typeof jsonAdObj !== 'object') {
      throw new Error(`Commit is not an object`);
    }

    const subject = jsonAdObj[urls.properties.commit.subject];
    const set = jsonAdObj[urls.properties.commit.set];
    const push = jsonAdObj[urls.properties.commit.push];
    const signer = jsonAdObj[urls.properties.commit.signer];
    const createdAt = jsonAdObj[urls.properties.commit.createdAt];
    const remove: string[] | undefined =
      jsonAdObj[urls.properties.commit.remove];
    const destroy: boolean | undefined =
      jsonAdObj[urls.properties.commit.destroy];
    const signature: string = jsonAdObj[urls.properties.commit.signature];
    const id: undefined | string = jsonAdObj['@id'];
    const previousCommit: undefined | string =
      jsonAdObj[urls.properties.commit.previousCommit];

    if (!signature) {
      throw new Error(`Commit has no signature`);
    }

    return {
      subject,
      set,
      push,
      signer,
      createdAt,
      remove,
      destroy,
      signature,
      id,
      previousCommit,
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
  const { set, remove, push } = commit;

  if (set) {
    execSetCommit(set, resource);
  }

  if (remove) {
    execRemoveCommit(remove, resource);
  }

  if (push) {
    execPushCommit(push, resource);
  }

  return resource;
}

/** Parses a JSON-AD Commit, applies it and adds it (and nested resources) to the store. */
export function parseAndApplyCommit(jsonAdObjStr: string, store: Store) {
  const commit = parseCommitJSON(jsonAdObjStr);
  const { subject, id, destroy, signature } = commit;

  let resource = store.resources.get(subject) as Resource;
  let isNew = false;

  // If the resource doesn't exist in the store, create the resource
  if (!resource) {
    resource = new Resource(subject);
    isNew = true;
  } else {
    // Commit has already been applied here, ignore the commit
    if (resource.appliedCommitSignatures.has(signature)) {
      return;
    }
  }

  resource = applyCommitToResource(resource, commit);

  if (id) {
    // This is something that the server does, too.
    resource.setUnsafe(properties.commit.lastCommit, id);
  }

  if (destroy) {
    store.removeResource(subject);

    return;
  } else {
    resource.appliedCommitSignatures.add(signature);

    store.addResources(resource);
  }
}

function execSetCommit(
  set: Record<string, JSONValue>,
  resource: Resource,
  store?: Store,
) {
  const parser = new JSONADParser();
  const parsedResources: Resource[] = [];

  for (const [key, value] of Object.entries(set)) {
    let newVal = value;

    if (value?.constructor === {}.constructor) {
      const [result, foundResources] = parser.parseValue(value, key);
      newVal = result;
      parsedResources.push(...foundResources);
    }

    if (isArray(value)) {
      newVal = value.map(resourceOrURL => {
        const [result, foundResources] = parser.parseValue(resourceOrURL, key);
        parsedResources.push(...foundResources);

        return result;
      });
    }

    resource.setUnsafe(key, newVal);
  }

  store && store.addResources(...parsedResources);
}

function execRemoveCommit(remove: string[], resource: Resource) {
  for (const prop of remove) {
    resource.removePropValLocally(prop);
  }
}

function execPushCommit(
  push: Record<string, JSONArray>,
  resource: Resource,
  store?: Store,
) {
  const parser = new JSONADParser();
  const parsedResources: Resource[] = [];

  for (const [key, value] of Object.entries(push)) {
    const current = (resource.get(key) as JSONArray) || [];
    const newArr = value as JSONArray;
    // The `push` arrays may contain full resources.
    // We parse these here and add them to a list of resources to add to the store.
    const stringArr = newArr.map(val => {
      const [result, foundResources] = parser.parseValue(val, key);
      parsedResources.push(...foundResources);

      return result;
    });
    // Merge both the old and new items
    const new_arr = [...current, ...stringArr];
    // Save it!
    resource.setUnsafe(key, new_arr);
  }

  store && store.addResources(...parsedResources);
}
