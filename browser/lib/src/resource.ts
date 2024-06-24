import type { Agent } from './agent.js';
import { Client } from './client.js';
import type { Collection } from './collection.js';
import { CollectionBuilder } from './collectionBuilder.js';
import {
  CommitBuilder,
  Commit,
  applyCommitToResource,
  parseCommitResource,
} from './commit.js';
import { validateDatatype } from './datatypes.js';
import { isUnauthorized } from './error.js';
import { core } from './ontologies/core.js';
import { server } from './ontologies/server.js';

import {
  getKnownNameBySubject,
  type InferTypeOfValueInTriple,
  type OptionalClass,
  type QuickAccesPropType,
} from './ontology.js';
import type { Store } from './store.js';
import { properties, instances, urls } from './urls.js';
import { valToArray, type JSONValue, type JSONArray } from './value.js';

/** Contains the PropertyURL / Value combinations */
export type PropVals = Map<string, JSONValue>;

/**
 * If a resource has no subject, it will have this subject. This means that the
 * Resource is not saved or fetched.
 */
export const unknownSubject = 'unknown-subject';

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
   * Is true when the Resource is currently being fetched, awaiting a response
   * from the Server
   */
  public loading = false;
  /**
   * Every commit that has been applied should be stored here, which prevents
   * applying the same commit twice
   */
  public appliedCommitSignatures: Set<string> = new Set();
  public readonly __internalObject = this;

  private commitBuilder: CommitBuilder;
  private _subject: string;
  private propvals: PropVals = new Map();

  private inProgressCommit: Promise<void> | undefined;
  private hasQueue = false;

  private _store?: Store;

  public constructor(subject: string, newResource?: boolean) {
    if (typeof subject !== 'string') {
      throw new Error(
        'Invalid subject given to resource, must be a string, found ' +
          typeof subject,
      );
    }

    this.new = !!newResource;
    this._subject = subject;
    this.commitBuilder = new CommitBuilder(subject);
  }

  /** The subject URL of the resource */
  public get subject(): string {
    return this._subject;
  }

  /** A human readable title for the resource, returns first of eighter: name, shortname, filename or subject */
  public get title(): string {
    return (this.get(core.properties.name) ??
      this.get(core.properties.shortname) ??
      this.get(server.properties.filename) ??
      this.subject) as string;
  }

  /**
   * Dynamic prop accessor, only works for known properties registered via an ontology.
   * @example const description = resource.props.description
   */
  public get props(): QuickAccesPropType<C> {
    const props: QuickAccesPropType<C> = {} as QuickAccesPropType<C>;

    for (const prop of this.propvals.keys()) {
      const name = getKnownNameBySubject(prop);

      if (name) {
        props[name] = this.get(prop);
      }
    }

    return props;
  }

  private get store(): Store {
    if (!this._store) {
      console.error(`Resource ${this.title} has no store`);
      throw new Error('Resource has no store');
    }

    return this._store;
  }

  /** @internal */
  public setStore(store: Store): void {
    this._store = store;
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
      JSON.stringify(Array.from(this.propvals.entries())) !==
      JSON.stringify(Array.from(resourceB.propvals.entries()))
    ) {
      return false;
    }

    if (
      JSON.stringify(Array.from(this.commitBuilder.set.entries())) !==
      JSON.stringify(Array.from(resourceB.commitBuilder.set.entries()))
    ) {
      return false;
    }

    return true;
  }

  /** Checks if the agent has write rights by traversing the graph. Recursive function. */
  public async canWrite(
    agent?: string,
    child?: string,
  ): Promise<[boolean, string | undefined]> {
    const writeArray = this.get(properties.write);

    if (!agent) {
      return [false, 'No agent given'];
    }

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

    // This should not happen, but it prevents an infinite loop
    if (child === parentSubject) {
      console.warn('Circular parent', child);

      return [true, `Circular parent in ${this.subject}`];
    }

    const parent: Resource = await this.store.getResource(parentSubject);

    // The recursive part
    return await parent.canWrite(agent, this.subject);
  }

  /**
   * Creates a clone of the Resource, which makes sure the reference is
   * different from the previous one. This can be useful when doing reference compares.
   */
  public clone(): Resource<C> {
    const res = new Resource(this.subject);
    res.propvals = structuredClone(this.propvals);
    res.loading = this.loading;
    res.new = this.new;
    res.error = structuredClone(this.error);
    res.commitError = this.commitError;
    res.commitBuilder = this.commitBuilder.clone();
    res.appliedCommitSignatures = this.appliedCommitSignatures;

    return res as Resource<C>;
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
    return this.propvals.get(propUrl) as Returns;
  }

  /**
   * Get a Value by its property, returns as Array with subjects instead of the
   * full resource or throws error. Returns empty array if there is no value
   */
  public getSubjects(propUrl: string): string[] {
    return this.getArray(propUrl).map(item => {
      if (typeof item === 'string') return item;

      return item!['@id'] as string;
    });
  }

  /**
   * Get a Value by its property, returns as Array or throws error. Returns
   * empty array if there is no value
   */
  public getArray(propUrl: string): JSONArray {
    const result = this.propvals.get(propUrl) ?? [];

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

  /** Returns true if the resource has changes in it's commit builder that are not yet saved to the server. */
  public hasUnsavedChanges(): boolean {
    return this.commitBuilder.hasUnsavedChanges();
  }

  public getCommitsCollectionSubject(): string {
    const url = new URL(this.subject);
    url.pathname = '/commits';
    url.searchParams.append('property', urls.properties.commit.subject);
    url.searchParams.append('value', this.subject);
    url.searchParams.append('sort_by', urls.properties.commit.createdAt);
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

  /** builds all versions using the Commits */
  public async getHistory(
    progressCallback?: (percentage: number) => void,
  ): Promise<Version[]> {
    const commitsCollection = await this.store.fetchResourceFromServer(
      this.getCommitsCollectionSubject(),
    );
    const commits = commitsCollection.get(
      properties.collection.members,
    ) as string[];

    const builtVersions: Version[] = [];

    let previousResource = new Resource(this.subject);

    for (let i = 0; i < commits.length; i++) {
      const commitResource = await this.store.getResource(commits[i]);
      const parsedCommit = parseCommitResource(commitResource);
      const builtResource = applyCommitToResource(
        previousResource.clone(),
        parsedCommit,
      );
      builtVersions.push({
        commit: parsedCommit,
        resource: builtResource,
      });
      previousResource = builtResource;

      // Every 30 cycles we report the progress
      if (progressCallback && i % 30 === 0) {
        progressCallback(Math.round((i / commits.length) * 100));
        await WaitForImmediate();
      }
    }

    return builtVersions;
  }

  public async setVersion(version: Version): Promise<void> {
    const versionPropvals = version.resource.getPropVals();

    // Remove any prop that doesn't exist in the version
    for (const prop of this.propvals.keys()) {
      if (!versionPropvals.has(prop)) {
        this.remove(prop);
      }
    }

    for (const [key, value] of versionPropvals.entries()) {
      await this.set(key, value);
    }

    await this.save();
  }

  /**
   * @deprecated use resource.subject
   */
  public getSubject(): string {
    return this.subject;
  }

  /** Returns the subject URL of the Resource */
  public getSubjectNoParams(): string {
    const url = new URL(this.subject);

    return url.origin + url.pathname;
  }

  /** Returns the internal Map of Property-Values */
  public getPropVals(): PropVals {
    return this.propvals;
  }

  /**
   * Iterates over the parents of the resource, returns who has read / write
   * rights for this resource
   */
  public async getRights(): Promise<Right[]> {
    const rights: Right[] = [];
    const write: string[] = this.getSubjects(properties.write);
    write.forEach((subject: string) => {
      rights.push({
        for: subject,
        type: RightType.WRITE,
        setIn: this.subject,
      });
    });

    const read: string[] = this.getSubjects(properties.read);
    read.forEach((subject: string) => {
      rights.push({
        for: subject,
        type: RightType.READ,
        setIn: this.subject,
      });
    });
    const parentSubject = this.get(properties.parent) as string;

    if (parentSubject) {
      if (parentSubject === this.subject) {
        console.warn('Circular parent', parentSubject);

        return rights;
      }

      const parent = await this.store.getResource(parentSubject);
      const parentRights = await parent.getRights();
      rights.push(...parentRights);
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

    if (agent === undefined) {
      agent = this.store.getAgent();
    }

    if (agent?.subject === undefined) {
      throw new Error(
        'No agent has been set or passed, you cannot delete this.',
      );
    }

    const commit = await newCommitBuilder.sign(agent.privateKey, agent.subject);
    const endpoint = new URL(this.subject).origin + `/commit`;
    await this.store.postCommit(commit, endpoint);
    this.store.removeResource(this.subject);
  }

  /** @deprecated use `resource.push` */
  public pushPropVal(propUrl: string, values: JSONArray, unique?: boolean) {
    this.push(propUrl, values, unique);
  }

  /** Appends a Resource to a ResourceArray */
  public push(propUrl: string, values: JSONArray, unique?: boolean): void {
    const propVal = (this.get(propUrl) as JSONArray) ?? [];

    if (unique) {
      values = values
        .filter(value => !propVal.includes(value))
        .filter(value => !this.commitBuilder.push[propUrl]?.includes(value))
        .filter((value, index, self) => self.indexOf(value) === index);
    }

    this.commitBuilder.addPushAction(propUrl, ...values);
    // Build a new array so that the reference changes. This is needed in most UI frameworks.
    this.propvals.set(propUrl, [...propVal, ...values]);
  }

  /** @deprecated use `resource.remove()` */
  public removePropVal(propertyUrl: string): void {
    this.remove(propertyUrl);
  }

  /** Removes a property value combination from the resource and adds it to the next Commit */
  public remove(propertyUrl: string): void {
    // Delete from this resource
    this.propvals.delete(propertyUrl);

    // Add it to the array of items that the server might need to remove after posting.
    this.commitBuilder.addRemoveAction(propertyUrl);
  }

  /**
   * Removes a property value combination from this resource, does not store the
   * remove action in Commit
   */
  public removePropValLocally(propertyUrl: string): void {
    this.propvals.delete(propertyUrl);
  }

  /**
   * Commits the changes and sends the Commit to the resource's `/commit`
   * endpoint. Returns the Url of the created Commit. If you don't pass an Agent
   * explicitly, the default Agent of the Store is used.
   * When there are no changes no commit is made and the function returns Promise<undefined>.
   */
  public async save(differentAgent?: Agent): Promise<string | undefined> {
    if (!this.commitBuilder.hasUnsavedChanges()) {
      console.warn(`No changes to ${this.subject}, not saving`);

      return undefined;
    }

    const agent = this.store.getAgent() ?? differentAgent;

    if (!agent) {
      throw new Error('No agent has been set or passed, you cannot save.');
    }

    if (this.hasQueue) {
      return;
    }

    // If the parent of this resource is new we can't save yet so we add it to a batched that gets saved when the parent does.
    if (this.isParentNew()) {
      this.store.batchResource(this.subject);

      return;
    }

    if (this.inProgressCommit) {
      this.hasQueue = true;
      await this.inProgressCommit;
      this.hasQueue = false;
      this.inProgressCommit = undefined;

      return this.save(differentAgent);
    }

    // The previousCommit is required in Commits. We should use the `lastCommit` value on the resource.
    // This makes sure that we're making adjustments to the same version as the server.
    const lastCommit = this.get(properties.commit.lastCommit)?.toString();

    if (lastCommit) {
      this.commitBuilder.setPreviousCommit(lastCommit);
    }

    const wasNew = this.new;

    let reportDone: () => void = () => undefined;

    this.inProgressCommit = new Promise(resolve => {
      reportDone = () => {
        resolve();
      };
    });

    // Cloning the CommitBuilder to prevent race conditions, and keeping a back-up of current state for when things go wrong during posting.
    const oldCommitBuilder = this.commitBuilder.clone();
    this.commitBuilder = new CommitBuilder(this.subject);
    const commit = await oldCommitBuilder.sign(
      agent.privateKey,
      agent.subject!,
    );
    // Add the signature to the list of applied ones, to prevent applying it again when the server
    this.appliedCommitSignatures.add(commit.signature);
    this.loading = false;
    this.new = false;

    // TODO: Check if all required props are there
    const endpoint = new URL(this.subject).origin + `/commit`;

    try {
      this.commitError = undefined;
      this.store.addResources(this, { skipCommitCompare: true });
      const createdCommit = await this.store.postCommit(commit, endpoint);
      // const res = store.getResourceLoading(this.subject);
      this.setUnsafe(properties.commit.lastCommit, createdCommit.id!);

      // Let all subscribers know that the commit has been applied
      // store.addResources(this);
      this.store.notifyResourceSaved(this);

      if (wasNew) {
        // The first `SUBSCRIBE` message will not have worked, because the resource didn't exist yet.
        // That's why we need to repeat the process
        // https://github.com/atomicdata-dev/atomic-data-rust/issues/486
        this.store.subscribeWebSocket(this.subject);

        // Save any children that have been batched while creating this resource
        await this.store.saveBatchForParent(this.subject);
      }

      reportDone();

      return createdCommit.id as string;
    } catch (e) {
      // Logic for handling error if the previousCommit is wrong.
      // Is not stable enough, and maybe not required at the time.
      if (e.message.includes('previousCommit')) {
        console.warn('previousCommit missing or mismatch, retrying...');
        // We try again, but first we fetch the latest version of the resource to get its `lastCommit`
        const resourceFetched = await this.store.fetchResourceFromServer(
          this.subject,
        );

        const fixedLastCommit = resourceFetched!
          .get(properties.commit.lastCommit)
          ?.toString();

        if (fixedLastCommit) {
          this.setUnsafe(properties.commit.lastCommit, fixedLastCommit);
        }

        // Try again!
        reportDone();

        return await this.save(agent);
      }

      // If it fails, revert to the old resource with the old CommitBuilder
      this.commitBuilder = oldCommitBuilder;
      this.commitError = e;
      this.store.addResources(this, { skipCommitCompare: true });
      reportDone();
      throw e;
    }
  }

  /**
   * Set a Property, Value combination and perform a validation. Will throw if
   * property is not valid for the datatype. Will fetch the datatype if it's not
   * available. Adds the property to the commitbuilder.
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
    if (this.store.isOffline() && validate) {
      console.warn('Offline, not validating');
      validate = false;
    }

    if (validate) {
      const fullProp = await this.store.getProperty(prop);

      try {
        validateDatatype(value, fullProp.datatype);
      } catch (e) {
        if (e instanceof Error) {
          e.message = `Error validating ${fullProp.shortname} with value ${value} for ${this.subject}: ${e.message}`;
        }

        throw e;
      }
    }

    if (value === undefined) {
      this.remove(prop);

      return;
    }

    this.propvals.set(prop, value);
    // Add the change to the Commit Builder, so we can commit our changes later
    this.commitBuilder.addSetAction(prop, value);
  }

  /**
   * Set a Property, Value combination without performing validations or adding
   * it to the CommitBuilder.
   */
  public setUnsafe(prop: string, val: JSONValue): void {
    this.propvals.set(prop, val);
  }

  /** Sets the error on the Resource. Does not Throw. */
  public setError(e: Error): void {
    this.error = e;
  }

  /** Set the Subject / ID URL of the Resource. Does not update the Store. */
  public setSubject(subject: string): void {
    Client.tryValidSubject(subject);
    this.commitBuilder.setSubject(subject);
    this._subject = subject;
  }

  private isParentNew() {
    const parentSubject = this.propvals.get(core.properties.parent) as string;

    if (!parentSubject) {
      return false;
    }

    const parent = this.store.getResourceLoading(parentSubject);

    return parent.new;
  }
}

/** Type of Rights (e.g. read or write) */
enum RightType {
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

export interface Version {
  commit: Commit;
  resource: Resource;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function proxyResource<C extends OptionalClass = any>(
  resource: Resource<C>,
): Resource<C> {
  if (resource.__internalObject !== resource) {
    console.warn('Attempted to proxy a proxy for ' + resource.subject);
  }

  return new Proxy(resource.__internalObject, {});
}

const WaitForImmediate = () => new Promise(resolve => setTimeout(resolve));
