import {
  Agent,
  CommitBuilder,
  isUnauthorized,
  JSONValue,
  properties,
  Store,
  validateDatatype,
  valToArray,
  instances,
  JSONArray,
  Client,
  urls,
  applyCommitToResource,
  Commit,
  parseCommitResource,
  InferTypeOfValueInTriple,
  QuickAccesPropType,
  getKnownNameBySubject,
  OptionalClass,
  core,
} from './index.js';

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
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export class Resource<C extends OptionalClass = any> {
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
  public loading: boolean;
  /**
   * Every commit that has been applied should be stored here, which prevents
   * applying the same commit twice
   */
  public appliedCommitSignatures: Set<string>;

  private commitBuilder: CommitBuilder;
  private subject: string;
  private propvals: PropVals;

  private queuedFetch: Promise<unknown> | undefined;

  public constructor(subject: string, newResource?: boolean) {
    if (typeof subject !== 'string') {
      throw new Error(
        'Invalid subject given to resource, must be a string, found ' + subject,
      );
    }

    this.new = newResource ? true : false;
    this.loading = false;
    this.subject = subject;
    this.propvals = new Map();
    this.appliedCommitSignatures = new Set();
    this.commitBuilder = new CommitBuilder(subject);
  }

  public get title(): string {
    return (this.get(properties.name) ??
      this.get(properties.shortname) ??
      this.get(properties.file.filename) ??
      this.subject) as string;
  }

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

  /** Checks if the content of two Resource instances is equal
   * Warning: does not check CommitBuilder, loading state
   */
  public static compare(resourceA: Resource, resourceB: Resource): boolean {
    if (resourceA.error !== resourceB.error) {
      return false;
    }

    return (
      resourceA.getSubject() === resourceB.getSubject() &&
      JSON.stringify(Array.from(resourceA.propvals.entries())) ===
        JSON.stringify(Array.from(resourceB.propvals.entries()))
    );
  }

  /** Checks if the agent has write rights by traversing the graph. Recursive function. */
  public async canWrite(
    store: Store,
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
      return [false, `No write right or parent in ${this.getSubject()}`];
    }

    // Agents can always edit themselves
    if (parentSubject === agent) {
      return [true, undefined];
    }

    // This should not happen, but it prevents an infinite loop
    if (child === parentSubject) {
      console.warn('Circular parent', child);

      return [true, `Circular parent in ${this.getSubject()}`];
    }

    const parent: Resource = await store.getResourceAsync(parentSubject);

    // The recursive part
    return await parent.canWrite(store, agent, this.getSubject());
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
    // structured clone
    res.error = structuredClone(this.error);
    res.commitError = this.commitError;
    res.commitBuilder = this.commitBuilder.clone();
    res.appliedCommitSignatures = this.appliedCommitSignatures;
    res.queuedFetch = this.queuedFetch;

    return res as Resource<C>;
  }

  /** Checks if the resource is both loaded and free from errors */
  public isReady(): boolean {
    return !this.loading && this.error === undefined;
  }

  /** Get a Value by its property */
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
    return this.getSubjects(properties.isA);
  }

  /** Checks if the resource is all of the given classes */
  public hasClasses(...classSubjects: string[]): boolean {
    return classSubjects.every(classSubject =>
      this.getClasses().includes(classSubject),
    );
  }

  /** Remove the given classes from the resource */
  public removeClasses(
    store: Store,
    ...classSubjects: string[]
  ): Promise<void> {
    return this.set(
      properties.isA,
      this.getClasses().filter(
        classSubject => !classSubjects.includes(classSubject),
      ),
      store,
    );
  }

  /** Adds the given classes to the resource */
  public addClasses(store: Store, ...classSubject: string[]): Promise<void> {
    const classesSet = new Set([...this.getClasses(), ...classSubject]);

    return this.set(properties.isA, Array.from(classesSet), store);
  }

  /** Returns true if the resource has changes in it's commit builder that are not yet saved to the server. */
  public hasUnsavedChanges(): boolean {
    return this.commitBuilder.hasUnsavedChanges();
  }

  public getCommitsCollection(): string {
    const url = new URL(this.subject);
    url.pathname = '/commits';
    url.searchParams.append('property', urls.properties.commit.subject);
    url.searchParams.append('value', this.subject);
    url.searchParams.append('sort_by', urls.properties.commit.createdAt);
    url.searchParams.append('include_nested', 'true');
    url.searchParams.append('page_size', '9999');

    return url.toString();
  }

  /** Returns the subject of the list of Children */
  public getChildrenCollection(): string {
    // We create a collection that contains all children of the current Subject
    const url = new URL(this.subject);
    url.pathname = '/query';
    url.searchParams.set('property', properties.parent);
    url.searchParams.set('value', this.subject);

    return url.toString();
  }

  /** builds all versions using the Commits */
  public async getHistory(store: Store): Promise<Version[]> {
    const commitsCollection = await store.fetchResourceFromServer(
      this.getCommitsCollection(),
    );
    const commits = commitsCollection.get(properties.collection.members);

    const builtVersions: Version[] = [];

    let previousResource = new Resource(this.subject);

    for (const commit of commits as unknown as string[]) {
      const commitResource = await store.getResourceAsync(commit);
      const parsedCommit = parseCommitResource(commitResource);
      const builtResource = await applyCommitToResource(
        previousResource.clone(),
        parsedCommit,
      );
      builtVersions.push({
        commit: parsedCommit,
        resource: builtResource.clone(),
      });
      previousResource = builtResource;
    }

    return builtVersions;
  }

  /** Returns the subject URL of the Resource */
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
  public async getRights(store: Store): Promise<Right[]> {
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
      if (parentSubject === this.getSubject()) {
        console.warn('Circular parent', parentSubject);

        return rights;
      }

      const parent = await store.getResourceAsync(parentSubject);
      const parentRights = await parent.getRights(store);
      rights.push(...parentRights);
    }

    return rights;
  }

  /** Returns true is the resource had an `Unauthorized` 401 response. */
  public isUnauthorized(): boolean {
    return !!this.error && isUnauthorized(this.error);
  }

  /** Removes the resource form both the server and locally */
  public async destroy(store: Store, agent?: Agent): Promise<void> {
    if (this.new) {
      store.removeResource(this.getSubject());

      return;
    }

    const newCommitBuilder = new CommitBuilder(this.getSubject());
    newCommitBuilder.setDestroy(true);

    if (agent === undefined) {
      agent = store.getAgent();
    }

    if (agent?.subject === undefined) {
      throw new Error(
        'No agent has been set or passed, you cannot delete this.',
      );
    }

    const commit = await newCommitBuilder.sign(agent.privateKey, agent.subject);
    const endpoint = new URL(this.getSubject()).origin + `/commit`;
    await store.postCommit(commit, endpoint);
    store.removeResource(this.getSubject());
  }

  /** Appends a Resource to a ResourceArray */
  public pushPropVal(
    propUrl: string,
    values: JSONArray,
    unique?: boolean,
  ): void {
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

  /** Removes a property value combination from the resource and adds it to the next Commit */
  public removePropVal(propertyUrl: string): void {
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
  public async save(
    store: Store,
    differentAgent?: Agent,
  ): Promise<string | undefined> {
    if (!this.commitBuilder.hasUnsavedChanges()) {
      console.warn(`No changes to ${this.subject}, not saving`);

      return undefined;
    }

    const agent = store.getAgent() ?? differentAgent;

    if (!agent) {
      throw new Error('No agent has been set or passed, you cannot save.');
    }

    // If the parent of this resource is new we can't save yet so we add it to a batched that gets saved when the parent does.
    if (this.isParentNew(store)) {
      store.batchResource(this.getSubject());

      return;
    }

    // The previousCommit is required in Commits. We should use the `lastCommit` value on the resource.
    // This makes sure that we're making adjustments to the same version as the server.
    const lastCommit = this.get(properties.commit.lastCommit)?.toString();

    if (lastCommit) {
      this.commitBuilder.setPreviousCommit(lastCommit);
    }

    const wasNew = this.new;

    // Cloning the CommitBuilder to prevent race conditions, and keeping a back-up of current state for when things go wrong during posting.
    const oldCommitBuilder = this.commitBuilder.clone();
    this.commitBuilder = new CommitBuilder(this.getSubject());
    const commit = await oldCommitBuilder.sign(
      agent.privateKey,
      agent.subject!,
    );
    // Add the signature to the list of applied ones, to prevent applying it again when the server
    this.appliedCommitSignatures.add(commit.signature);
    this.loading = false;
    this.new = false;

    // TODO: Check if all required props are there
    const endpoint = new URL(this.getSubject()).origin + `/commit`;

    try {
      // We optimistically update all viewed instances for snappy feedback
      store.addResources(this);
      store.notify(this);

      // If a commit is already being posted we wait for it to finish
      // because the server can not guarantee the commits will be processed in the correct order.

      if (this.queuedFetch) {
        try {
          await this.queuedFetch;
        } catch (e) {
          // Continue
        }
      }

      this.commitError = undefined;
      const createdCommitPromise = store.postCommit(commit, endpoint);
      this.queuedFetch = createdCommitPromise;
      store.notify(this);
      const createdCommit = await createdCommitPromise;

      this.setUnsafe(properties.commit.lastCommit, createdCommit.id!);

      if (wasNew) {
        // The first `SUBSCRIBE` message will not have worked, because the resource didn't exist yet.
        // That's why we need to repeat the process
        // https://github.com/atomicdata-dev/atomic-data-rust/issues/486
        store.subscribeWebSocket(this.subject);

        // Save any children that have been batched while creating this resource
        await store.saveBatchForParent(this.getSubject());
      }

      // Let all subscribers know that the commit has been applied
      store.notifyResourceSaved(this);

      return createdCommit.id as string;
    } catch (e) {
      // Logic for handling error if the previousCommit is wrong.
      // Is not stable enough, and maybe not required at the time.
      if (e.message.includes('previousCommit')) {
        console.warn('previousCommit missing or mismatch, retrying...');
        // We try again, but first we fetch the latest version of the resource to get its `lastCommit`
        const resourceFetched = await store.fetchResourceFromServer(
          this.getSubject(),
        );

        const fixedLastCommit = resourceFetched!
          .get(properties.commit.lastCommit)
          ?.toString();

        if (fixedLastCommit) {
          this.setUnsafe(properties.commit.lastCommit, fixedLastCommit);
        }

        // Try again!
        return await this.save(store, agent);
      }

      // If it fails, revert to the old resource with the old CommitBuilder
      this.commitBuilder = oldCommitBuilder;
      this.commitError = e;
      store.addResources(this);
      store.notify(this.clone());
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
    store: Store,
    /**
     * Disable validation if you don't need it. It might cause a fetch if the
     * Property is not present when set is called
     */
    validate = true,
  ): Promise<void> {
    // If the value is the same, don't do anything. We don't want unnecessary commits.
    if (this.equalsCurrentValue(prop, value)) {
      return;
    }

    if (store.isOffline()) {
      console.warn('Offline, not validating');
      validate = false;
    }

    if (validate) {
      const fullProp = await store.getProperty(prop);
      validateDatatype(value, fullProp.datatype);
    }

    if (value === undefined) {
      this.removePropVal(prop);
      store.notify(this.clone());

      return;
    }

    this.propvals.set(prop, value);
    // Add the change to the Commit Builder, so we can commit our changes later
    this.commitBuilder.addSetAction(prop, value);
    store.notify(this.clone());
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
    this.subject = subject;
  }

  /** Returns true if the value has not changed */
  private equalsCurrentValue(prop: string, value: JSONValue) {
    const ownValue = this.get(prop);

    if (value === Object(value)) {
      return JSON.stringify(ownValue) === JSON.stringify(value);
    }

    return ownValue === value;
  }

  private isParentNew(store: Store) {
    const parentSubject = this.propvals.get(core.properties.parent) as string;

    if (!parentSubject) {
      return false;
    }

    const parent = store.getResourceLoading(parentSubject);

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
