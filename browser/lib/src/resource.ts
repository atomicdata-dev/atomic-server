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
export class Resource {
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
  public clone(): Resource {
    const res = new Resource(this.subject);
    res.propvals = structuredClone(this.propvals);
    res.loading = this.loading;
    res.new = this.new;
    // structured clone
    res.error = structuredClone(this.error);
    res.commitError = this.commitError;
    res.commitBuilder = this.commitBuilder.clone();
    res.appliedCommitSignatures = this.appliedCommitSignatures;

    return res;
  }

  /** Checks if the resource is both loaded and free from errors */
  public isReady(): boolean {
    return !this.loading && this.error === undefined;
  }

  /** Get a Value by its property */
  public get(propUrl: string): JSONValue {
    return this.propvals.get(propUrl);
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

  /** Get a Value by its property */
  public getClasses(): string[] {
    return this.getSubjects(properties.isA);
  }

  /** Checks if the resource is all of the given classes */
  public hasClasses(...classSubjects: string[]): boolean {
    return classSubjects.every(classSubject =>
      this.getClasses().includes(classSubject),
    );
  }

  /**
   * Returns the current Commit Builder, which describes the pending changes of
   * the resource
   */
  public getCommitBuilder(): CommitBuilder {
    return this.commitBuilder;
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
    url.pathname = '/collections';
    url.searchParams.set('property', properties.parent);
    url.searchParams.set('value', this.subject);

    return url.toString();
  }

  /** builds all versions using the Commits */
  public async getHistory(store: Store): Promise<Version[]> {
    const commitsCollection = await store.fetchResourceFromServer(
      this.getCommitsCollection(),
    );

    if (commitsCollection.error) {
      throw commitsCollection.error;
    }

    const commits = commitsCollection.get(properties.collection.members);

    const builtVersions: Version[] = [];

    let previousResource = new Resource(this.subject);

    if (!commits) {
      throw new Error(
        `Couldn't find commits for ${this.getSubject()} in CommitCollection: ` +
          this.getCommitsCollection(),
      );
    }

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
  public pushPropVal(propUrl: string, ...values: JSONArray): void {
    const propVal = (this.get(propUrl) as JSONArray) ?? [];
    propVal.push(...values);
    this.commitBuilder.addPushAction(propUrl, ...values);
    this.propvals.set(propUrl, propVal);
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
   */
  public async save(store: Store, differentAgent?: Agent): Promise<string> {
    // Instantly (optimistically) save for local usage
    // Doing this early is essential for having a snappy UX in the document editor
    store.addResources(this);

    const agent = store.getAgent() ?? differentAgent;

    if (!agent) {
      throw new Error('No agent has been set or passed, you cannot save.');
    }

    // The previousCommit is required in Commits. We should use the `lastCommit` value on the resource.
    // This makes sure that we're making adjustments to the same version as the server.
    const lastCommit = this.get(properties.commit.lastCommit)?.toString();

    if (lastCommit) {
      this.commitBuilder.setPreviousCommit(lastCommit);
    }

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
      this.commitError = undefined;
      const createdCommit = await store.postCommit(commit, endpoint);

      this.setUnsafe(properties.commit.lastCommit, createdCommit.id!);
      // The first `SUBSCRIBE` message will not have worked, because the resource didn't exist yet.
      // That's why we need to repeat the process
      // https://github.com/atomicdata-dev/atomic-data-rust/issues/486
      store.subscribeWebSocket(this.subject);

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
      throw e;
    }
  }

  /**
   * Set a Property, Value combination and perform a validation. Will throw if
   * property is not valid for the datatype. Will fetch the datatype if it's not
   * available. Adds the property to the commitbuilder.
   */
  public async set(
    prop: string,
    value: JSONValue,
    store: Store,
    /**
     * Disable validation if you don't need it. It might cause a fetch if the
     * Property is not present when set is called
     */
    validate = true,
  ): Promise<void> {
    if (store.isOffline()) {
      console.warn('Offline, not validating');
      validate = false;
    }

    if (validate) {
      const fullProp = await store.getProperty(prop);
      validateDatatype(value, fullProp.datatype);
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
    this.subject = subject;
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
