import { ulid } from 'ulid';
import {
  removeCookieAuthentication,
  setCookieAuthentication,
} from './authentication.js';
import { EventManager } from './EventManager.js';
import { hasBrowserAPI } from './hasBrowserAPI.js';
import {
  Agent,
  Datatype,
  datatypeFromUrl,
  Client,
  Resource,
  unknownSubject,
  urls,
  Commit,
  JSONADParser,
  FileOrFileLike,
  OptionalClass,
  UnknownClass,
  Server,
  core,
  commits,
  collections,
  JSONValue,
  SearchOpts,
  buildSearchSubject,
  server,
} from './index.js';
import { stringToSlug } from './stringToSlug.js';
import { authenticate, fetchWebSocket, startWebsocket } from './websockets.js';

/** Function called when a resource is updated or removed */
type ResourceCallback<C extends OptionalClass = UnknownClass> = (
  resource: Resource<C>,
) => void;
/** Callback called when the stores agent changes */
type AgentCallback = (agent: Agent | undefined) => void;
type ErrorCallback = (e: Error) => void;

type ServerURLCallback = (serverURL: string) => void;
type Fetch = typeof fetch;

type AddResourcesOpts = {
  skipCommitCompare?: boolean;
};

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
};

export interface StoreOpts {
  /** The default store URL, where to send commits and where to create new instances */
  serverUrl?: string;
  /** Default Agent, used for signing commits. Is required for posting things. */
  agent?: Agent;
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
  /** Event that gets called whenever the store encounters an error */
  Error = 'error',
}

/**
 * Handlers are functions that are called when a certain event occurs.
 */
type StoreEventHandlers = {
  [StoreEvents.ResourceSaved]: ResourceCallback;
  [StoreEvents.ResourceRemoved]: ResourceCallback;
  [StoreEvents.ResourceManuallyCreated]: ResourceCallback;
  [StoreEvents.AgentChanged]: AgentCallback;
  [StoreEvents.ServerURLChanged]: ServerURLCallback;
  [StoreEvents.Error]: ErrorCallback;
};

/** Returns True if the client has WebSocket support */
const supportsWebSockets = () => typeof WebSocket !== 'undefined';

/**
 * An in memory store that has a bunch of usefful methods for retrieving Atomic
 * Data Resources. It is also resposible for keeping the Resources in sync with
 * Subscribers (components that use the Resource), and for managing the current
 * Agent (User).
 */
export class Store {
  /** A list of all functions that need to be called when a certain resource is updated */
  public subscribers: Map<string, Array<ResourceCallback>>;
  private injectedFetch: Fetch;
  /**
   * The base URL of an Atomic Server. This is where to send commits, create new
   * instances, search, etc.
   */
  private serverUrl: string;
  /** All the resources of the store */
  private _resources: Map<string, Resource>;

  /** List of resources that have parents that are not saved to the server, when a parent is saved it should also save its children */
  private batchedResources: Map<string, Set<string>> = new Map();

  /** Current Agent, used for signing commits. Is required for posting things. */
  private agent?: Agent;
  /** Mapped from origin to websocket */
  private webSockets: Map<string, WebSocket>;

  private eventManager = new EventManager<StoreEvents, StoreEventHandlers>();

  private client: Client;

  public constructor(opts: StoreOpts = {}) {
    this._resources = new Map();
    this.webSockets = new Map();
    this.subscribers = new Map();
    opts.serverUrl && this.setServerUrl(opts.serverUrl);
    opts.agent && this.setAgent(opts.agent);
    this.client = new Client(this.injectedFetch);

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

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public addResources(
    resources: Resource | Resource[],
    opts?: AddResourcesOpts,
  ): void {
    for (const resource of Array.isArray(resources) ? resources : [resources]) {
      this.addResource(resource, opts ?? {});
    }
  }

  /**
   * @deprecated Will be marked private in the future, please use `addResources`
   *
   * Adds a Resource to the store and notifies subscribers. Replaces existing
   * resources, unless this new resource is explicitly incomplete.
   */
  public addResource(
    resource: Resource,
    { skipCommitCompare }: AddResourcesOpts,
  ): void {
    // The resource might be new and not have a store yet. We set it here.
    resource.setStore(this);

    // Incomplete resources may miss some properties
    if (resource.get(urls.properties.incomplete)) {
      // If there is a resource with the same subject, we won't overwrite it with an incomplete one
      const existing = this.resources.get(resource.subject);

      if (existing && !existing.loading) {
        return;
      }
    }

    // Check if the resource has the same last commit as the one already in the store, if so, we don't want to notify so we don't trigger rerenders.
    if (!skipCommitCompare) {
      const storeResource = this.resources.get(resource.subject);

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

    this.resources.set(resource.subject, resource.__internalObject);

    this.notify(resource.__internalObject);
  }

  /**
   * A helper function for creating new resources.
   * Options take:
   * subject (optional) - defaults to random subject,
   * parent (optional) - defaults to serverUrl,
   * isA (optional),
   * properties (optional) - any additional properties to be set on the resource.
   */
  public async newResource<C extends OptionalClass = UnknownClass>({
    subject,
    parent,
    isA,
    propVals,
    noParent,
  }: CreateResourceOptions = {}): Promise<Resource<C>> {
    const normalizedIsA = Array.isArray(isA) ? isA : [isA];
    const newSubject = subject ?? this.createSubject();

    const resource = this.getResourceLoading(newSubject, { newResource: true });

    if (normalizedIsA[0]) {
      await resource.addClasses(...(normalizedIsA as string[]));
    }

    if (!noParent) {
      await resource.set(core.properties.parent, parent ?? this.serverUrl);
    }

    if (propVals) {
      for (const [key, value] of Object.entries(propVals)) {
        await resource.set(key, value);
      }
    }

    return resource;
  }

  public async search(query: string, opts: SearchOpts = {}): Promise<string[]> {
    const searchSubject = buildSearchSubject(this.serverUrl, query, opts);
    const searchResource = await this.fetchResourceFromServer(searchSubject, {
      noWebSocket: true,
    });
    const results = searchResource.get(server.properties.results) ?? [];

    return results;
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
    } catch (e) {
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

  /** Creates a random subject url. You can pass a parent subject if you want that to be included in the url. */
  public createSubject(parentSubject?: string): string {
    if (parentSubject) {
      return `${parentSubject}/${this.randomPart()}`;
    }

    return new URL(`/${this.randomPart()}`, this.serverUrl).toString();
  }

  /**
   * Always fetches resource from the server then adds it to the store.
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
    } = {},
  ): Promise<Resource<C>> {
    if (opts.setLoading) {
      const newR = new Resource<C>(subject);
      newR.loading = true;
      this.addResources(newR);
    }

    // Use WebSocket if available, else use HTTP(S)
    const ws = this.getWebSocketForSubject(subject);

    if (
      !opts.fromProxy &&
      !opts.noWebSocket &&
      supportsWebSockets() &&
      ws?.readyState === WebSocket.OPEN
    ) {
      // Use WebSocket
      await fetchWebSocket(ws, subject);
      // Resource should now have been added to the store by the websocket client.
    } else {
      // Use HTTPS
      const signInfo = this.agent
        ? { agent: this.agent, serverURL: this.getServerUrl() }
        : undefined;

      const { createdResources } = await this.client.fetchResourceHTTP(
        subject,
        {
          from: opts.fromProxy ? this.getServerUrl() : undefined,
          method: opts.method,
          body: opts.body,
          signInfo,
        },
      );

      this.addResources(createdResources);
    }

    return this.resources.get(subject)!;
  }

  public getAllSubjects(): string[] {
    return Array.from(this.resources.keys());
  }

  /** Returns the WebSocket for the current Server URL */
  public getDefaultWebSocket(): WebSocket | undefined {
    return this.webSockets.get(this.getServerUrl());
  }

  /** Opens a Websocket for some subject URL, or returns the existing one. */
  public getWebSocketForSubject(subject: string): WebSocket | undefined {
    const url = new URL(subject);
    const found = this.webSockets.get(url.origin);

    if (found) {
      return found;
    } else {
      if (typeof window !== 'undefined') {
        this.webSockets.set(url.origin, startWebsocket(url.origin, this));
      }
    }

    return;
  }

  /** Returns the base URL of the companion server */
  public getServerUrl(): string {
    return this.serverUrl;
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
    subject: string = unknownSubject,
    opts: FetchOpts = {},
  ): Resource<C> {
    // This is needed because it can happen that the useResource react hook is called while there is no subject passed.
    if (subject === unknownSubject || subject === null) {
      const newR = new Resource<C>(unknownSubject, opts.newResource);
      newR.setStore(this);

      return newR;
    }

    let resource = this.resources.get(subject);

    if (!resource) {
      resource = new Resource<C>(subject, opts.newResource);
      resource.loading = true;
      this.addResources(resource);

      if (!opts.newResource) {
        this.fetchResourceFromServer(subject, opts);
      }

      return resource;
    } else if (!opts.allowIncomplete && resource.loading === false) {
      // In many cases, a user will always need a complete resource.
      // This checks if the resource is incomplete and fetches it if it is.
      if (resource.get(urls.properties.incomplete)) {
        resource.loading = true;
        this.addResources(resource);
        this.fetchResourceFromServer(subject, opts);
      }
    }

    return resource;
  }

  /**
   * @deprecated
   * renamed to `getResource`
   */
  public async getResourceAsync<C extends OptionalClass = UnknownClass>(
    subject: string,
  ): Promise<Resource<C>> {
    return this.getResource(subject);
  }

  /**
   * Gets a resource by URL. Fetches and parses it if it's not available in the
   * store. Not recommended to use this for rendering, because it might cause
   * resources to be fetched multiple times.
   */
  public async getResource<C extends OptionalClass = UnknownClass>(
    subject: string,
  ): Promise<Resource<C>> {
    const found = this.resources.get(subject);

    if (found && found.isReady()) {
      return found;
    }

    /** Fix the case where a resource was previously requested but still not ready */
    if (found && !found.isReady()) {
      return new Promise((resolve, reject) => {
        const defaultTimeout = 5000;

        const cb: ResourceCallback<C> = res => {
          this.unsubscribe(subject, cb);
          resolve(res);
        };

        this.subscribe(subject, cb);

        setTimeout(() => {
          this.unsubscribe(subject, cb);
          reject(
            new Error(
              `Async Request for subject "${subject}" timed out after ${defaultTimeout}ms.`,
            ),
          );
        }, defaultTimeout);
      });
    }

    const result = await this.fetchResourceFromServer(subject);

    // If the resource was not in the store yet, subscripe to changes so we don't return stale results when the resource is updated.
    this.subscribeWebSocket(subject);

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
        `Property ${subject} has no datatype: ${resource.getPropVals()}`,
      );
    }

    const shortname = resource.get(core.properties.shortname);

    if (shortname === undefined) {
      throw Error(
        `Property ${subject} has no shortname: ${resource.getPropVals()}`,
      );
    }

    const description = resource.get(core.properties.description);

    if (description === undefined) {
      throw Error(
        `Property ${subject} has no description: ${resource.getPropVals()}`,
      );
    }

    const classTypeURL = resource.get(core.properties.classtype)?.toString();

    const propery: Property = {
      subject,
      classType: classTypeURL,
      shortname: shortname.toString(),
      description: description.toString(),
      datatype: datatypeFromUrl(datatypeUrl.toString()),
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
   * If the store does not have an active internet connection, will return
   * false. This may affect some functionality. For example, some checks will
   * not be performed client side when offline.
   */
  public isOffline(): boolean {
    // If we are in a node/server environment assume we are online.
    if (!hasBrowserAPI()) {
      return false;
    }

    return !window?.navigator?.onLine;
  }

  public async notifyResourceSaved(resource: Resource): Promise<void> {
    await this.eventManager.emit(StoreEvents.ResourceSaved, resource);
  }

  public async notifyResourceManuallyCreated(
    resource: Resource,
  ): Promise<void> {
    await this.eventManager.emit(StoreEvents.ResourceManuallyCreated, resource);
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

      // convert base64 content to JSON
      const json = JSON.parse(atob(content));

      const [_, resources] = parser.parseObject(json);
      this.addResources(resources);
    });
  }

  /**
   * Fetches all Classes and Properties from your current server, including external resources.
   * This helps to speed up time to interactive, but may not be necessary for all applications.
   */
  public async preloadPropsAndClasses(): Promise<void> {
    // TODO: use some sort of CollectionBuilder for this.
    const classesUrl = new URL('/classes', this.serverUrl);
    const propertiesUrl = new URL('/properties', this.serverUrl);
    classesUrl.searchParams.set('include_external', 'true');
    propertiesUrl.searchParams.set('include_external', 'true');
    classesUrl.searchParams.set('include_nested', 'true');
    propertiesUrl.searchParams.set('include_nested', 'true');
    classesUrl.searchParams.set('page_size', '999');
    propertiesUrl.searchParams.set('page_size', '999');
    await Promise.all([
      this.fetchResourceFromServer(classesUrl.toString()),
      this.fetchResourceFromServer(propertiesUrl.toString()),
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

  /** Removes (destroys / deletes) resource from this store */
  public removeResource(subject: string): void {
    const resource = this.resources.get(subject);

    if (resource) {
      this.resources.delete(subject);
      this.eventManager.emit(StoreEvents.ResourceRemoved, resource);
    }
  }

  /**
   * Changes the Subject of a Resource. Checks if the new name is already taken,
   * errors if so.
   */
  public async renameSubject(
    resource: Resource,
    newSubject: string,
  ): Promise<void> {
    Client.tryValidSubject(newSubject);
    const oldSubject = resource.subject;

    if (await this.checkSubjectTaken(newSubject)) {
      throw Error(`New subject name is already taken: ${newSubject}`);
    }

    resource.setSubject(newSubject);

    const subs = this.subscribers.get(oldSubject) ?? [];
    this.subscribers.set(newSubject, subs);
    this.removeResource(oldSubject);

    this.addResources(resource);
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

    if (agent && agent.subject) {
      if (hasBrowserAPI()) {
        setCookieAuthentication(this.serverUrl, agent);
      }

      this.webSockets.forEach(ws => {
        // If WebSocket is already open, authenticate immediately
        if (ws.readyState === ws.OPEN) {
          authenticate(ws, this, true);
        } else {
          // Otherwise, wait for it to open before authenticating
          ws.onopen = () => {
            authenticate(ws, this, true);
          };
        }
      });
    } else {
      if (hasBrowserAPI()) {
        removeCookieAuthentication();
      }
    }

    this.eventManager.emit(StoreEvents.AgentChanged, agent);
  }

  /** Sets the Server base URL, without the trailing slash. */
  public setServerUrl(url: string): void {
    Client.tryValidSubject(url);

    if (url.substring(-1) === '/') {
      throw Error('baseUrl should not have a trailing slash');
    }

    this.serverUrl = url;
    this.eventManager.emit(StoreEvents.ServerURLChanged, url);
    // TODO This is not the right place
    supportsWebSockets() && this.openWebSocket(url);
  }

  /** Opens a WebSocket for this Atomic Server URL */
  public openWebSocket(url: string) {
    // Check if we're running in a webbrowser
    if (supportsWebSockets()) {
      if (this.webSockets.has(url)) {
        return;
      }

      this.webSockets.set(url, startWebsocket(url, this));
    } else {
      console.warn('WebSockets not supported, no window available');
    }
  }

  /**
   * Registers a callback for when the a resource is updated. When you call
   * this
   * The method returns a function that you can call to unsubscribe. You can also unsubscribe by calling `store.unsubscribe()`.
   */
  // TODO: consider subscribing to properties, maybe add a second subscribe function, use that in useValue
  public subscribe(subject: string, callback: ResourceCallback): () => void {
    if (subject === undefined) {
      throw Error('Cannot subscribe to undefined subject');
    }

    let callbackArray = this.subscribers.get(subject);

    if (callbackArray === undefined) {
      // Only subscribe once
      this.subscribeWebSocket(subject);
      callbackArray = [];
    }

    callbackArray.push(callback);
    this.subscribers.set(subject, callbackArray);

    return () => {
      this.unsubscribe(subject, callback);
    };
  }

  public subscribeWebSocket(subject: string): void {
    if (subject === unknownSubject) {
      return;
    }

    // TODO: check if there is a websocket for this server URL or not
    try {
      const ws = this.getWebSocketForSubject(subject);

      // Only subscribe if there's a websocket. When it's opened, all subject will be iterated and subscribed
      if (ws?.readyState === 1) {
        ws?.send(`SUBSCRIBE ${subject}`);
      }
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error(e);
    }
  }

  public unSubscribeWebSocket(subject: string): void {
    if (subject === unknownSubject) {
      return;
    }

    try {
      this.getDefaultWebSocket()?.send(`UNSUBSCRIBE ${subject}`);
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error(e);
    }
  }

  /** Unregisters the callback (see `subscribe()`) */
  public unsubscribe(subject: string, callback: ResourceCallback): void {
    if (subject === undefined) {
      return;
    }

    let callbackArray = this.subscribers.get(subject);

    if (callbackArray) {
      // Remove the function from the callBackArray
      callbackArray = callbackArray?.filter(item => item !== callback);
      this.subscribers.set(subject, callbackArray);
    }
  }

  public on<T extends StoreEvents>(event: T, callback: StoreEventHandlers[T]) {
    return this.eventManager.register(event, callback);
  }

  /** Uploads files to atomic server and create resources for them, then returns the subjects.
   * If using this in Node.js and it does not work, try injecting node-fetch using `Store.injectFetch()` Some versions of Node create mallformed FormData when using the build-in fetch.
   */
  public async uploadFiles(
    files: FileOrFileLike[],
    parent: string,
  ): Promise<string[]> {
    const agent = this.getAgent();

    if (!agent) {
      throw Error('No agent set, cannot upload files');
    }

    const resources = await this.client.uploadFiles(
      files,
      this.getServerUrl(),
      agent,
      parent,
    );

    this.addResources(resources);

    return resources.map(r => r.subject);
  }

  /** Posts a Commit to some endpoint. Returns the Commit created by the server. */
  public async postCommit(commit: Commit, endpoint: string): Promise<Commit> {
    return this.client.postCommit(commit, endpoint);
  }

  /**
   * Returns the ancestry of a resource, starting with the resource itself.
   */
  public async getResourceAncestry(resource: Resource): Promise<string[]> {
    const ancestry: string[] = [resource.subject];

    let lastAncestor: string = resource.get(urls.properties.parent) as string;
    lastAncestor && ancestry.push(lastAncestor);

    while (lastAncestor) {
      const lastResource = await this.getResourceAsync(lastAncestor);

      if (lastResource) {
        lastAncestor = lastResource.get(urls.properties.parent) as string;

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

  /** Lets subscribers know that a resource has been changed. Time to update your views.
   * Make sure the resource is a new reference, otherwise React will not rerender.
   */
  private async notify(resource: Resource): Promise<void> {
    const subject = resource.subject;
    const callbacks = this.subscribers.get(subject);

    if (callbacks === undefined) {
      return;
    }

    Promise.allSettled(callbacks.map(async cb => cb(resource)));
  }
}

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
