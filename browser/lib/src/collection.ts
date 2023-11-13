import { isNumber } from './datatypes.js';
import { Resource } from './resource.js';
import { Store } from './store.js';
import { urls } from './urls.js';

export interface QueryFilter {
  property?: string;
  value?: string;
  sort_by?: string;
  sort_desc?: boolean;
}

export interface CollectionParams extends QueryFilter {
  page_size: string;
}

/**
 * A collection is a dynamic resource that queries the server for a list of resources that meet it's criteria.
 * Checkout [the docs](https://docs.atomicdata.dev/schema/collections.html) for more information.
 *
 * Keep in mind that the collection does currently not subscribe to changes in the store and will therefore not update if items are added or removed.
 * Use the `invalidate` method to force a refresh.
 */
export class Collection {
  public readonly __internalObject = this;
  private store: Store;
  private pages = new Map<number, Resource>();
  private server: string;
  private params: CollectionParams;

  private _totalMembers = 0;

  private _waitForReady: Promise<void>;

  public constructor(
    store: Store,
    server: string,
    params: CollectionParams,
    noFetch = false,
  ) {
    this.store = store;
    this.server = server;
    this.params = params;

    if (!noFetch) {
      this._waitForReady = this.fetchPage(0);
    }

    this.clearPages = this.clearPages.bind(this);
  }

  public get property(): string | undefined {
    return this.params.property;
  }

  public get value(): string | undefined {
    return this.params.value;
  }

  public get sortBy(): string | undefined {
    return this.params.sort_by;
  }

  public get sortDesc(): boolean {
    return !!this.params.sort_desc;
  }

  public get pageSize(): number {
    return parseInt(this.params.page_size, 10);
  }

  public get totalMembers(): number {
    return this._totalMembers;
  }

  public waitForReady(): Promise<void> {
    return this._waitForReady;
  }

  public async getMemberWithIndex(index: number): Promise<string> {
    if (index >= this.totalMembers) {
      throw new Error('Index out of bounds');
    }

    const page = Math.floor(index / this.pageSize);

    if (!this.pages.has(page)) {
      this._waitForReady = this.fetchPage(page);
      await this._waitForReady;
    }

    const resource = this.pages.get(page)!;
    const members = resource.getArray(
      urls.properties.collection.members,
    ) as string[];

    return members[index % this.pageSize];
  }

  public clearPages(): void {
    this.pages = new Map();
  }

  public async refresh(): Promise<void> {
    this.clearPages();
    this._waitForReady = this.fetchPage(0);

    return this._waitForReady;
  }

  public clone() {
    const collection = new Collection(this.store, this.server, this.params);
    collection._totalMembers = this._totalMembers;
    collection._waitForReady = this._waitForReady;
    collection.pages = this.pages;

    return collection;
  }

  private buildSubject(page: number): string {
    const url = new URL(`${this.server}/query`);

    for (const [key, value] of Object.entries(this.params)) {
      url.searchParams.set(key, value);
    }

    url.searchParams.set('current_page', `${page}`);

    return url.toString();
  }

  private async fetchPage(page: number): Promise<void> {
    const subject = this.buildSubject(page);
    const resource = await this.store.fetchResourceFromServer(subject);

    if (!resource) {
      throw new Error('Invalid collection: resource does not exist');
    }

    if (resource.error) {
      throw new Error(
        `Invalid collection: resource has error: ${resource.error}`,
      );
    }

    this.pages.set(page, resource);

    const totalMembers = resource.get(urls.properties.collection.totalMembers);

    if (!isNumber(totalMembers)) {
      throw new Error('Invalid collection: total-members is not a number');
    }

    this._totalMembers = totalMembers;
  }
}

export function proxyCollection(collection: Collection): Collection {
  if (collection.__internalObject !== collection) {
    console.warn('Attempted to proxy a proxy for a collection');
  }

  return new Proxy(collection.__internalObject, {});
}
