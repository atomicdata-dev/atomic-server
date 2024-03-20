import { Collection, CollectionParams } from './collection.js';
import { Store } from './store.js';

export class CollectionBuilder {
  private store: Store;
  private server: string;

  private params: CollectionParams = {
    page_size: '30',
  };

  public constructor(store: Store, server?: string) {
    this.store = store;
    this.server = server ?? new URL(store.getServerUrl()).origin;
  }

  public setProperty(property: string): CollectionBuilder {
    this.params.property = property;

    return this;
  }

  public setValue(value: string): CollectionBuilder {
    this.params.value = value;

    return this;
  }

  public setSortBy(sortBy: string): CollectionBuilder {
    this.params.sort_by = sortBy;

    return this;
  }

  public setSortDesc(sortDesc: boolean): CollectionBuilder {
    this.params.sort_desc = sortDesc;

    return this;
  }

  public setPageSize(pageSize: number): CollectionBuilder {
    this.params.page_size = `${pageSize}`;

    return this;
  }

  public build(): Collection {
    return new Collection(this.store, this.server, this.params);
  }

  public async buildAndFetch(): Promise<Collection> {
    const collection = this.build();

    await collection.waitForReady();

    return collection;
  }
}
