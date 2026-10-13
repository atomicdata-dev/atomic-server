import {
  Aggregation,
  Collection,
  CollectionParams,
  ExpressionFilter,
  PropVal,
} from './collection.js';
import { Store } from './store.js';
import { core } from './ontologies/core.js';
import { isAtomicIdentifier } from './subject.js';
import { server as serverOntology } from './ontologies/server.js';

export class CollectionBuilder {
  private store: Store;
  private server: string | undefined;
  private explicitDrive = false;
  private preferServer = false;

  private params: CollectionParams = {
    page_size: '30',
    include_nested: false,
    drive: undefined,
  };

  public constructor(store: Store, server?: string) {
    this.store = store;
    this.server = server;
    // Default the drive filter to the active drive DID. The old fallback
    // was `this.server` (a URL like `http://localhost:9883`), which the
    // server then tried to filter `drive == <server-origin>` against —
    // never matched any real resource (resources are scoped by drive DID),
    // so every default-drive query returned zero rows.
    const activeDrive = store.getDrive();
    this.params.drive = this.params.drive ?? activeDrive;
  }

  public setProperty(property: string): CollectionBuilder {
    this.params.property = property;

    return this;
  }

  public setValue(value: string): CollectionBuilder {
    this.params.value = value;

    return this;
  }

  /**
   * Adds an extra `(property, value)` constraint, combined with the rest using
   * **AND**. Call multiple times to filter on multiple properties, e.g.
   * `.setProperty(isA).setValue(commit).addFilter({ property: signer, value: agent })`.
   */
  public addFilter(filter: PropVal): CollectionBuilder {
    this.params.filters = [...(this.params.filters ?? []), filter];

    return this;
  }

  /** Replaces all extra AND constraints at once. */
  public setFilters(filters: PropVal[]): CollectionBuilder {
    this.params.filters = filters;

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

  public setIncludeNested(includeNested: boolean): CollectionBuilder {
    this.params.include_nested = includeNested;

    return this;
  }

  /**
   * Answer from the server when it is connected, instead of building every
   * member from the local database to sort it. For lists that grow large (a
   * chat) where only a page or two is ever shown; falls back to the local
   * database when the server cannot answer.
   */
  public setPreferServer(preferServer: boolean): CollectionBuilder {
    this.preferServer = preferServer;

    return this;
  }

  public setDrive(drive: string): CollectionBuilder {
    this.explicitDrive = true;
    this.params.drive = drive;

    return this;
  }

  /**
   * Asks the store for statistics over every matching resource — a sum, a
   * count, an average — optionally broken down per distinct value of a
   * property. Read them back from `collection.aggregates`.
   */
  /**
   * Constrains members by a value computed per resource — "logged more than an
   * hour", "overdue". Evaluated by the store; see {@link ExpressionFilter}.
   */
  public setExpressionFilters(filters: ExpressionFilter[]): CollectionBuilder {
    this.params.expression_filters = filters;

    return this;
  }

  public setAggregation(aggregation: Aggregation): CollectionBuilder {
    this.params.aggregation = aggregation;

    return this;
  }

  public build(): Collection {
    const params = { ...this.params };

    const httpOrigin = (subject: string | undefined): string | undefined => {
      try {
        const url = new URL(subject ?? '');

        return ['http:', 'https:'].includes(url.protocol)
          ? url.origin
          : undefined;
      } catch {
        return undefined;
      }
    };

    // A parent URL names the authority for its children. Other URL-valued
    // filters (e.g. isA=Document) name vocabulary, not a query server.
    const parentOrigin =
      params.property === core.properties.parent
        ? httpOrigin(params.value)
        : undefined;

    if (
      !this.explicitDrive &&
      params.property === core.properties.parent &&
      params.value &&
      isAtomicIdentifier(params.value) &&
      httpOrigin(params.drive)
    ) {
      params.drive = undefined;
    }

    if (
      !this.explicitDrive &&
      parentOrigin &&
      params.value &&
      this.store.resources
        .get(params.value)
        ?.hasClasses(serverOntology.classes.drive)
    ) {
      params.drive = params.value;
    }

    const driveOrigin = httpOrigin(params.drive);
    const server =
      this.server ?? parentOrigin ?? driveOrigin ?? this.store.getServerUrl();

    // A deep link can be opened while the local personal drive is selected.
    // Do not send that unrelated default scope to the remote parent server.
    if (
      !this.explicitDrive &&
      parentOrigin &&
      parentOrigin !== driveOrigin &&
      parentOrigin !== new URL(this.store.getServerUrl()).origin
    ) {
      params.drive = undefined;
    }

    return new Collection(this.store, server, params, false, {
      preferServer: this.preferServer,
      explicitDrive: this.explicitDrive,
    });
  }

  public async buildAndFetch(): Promise<Collection> {
    const collection = this.build();

    await collection.waitForReady();

    return collection;
  }
}
