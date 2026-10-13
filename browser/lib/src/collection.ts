import { isNumber } from './datatypes.js';
import { enableLoro } from './loro-loader.js';
import { Collections, collections } from './ontologies/collections.js';
import { Resource, normalizeLoroChangeTimestampMs } from './resource.js';
import { decodeB64 } from './base64.js';
import { decodeGenesisCert } from './genesis.js';
import { GENESIS } from './urls.js';
import { Store } from './store.js';
import { commits } from './ontologies/commits.js';
import { dataBrowser } from './ontologies/dataBrowser.js';
import { isCommitSubject } from './commit.js';
import { core } from './ontologies/core.js';
import { withDeadline } from './withDeadline.js';

/**
 * Strips `did:ad:commit:` subjects from a member list. Commit resources don't
 * have user-facing properties like `parent` or `messages`, but a hydration
 * bug elsewhere can register the committed-resource's atoms under the commit
 * subject (importing a Commit's `loroUpdate` field into the Commit's own
 * propvals). Filtering at the collection-iterator boundary keeps the leak
 * from showing up in chatroom message lists, sidebar children, table rows,
 * etc., regardless of whether the corruption came from the local or server-
 * side index. The proper fix is upstream — see TODO.
 */
function filterIndexLeakage(subjects: string[]): string[] {
  return subjects.filter(s => !isCommitSubject(s));
}

/**
 * How long a query waits for the local database to finish becoming ready
 * before asking the server instead.
 *
 * `waitForReady` waits for the WASM worker AND for the bootstrap seed, and the
 * seed is the whole bundled ontology: seventy-odd properties first, so later
 * resources parse with the right datatypes, then everything else. Measured on
 * a four-core box running four Playwright workers, that wait was 0.3 to 16s
 * routinely and **91 seconds** in the round that failed, with the worker
 * already initialized the whole time. An app's view asked its table for its
 * rows, the answer arrived 98 seconds later, and the page sat empty: the row
 * was on the server and in the local index all along.
 *
 * So the wait is bounded and the server answers when it runs out — which is
 * what a client with no local database does anyway, and the server is
 * authoritative. Three seconds is what {@link Collection.fetchPage} already
 * gives the socket a few lines down.
 */
const LOCAL_DB_READY_GRACE_MS = 3000;

/**
 * How a {@link PropVal} compares the resource's value to the filter value.
 * `eq` (default) is equality / array membership; the rest are value-comparison
 * predicates. Mirrors the Rust `FilterOperator`.
 */
export type FilterOperator =
  | 'eq'
  | 'gt'
  | 'gte'
  | 'lt'
  | 'lte'
  | 'starts_with'
  | 'contains';

/** Compares two scalar values for the ordering operators — numeric when both
 * parse as numbers (ints, floats, timestamps), else lexical. */
function compareValues(actual: string, query: string): number {
  const a = Number(actual);
  const b = Number(query);

  if (!Number.isNaN(a) && !Number.isNaN(b)) {
    return a - b;
  }

  return actual < query ? -1 : actual > query ? 1 : 0;
}

/** Whether one scalar value satisfies the filter value + operator. */
function valueMatches(
  actual: string,
  query: string,
  operator: FilterOperator,
): boolean {
  switch (operator) {
    case 'gt':
      return compareValues(actual, query) > 0;
    case 'gte':
      return compareValues(actual, query) >= 0;
    case 'lt':
      return compareValues(actual, query) < 0;
    case 'lte':
      return compareValues(actual, query) <= 0;
    case 'starts_with':
      return actual.startsWith(query);
    case 'contains':
      return actual.includes(query);
    default:
      return actual === query;
  }
}

/**
 * Whether a resource's `property` satisfies the constraint, matching the
 * server's "value-in-property" semantics: single-valued props compare directly,
 * multi-valued props (arrays like `isA`) test per-element.
 */
function constraintMatches(
  resource: Resource,
  property: string,
  value: string,
  operator: FilterOperator = 'eq',
): boolean {
  const propVal = resource.get(property);

  if (Array.isArray(propVal)) {
    return propVal.some(v => valueMatches(`${v}`, value, operator));
  }

  return valueMatches(`${propVal}`, value, operator);
}

/** A single `(property, value)` constraint. Both are optional, mirroring the
 * server: property-only (resource has the prop), value-only (any prop holds
 * the value), or both. `operator` selects how value is compared (default
 * `eq`). */
export interface PropVal {
  property?: string;
  value?: string;
  operator?: FilterOperator;
}

export interface QueryFilter {
  property?: string;
  value?: string;
  /**
   * Extra constraints, combined with `property`/`value` using **AND**. Use
   * this to filter on more than one property (e.g. `isA = Commit` AND
   * `signer = <agent>`). The primary `property`/`value` above stay as
   * single-filter sugar.
   */
  filters?: PropVal[];
  sort_by?: string;
  sort_desc?: boolean;
  drive?: string;
  /**
   * Statistics to compute over **every** matching resource, not just the
   * current page. Computed by the store (server or local DB), so a total costs
   * one number rather than a fetch of every member.
   */
  aggregation?: Aggregation;
  /**
   * Constraints on values *computed* per resource — a duration, an amount, a
   * days-since — rather than stored on it. ANDed with `filters`.
   *
   * These can't use the query index (a running duration has no stable value to
   * key by), so the store evaluates them over the set the index narrows to. The
   * count and any aggregates describe the filtered set.
   */
  expression_filters?: ExpressionFilter[];
}

/** One constraint on a computed value: "logged more than an hour". */
export interface ExpressionFilter {
  expression: Expression;
  /** Numeric comparison, in the expression's own unit (milliseconds for a
   *  duration, days for a days-since). Defaults to `eq`. */
  operator?: 'eq' | 'gt' | 'gte' | 'lt' | 'lte';
  value: number;
  /** The instant to measure "now" against, for expressions that do. Send the
   *  same one for every filter in a query. */
  now_ms?: number;
}

/** One statistic to compute. `count` needs no property. */
export interface Aggregate {
  /** Your own name for this statistic, echoed on the outcome. Needed to tell two
   *  statistics apart when neither names a property (two computed values). */
  id?: string;
  property?: string;
  /** A value computed per resource instead of read off it. Takes precedence over
   *  `property`. */
  expression?: Expression;
  function: AggregateFunction;
}

export type AggregateFunction = 'sum' | 'count' | 'avg' | 'min' | 'max';

/** A property to read off the resource, or a fixed number. */
export type Operand = string | number;

/**
 * A value computed from a resource rather than stored on it: a duration, an
 * amount, a days-since, a next-due date. Evaluated by the store, so a total or a
 * filter can name one wherever it can name a property.
 *
 * A fixed set of five, not a formula language — the same five the data-browser's
 * computed columns offer, in the same argument names.
 */
export type Expression =
  /** `to − from`, in milliseconds. */
  | { kind: 'difference'; from: Operand; to: Operand }
  /** `(until ?? now) − from`, in milliseconds: still running while `until` is
   *  empty. */
  | { kind: 'elapsed'; from: Operand; until?: Operand | null }
  /** Whole days between `from` and now. */
  | { kind: 'daysSince'; from: Operand }
  /** `a × b` — quantity × price, hours × rate. */
  | { kind: 'product'; a: Operand; b: Operand }
  /** `from + days`, as an instant. */
  | { kind: 'offset'; from: Operand; days: Operand };

/** Break the statistics down per distinct value of a property. */
export interface AggregateGrouping {
  property: string;
  /** Date and timestamp properties are bucketed; `exact` gives one group per
   *  distinct value, which for a timestamp means one per row. */
  granularity?: 'exact' | 'day' | 'month';
  /** Minutes to add before bucketing, so days are the caller's days.
   *  `-new Date().getTimezoneOffset()`. */
  tz_offset_minutes?: number;
  /** Most buckets to return (the store defaults to 100). */
  limit?: number;
}

export interface Aggregation {
  aggregates: Aggregate[];
  group_by?: AggregateGrouping;
  /** The instant a computed value that measures against "now" (a running
   *  duration, a days-since) is evaluated at. Send `Date.now()` so the number
   *  agrees with the cells the client computed itself. */
  now_ms?: number;
}

/** One bucket of a breakdown. */
export interface AggregateGroup {
  /** A value's string form, an ISO day (`2026-07-30`) or month (`2026-07`).
   *  Empty for the resources that have no value for the grouping property. */
  key: string;
  value: number | null;
  count: number;
}

/** The answer to one requested statistic, over every matching resource. */
export interface AggregateOutcome {
  /** Echoes the request's `id`. */
  id?: string;
  property?: string;
  function: AggregateFunction;
  /** `null` when no resource had a usable value — not the same as `0`. */
  value: number | null;
  /** How many resources contributed a value. */
  count: number;
  groups?: AggregateGroup[];
  /** True when there were more buckets than the limit allowed. */
  groups_truncated?: boolean;
}

export interface CollectionParams extends QueryFilter {
  page_size: string;
  include_nested: boolean;
}

export interface CollectionOptions {
  noFetch?: boolean;
  endpoint?: string;
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
  private pages = new Map<number, Resource<Collections.Collection>>();
  /**
   * subject → page index. Lets `applyResourceChange` answer "is this
   * subject already a member" in O(1) instead of scanning every loaded
   * page on every incoming `ResourceUpdated`. Maintained in lockstep
   * with `pages` via {@link setPage} / {@link clearPages}; the
   * applyResourceChange add/remove branches keep it consistent on
   * surgical mutations.
   */
  private _memberIndex = new Map<string, number>();
  /** Subjects that were added by `applyResourceChange`'s optimistic
   * path (matching newly-created resources whose server-side
   * `/query` index might lag). Preserved across `setPage` writes
   * from background fetches — without this, a stale server response
   * that says "0 members" silently wipes the optimistic add and the
   * UI loses the just-created resource until the next reload. */
  private _optimisticAdds = new Set<string>();
  /**
   * True when the store has destroyed `subject`.
   *
   * This used to be a `_removedSubjects` Set on each Collection, which meant
   * a Collection built after the delete — a second view on the same query, a
   * folder re-expanded — had no memory of it and admitted the subject from
   * the next stale answer. The store owns the fact now, so every Collection
   * on the same store agrees regardless of when it was built.
   */
  private isDestroyed(subject: string): boolean {
    return this.store.isDestroyed(subject);
  }
  private server: string;
  private params: CollectionParams;

  private _totalMembers = 0;
  /** Full local query membership, including rows outside cached pages. */
  private _queriedMembers = new Set<string>();

  /** Statistics from the last loaded page. The store computes them over every
   *  matching resource, so any page carries the same numbers. */
  private _aggregates: AggregateOutcome[] = [];

  private _waitForReady: Promise<void>;
  /** One in-flight fetch per page. A virtualized list mounts several rows from
   * the same missing page in one render; without sharing this promise, every
   * row starts the same local query and the competing hydrations can leave the
   * page unresolved for all of their consumers. */
  private _pageFetches = new Map<number, Promise<void>>();
  /**
   * True while `fetchPage` is hydrating members into the store. Query
   * hydration fires `ResourceUpdated` for every row; `useCollection`
   * would otherwise optimistic-add them in arrival (unsorted) order
   * before `setPage` lands the sorted list — the table/sidebar flash
   * on open. Skip those adds; the in-flight fetch is about to write
   * the ordered page.
   */
  private _assemblingPage = false;
  private static legacyQueryServers = new WeakMap<Store, Set<string>>();
  /** Pages of unsynced drives the server has answered this session. Its
   * members were written to the local DB as they loaded and live updates keep
   * it current, so the local answer is whole from then on. */
  private static completedByServer = new WeakMap<Store, Set<string>>();
  private legacyQuery = false;
  private readonly preferServer: boolean;
  private legacyMembers?: Promise<string[]>;

  public constructor(
    store: Store,
    server: string,
    params: CollectionParams,
    noFetch = false,
    options: { preferServer?: boolean } = {},
  ) {
    this.store = store;
    this.server = server;
    this.params = params;
    this.preferServer = !!options.preferServer;

    if (!noFetch) {
      store.registerBulkRefreshable(this);
      // Route the initial fetch through `refresh()` rather than calling
      // `fetchPage(0)` directly. `refresh()` sets `_refreshInFlight`,
      // which `applyResourceChange` reads to know whether a late-
      // arriving matching subject (one whose `ResourceUpdated` event
      // fires while the initial WS `/query` GET is still blocked
      // behind auth) should set `_refreshPending` so the loop iterates
      // and re-queries the server. Without this, the matching subject
      // is silently dropped: the collection's pages stay empty and the
      // sidebar/table never reflects the just-created resource.
      // Reproducible under `ATOMIC_TEST_CPU_THROTTLE=5` via
      // `perf-sidebar-reload.spec.ts`.
      this._waitForReady = this.refresh();
    }

    this.clearPages = this.clearPages.bind(this);
  }

  public get property(): string | undefined {
    return this.params.property;
  }

  public get value(): string | undefined {
    return this.params.value;
  }

  public get filters(): PropVal[] {
    return this.params.filters ?? [];
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

  /** Read at notification time, before deferring a membership update.
   * Query hydration is not a new row; the guard ends when assembly finishes. */
  public get isAssemblingPage(): boolean {
    return this._assemblingPage;
  }

  public get totalMembers(): number {
    return this._totalMembers;
  }

  public get totalPages(): number {
    return Math.ceil(this.totalMembers / this.pageSize);
  }

  /** The constraints on computed values this collection was built with. */
  public get expressionFilters(): ExpressionFilter[] {
    return this.params.expression_filters ?? [];
  }

  /** The aggregation this collection was built with, if any. */
  public get aggregation(): Aggregation | undefined {
    return this.params.aggregation;
  }

  /**
   * The statistics this collection asked for, over every matching resource.
   * Empty until a page has loaded (or when none were requested). They do not
   * change as you page: the store computed them over the whole filtered set.
   */
  public get aggregates(): AggregateOutcome[] {
    return this._aggregates;
  }

  public waitForReady(): Promise<void> {
    return this._waitForReady;
  }

  public async getMemberWithIndex(index: number): Promise<string | undefined> {
    if (index >= this.totalMembers) {
      throw new Error('Index out of bounds');
    }

    const page = Math.floor(index / this.pageSize);

    if (!this.pages.has(page)) {
      let fetch = this._pageFetches.get(page);

      if (!fetch) {
        fetch = this.fetchPage(page).finally(() => {
          if (this._pageFetches.get(page) === fetch) {
            this._pageFetches.delete(page);
          }
        });
        this._pageFetches.set(page, fetch);
      }

      this._waitForReady = fetch;
      await fetch;
    }

    // `fetchPage` short-circuits without populating `pages` when there's
    // nothing to filter by or when local + server fetches both fail. Don't
    // crash the consumer — return undefined so iterators just skip the slot.
    const resource = this.pages.get(page);
    if (!resource) return undefined;

    const members = filterIndexLeakage(
      resource.getSubjects(collections.properties.members),
    );

    return members[index % this.pageSize];
  }

  public clearPages(): void {
    this.pages = new Map();
    this.legacyMembers = undefined;
    this._memberIndex.clear();
    this._queriedMembers.clear();
    // Note: `_optimisticAdds` is preserved on `clearPages` — they
    // represent subjects we trust are members (locally-created and
    // confirmed at the resource layer); the next `setPage` merges
    // them into whatever the fetch returned.
  }

  /** Write `members` + `totalMembers` propvals onto a page Resource. */
  private writePageMembers(
    page: Resource<Collections.Collection>,
    members: string[],
    total: number,
  ): void {
    page.applyHydratedValues([
      [collections.properties.members, members],
      [collections.properties.totalMembers, total],
    ]);
  }

  /** Stamp an empty page so callers see `pages.has(page) === true`
   * + `totalMembers === 0` as the authoritative "no children" state. */
  private setEmptyPage(page: number): void {
    const empty = new Resource<Collections.Collection>(this.buildSubject(page));
    this.writePageMembers(empty, [], 0);
    this.setPage(page, empty);
    this._totalMembers = 0;
  }

  /**
   * Single point that mutates `pages` so the member-subject index stays
   * in sync. Replaces any existing mapping for the same page index.
   *
   * Preserves `_optimisticAdds` subjects across the swap. A background
   * fetch (server `/query` or OPFS) can race a just-completed
   * optimistic add: if the server's `parent=` index hasn't caught up
   * with the just-pushed commit, it returns a member list that
   * doesn't include the new resource. Without this merge,
   * `setPage(0, server_empty)` clobbers the optimistic state and the
   * UI loses the resource. With it, the resource sticks until the
   * next iteration sees it server-side (or the user reloads).
   */
  private setPage(
    pageIdx: number,
    resource: Resource<Collections.Collection>,
  ): void {
    const incomingMembers = resource.getSubjects(
      collections.properties.members,
    );
    const retained = incomingMembers.filter(s => !this.isDestroyed(s));

    if (retained.length !== incomingMembers.length) {
      const total = resource.get(collections.properties.totalMembers);
      this.writePageMembers(
        resource,
        retained,
        Math.max(
          0,
          (typeof total === 'number' ? total : incomingMembers.length) -
            (incomingMembers.length - retained.length),
        ),
      );
    }

    // Drop the old page's members from the index first, then re-add the
    // new page's. Members can move between pages on `refresh`, so we
    // can't just additively merge.
    const existing = this.pages.get(pageIdx);

    if (existing) {
      for (const s of existing.getSubjects(collections.properties.members)) {
        if (this._memberIndex.get(s) === pageIdx) {
          this._memberIndex.delete(s);
        }
      }
    }

    if (this._optimisticAdds.size > 0 && pageIdx === 0) {
      const incoming = resource.getSubjects(collections.properties.members);
      const incomingSet = new Set(incoming);
      const toAppend: string[] = [];

      for (const s of this._optimisticAdds) {
        if (!incomingSet.has(s)) toAppend.push(s);
      }

      if (toAppend.length > 0) {
        const merged = [...incoming, ...toAppend];
        const totalProp = resource.get(collections.properties.totalMembers);
        const baseTotal =
          typeof totalProp === 'number' ? totalProp : incoming.length;
        const newTotal = baseTotal + toAppend.length;
        this.writePageMembers(resource, merged, newTotal);
        // The merged total is the source of truth — caller (fetch
        // paths) will write `this._totalMembers = resource.props.totalMembers`
        // after setPage; ensure they read the post-merge value.
      }
    }

    this.pages.set(pageIdx, resource);

    for (const s of resource.getSubjects(collections.properties.members)) {
      this._memberIndex.set(s, pageIdx);
    }
  }

  /** Tracks an in-flight `refresh()` so concurrent callers reuse the same
   * promise instead of each kicking their own query. */
  private _refreshInFlight: Promise<void> | undefined;

  /** Set when `applyResourceChange` sees a new matching subject while a
   * refresh is already in flight. The active loop checks this after
   * `fetchPage` resolves and re-fetches if true — so the returned promise
   * resolves only AFTER the final state lands. Without this, a fast burst
   * of new matching resources (e.g. rapid row entry into a sorted table)
   * loses late arrivals: the in-flight `queryLocalDb` was queued before
   * they hit OPFS, no follow-up runs, and the cache stays stale until the
   * user reloads. */
  private _refreshPending = false;

  public async refresh(): Promise<void> {
    if (this._refreshInFlight) {
      this._refreshPending = true;

      return this._refreshInFlight;
    }

    this._refreshInFlight = (async () => {
      while (true) {
        this._refreshPending = false;
        this.clearPages();
        this._waitForReady = this.fetchPage(0);
        await this._waitForReady;
        if (!this._refreshPending) break;
      }
    })().finally(() => {
      this._refreshInFlight = undefined;
    });

    return this._refreshInFlight;
  }

  /**
   * Decide whether a single-resource change is relevant to this collection's
   * filter. Returns one of:
   *   - `'unchanged'` — not a member, not affected, do nothing
   *   - `'member-removed'` — resource was a member and isn't anymore; we
   *     surgically strip it from the cached page (cheap, no network)
   *   - `'member-added'` — resource is new and matches the filter; we
   *     surgically append it to the last loaded page. The server already
   *     confirmed the resource exists (we got the actual resource object
   *     here, delivered as a drive-wide `UPDATE` push). Trusting that
   *     authority avoids the race where the server's `/query` index hasn't
   *     yet caught up with the just-applied commit — refresh would return
   *     stale state and the new row would never appear in the UI without
   *     a page reload.
   *   - `'membership-stale'` — a *possible* new member surfaced (e.g.
   *     locally-applied resource not yet pushed). The caller should
   *     `refresh()` so the server-authoritative count and ordering land.
   *     Used when we don't have a confirmed `resource` object.
   *
   * The storm reduction this is designed for is still real: only collections
   * whose filter matches the change ever invalidate. Unrelated collections
   * (sidebar children of *other* folders, ontology lists, etc.) ignore.
   *
   * Pass `resource: undefined` to signal a removal.
   */
  public applyResourceChange(
    subject: string,
    resource: Resource | undefined,
  ): 'unchanged' | 'member-removed' | 'member-added' | 'membership-stale' {
    const fp = this.params.property;
    const fv = this.params.value;

    // No filter, nothing to evaluate. Same short-circuit as `fetchPage`.
    if (!fp || !fv) return 'unchanged';

    // Commit subjects leak into `parent=` indexes on both server and client.
    // `filterIndexLeakage` strips them at iteration; mirror that here so we
    // don't even consider treating one as a member.
    if (isCommitSubject(subject)) return 'unchanged';

    // `_new:` is the placeholder subject the store assigns before async
    // signing renames the resource to its real DID. The placeholder is UI
    // scaffold (e.g. `TableNewRow` pre-populates parent so the empty editor
    // row renders) and must not affect membership.
    if (subject.startsWith('_new:')) return 'unchanged';

    // `r.get(fp)` is a string for single-valued properties (e.g. `parent`)
    // and an array for multi-valued ones (e.g. `isA`). Match like
    // server-side `/query` does ("value-in-property").
    const matches =
      !!resource &&
      // A destroyed subject is never a member, whatever state arrives for it.
      // Answers and pushes that were produced before the destroy landed keep
      // carrying its full body, and each one used to read as a member that
      // matches the filter.
      !this.isDestroyed(subject) &&
      constraintMatches(resource, fp, fv) &&
      // Every extra AND constraint must also hold (multi-property filtering).
      (this.params.filters ?? []).every(
        f =>
          f.property === undefined ||
          f.value === undefined ||
          constraintMatches(resource, f.property, f.value, f.operator ?? 'eq'),
      );

    if (!resource) {
      // The store recorded the tombstone before it notified, so there is
      // nothing to remember here — only the optimistic add to retract.
      this._optimisticAdds.delete(subject);
    }

    // O(1) lookup via the maintained subject→page index instead of
    // scanning every loaded page on every incoming event. The within-
    // page `indexOf` for the remove path stays — that's the array
    // splice position, which we don't track separately.
    const foundInPage = this._memberIndex.get(subject);
    const currentlyMember = foundInPage !== undefined;

    // Computed constraints are evaluated by the query engine. Matching the
    // stored parent/class alone must not admit a row that the computed filter
    // excluded (especially while cold-load notifications arrive after a query).
    if (
      this.params.expression_filters?.length &&
      (matches || currentlyMember)
    ) {
      if (this._assemblingPage || resource?.new) return 'unchanged';

      return 'membership-stale';
    }

    // Fast path for the overwhelming majority of events: a resource we
    // don't track had a property change that doesn't make it a member.
    // Bail before the more expensive add/remove logic below.
    if (!matches && !currentlyMember) {
      return this._queriedMembers.has(subject)
        ? 'membership-stale'
        : 'unchanged';
    }

    if (matches && !currentlyMember) {
      // A later page being hydrated (possibly by another collection) is not
      // a new member. The count already includes the complete query result.
      if (this._queriedMembers.has(subject)) return 'unchanged';
      // Local-only drafts (`newResource()` created a genesis but no commit
      // has been signed-and-applied yet) shouldn't count as members.
      // `resource.new === true` until `signChanges` runs. Each
      // `TableNewRow` mounts and creates a draft with `parent` set;
      // without this filter every placeholder would be admitted as a
      // phantom row, and reloading an empty table would show 20+ ghost
      // rows. Once the resource is signed (and eventually pushed), it
      // fires another `ResourceUpdated` with `new=false` and lands here.
      if (resource.new) return 'unchanged';

      // Hydrating a local-DB page notifies `ResourceUpdated` for every
      // member before `setPage` writes the sorted list. Optimistic-adding
      // those in arrival order is the table/sidebar flash on open. The
      // in-flight fetch is about to land the ordered page; skip the add.
      // Keep this *off* during `queryLocalDb()` itself so a resource the
      // user creates while the query is in flight still appears.
      if (this._assemblingPage) return 'unchanged';

      // No page loaded yet — either the constructor's initial
      // `fetchPage(0)` hasn't completed, or `refresh()`'s active loop
      // just called `clearPages()` and is mid-fetch. Bootstrap a
      // page 0 with this resource so consumers see it immediately.
      //
      // Don't set `_refreshPending`: the refresh loop would call
      // `clearPages` and re-fetch, and under load the server's
      // `/query` index can lag the just-pushed commit by enough that
      // it returns an EMPTY page — which would clobber our optimistic
      // add and the resource would vanish from the UI even though
      // it's in the store. Trust the local data; the next user-
      // initiated refresh (page reload, sort change) will reconcile
      // against the server.
      if (!this.pages.has(0)) {
        this._optimisticAdds.add(subject);
        const page = new Resource<Collections.Collection>(this.buildSubject(0));
        this.writePageMembers(page, [subject], 1);
        this.setPage(0, page);
        this._totalMembers = 1;

        return 'member-added';
      }

      // Append to the last loaded page directly. This handles both
      // unsorted collections and the `createdAt`-sorted default (where
      // append IS correct order). Other sort keys (e.g. `name`) may
      // place the row at the wrong position until the next page reload
      // re-queries `fetchPageFromLocalDb` via the OPFS index.
      //
      // Why not refresh-via-OPFS for sorted collections? In principle
      // `Collection.refresh()` → `fetchPageFromLocalDb()` would
      // re-sort correctly, and OPFS already has the resource (its put
      // was queued in `addResource` before this event fired). The
      // chain mechanism in `refresh()` (`_refreshPending` loop) handles
      // bursts. In practice the loop didn't recover all rows during
      // fast-burst tests — debugging deferred. For now: trust direct
      // append for the common case; full re-sort on user reload.
      const lastPageIdx = Math.max(...this.pages.keys());
      const lastPage = this.pages.get(lastPageIdx)!;
      const members = lastPage.getSubjects(collections.properties.members);
      if (members.includes(subject)) return 'unchanged'; // paranoia
      this._optimisticAdds.add(subject);
      this._totalMembers += 1;
      this._memberIndex.set(subject, lastPageIdx);
      this.writePageMembers(
        lastPage,
        this.withMemberInSortedPosition(
          members,
          subject,
          this.pages.size === 1,
        ),
        this._totalMembers,
      );

      return 'member-added';
    }

    if (!matches && currentlyMember) {
      // Resource no longer matches (deleted, or its `parent` changed). Strip
      // from the cached page in place — cheap, no fetch, and the count is
      // straightforwardly N-1 since we know the subject was a member.
      const page = this.pages.get(foundInPage!)!;
      const members = page.getSubjects(collections.properties.members);
      const idx = members.indexOf(subject);

      if (idx === -1) {
        // Index drift — the subject was indexed but not present on the
        // page. Drop the stale index entry and treat as no-op rather
        // than corrupt state further.
        this._memberIndex.delete(subject);

        return 'unchanged';
      }

      const next = [...members];
      next.splice(idx, 1);
      this._totalMembers = Math.max(0, this._totalMembers - 1);
      this._memberIndex.delete(subject);
      this._optimisticAdds.delete(subject);
      this.writePageMembers(page, next, this._totalMembers);

      return 'member-removed';
    }

    return 'unchanged';
  }

  public clone() {
    const collection = new Collection(this.store, this.server, this.params);
    collection._totalMembers = this._totalMembers;
    collection._waitForReady = this._waitForReady;
    collection.pages = this.pages;
    // Share the index too — both clones look at the same `pages` Map,
    // so they should observe the same membership.
    collection._memberIndex = this._memberIndex;
    collection._queriedMembers = this._queriedMembers;

    return collection;
  }

  public async *[Symbol.asyncIterator]() {
    await this.waitForReady();

    for (let i = 0; i < this.totalMembers; i++) {
      const member = await this.getMemberWithIndex(i);

      if (member === undefined) {
        continue;
      }

      yield member;
    }
  }

  public async getAllMembers(): Promise<string[]> {
    const members: string[] = [];

    for await (const member of this) {
      members.push(member);
    }

    return members;
  }

  public async getMembersOnPage(page: number): Promise<string[]> {
    if (!this.pages.has(page)) {
      await this.fetchPage(page);
    }

    const resource = this.pages.get(page);

    if (!resource) {
      return [];
    }

    return filterIndexLeakage(
      (resource.props.members ?? []).filter(m => m !== undefined),
    );
  }

  private buildSubject(page: number): string {
    const url = new URL(`${this.server}/query`);

    for (const [key, value] of Object.entries(this.params)) {
      // `filters` and `aggregation` are structured — serialised as JSON
      // below, not via the scalar `set()` (which would stringify to
      // "[object Object]").
      if (
        key === 'filters' ||
        key === 'aggregation' ||
        key === 'expression_filters'
      ) {
        continue;
      }

      if (value !== undefined) {
        url.searchParams.set(key, value);
      }
    }

    // AND constraints beyond the primary property/value, as a JSON array the
    // server parses in `construct_collection_from_params`.
    if (this.params.filters && this.params.filters.length > 0) {
      url.searchParams.set('filters', JSON.stringify(this.params.filters));
    }

    // Statistics over the whole matching set, computed by the store.
    if (this.params.aggregation?.aggregates.length) {
      url.searchParams.set(
        'aggregation',
        JSON.stringify(this.params.aggregation),
      );
    }

    // Constraints the index can't answer, evaluated by the store per row.
    if (this.params.expression_filters?.length) {
      url.searchParams.set(
        'expression_filters',
        JSON.stringify(this.params.expression_filters),
      );
    }

    url.searchParams.set('current_page', `${page}`);

    return url.toString();
  }

  private async fetchPage(page: number): Promise<void> {
    // No-op when there's nothing to filter by. Without this, callers who
    // pass an undefined `value` (e.g. `useChildren(undefined)` for tables
    // and chatrooms that render children in their own UI) would fall
    // through to a server fetch that returns *every* resource with the
    // given property — wasted bandwidth and a real source of WS-storm
    // refetches triggered by drive-wide UPDATE pushes.
    if (!this.params.property || !this.params.value) {
      return;
    }

    // A foreign HTTP authority has not replicated its complete index into
    // this client's OPFS. Neither an empty nor a partially cached local set
    // answers its query, and its HTTP availability is independent of our
    // home server's WebSocket handshake.
    if (
      new URL(this.server).origin !== new URL(this.store.getServerUrl()).origin
    ) {
      await this.fetchPageFromServer(page);

      return;
    }

    // A list that grows large is cheaper for the server to sort and page than
    // for this client to build every member of. Wait briefly for the
    // connection; without one the local database answers as usual.
    if (
      this.preferServer &&
      (this.store.serverConnected ||
        (await this.store.waitForServerConnected(3000)))
    ) {
      try {
        await this.fetchPageFromServer(page);

        return;
      } catch {
        // Fall through to the local database.
      }
    }

    // The worker may still be attaching after agent-key initialization.
    // An expected database is different from an app that opted out of OPFS;
    // share the resource loader's bounded attachment wait before going remote.
    const hasClientDb = await this.store.waitForClientDb();

    // OPFS-first: try the local WASM DB before reaching for the
    // network. After the initial drive-sync, the WASM DB is the
    // source of truth for `parent=` queries — an authoritative empty
    // result lands as `'ok'`. We only fall through to a server
    // `/query` when OPFS is absent, not ready, or doesn't have the
    // data yet (returns `'no-db'`).
    //
    // History: an earlier revision raced server vs OPFS to win the
    // race on cold loads. That was paid for by every populated drive
    // firing a redundant `/query` for every `useChildren` /
    // `useCollection` mount on every page load — visible in the
    // user's WS log as 30+ duplicate frames after refresh. Reversed
    // here. The cold-load case pays at most one extra OPFS wait
    // before the server fetch fires.
    if (hasClientDb && (await this.fetchPageFromLocalDb(page)) === 'ok') {
      // Only a drive synced into this client has its whole membership here.
      // Anything else holds what this client happened to fetch or create: a
      // guest in a chatroom shared from someone else's drive had their own
      // messages and the ones present when they joined, and trusting that
      // hid every later message from the host, on every reload. Asked once
      // per page per session, not on every mount.
      if (
        this.store.serverConnected &&
        !this.store.hasCompletedDriveSyncFor(
          this.params.drive ?? this.store.getDrive(),
        ) &&
        !Collection.completedByServer
          .get(this.store)
          ?.has(this.buildSubject(page))
      ) {
        await this.completeFromServer(page);
      }

      return;
    }

    // Local-only parents (e.g. the demo drive's folders/tables) have no
    // server-side members by definition — a `/query` can only return
    // empty while leaking local subjects. The local DB result above is
    // authoritative; when it couldn't answer, empty is the truth.
    if (
      typeof this.params.value === 'string' &&
      this.store.isLocalOnlySubject(this.params.value)
    ) {
      this.setEmptyPage(page);

      return;
    }

    if (this.store.serverConnected) {
      await this.fetchPageFromServer(page).catch(() => undefined);

      return;
    }

    // The local DB couldn't answer and the socket isn't up yet — the cold-load
    // window. This wait used to be reserved for stores with no OPFS at all,
    // which left the far more common case (OPFS present, index not populated
    // for this parent) falling off the end of this method: no fetch, no retry,
    // and `_waitForReady` resolving anyway, so the UI rendered "no members"
    // with neither a loader nor an error and nothing ever asked again. A
    // signed-in session loses this race by design — `serverConnected` only
    // flips after AUTH_OK — which is why the sidebar came up empty when signed
    // in and full when signed out. Being offline for real costs one bounded
    // wait, and the page still ends up empty, which is the truth then.
    await this.store.waitForServerConnected(3000);

    if (this.store.serverConnected) {
      await this.fetchPageFromServer(page).catch(() => undefined);
    }
  }

  /**
   * A member's sort key, read from the store. `sortOrder` (fractional
   * sibling-order key) falls back to the creation time, mirroring the server's
   * query index, so explicitly positioned resources interleave with untouched
   * ones. Client resources usually lack a materialized `createdAt` propval, so
   * the genesis Loro change is read directly.
   */
  private sortKeyOf(subject: string, sortBy: string): unknown {
    const isSortOrder = sortBy === dataBrowser.properties.sortOrder;
    const isCreatedAt = sortBy === commits.properties.createdAt;
    const resource = this.store.resources.get(subject);
    let key = resource?.get(sortBy);

    if (typeof key === 'number' && (isSortOrder || isCreatedAt)) {
      key = isCreatedAt ? normalizeLoroChangeTimestampMs(key) : key;
    } else if (key === undefined && resource && (isSortOrder || isCreatedAt)) {
      key = resource.getCreatedAt();
    }

    return key;
  }

  /**
   * `members` with `subject` added: in its sorted place when the collection is
   * sorted on a key the store can read and the page holds the whole list,
   * else at the end. A local database that has only some of the members at
   * load (the rest arrive a moment later) would otherwise list them in the
   * order they arrive, so a row that belongs between two others ends up first.
   */
  private withMemberInSortedPosition(
    members: string[],
    subject: string,
    wholeList: boolean,
  ): string[] {
    const sortBy = this.params.sort_by;

    if (!sortBy || !wholeList) return [...members, subject];

    const sortDesc = !!this.params.sort_desc;
    const key = this.sortKeyOf(subject, sortBy);

    // A member the store does not hold yet has no key to compare against.
    if (key === undefined) return [...members, subject];

    // Walk back from the end only as far as the new member sorts before the
    // one it is compared with. A late arrival usually belongs at the end, so
    // this reads one key, not the whole list: reading every key per added
    // member made loading a large collection quadratic.
    let at = members.length;

    while (at > 0) {
      const prev = this.sortKeyOf(members[at - 1]!, sortBy);

      if (prev === undefined) return [...members, subject];

      if (
        compareSortKeys(prev, key, members[at - 1]!, subject, sortDesc) <= 0
      ) {
        break;
      }

      at -= 1;
    }

    return [...members.slice(0, at), subject, ...members.slice(at)];
  }

  /**
   * Replace a page the local DB answered with the server's, keeping any member
   * only the local DB knows: a write the server hasn't acknowledged yet must
   * not vanish because the server answered first. When the server can't be
   * reached, the local page stands.
   */
  private async completeFromServer(page: number): Promise<void> {
    const local = this.pages.get(page)?.props.members ?? [];

    try {
      await this.fetchPageFromServer(page);
    } catch {
      return;
    }

    const answered =
      Collection.completedByServer.get(this.store) ?? new Set<string>();
    answered.add(this.buildSubject(page));
    Collection.completedByServer.set(this.store, answered);

    const fetched = this.pages.get(page);

    if (!fetched) return;

    const members = fetched.props.members ?? [];
    const localOnly = local.filter(s => !members.includes(s));

    if (localOnly.length === 0) return;

    const total = (this._totalMembers ?? members.length) + localOnly.length;
    this.writePageMembers(fetched, [...members, ...localOnly], total);
    this.setPage(page, fetched);
    this._totalMembers = total;
  }

  /**
   * Resolve a page from the local WASM DB. Returns:
   *   - `'ok'` — query ran and the page is populated (possibly with zero
   *     members, which is a legitimate empty result for this filter).
   *   - `'no-db'` — local DB can't answer (no clientDb, query failed, or an
   *     indexed query with no drive scope to run it under). Caller may fall
   *     back to a server `/query`.
   *
   * After the first drive-sync the WASM index is the source of truth for
   * `parent=…` queries; an empty result means "this parent really has no
   * children", not "I haven't loaded yet". Falling back to a server
   * `/query` in that case just produces redundant traffic — sync already
   * delivered everything the server has.
   */
  private async fetchPageFromLocalDb(page: number): Promise<'ok' | 'no-db'> {
    // Both property and value are required for a meaningful local query.
    if (!this.params.property || !this.params.value) {
      return 'no-db';
    }

    // Wait for WASM DB to be ready (important on initial page load), but only
    // for so long: see {@link LOCAL_DB_READY_GRACE_MS}. Running out is not an
    // error, it just means this query is answered by the server, which the
    // `'no-db'` below already arranges.
    const clientDb = this.store.getClientDb();

    if (clientDb && !clientDb.isReady) {
      let ranOut: ReturnType<typeof setTimeout> | undefined;

      try {
        await Promise.race([
          clientDb.waitForReady(),
          new Promise<void>(resolve => {
            ranOut = setTimeout(resolve, LOCAL_DB_READY_GRACE_MS);
          }),
        ]);
      } finally {
        clearTimeout(ranOut);
      }

      // Running out of patience only helps because the server can answer
      // instead. With no server to ask, this database is the only source this
      // query has, so it is worth every second it takes — an offline page that
      // asked nobody would render as if the drive were empty.
      if (!clientDb.isReady && !this.store.serverConnected) {
        await clientDb.waitForReady();
      }
    }

    if (!clientDb || !clientDb.isReady) {
      return 'no-db';
    }

    // Query without sort — sorted queries with DID drives don't work in the
    // WASM DB yet (drive-scoped index keys don't match DID subjects).
    // We fetch all matching subjects with their JSON-AD payloads, hydrate
    // them into the store, and sort client-side. Hydrating up front matters:
    // immediately after a page reload `store.resources` is empty, so without
    // it the sort key lookup returns `undefined` for every member and the
    // sort silently degrades to the index's natural order.
    const hasExtraFilters =
      !!this.params.filters && this.params.filters.length > 0;

    // Resolve the drive scope at query time, not at construction time.
    // `CollectionBuilder` snapshots `store.getDrive()` in its constructor, and
    // a Collection built during cold start — before `setDrive` ran, or while
    // an async drive adoption (deep link) is still resolving — would keep
    // `drive: undefined` for the rest of its life even once the drive is
    // known. Falling back to the store's current drive here is the same value
    // the builder would have captured a moment later.
    const drive = this.params.drive ?? this.store.getDrive();

    // Extra AND constraints route through the indexed path
    // (`query_complex`), which REQUIRES a drive scope: the query index is
    // keyed by drive. Without one the worker can only answer with
    // "Indexed queries require a drive scope", so don't ask — fall back to
    // the server `/query` instead of burning a worker round-trip on a
    // guaranteed error.
    if (hasExtraFilters && !drive) {
      return 'no-db';
    }

    // While a drive sync is still pulling data, the local database may hold
    // only part of the members (a chat of thousands of messages, say). The
    // server has them all, so let it answer instead of a partial list, and do
    // not queue a query behind the sync's writes first.
    if (
      this.store.serverConnected &&
      this.store.isDriveSyncPulling() &&
      !this.store.hasCompletedDriveSyncFor(drive)
    ) {
      return 'no-db';
    }

    const query = this.store.queryLocalDb({
      property: this.params.property,
      value: this.params.value,
      filters: this.params.filters,
      // Single property/value queries use the basic path and intentionally
      // omit `drive` (see the sort note above). We still don't pass
      // `sort_by`, so the indexed query stays drive-scoped without the
      // DID-sort issue.
      drive: hasExtraFilters ? drive : undefined,
      includeResources: true,
      // Aggregated in WASM over the whole matching set, exactly as the server
      // would — the local DB is not a lesser source here.
      expressionFilters: this.params.expression_filters?.length
        ? this.params.expression_filters
        : undefined,
      aggregation: this.params.aggregation?.aggregates.length
        ? this.params.aggregation
        : undefined,
    });

    // With a server to ask, a local query that has not answered by the read
    // deadline (a worker busy with a drive sync's writes) is no answer. A
    // local-only parent has no server to ask, so it waits as long as it takes.
    const result =
      this.store.serverConnected &&
      !(
        typeof this.params.value === 'string' &&
        this.store.isLocalOnlySubject(this.params.value)
      )
        ? await withDeadline(query, this.store.localReadDeadlineMs(), null)
        : await query;

    // Worker returned no result (query error / DB not available). Don't
    // overwrite the page — `fetchPage` races us against `/query`, and a
    // late `setEmptyPage` here can clobber a server result that already
    // landed. Just signal "no-db" so callers fall back.
    if (!result) {
      return 'no-db';
    }

    // The sync may have started pulling while the query ran.
    if (
      this.store.serverConnected &&
      this.store.isDriveSyncPulling() &&
      !this.store.hasCompletedDriveSyncFor(drive)
    ) {
      return 'no-db';
    }

    // Hydrate + sort + setPage must not optimistic-add via ResourceUpdated.
    // Set the flag only around this slice — not the `queryLocalDb` wait
    // above — so a locally created member during the query still lands.
    this._assemblingPage = true;

    try {
      return this.finishLocalDbPage(page, result, drive);
    } finally {
      this._assemblingPage = false;
    }
  }

  /** Hydrate query payloads, sort, and write the page. Caller holds
   *  `_assemblingPage`. */
  private finishLocalDbPage(
    page: number,
    result: {
      subjects: string[];
      resources?: string[];
      count: number;
      aggregates?: AggregateOutcome[];
    },
    drive: string | undefined,
  ): 'ok' | 'no-db' {
    if (result.count === 0) {
      this._queriedMembers.clear();

      // Empty local result is normally authoritative — but it's ambiguous
      // until THIS drive has been synced (the index may be mid-populate, or
      // never populated at all). Once its sync has completed we trust the
      // empty: a freshly-created table or folder just has no children.
      // Otherwise fall back to `/query`.
      //
      // Per-drive on purpose. Asking whether *any* sync had finished meant a
      // synced personal drive vouched for every other drive too, so browsing
      // a drive that was never synced locally showed nothing at all.
      if (this.store.hasCompletedDriveSyncFor(drive)) {
        // `fetchPage` races us against `/query`. If the server already
        // populated the page with non-empty data, leave it — server is
        // authoritative for the instant of the query.
        if (!this.pages.has(page)) {
          this.setEmptyPage(page);
        }

        // An empty matching set still has statistics (count = 0, sum = null).
        // Dropping them left dashboard/table totals as an em-dash: the UI
        // treated "no outcomes" as "not yet computed" and nothing re-asked,
        // because the resources were already in the JS store.
        this._aggregates = result.aggregates ?? [];

        return 'ok';
      }

      return 'no-db';
    }

    // Destroyed subjects are dropped from the page below, so they must not
    // count as "the query accounted for this one" either — that is what the
    // add path reads to decide a matching subject is not new. Leaving them in
    // would keep a subject unaddable after its tombstone is lifted.
    this._queriedMembers = new Set(
      filterIndexLeakage(result.subjects).filter(s => !this.isDestroyed(s)),
    );

    // Notifications may have arrived while the local query was pending.
    // Its full result already accounts for them, even outside page zero.
    for (const subject of this._queriedMembers) {
      this._optimisticAdds.delete(subject);
    }

    // A big collection is sorted from the sort key read out of each member's
    // JSON, and only the members on the requested page are built into
    // resources. Building all of them (a chat of thousands of messages) took
    // tens of seconds to show the first fifty.
    let jsonBySubject: Map<string, string> | undefined;
    let jsonSortKeys: Map<string, unknown> | undefined;

    if (
      result.resources &&
      result.resources.length === result.subjects.length &&
      result.subjects.length > LAZY_HYDRATE_THRESHOLD &&
      this.params.sort_by
    ) {
      jsonBySubject = new Map(
        result.subjects.map((subject, i) => [subject, result.resources![i]!]),
      );
      jsonSortKeys = sortKeysFromJsonAd(this.params.sort_by, jsonBySubject);

      if (!jsonSortKeys) jsonBySubject = undefined;
    }

    if (
      !jsonBySubject &&
      result.resources &&
      result.resources.length === result.subjects.length
    ) {
      for (let i = 0; i < result.subjects.length; i++) {
        if (this.isDestroyed(result.subjects[i]!)) continue;
        this.store.hydrateResourceFromJsonAd(
          result.subjects[i]!,
          result.resources[i]!,
        );
      }
    }

    // Strip commit subjects from BOTH the subjects array AND the count.
    // Filtering only at iteration time (`getMemberWithIndex`) leaves the
    // inflated count in `collection.totalMembers`, so consumers like
    // `TableResource` and react-window render an empty `TableRow` slot
    // for the missing index that gets stuck on a loading shimmer. Stripping
    // here keeps the count and the addressable members consistent.
    result.subjects = filterIndexLeakage(result.subjects).filter(
      subject => !this.isDestroyed(subject),
    );
    result.count = result.subjects.length;

    if (result.subjects.length === 0) {
      this.setEmptyPage(page);
      this._aggregates = result.aggregates ?? [];

      return 'ok';
    }

    // Client-side sorting — pre-fetch sort keys to avoid repeated Map lookups.
    const sortBy = this.params.sort_by;

    if (sortBy) {
      const sortDesc = !!this.params.sort_desc;
      const sortKeys = new Map<string, unknown>();
      // `sortOrder` (fractional sibling-order key) falls back to the creation
      // time — mirroring the server's query index — so explicitly positioned
      // resources interleave with untouched ones. Client resources usually
      // lack a materialized `createdAt` propval, so read the genesis Loro
      // change directly.

      for (const s of result.subjects) {
        if (jsonSortKeys) {
          sortKeys.set(s, jsonSortKeys.get(s));
          continue;
        }

        sortKeys.set(s, this.sortKeyOf(s, sortBy));
      }

      // Ordered to match the server, because the same collection can be
      // answered by either and the two must not disagree. A row list that
      // reshuffles depending on which side answered reads as data changing
      // under you.
      //
      //   - Missing values FIRST. The server encodes them as `TAG_NONE`
      //     (0x05), below every value tag, so they lead an ascending sort.
      //     This used to return 1 and push them last.
      //   - Ties broken by subject. The server's member key is
      //     `id || sort_key || subject`, so equal sort keys come back in
      //     subject order. Returning 0 here left them in whatever order the
      //     local index happened to yield — stable, but stable at a
      //     different order than the server's, which is exactly the case
      //     where every row shares a value (an unfilled column).
      result.subjects.sort((a, b) =>
        compareSortKeys(sortKeys.get(a), sortKeys.get(b), a, b, sortDesc),
      );
    }

    // Client-side pagination
    const pageSize = parseInt(this.params.page_size, 10);
    const offset = page * pageSize;
    const pageSubjects = result.subjects.slice(offset, offset + pageSize);

    if (jsonBySubject) {
      for (const subject of pageSubjects) {
        const json = jsonBySubject.get(subject);

        if (json) this.store.hydrateResourceFromJsonAd(subject, json);
      }
    }

    // Build a synthetic collection resource from the query result
    const resource = new Resource<Collections.Collection>(
      this.buildSubject(page),
    );
    this.writePageMembers(resource, pageSubjects, result.count);
    this.setPage(page, resource);
    // `setPage` may have merged optimistic adds (resources created locally
    // but not yet in the local-DB query result) into the page. Use the
    // post-merge total it wrote — `result.count` is the pre-merge count, and
    // setting it here would make consumers that iterate `0..totalMembers`
    // skip the just-added resource. `fetchPageFromServer` already does this.
    const mergedTotal = resource.props.totalMembers;
    this._totalMembers = isNumber(mergedTotal) ? mergedTotal : result.count;
    // Computed by the same Rust code the server runs, so an offline table shows
    // the same totals rather than none.
    this._aggregates = result.aggregates ?? [];

    return 'ok';
  }

  /** Old nodes have no drive or multi-filter query support. Fetch the base
   * match set, then apply scope, AND filters, sorting and pagination here. */
  private async fetchLegacyPage(page: number): Promise<void> {
    this.legacyMembers ??= this.loadLegacyMembers();
    const subjects = [...(await this.legacyMembers)];

    if (subjects.length === 0) {
      this.setEmptyPage(page);

      return;
    }

    this.finishLocalDbPage(
      page,
      { subjects, count: subjects.length },
      this.params.drive,
    );
  }

  private async loadLegacyMembers(): Promise<string[]> {
    if (this.params.aggregation || this.params.expression_filters?.length) {
      throw new Error(
        'This legacy server does not support query expressions or aggregation',
      );
    }

    const raw = new Collection(
      this.store,
      this.server,
      {
        ...this.params,
        drive: undefined,
        filters: undefined,
        sort_by: undefined,
        sort_desc: undefined,
        include_nested: true,
        page_size: '500',
      },
      true,
    );
    await raw.fetchPageFromServer(0);
    const candidates = await raw.getAllMembers();
    const subjects: string[] = [];
    const drive = this.params.drive;

    const inDrive = async (subject: string): Promise<boolean> => {
      const seen = new Set<string>();
      let current: string | undefined = subject;

      while (current) {
        if (current === drive) return true;
        if (seen.has(current)) return false;
        seen.add(current);
        const ancestor = await this.store.getResource(current);
        if (ancestor.error) throw ancestor.error;
        current = ancestor.get(core.properties.parent) as string | undefined;
      }

      return false;
    };

    for (const subject of candidates) {
      // A direct parent query is already scoped when the parent is the drive.
      if (
        drive &&
        !(
          this.params.property === core.properties.parent &&
          this.params.value === drive
        ) &&
        !(await inDrive(subject))
      )
        continue;
      const filters = this.params.filters ?? [];

      if (filters.length || this.params.sort_by) {
        const resource = await this.store.getResource(subject);
        if (resource.error) throw resource.error;
        if (
          !filters.every(filter => {
            const entries = filter.property
              ? ([[filter.property, resource.get(filter.property)]] as const)
              : Object.entries(resource.getPropVals());

            return entries.some(([property, value]) =>
              filter.value === undefined
                ? value !== undefined
                : constraintMatches(
                    resource,
                    property,
                    filter.value,
                    filter.operator,
                  ),
            );
          })
        )
          continue;
      }

      subjects.push(subject);
    }

    return subjects;
  }

  private async fetchPageFromServer(page: number): Promise<void> {
    if (
      this.legacyQuery ||
      (/^https?:\/\//.test(this.params.drive ?? '') &&
        Collection.legacyQueryServers.get(this.store)?.has(this.server))
    )
      return this.fetchLegacyPage(page);
    const subject = this.buildSubject(page);
    const resource =
      await this.store.fetchResourceFromServer<Collections.Collection>(subject);

    if (!resource) {
      throw new Error('Invalid collection: resource does not exist');
    }

    if (resource.error) {
      // Negotiate only on the explicit unsupported-parameter response.
      if (
        new URL(subject).searchParams.has('drive') &&
        /^https?:\/\//.test(this.params.drive ?? '') &&
        resource.error.message.endsWith('Invalid query param: drive')
      ) {
        this.legacyQuery = true;
        const servers =
          Collection.legacyQueryServers.get(this.store) ?? new Set<string>();
        servers.add(this.server);
        Collection.legacyQueryServers.set(this.store, servers);

        return this.fetchPageFromServer(page);
      }

      throw new Error(
        `Invalid collection: resource has error: ${resource.error}`,
      );
    }

    // The `/query` response is a Loro snapshot. If it arrived before Loro WASM
    // finished loading it was BUFFERED (not materialized), so `members` /
    // `totalMembers` read as undefined — the collection lands empty and the
    // `total-members is not a number` throw below is swallowed by the caller's
    // `.catch`, leaving the sidebar/table blank with no error. This is the same
    // GET-before-Loro-ready race that affected the drive resource. Ensure Loro
    // is loaded and force-materialize the doc before reading its props.
    await enableLoro();
    resource.getLoroDoc();

    // Same leak as `fetchPageFromLocalDb`: the server's atom-by-atom index
    // can register a Commit's `subject` (a `did:ad:commit:` URI) under the
    // committed-resource's parent, so a `parent=<table>` query comes back
    // with phantom commit-id members that point at nothing useful for
    // table-row rendering. Strip them and recount so the synthetic
    // collection page exposes the right `totalMembers`.
    const rawMembers = (resource.props.members ?? []).filter(
      (m): m is string => m !== undefined,
    );
    const filteredMembers = filterIndexLeakage(rawMembers);
    const answeredTotal = resource.props.totalMembers;

    if (!isNumber(answeredTotal)) {
      throw new Error('Invalid collection: total-members is not a number');
    }

    // The answer is the store's copy of the query resource, shared by every
    // collection that asks the same question. Members added live are written
    // into the page, so each collection keeps a page of its own, as the local
    // database path does. Sharing it made the second collection find the
    // member already listed, report no change, and never redraw.
    const own = new Resource<Collections.Collection>(this.buildSubject(page));
    this.writePageMembers(
      own,
      filteredMembers,
      filteredMembers.length !== rawMembers.length
        ? filteredMembers.length
        : answeredTotal,
    );
    this.setPage(page, own);

    const totalMembers = own.props.totalMembers;

    if (!isNumber(totalMembers)) {
      throw new Error('Invalid collection: total-members is not a number');
    }

    this._totalMembers = totalMembers;
    this._aggregates = readAggregates(resource);
  }
}

/** Reads the aggregates the server computed off a collection page. */
function readAggregates(resource: Resource): AggregateOutcome[] {
  const value = resource.get(collections.properties.aggregates);

  return Array.isArray(value) ? (value as unknown as AggregateOutcome[]) : [];
}

/**
 * Orders two members by their sort keys the way the server does, because the
 * same collection can be answered by either and the two must not disagree.
 * A row list that reshuffles depending on which side answered reads as data
 * changing under you.
 *
 *   - Missing values FIRST. The server encodes them as `TAG_NONE` (0x05),
 *     below every value tag, so they lead an ascending sort.
 *   - Ties broken by subject. The server's member key is
 *     `id || sort_key || subject`, so equal sort keys come back in subject
 *     order.
 */
function compareSortKeys(
  valA: unknown,
  valB: unknown,
  subjectA: string,
  subjectB: string,
  sortDesc: boolean,
): number {
  const aMissing = valA === null || valA === undefined;
  const bMissing = valB === null || valB === undefined;

  let cmp: number;

  if (aMissing && bMissing) {
    cmp = 0;
  } else if (aMissing) {
    cmp = -1;
  } else if (bMissing) {
    cmp = 1;
  } else {
    cmp =
      typeof valA === 'number' && typeof valB === 'number'
        ? valA - valB
        : String(valA).localeCompare(String(valB));
  }

  if (cmp === 0) {
    cmp = subjectA.localeCompare(subjectB);
  }

  return sortDesc ? -cmp : cmp;
}

/** Collections with more members than this are sorted from their JSON and only
 *  the requested page is built into resources. */
const LAZY_HYDRATE_THRESHOLD = 200;

/**
 * The sort key of each member, read from its JSON-AD without building a
 * resource. `undefined` when a key a resource would derive another way (the
 * creation time, from the genesis change) is not in the JSON, so the caller
 * builds the resources instead and gets the same order as before.
 */
/** Creation time (ms) of a JSON-AD member, as `Resource.getCreatedAt` reads it:
 *  the genesis certificate first, then the materialized `createdAt`. */
function createdAtFromJson(
  parsed: Record<string, unknown>,
): number | undefined {
  const encoded = parsed[GENESIS];

  if (typeof encoded === 'string' && encoded.length > 0) {
    try {
      const cert = decodeGenesisCert(decodeB64(encoded));

      if (cert.createdAt > 0) return cert.createdAt;
    } catch {
      // Fall through to the propval.
    }
  }

  const fromPropval = parsed[commits.properties.createdAt];

  return typeof fromPropval === 'number'
    ? normalizeLoroChangeTimestampMs(fromPropval)
    : undefined;
}

function sortKeysFromJsonAd(
  sortBy: string,
  jsonBySubject: Map<string, string>,
): Map<string, unknown> | undefined {
  const derived =
    sortBy === commits.properties.createdAt ||
    sortBy === dataBrowser.properties.sortOrder;
  const keys = new Map<string, unknown>();

  for (const [subject, json] of jsonBySubject) {
    let value: unknown;

    try {
      const parsed = JSON.parse(json) as Record<string, unknown>;

      value = parsed[sortBy];

      // Rows nobody has repositioned have no `sortOrder`: they sort by
      // creation time, which `Resource.getCreatedAt` reads from the genesis
      // certificate. Read it from the JSON too, or every page of such a table
      // (most of them) builds all its rows into resources just to sort.
      if (value === undefined && derived) {
        value = createdAtFromJson(parsed);
      }
    } catch {
      return undefined;
    }

    if (value === undefined && derived) return undefined;

    keys.set(
      subject,
      typeof value === 'number' && sortBy === commits.properties.createdAt
        ? normalizeLoroChangeTimestampMs(value)
        : value,
    );
  }

  return keys;
}

export function proxyCollection(collection: Collection): Collection {
  if (collection.__internalObject !== collection) {
    console.warn('Attempted to proxy a proxy for a collection');
  }

  return new Proxy(collection.__internalObject, {});
}
