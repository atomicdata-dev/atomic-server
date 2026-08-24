import {
  commits,
  core,
  dataBrowser,
  JSONValue,
  Resource,
  unknownSubject,
  useArray,
  useBoolean,
  useCanWrite,
  useResource,
  useStore,
  useString,
  useValue,
} from '@tomic/react';
import {
  useCallback,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
} from 'react';
import { ShowRoute } from '../../routes/ShowRoute';
import {
  filterKey,
  parseFilterKey,
  type FilterOperator,
  type TableFilter,
} from './tableFiltering';
import {
  parseDerivedColumnSpecs,
  type DerivedColumnSpec,
} from './derivedColumns';
import { parseColumnOrder } from './columnOrder';
import {
  parseAggregates,
  type GroupGranularity,
  type TableAggregate,
} from './tableAggregates';
import { parseRowActions, type RowActionSpec } from './rowActions';
import { parseQuickAdd, type QuickAddSpec } from './quickAdd';
import { TableSorting, DEFAULT_SORT_PROP } from './tableSorting';
import {
  ViewKind,
  DEFAULT_VIEW_KIND,
  appViewOf,
  normalizeViewKind,
  VIEW_KIND_LABELS,
} from './tableViewKinds';

const DEFAULT_SORT: TableSorting = { prop: DEFAULT_SORT_PROP, sortDesc: false };

type SortAction =
  | { type: 'cycle'; property: string }
  | { type: 'hydrate'; prop: string; sortDesc: boolean };

/** Same 3-click cycle as the old `useTableSorting`, plus a hydrate action. */
function sortReducer(state: TableSorting, action: SortAction): TableSorting {
  if (action.type === 'hydrate') {
    return { prop: action.prop, sortDesc: action.sortDesc };
  }

  if (state.prop === action.property && state.sortDesc) {
    return DEFAULT_SORT;
  }

  if (state.prop === action.property) {
    return { ...state, sortDesc: true };
  }

  return { prop: action.property, sortDesc: false };
}

export interface UseTableViewResult {
  filters: TableFilter[];
  /** Adds an empty filter for a target (`filterKey`: a property subject, or
   *  `derived:<id>` for a computed column). No-op if one already exists. */
  addFilter: (key: string) => void;
  setFilterValue: (key: string, value: string) => void;
  setFilterOperator: (key: string, operator: FilterOperator) => void;
  removeFilter: (key: string) => void;
  clearFilters: () => void;
  sorting: TableSorting;
  setSortBy: (property: string) => void;
  /** The active View resource (or an unknown resource until one exists). */
  view: Resource;
  /** Configured column order (visible property subjects); empty = class default. */
  viewColumns: string[];
  /** Persist the column order/visibility to the active View (lazy-creates it). */
  setViewColumns: (columns: string[]) => void;
  /** The active View's name ('Default View' until renamed / created). */
  viewName: string;
  renameView: (name: string) => void;
  /** All saved View subjects of the table, in order (the tabs). */
  views: string[];
  /** The active View subject (undefined until one exists). */
  activeView: string | undefined;
  /** Switch the active view, via the `?view=` search param. */
  setActiveView: (subject: string) => void;
  /** Create a new (empty) view of the given kind, link it, and switch to it. */
  createView: (kind?: ViewKind | string, label?: string) => void;
  /** Change a view's renderer kind (table/kanban/calendar/timer). */
  setViewKind: (subject: string, kind: ViewKind | string) => void;
  /** Copy a view (its config) into a new "<name> copy" view and switch to it. */
  duplicateView: (subject: string) => void;
  /** Remove a view from the table and destroy its resource. */
  deleteView: (subject: string) => void;
  /** Which renderer the active view uses ('table' until a View exists). */
  viewKind: ViewKind;
  /** Set when this view is rendered by an app rather than a built-in kind. */
  appView: string | undefined;
  /**
   * The property this view arranges rows by: a SelectProperty (kanban), a date
   * property (calendar), or the start timestamp (timer).
   */
  viewGroupBy: string | undefined;
  /** Persist the group-by property to the active View (lazy-creates it). */
  setViewGroupBy: (property: string) => void;
  /** For timer views: the timestamp property holding each entry's end. */
  viewEndProp: string | undefined;
  /** Persist the end property to the active View (lazy-creates it). */
  setViewEndProp: (property: string) => void;
  /**
   * For timer views: whether starting an entry stops whatever else is running.
   * Defaults to true (one timer at a time) when the View has no stored value.
   */
  viewTimerExclusive: boolean;
  /** Persist the exclusivity toggle to the active View (lazy-creates it). */
  setViewTimerExclusive: (exclusive: boolean) => void;
  /** LocalizedText properties split into one column per language tag. */
  viewSplitLanguages: string[];
  /** Persist the split-language property list to the active View (lazy-creates it). */
  setViewSplitLanguages: (properties: string[]) => void;
  /**
   * The computed columns this view shows next to its stored ones — a duration,
   * a days-since. Pure configuration: see `derivedColumns.ts`.
   */
  viewDerivedColumns: DerivedColumnSpec[];
  /**
   * Whether the View has a derived-column list at all. An empty list is a
   * decision ("I removed the last one"); an absent one is silence, which is what
   * lets a timer view supply its Duration without ever writing config.
   */
  viewDerivedColumnsSet: boolean;
  /** Persist the derived columns to the active View (lazy-creates it). */
  setViewDerivedColumns: (specs: DerivedColumnSpec[]) => void;
  /**
   * The display order of this view's columns, by key — property subjects for
   * stored columns, `derived:<id>` / `timer-action` for the ones a view adds.
   * Empty = the default order for the view kind.
   */
  viewColumnOrder: string[];
  /** Persist the column order to the active View (lazy-creates it). */
  setViewColumnOrder: (order: string[]) => void;
  /**
   * The statistics shown under the rows. The store computes them over every row
   * the view matches, so they are exact regardless of paging.
   */
  viewAggregates: TableAggregate[];
  /** Persist the statistics to the active View (lazy-creates it). */
  setViewAggregates: (aggregates: TableAggregate[]) => void;
  /**
   * The buttons this view puts on each row — "Watered", "Mark done", "+1".
   * Configuration, like the computed columns: a closed set of patches the store
   * can execute, never code. See `rowActions.ts`.
   */
  viewRowActions: RowActionSpec[];
  /** Persist the row actions to the active View (lazy-creates it). */
  setViewRowActions: (actions: RowActionSpec[]) => void;
  /**
   * The button this view offers for creating a row — "Log a feed", "Add item".
   * Undefined when the view offers none.
   */
  viewQuickAdd: QuickAddSpec | undefined;
  /** Persist the quick-add (undefined removes it). */
  setViewQuickAdd: (spec: QuickAddSpec | undefined) => void;
  /** The property the statistics are broken down by, if any. */
  viewGroupByColumn: string | undefined;
  /** Persist the breakdown property (empty string clears it). */
  setViewGroupByColumn: (property: string) => void;
  /** How a date/timestamp breakdown column is bucketed. */
  viewGroupGranularity: GroupGranularity;
  /** Persist the bucket size of the breakdown. */
  setViewGroupGranularity: (granularity: GroupGranularity) => void;
}

/**
 * View-backed table state. Filters + sort live on the table's default View
 * resource (`view-filters` JSON, `view-sort-by`/`view-sort-desc`) so they
 * persist across reloads. Local React state is the live source for instant UI;
 * it's hydrated once from the View and then debounce-persisted back. The View
 * is lazily created on the first change (writers only) — until then a table
 * behaves exactly as before.
 */
export function useTableView(
  table: Resource,
  /**
   * Which view to show, when the caller decides rather than the URL. A dashboard
   * embeds a table per block, so `?view=` — one param for the whole page —
   * cannot say which view each of them shows.
   */
  viewOverride?: string,
): UseTableViewResult {
  const store = useStore();
  const canWrite = useCanWrite(table);

  const [defaultViewSubject] = useString(
    table,
    dataBrowser.properties.tableDefaultView,
  );
  const [views] = useArray(table, dataBrowser.properties.tableViews);

  // The active view lives in the URL (`?view=`), so a tab is linkable, survives
  // a reload, and lands in browser history — back/forward moves between views
  // instead of leaving the page. Absent = the table's `default-view` (or the
  // first one) once they load.
  const activeViewParam = ShowRoute.useSearch({ select: s => s.view });
  const navigate = ShowRoute.useNavigate();
  const activeView =
    viewOverride ??
    activeViewParam ??
    defaultViewSubject ??
    views[0] ??
    undefined;
  const view = useResource(activeView ?? unknownSubject);

  // Reactive reads of the View's persisted config.
  const [viewName] = useString(view, core.properties.name);
  const [storedFilters] = useValue(view, dataBrowser.properties.viewFilters);
  const [storedSortBy] = useString(view, dataBrowser.properties.viewSortBy);
  const [storedSortDesc] = useBoolean(
    view,
    dataBrowser.properties.viewSortDesc,
  );
  const [storedColumns] = useArray(view, dataBrowser.properties.viewColumns);
  const [storedKind] = useString(view, dataBrowser.properties.viewKind);
  const [viewGroupBy] = useString(view, dataBrowser.properties.viewGroupBy);
  const [viewEndProp] = useString(view, dataBrowser.properties.viewEndProp);
  // Deliberately NOT `useBoolean`: it treats an unset value as `false` AND
  // writes that back, which would silently flip this toggle off (its default is
  // on) the first time any timer view rendered.
  const [storedTimerExclusive] = useValue(
    view,
    dataBrowser.properties.viewTimerExclusive,
  );
  const [storedSplitLanguages] = useArray(
    view,
    dataBrowser.properties.viewSplitLanguages,
  );
  const [storedDerivedColumns] = useValue(
    view,
    dataBrowser.properties.viewDerivedColumns,
  );
  const [storedColumnOrder] = useValue(
    view,
    dataBrowser.properties.viewColumnOrder,
  );
  const [storedAggregates] = useValue(
    view,
    dataBrowser.properties.viewAggregates,
  );
  const [storedRowActions] = useValue(
    view,
    dataBrowser.properties.viewRowActions,
  );
  const [storedQuickAdd] = useValue(view, dataBrowser.properties.viewQuickAdd);
  const [storedGroupByColumn] = useString(
    view,
    dataBrowser.properties.viewGroupByColumn,
  );
  const [storedGroupGranularity] = useString(
    view,
    dataBrowser.properties.viewGroupGranularity,
  );

  // Parsing JSON hands back a fresh array every render, and this one reaches the
  // grid's context — so key it on the stored shape instead. Without it every
  // render of the table re-renders every cell.
  const derivedColumnsKey = JSON.stringify(storedDerivedColumns ?? null);
  const viewDerivedColumns = useMemo(
    () => parseDerivedColumnSpecs(JSON.parse(derivedColumnsKey)),
    [derivedColumnsKey],
  );

  // Value-stable for the same reason as the derived columns: this one is a
  // dependency of the rendered column list.
  const columnOrderKey = JSON.stringify(storedColumnOrder ?? null);
  const viewColumnOrder = useMemo(
    () => parseColumnOrder(JSON.parse(columnOrderKey)),
    [columnOrderKey],
  );

  // Same reason: this feeds the collection query, and a fresh array every render
  // would rebuild the collection (and re-query) on every render.
  const aggregatesKey = JSON.stringify(storedAggregates ?? null);
  const viewAggregates = useMemo(
    () => parseAggregates(JSON.parse(aggregatesKey)),
    [aggregatesKey],
  );

  // Same reason as the aggregates: this reaches the rendered column list, and a
  // fresh array every render would remount every action button.
  const rowActionsKey = JSON.stringify(storedRowActions ?? null);
  const viewRowActions = useMemo(
    () => parseRowActions(JSON.parse(rowActionsKey)),
    [rowActionsKey],
  );

  // Serialized dep, like the rest of the JSON config: this reaches the rendered
  // bar, and a fresh object every render would remount it.
  const quickAddKey = JSON.stringify(storedQuickAdd ?? null);
  const viewQuickAdd = useMemo(
    () => parseQuickAdd(JSON.parse(quickAddKey)),
    [quickAddKey],
  );

  const [filters, setFilters] = useState<TableFilter[]>([]);
  const [sorting, dispatchSort] = useReducer(sortReducer, DEFAULT_SORT);

  // --- Hydrate from the active View; re-hydrates whenever it changes. ---
  // Tracks which view's config the local state currently mirrors.
  const hydratedForRef = useRef<string | null>(null);
  const lastPersistedRef = useRef<string>('');
  /** True while lazily creating the View that will hold local state. */
  const creatingViewRef = useRef(false);

  useEffect(() => {
    const key = activeView ?? '__none__';

    if (hydratedForRef.current === key) {
      return;
    }

    // Mid-creation of the View that is about to hold local state — see
    // `ensureView`. Reading it now would hydrate from a View whose config
    // hasn't been written yet and wipe the change that caused the creation.
    if (creatingViewRef.current) {
      return;
    }

    // No View yet — start from defaults. Seed `lastPersistedRef` with the
    // empty baseline so merely opening the table does NOT eagerly create a
    // View; only a real filter/sort change does.
    if (!activeView) {
      setFilters([]);
      dispatchSort({
        type: 'hydrate',
        prop: DEFAULT_SORT.prop,
        sortDesc: DEFAULT_SORT.sortDesc,
      });
      lastPersistedRef.current = JSON.stringify({
        filters: [],
        sort: DEFAULT_SORT,
      });
      hydratedForRef.current = key;

      return;
    }

    // Read straight from the resource, not the `useValue`/`useString` hook
    // results: those update a render LATE when the active view switches, so a
    // switch-back would hydrate from the previous view's (stale) values and
    // then lock out the correct re-hydration. `view.get` reflects the resource
    // synchronously, and resources load atomically (so a present `name` means
    // every prop is loaded). The hook results stay in the dep array to re-run
    // this effect once the view's data arrives.
    const loadedName = view.get(core.properties.name);

    if (loadedName === undefined) {
      return;
    }

    const rawFilters = view.get(dataBrowser.properties.viewFilters);
    const rawSortBy = view.get(dataBrowser.properties.viewSortBy) as
      | string
      | undefined;
    const rawSortDesc = view.get(dataBrowser.properties.viewSortDesc) as
      | boolean
      | undefined;

    const initialFilters = Array.isArray(rawFilters)
      ? (rawFilters as unknown as TableFilter[])
      : [];
    // Views saved before `sortOrder` became the default persisted `createdAt`
    // as their sort. That was the old default — not a user choice (createdAt
    // isn't a column) — and `sortOrder` sorts identically via its createdAt
    // fallback, so normalize. Keeps positional row insertion working on old
    // tables.
    const normalizedSortBy =
      rawSortBy === commits.properties.createdAt
        ? DEFAULT_SORT.prop
        : rawSortBy;
    const initialSort: TableSorting = normalizedSortBy
      ? { prop: normalizedSortBy, sortDesc: !!rawSortDesc }
      : DEFAULT_SORT;

    setFilters(initialFilters);
    dispatchSort({
      type: 'hydrate',
      prop: initialSort.prop,
      sortDesc: initialSort.sortDesc,
    });
    lastPersistedRef.current = JSON.stringify({
      filters: initialFilters,
      sort: initialSort,
    });
    hydratedForRef.current = key;
  }, [activeView, viewName, storedFilters, storedSortBy, storedSortDesc]);

  // --- View creation / linking. ---
  const createViewResource = useCallback(
    async (
      name: string,
      kind: ViewKind | string = DEFAULT_VIEW_KIND,
    ): Promise<Resource> => {
      const isFirst = views.length === 0 && !defaultViewSubject;
      const created = await store.newResource({
        parent: table.subject,
        isA: dataBrowser.classes.view,
        propVals: {
          [core.properties.name]: name,
          [dataBrowser.properties.viewKind]: kind,
        },
      });
      await created.save();
      await table.push(
        dataBrowser.properties.tableViews,
        [created.subject],
        true,
      );

      if (isFirst) {
        await table.set(
          dataBrowser.properties.tableDefaultView,
          created.subject,
        );
      }

      await table.save();

      return created;
    },
    [views.length, defaultViewSubject, store, table],
  );

  /**
   * Switches the active view by rewriting `?view=`. Picking a tab is a
   * navigation, so it pushes history; the programmatic switches below (after
   * creating or deleting a view) replace instead, so Back doesn't return to a
   * view that no longer exists or that the user never chose.
   */
  const goToView = useCallback(
    (subject: string | undefined, replace: boolean) => {
      void navigate({
        // `.` keeps us on this resource; only the search param changes.
        to: '.',
        search: prev => ({ ...prev, view: subject }),
        replace,
      });
    },
    [navigate],
  );

  const setActiveView = useCallback(
    (subject: string) => goToView(subject, false),
    [goToView],
  );

  const createView = useCallback(
    (kind: ViewKind | string = DEFAULT_VIEW_KIND, label?: string) => {
      void (async () => {
        // A table with no saved views shows one implicit Table tab, and that
        // tab disappears the moment a real view exists. So adding an app to a
        // fresh table would take the table away — the one thing an extra way
        // of looking at rows must never do. Give it back explicitly first.
        if (appViewOf(kind) && views.length === 0 && !defaultViewSubject) {
          await createViewResource(
            VIEW_KIND_LABELS[DEFAULT_VIEW_KIND],
            DEFAULT_VIEW_KIND,
          );
        }

        // Named after its kind ("Table" / "Kanban" / …), or after the app,
        // whose subject would be a meaningless tab title.
        const created = await createViewResource(
          label ?? VIEW_KIND_LABELS[kind as ViewKind],
          kind,
        );
        goToView(created.subject, true);
      })().catch(() => undefined);
    },
    [createViewResource, views.length, defaultViewSubject],
  );

  // --- Persist (debounced) whenever the local config changes post-hydration. ---
  const ensureView = useCallback(async (): Promise<Resource | undefined> => {
    if (activeView) {
      return store.getResourceLoading(activeView);
    }

    // Creating the View flips `activeView` from undefined to its subject, which
    // trips the hydrate effect below — and it reads the View BEFORE the caller
    // has written the config that prompted the creation, hydrating local state
    // back to empty and dropping the change. This View exists precisely to hold
    // what's already in local state, so hydration must not run for it at all.
    //
    // The flag is raised synchronously, before the first await: the re-render
    // can land midway through `createViewResource`, so marking it hydrated
    // afterwards is already too late. Without this, adding the first filter to
    // a table silently lost it whenever the re-render won that race.
    creatingViewRef.current = true;

    try {
      const created = await createViewResource('Default View');
      hydratedForRef.current = created.subject;

      return created;
    } finally {
      creatingViewRef.current = false;
    }
  }, [activeView, store, createViewResource]);

  useEffect(() => {
    if (hydratedForRef.current !== (activeView ?? '__none__') || !canWrite) {
      return;
    }

    const snapshot = JSON.stringify({ filters, sort: sorting });

    if (snapshot === lastPersistedRef.current) {
      return;
    }

    const timer = setTimeout(() => {
      void (async () => {
        const v = await ensureView();

        if (!v) {
          return;
        }

        // `false` = skip the client-side property fetch; the server validates
        // the commit against its (locally-seeded) property definitions.
        await v.set(dataBrowser.properties.viewFilters, filters, false);
        await v.set(dataBrowser.properties.viewSortBy, sorting.prop, false);
        await v.set(
          dataBrowser.properties.viewSortDesc,
          sorting.sortDesc,
          false,
        );
        await v.save();
        lastPersistedRef.current = snapshot;
      })().catch(error => {
        // Never swallow this: a filter or sort that fails to persist is silently
        // lost on the next reload, and the user has no way to know.
        console.error('Could not persist the view configuration:', error);
      });
    }, 600);

    return () => clearTimeout(timer);
  }, [filters, sorting, canWrite, ensureView, store, activeView]);

  // --- Filter mutators (same shape as the old `useTableFilters`). ---
  // Keyed by `filterKey`: a property subject, or `derived:<id>` for a constraint
  // on a computed column. One key keeps every setter working for both kinds.
  const addFilter = useCallback((key: string) => {
    setFilters(prev =>
      prev.some(f => filterKey(f) === key)
        ? prev
        : [
            ...prev,
            {
              ...parseFilterKey(key),
              // A computed column's value is a number, so the useful default is
              // a comparison rather than equality.
              operator: key.startsWith('derived:')
                ? ('gte' as FilterOperator)
                : ('eq' as FilterOperator),
              value: '',
            },
          ],
    );
  }, []);

  const setFilterValue = useCallback((key: string, value: string) => {
    setFilters(prev =>
      prev.map(f => (filterKey(f) === key ? { ...f, value } : f)),
    );
  }, []);

  const setFilterOperator = useCallback(
    (key: string, operator: FilterOperator) => {
      setFilters(prev =>
        prev.map(f => (filterKey(f) === key ? { ...f, operator } : f)),
      );
    },
    [],
  );

  const removeFilter = useCallback((key: string) => {
    setFilters(prev => prev.filter(f => filterKey(f) !== key));
  }, []);

  const clearFilters = useCallback(() => setFilters([]), []);

  const setSortBy = useCallback((property: string) => {
    dispatchSort({ type: 'cycle', property });
  }, []);

  // --- Column order/visibility + name. Persisted immediately (discrete
  // actions), lazy-creating the View like the filter/sort path. ---
  const setViewColumns = useCallback(
    (columns: string[]) => {
      void (async () => {
        const v = await ensureView();

        if (!v) {
          return;
        }

        await v.set(dataBrowser.properties.viewColumns, columns, false);
        await v.save();
      })().catch(() => undefined);
    },
    [ensureView],
  );

  const renameView = useCallback(
    (name: string) => {
      void (async () => {
        const v = await ensureView();

        if (!v) {
          return;
        }

        await v.set(core.properties.name, name, false);
        await v.save();
      })().catch(() => undefined);
    },
    [ensureView],
  );

  const setViewGroupBy = useCallback(
    (property: string) => {
      void (async () => {
        const v = await ensureView();

        if (!v) {
          return;
        }

        await v.set(dataBrowser.properties.viewGroupBy, property, false);
        await v.save();
      })().catch(() => undefined);
    },
    [ensureView],
  );

  const setViewEndProp = useCallback(
    (property: string) => {
      void (async () => {
        const v = await ensureView();

        if (!v) {
          return;
        }

        await v.set(dataBrowser.properties.viewEndProp, property, false);
        await v.save();
      })().catch(() => undefined);
    },
    [ensureView],
  );

  const setViewTimerExclusive = useCallback(
    (exclusive: boolean) => {
      void (async () => {
        const v = await ensureView();

        if (!v) {
          return;
        }

        await v.set(
          dataBrowser.properties.viewTimerExclusive,
          exclusive,
          false,
        );
        await v.save();
      })().catch(() => undefined);
    },
    [ensureView],
  );

  const setViewSplitLanguages = useCallback(
    (splitProperties: string[]) => {
      void (async () => {
        const v = await ensureView();

        if (!v) {
          return;
        }

        await v.set(
          dataBrowser.properties.viewSplitLanguages,
          splitProperties,
          false,
        );
        await v.save();
      })().catch(() => undefined);
    },
    [ensureView],
  );

  const setViewDerivedColumns = useCallback(
    (specs: DerivedColumnSpec[]) => {
      void (async () => {
        const v = await ensureView();

        if (!v) {
          return;
        }

        await v.set(dataBrowser.properties.viewDerivedColumns, specs, false);
        await v.save();
      })().catch(() => undefined);
    },
    [ensureView],
  );

  const setViewColumnOrder = useCallback(
    (order: string[]) => {
      void (async () => {
        const v = await ensureView();

        if (!v) {
          return;
        }

        await v.set(dataBrowser.properties.viewColumnOrder, order, false);
        await v.save();
      })().catch(() => undefined);
    },
    [ensureView],
  );

  const setViewAggregates = useCallback(
    (aggregates: TableAggregate[]) => {
      void (async () => {
        const v = await ensureView();

        if (!v) {
          return;
        }

        await v.set(dataBrowser.properties.viewAggregates, aggregates, false);
        await v.save();
      })().catch(() => undefined);
    },
    [ensureView],
  );

  const setViewRowActions = useCallback(
    (actions: RowActionSpec[]) => {
      void (async () => {
        const v = await ensureView();

        if (!v) {
          return;
        }

        await v.set(dataBrowser.properties.viewRowActions, actions, false);
        await v.save();
      })().catch(() => undefined);
    },
    [ensureView],
  );

  const setViewQuickAdd = useCallback(
    (spec: QuickAddSpec | undefined) => {
      void (async () => {
        const v = await ensureView();

        if (!v) {
          return;
        }

        if (spec === undefined) {
          v.remove(dataBrowser.properties.viewQuickAdd);
        } else {
          // Validated (no `false`): the property fetch is what records the JSON
          // datatype tag, without which a plain object is stored as a string.
          await v.set(dataBrowser.properties.viewQuickAdd, spec as never);
        }

        await v.save();
      })().catch(() => undefined);
    },
    [ensureView],
  );

  const setViewGroupByColumn = useCallback(
    (property: string) => {
      void (async () => {
        const v = await ensureView();

        if (!v) {
          return;
        }

        await v.set(dataBrowser.properties.viewGroupByColumn, property, false);
        await v.save();
      })().catch(() => undefined);
    },
    [ensureView],
  );

  const setViewGroupGranularity = useCallback(
    (granularity: GroupGranularity) => {
      void (async () => {
        const v = await ensureView();

        if (!v) {
          return;
        }

        await v.set(
          dataBrowser.properties.viewGroupGranularity,
          granularity,
          false,
        );
        await v.save();
      })().catch(() => undefined);
    },
    [ensureView],
  );

  const setViewKind = useCallback(
    (subject: string, kind: ViewKind | string) => {
      void (async () => {
        const v = store.getResourceLoading(subject);
        await v.set(dataBrowser.properties.viewKind, kind, false);
        await v.save();
      })().catch(() => undefined);
    },
    [store],
  );

  const duplicateView = useCallback(
    (subject: string) => {
      void (async () => {
        const src = store.getResourceLoading(subject);
        const srcName = (src.get(core.properties.name) as string) ?? 'View';

        // Copy the source config; only include props that are actually set so
        // we don't write `undefined` values onto the copy.
        const propVals: Record<string, JSONValue> = {
          [core.properties.name]: `${srcName} copy`,
          [dataBrowser.properties.viewKind]:
            (src.get(dataBrowser.properties.viewKind) as string) ??
            DEFAULT_VIEW_KIND,
        };

        for (const prop of [
          dataBrowser.properties.viewFilters,
          dataBrowser.properties.viewSortBy,
          dataBrowser.properties.viewSortDesc,
          dataBrowser.properties.viewColumns,
          dataBrowser.properties.viewGroupBy,
          dataBrowser.properties.viewEndProp,
          dataBrowser.properties.viewTimerExclusive,
          dataBrowser.properties.viewSplitLanguages,
          dataBrowser.properties.viewDerivedColumns,
          dataBrowser.properties.viewColumnOrder,
          dataBrowser.properties.viewAggregates,
          dataBrowser.properties.viewRowActions,
          dataBrowser.properties.viewQuickAdd,
          dataBrowser.properties.viewGroupByColumn,
          dataBrowser.properties.viewGroupGranularity,
        ]) {
          const value = src.get(prop);

          if (value !== undefined) {
            propVals[prop] = value as JSONValue;
          }
        }

        const created = await store.newResource({
          parent: table.subject,
          isA: dataBrowser.classes.view,
          propVals,
        });
        await created.save();
        await table.push(
          dataBrowser.properties.tableViews,
          [created.subject],
          true,
        );
        await table.save();
        goToView(created.subject, true);
      })().catch(() => undefined);
    },
    [store, table],
  );

  const deleteView = useCallback(
    (subject: string) => {
      void (async () => {
        const next = (views as string[]).filter(v => v !== subject);
        await table.set(dataBrowser.properties.tableViews, next, false);

        // The default view must not dangle at a deleted subject.
        if (defaultViewSubject === subject) {
          await table.set(
            dataBrowser.properties.tableDefaultView,
            next[0] ?? '',
            false,
          );
        }

        await table.save();

        // Switch off the deleted tab before destroying it.
        if (activeView === subject) {
          goToView(next[0], true);
        }

        await store.getResourceLoading(subject).destroy();
      })().catch(() => undefined);
    },
    [views, table, defaultViewSubject, activeView, store],
  );

  return {
    filters,
    addFilter,
    setFilterValue,
    setFilterOperator,
    removeFilter,
    clearFilters,
    sorting,
    setSortBy,
    view,
    viewColumns: Array.isArray(storedColumns)
      ? (storedColumns as string[])
      : [],
    setViewColumns,
    viewName: viewName ?? 'Default View',
    renameView,
    views: views as string[],
    activeView,
    setActiveView,
    createView,
    setViewKind,
    duplicateView,
    deleteView,
    viewKind: normalizeViewKind(storedKind),
    appView: appViewOf(storedKind),
    viewGroupBy,
    setViewGroupBy,
    viewEndProp,
    setViewEndProp,
    viewTimerExclusive:
      storedTimerExclusive === undefined ? true : !!storedTimerExclusive,
    setViewTimerExclusive,
    viewSplitLanguages: Array.isArray(storedSplitLanguages)
      ? (storedSplitLanguages as string[])
      : [],
    setViewSplitLanguages,
    viewDerivedColumns,
    viewDerivedColumnsSet: Array.isArray(storedDerivedColumns),
    setViewDerivedColumns,
    viewColumnOrder,
    setViewColumnOrder,
    viewAggregates,
    setViewAggregates,
    viewRowActions,
    setViewRowActions,
    viewQuickAdd,
    setViewQuickAdd,
    viewGroupByColumn: storedGroupByColumn || undefined,
    setViewGroupByColumn,
    viewGroupGranularity: (storedGroupGranularity as GroupGranularity) || 'day',
    setViewGroupGranularity,
  };
}
