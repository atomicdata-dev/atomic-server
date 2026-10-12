import {
  core,
  dataBrowser,
  unknownSubject,
  type AggregateFunction,
  type Aggregation,
  useCanWrite,
  useStore,
  type DataBrowser,
  type ExpressionFilter,
  type Property,
  type PropVal,
  type Resource,
} from '@tomic/react';
import type { CellIndex } from '@chunks/TableEditor';
import toast from 'react-hot-toast';
import { styled } from 'styled-components';
import { AppFrame } from '@chunks/AppPage/AppFrame';
import { computeSortOrder, readSortKey } from '@helpers/fractionalSortOrder';
import { useHandleClearCells } from '@chunks/TablePage/helpers/useHandleClearCells';
import { useHandleColumnResize } from '@chunks/TablePage/helpers/useHandleColumnResize';
import { useHandleCopyCommand } from '@chunks/TablePage/helpers/useHandleCopyCommand';
import { useHandlePaste } from '@chunks/TablePage/helpers/useHandlePaste';
import {
  useTableHistory,
  createResourceDeletedHistoryItem,
} from '@chunks/TablePage/helpers/useTableHistory';
import {
  TablePageContext,
  type RowSource,
  type TablePageContextType,
} from '@chunks/TablePage/tablePageContext';
import { TableNewRow, TableRow } from '@chunks/TablePage/TableRow';
import {
  hasUserContent,
  isSavedDraft,
  isUnsavedDraft,
} from '@chunks/TablePage/draftRow';
import {
  useTableColumns,
  type TableColumn,
} from '@chunks/TablePage/useTableColumns';
import { useTableData } from '@chunks/TablePage/useTableData';
import {
  useId,
  useState,
  useCallback,
  useEffect,
  useMemo,
  useRef,
} from 'react';
import { FancyTable } from '@chunks/TableEditor/TableEditor';
import { DEFAULT_SIZE_PX } from '@chunks/TableEditor/hooks/useCellSizes';
import { NewColumnButton } from './NewColumnButton';
import { TableHeading } from './TableHeading';
import { TableFilterBar } from './TableFilterBar';
import { RowSelectCheckbox } from './RowSelectCheckbox';
import { CellSelectionMenu } from './CellSelectionMenu';
import { useResourceContextMenu } from '@components/ResourceContextMenu/ResourceContextMenuContext';
import { TableViewTabs } from './TableViewTabs';
import { VIEW_KIND_LABELS } from './tableViewKinds';
import { ExpandedRowDialog } from './ExpandedRowDialog';
import { RowCommentButton } from './RowCommentButton';
import { KanbanView } from './Kanban/KanbanView';
import { CalendarView } from './Calendar/CalendarView';
import {
  TableCalendarRowContext,
  useTableCalendarRow,
} from './Calendar/useTableCalendarRow';
import { DashboardView } from './Dashboard/DashboardView';
import { IssuesView } from './Issues/IssuesView';
import { TimerToolbar } from './Timer/TimerToolbar';
import { useTimerColumns } from './Timer/useTimerColumns';
import { useDerivedColumns } from './useDerivedColumns';
import { useRowActions } from './useRowActions';
import { rowActionKey, type RowActionSpec } from './rowActions';
import { QuickAddBar } from './QuickAddBar';
import { useTableAggregates } from './useTableAggregates';
import { TableTotalsFooter } from './TableTotalsFooter';
import { toAggregation } from './tableAggregates';
import { stringToSlug } from '@helpers/stringToSlug';
import { orderColumns, reorderColumnKeys } from './columnOrder';
import { TableSummaryBar } from './TableSummaryBar';
import type { GroupGranularity } from './tableAggregates';
import type { AggregateTarget } from './tablePageContext';
import type { DerivedColumnSpec } from './derivedColumns';
import { TablePresenceContext, useTablePresence } from './TablePresence';
import { withRowDefaults } from './rowDefaults';
import { useQuickFilter, useQuickFilterAggregates } from './useQuickFilter';

interface TableResourceProps {
  resource: Resource<DataBrowser.Table>;
  /**
   * Which view to render. Defaults to the `?view=` search param, then the
   * table's own default — which is what its own page wants, and what an
   * embedded copy cannot use, since one param can't address several tables.
   */
  viewSubject?: string;
  /**
   * Rendered inside something else, e.g. a dashboard block. The view tab bar and
   * the filter bar are the table page's own chrome: the tabs would rewrite the
   * host page's `?view=`, and an embedded block's filters are its configuration
   * rather than something to fiddle with in place.
   */
  embedded?: boolean;
}

const columnToKey = (column: TableColumn) => column.key;

/** Draft rows minted ahead, so adding a row never waits on a signature. */
const DRAFT_POOL_SIZE = 2;

const NO_ROWS: string[] = [];

/**
 * Which rows a query asks for, as one comparable string — so the collection in
 * hand can be told apart from the one that was asked for. Built from the same
 * fields on both sides (`Collection` stores them verbatim), so the two are
 * directly comparable. Paging is left out: pages of one query answer it all.
 */
const queryIdentity = (
  filters: PropVal[],
  expressionFilters: ExpressionFilter[],
  sortBy: string | undefined,
  sortDesc: boolean,
): string =>
  JSON.stringify({
    f: filters,
    e: expressionFilters,
    s: [sortBy ?? null, !!sortDesc],
  });

export const TableResource: React.FC<TableResourceProps> = ({
  resource,
  viewSubject,
  embedded,
}) => {
  const store = useStore();
  const titleId = useId();
  const canWrite = useCanWrite(resource);

  const {
    tableClass,
    sorting,
    setSortBy,
    filters,
    addFilter,
    setFilterValue,
    setFilterOperator,
    removeFilter,
    viewColumns,
    setViewColumns,
    viewName,
    renameView,
    views,
    activeView,
    setActiveView,
    createView,
    setViewKind,
    duplicateView,
    deleteView,
    reorderViews,
    collection,
    ready,
    invalidateCollection,
    viewKind,
    appView,
    viewDashboard,
    viewGroupBy,
    setViewGroupBy,
    viewEndProp,
    setViewEndProp,
    viewTimerExclusive,
    setViewTimerExclusive,
    viewSplitLanguages,
    setViewSplitLanguages,
    viewDerivedColumns,
    viewDerivedColumnsSet,
    setViewDerivedColumns,
    viewColumnOrder,
    setViewColumnOrder,
    viewAggregates,
    setViewAggregates,
    viewGroupByColumn,
    setViewGroupByColumn,
    viewGroupGranularity,
    setViewGroupGranularity,
    viewRowActions,
    setViewRowActions,
    viewQuickAdd,
    setViewQuickAdd,
    queryFilters,
    queryExpressionFilters,
  } = useTableData(resource, viewSubject, embedded);

  const { columns, allColumns, hideColumn, showColumn } = useTableColumns(
    tableClass,
    viewColumns,
    setViewColumns,
    viewSplitLanguages,
  );
  const calendarRow = useTableCalendarRow(tableClass, allColumns);

  // The toolbar's quick filter. Session state, not View configuration: it is
  // tagged with the view it was typed in, so switching views (or leaving the
  // table) starts that view unfiltered. See `quickFilter.ts`.
  const [quickFilterState, setQuickFilterState] = useState<{
    view: string | undefined;
    text: string;
  }>({ view: undefined, text: '' });
  const quickFilterText =
    quickFilterState.view === activeView ? quickFilterState.text : '';
  const setQuickFilterText = useCallback(
    (text: string) => setQuickFilterState({ view: activeView, text }),
    [activeView],
  );

  // A dashboard or an app shows no rows of its own, so there's nothing to narrow.
  const showsRows = appView === undefined && viewKind !== 'dashboard';

  // The visible stored columns, each language of a split column on its own:
  // what the quick filter reads a row's text from.
  const quickFilterSources = useMemo(
    () =>
      columns.flatMap(c =>
        c.property
          ? [{ property: c.property, languageTag: c.languageTag }]
          : [],
      ),
    [columns],
  );

  // Narrows the view's own (column-filtered, sorted) rows. Every row view below
  // reads `quickFilter.collection`, which is the view's collection while the
  // field is empty.
  const quickFilter = useQuickFilter(
    collection,
    quickFilterSources,
    showsRows ? quickFilterText : '',
  );
  const rowCollection = quickFilter.collection;
  const quickFilterQuery = quickFilterText.trim();

  // The rendered column's property, per grid index (split columns repeat
  // theirs) — for consumers that need index alignment (presence). Virtual
  // columns have no property and are appended after the real ones, so dropping
  // them leaves the leading indexes aligned.
  const columnProperties = useMemo(
    () =>
      columns
        .map(c => c.property)
        .filter((p): p is Property => p !== undefined),
    [columns],
  );

  // The visible properties, deduplicated — for consumers that work per
  // property, not per rendered column (filters, visibility menu, kanban).
  const uniqueColumnProperties = useMemo(() => {
    const seen = new Set<string>();

    return columnProperties.filter(p => {
      if (seen.has(p.subject)) {
        return false;
      }

      seen.add(p.subject);

      return true;
    });
  }, [columnProperties]);

  // The timer doesn't replace the grid, it augments it: a start/stop button
  // appended to the real columns, a Duration derived column, plus a toolbar
  // above. Everything else — editing, sorting, resizing, keyboard navigation,
  // virtualisation — stays the table's.
  const isTimer = viewKind === 'timer';
  // `incrementMemberCount` is declared further down (it needs the member-count
  // refs); this stable indirection lets the timer call it from up here.
  const incrementMemberCountRef = useRef<() => void>(() => undefined);
  const notifyEntryCreated = useCallback(() => {
    incrementMemberCountRef.current();
    // The count lives in a ref, so bumping it alone renders nothing — the row
    // would only appear on the next unrelated render (in practice: a reload).
    // Refreshing the collection is what actually puts it on screen.
    void invalidateCollection();
  }, [invalidateCollection]);
  const timer = useTimerColumns(
    resource.subject,
    tableClass,
    allColumns,
    collection,
    viewGroupBy,
    setViewGroupBy,
    viewEndProp,
    setViewEndProp,
    viewTimerExclusive,
    !canWrite,
    isTimer,
    notifyEntryCreated,
  );

  // Computed columns are configuration on the View, not a feature of one view
  // kind — a table can show a days-since just as a timer shows a duration. A
  // timer view that has never had a derived-column list falls back to timing
  // its start/end pair, so a view added from the view menu still has a
  // Duration; once the user edits or removes it the stored list takes over
  // (which is why "has a list" and "the list is empty" must stay distinct).
  const effectiveDerivedSpecs =
    isTimer && !viewDerivedColumnsSet
      ? [...viewDerivedColumns, ...timer.derivedColumns]
      : viewDerivedColumns;

  // Keyed on their shape, not their identity: the timer's contribution is
  // rebuilt whenever its props resolve, and these specs feed both the grid and
  // the page context — an unstable array there re-renders every cell.
  const derivedSpecsKey = JSON.stringify(effectiveDerivedSpecs);
  const derivedSpecs = useMemo(
    () => JSON.parse(derivedSpecsKey) as DerivedColumnSpec[],
    [derivedSpecsKey],
  );

  const derivedColumns = useDerivedColumns(derivedSpecs);

  // Every edit writes the *effective* list, so acting on a timer's implicit
  // Duration materializes it instead of silently dropping it.
  const addDerivedColumn = useCallback(
    (spec: DerivedColumnSpec) => {
      // Ids are the column's identity in the grid; keep them unique.
      const taken = new Set(derivedSpecs.map(s => s.id));
      let id = spec.id || 'computed';

      for (let n = 2; taken.has(id); n++) {
        id = `${spec.id}-${n}`;
      }

      setViewDerivedColumns([...derivedSpecs, { ...spec, id }]);
    },
    [derivedSpecs, setViewDerivedColumns],
  );

  const updateDerivedColumn = useCallback(
    (spec: DerivedColumnSpec) => {
      setViewDerivedColumns(
        derivedSpecs.map(existing =>
          existing.id === spec.id ? spec : existing,
        ),
      );
    },
    [derivedSpecs, setViewDerivedColumns],
  );

  /**
   * Sets the statistic shown under one column (or clears it). One column holds
   * at most one, which is what the footer can express — and what a spreadsheet
   * does.
   */
  const setColumnAggregate = useCallback(
    (target: AggregateTarget, fn: AggregateFunction | undefined, row = 0) => {
      // One statistic per column per totals row — a column being either a stored
      // property or one this view computes.
      const rest = viewAggregates.filter(
        aggregate =>
          aggregate.property !== target.property ||
          aggregate.derived !== target.derived ||
          (aggregate.row ?? 0) !== row,
      );

      if (!fn) {
        setViewAggregates(rest);

        // A breakdown with nothing to break down shows nothing, so it goes with
        // the last total.
        if (rest.length === 0 && viewGroupByColumn) {
          setViewGroupByColumn('');
        }

        return;
      }

      const name =
        target.derived ?? target.property?.split('/').pop() ?? 'column';

      setViewAggregates([
        ...rest,
        {
          id: `${fn}-${stringToSlug(name)}-${row}`,
          ...target,
          function: fn,
          row,
        },
      ]);
    },
    [
      viewAggregates,
      setViewAggregates,
      setViewGroupByColumn,
      viewGroupByColumn,
    ],
  );

  /** Drops a whole totals row, moving the ones below it up. */
  const removeAggregateRow = useCallback(
    (row: number) => {
      const remaining = viewAggregates
        .filter(aggregate => (aggregate.row ?? 0) !== row)
        .map(aggregate =>
          (aggregate.row ?? 0) > row
            ? { ...aggregate, row: (aggregate.row ?? 0) - 1 }
            : aggregate,
        );

      setViewAggregates(remaining);

      if (remaining.length === 0 && viewGroupByColumn) {
        setViewGroupByColumn('');
      }
    },
    [
      viewAggregates,
      setViewAggregates,
      setViewGroupByColumn,
      viewGroupByColumn,
    ],
  );

  const setBreakdown = useCallback(
    (config: { groupByColumn: string; granularity: GroupGranularity }) => {
      setViewGroupByColumn(config.groupByColumn);
      setViewGroupGranularity(config.granularity);
    },
    [setViewGroupByColumn, setViewGroupGranularity],
  );

  const removeDerivedColumn = useCallback(
    (id: string) => {
      setViewDerivedColumns(derivedSpecs.filter(spec => spec.id !== id));
    },
    [derivedSpecs, setViewDerivedColumns],
  );

  // Configured row-action buttons. Hidden entirely from a viewer who cannot
  // write: a button that is going to be rejected is worse than no button.
  const actionColumns = useRowActions(viewRowActions, allColumns, !canWrite);

  const addRowAction = useCallback(
    (spec: RowActionSpec) => {
      // Same id minting as a computed column: derived from the label, and
      // suffixed until it is unique within the view.
      const base = stringToSlug(spec.label) || 'action';
      const taken = new Set(viewRowActions.map(existing => existing.id));
      let id = base;
      let n = 2;

      while (taken.has(id)) {
        id = `${base}-${n++}`;
      }

      setViewRowActions([...viewRowActions, { ...spec, id }]);
    },
    [viewRowActions, setViewRowActions],
  );

  const updateRowAction = useCallback(
    (spec: RowActionSpec) => {
      setViewRowActions(
        viewRowActions.map(existing =>
          existing.id === spec.id ? spec : existing,
        ),
      );
    },
    [viewRowActions, setViewRowActions],
  );

  const removeRowAction = useCallback(
    (id: string) => {
      setViewRowActions(viewRowActions.filter(spec => spec.id !== id));
      // Its placement in the column order would otherwise linger as dead config
      // that a later drag writes back forever.
      setViewColumnOrder(
        viewColumnOrder.filter(key => key !== rowActionKey(id)),
      );
    },
    [viewRowActions, setViewRowActions, viewColumnOrder, setViewColumnOrder],
  );

  // Computed columns, then configured buttons, then the timer's Start/Stop — so
  // the buttons stay at the end of the row where a thumb can find them.
  const virtualColumns = useMemo(
    () =>
      isTimer
        ? [...derivedColumns, ...actionColumns, ...timer.columns]
        : [...derivedColumns, ...actionColumns],
    [isTimer, derivedColumns, actionColumns, timer.columns],
  );

  // The default order: stored columns, then the ones the view adds — except in a
  // timer view, where its Duration and Start/Stop lead. Timing something is the
  // point of that view, so its controls belong where the eye starts, not past
  // four columns of data.
  const defaultOrder = useMemo(
    () =>
      virtualColumns.length === 0
        ? columns
        : isTimer
          ? [...virtualColumns, ...columns]
          : [...columns, ...virtualColumns],
    [isTimer, columns, virtualColumns],
  );

  // A saved order (from dragging a heading) wins over that default, for every
  // kind of column alike.
  const gridColumns = useMemo(
    () => orderColumns(defaultOrder, viewColumnOrder),
    [defaultOrder, viewColumnOrder],
  );

  /**
   * Dragging a heading writes the whole order — including the columns the view
   * added, which is the only way to place them. `view-columns` is rewritten in
   * the same relative order so the visibility list and the display order can't
   * drift apart (it still decides *which* properties show).
   */
  const handleColumnReorder = useCallback(
    async (sourceIndex: number, destinationIndex: number) => {
      const order = reorderColumnKeys(
        gridColumns,
        sourceIndex,
        destinationIndex,
      );
      setViewColumnOrder(order);

      const propertySubjects = new Set(
        gridColumns
          .map(column => column.property?.subject)
          .filter((subject): subject is string => subject !== undefined),
      );
      setViewColumns(order.filter(key => propertySubjects.has(key)));
    },
    [gridColumns, setViewColumnOrder, setViewColumns],
  );

  // Rebuilt every render (it carries a quantized `now`), so keyed on content.
  const aggregationKey = JSON.stringify(
    toAggregation(
      viewAggregates,
      viewGroupByColumn,
      viewGroupGranularity,
      derivedSpecs,
    ) ?? null,
  );
  const aggregation = useMemo(
    () => (JSON.parse(aggregationKey) as Aggregation | null) ?? undefined,
    [aggregationKey],
  );

  // Totals ride their own query so they can be re-read on every edit without
  // clearing the grid's pages. See `useTableAggregates`.
  const viewAggregateOutcomes = useTableAggregates({
    property: core.properties.parent,
    value: resource.subject,
    filters: queryFilters,
    expressionFilters: queryExpressionFilters,
    aggregation,
    drive: store.getDrive(),
    server: resource.subject.startsWith('http')
      ? new URL(resource.subject).origin
      : undefined,
  });

  // Under the quick filter, the totals cover the rows that match — the rows on
  // screen, and the ones the footer counts.
  const aggregateOutcomes = useQuickFilterAggregates(
    quickFilter,
    aggregation,
    viewAggregateOutcomes,
  );

  const [columnSizes, handleColumnResize] = useHandleColumnResize(resource);

  // Widths follow the *rendered* order, since that is how `tableColumnWidths`
  // stores them (a plain positional array). A column with no stored width falls
  // back to its own default — an icon button doesn't want the 300px a text
  // column does — but a width the user dragged always wins, which is what makes
  // the view-added columns resizable at all.
  //
  // Positional means reordering columns swaps their widths, the same quirk
  // stored property widths have always had.
  const gridColumnSizes = useMemo(() => {
    if (virtualColumns.length === 0) {
      return columnSizes;
    }

    const stored = columnSizes ?? [];

    return gridColumns.map(
      (column, index) =>
        stored[index] ?? column.virtual?.width ?? DEFAULT_SIZE_PX,
    );
  }, [columnSizes, gridColumns, virtualColumns.length]);

  // Properties the active view renders (or groups by) no matter what the
  // column config says. Offering to hide them would do nothing, so the menu
  // shows them locked with a reason instead.
  const lockedColumns = useMemo(() => {
    const locked = new Set<string>();

    if (viewKind === 'timer') {
      // The row's title, plus the two timestamps the whole view is built on.
      locked.add(core.properties.name);

      if (viewEndProp) {
        locked.add(viewEndProp);
      }
    }

    // Kanban groups by it, calendar places days by it, timer starts from
    // it, the issue list splits open from closed by it.
    if (viewKind !== 'table' && viewGroupBy) {
      locked.add(viewGroupBy);
    }

    return locked;
  }, [viewKind, viewGroupBy, viewEndProp]);

  const lockedReason = `Always used by the ${VIEW_KIND_LABELS[
    viewKind
  ].toLowerCase()} view`;

  const toggleSplitLanguages = useCallback(
    (subject: string) => {
      const next = viewSplitLanguages.includes(subject)
        ? viewSplitLanguages.filter(s => s !== subject)
        : [...viewSplitLanguages, subject];
      setViewSplitLanguages(next);
    },
    [viewSplitLanguages, setViewSplitLanguages],
  );

  const { undoLastItem, addItemsToHistoryStack } =
    useTableHistory(invalidateCollection);

  const handlePaste = useHandlePaste(
    resource,
    rowCollection,
    tableClass,
    invalidateCollection,
    addItemsToHistoryStack,
  );

  // Each new row is a draft minted with `store.newResource({ deferGenesis:
  // true })`: it has its final subject from the start, and saving it signs the
  // genesis under that same subject. The subject is minted ONCE, here in the
  // parent, and used as both its react-window key and the subject handed to
  // `TableNewRow`. This is what keeps row identity stable: react-window
  // recycles/remounts row components freely, so if `TableNewRow` minted its
  // own draft a remount would orphan the typed data on the old one and show a
  // fresh empty row. Binding subject↔key in the parent means a remount reuses
  // the same draft.
  //
  // Minting is async (it signs a genesis certificate), but adding a row must
  // not wait: Enter and Shift+Enter move the cursor into the new row in the
  // same handler. So a few drafts are minted ahead and handed out
  // synchronously, and the pool refills in the background. A draft nobody
  // uses is never saved, so it never reaches the server.
  const classtype = resource.props.classtype;
  const draftPool = useRef<string[]>([]);
  const refillingDrafts = useRef(false);

  const mintDraft = useCallback(async () => {
    const draft = await store.newResource({
      parent: resource.subject,
      isA: classtype,
      deferGenesis: true,
    });

    return draft.subject;
  }, [store, resource.subject, classtype]);

  const refillDrafts = useCallback(() => {
    if (refillingDrafts.current) return;

    refillingDrafts.current = true;

    const fill = async () => {
      while (draftPool.current.length < DRAFT_POOL_SIZE) {
        draftPool.current.push(await mintDraft());
      }
    };

    const done = () => {
      refillingDrafts.current = false;
    };

    fill().then(done, e => {
      done();
      store.notifyError(e);
    });
  }, [mintDraft, store]);

  // Fractional order key per session row, set when the row is handed out.
  // Seeded into the draft (see TableNewRow) so a row's on-screen position
  // persists when it materializes — including rows spliced mid-session via
  // Shift+Enter, whose `createdAt` wouldn't match their visual position.
  const [sessionSortOrders] = useState(() => new Map<string, number>());

  /** Hands a draft row to `use`, synchronously whenever one is ready. */
  const withSessionRow = useCallback(
    (sortOrder: number, use: (subject: string) => void) => {
      const take = (subject: string) => {
        sessionSortOrders.set(subject, sortOrder);
        use(subject);
        refillDrafts();
      };

      const pooled = draftPool.current.shift();

      if (pooled) {
        take(pooled);

        return;
      }

      mintDraft().then(take, e => store.notifyError(e));
    },
    [mintDraft, refillDrafts, sessionSortOrders, store],
  );

  const [newRowSubjects, setNewRowSubjects] = useState<string[]>([]);

  // Start with one empty trailing row (and fill the pool behind it). Drafts
  // minted for another parent or class are not handed out.
  useEffect(() => {
    draftPool.current = [];
    withSessionRow(Date.now(), subject =>
      setNewRowSubjects(prev => (prev.length > 0 ? prev : [subject])),
    );
  }, [withSessionRow]);

  // `memberCount` is the number of rows the collection already had when it
  // FIRST finished loading — captured once, at `ready`. Those render as real
  // `TableRow` collection members (by index). Everything after them is a
  // this-session row from `newRowSubjects`, rendered as a `TableNewRow` keyed
  // by its draft subject.
  //
  // Freezing the count (rather than tracking `collection.totalMembers` live) is
  // the whole point: a session row NEVER flips from `TableNewRow` to `TableRow`
  // when it materializes. It keeps its key — saving a draft does not change
  // its subject — and react-window therefore never remounts it. That remount was the churn
  // that desynced the table editor's active-cell / cursor state and dropped
  // keystrokes mid-edit. Capturing at the initial load (not inferring from
  // later growth) is also what makes a RELOAD correct: every persisted row is
  // part of that first count and renders as a member. (The growth-inference
  // version mistook the initial `0 → N` load for this-session materializations
  // and hid the rows.)
  //
  // Caveat: with a non-default sort AND pre-existing rows, a materialized
  // session row can sort into the member range and briefly render twice until a
  // reload re-seeds the session. For a fresh table `memberCount` is 0, so this
  // never happens — covering new-table entry, the common case.
  // What the user asked to see: value-bearing filters (incl. operator), sort,
  // and active view. Only the session rows key off this (they rebase when it
  // changes); the member baseline below compares against the collection itself,
  // because what was asked for and what has arrived are not the same thing.
  const queryKey = useMemo(
    () =>
      JSON.stringify({
        f: filters
          .filter(x => x.value !== '')
          .map(x => [x.property, x.operator, x.value]),
        s: [sorting.prop, sorting.sortDesc],
        v: activeView ?? null,
      }),
    [filters, sorting, activeView],
  );

  const baselineMemberCountRef = useRef<number | null>(null);
  const deletedSessionRowsRef = useRef(0);
  const baselineQueryKeyRef = useRef<string | null>(null);

  // What the grid is asking for, and what the collection in hand answers.
  // `useCollection` keeps serving the previous collection while it builds the
  // new one, so these differ for a moment after every filter or sort edit.
  const requestedQuery = queryIdentity(
    queryFilters,
    queryExpressionFilters,
    sorting.prop,
    sorting.sortDesc,
  );
  const answeredQuery = queryIdentity(
    collection.filters,
    collection.expressionFilters,
    collection.sortBy,
    collection.sortDesc,
  );

  // A count captured under a different query says nothing about this one.
  if (baselineQueryKeyRef.current !== requestedQuery) {
    baselineMemberCountRef.current = null;
  }

  // A session row that has already been persisted is counted by the collection
  // AND still rendered from `newRowSubjects` (it keeps its key, see above). Every count derived from the collection has to leave those out, or
  // the row is drawn twice: once as a member, once as itself.
  const materialisedSessionRows = newRowSubjects.filter(subject =>
    isSavedDraft(store.getResourceLoading(subject)),
  ).length;

  // Session rows the person deleted: they left `newRowSubjects` at once, but the
  // collection still counts them until its own removal lands. Without this the
  // gap reads as a row from somewhere else, the baseline is raised for it, and
  // the grid draws a member that no longer exists (a duplicated neighbour).
  // Bounded by what the collection really has in excess, so it drains itself.
  deletedSessionRowsRef.current = Math.min(
    deletedSessionRowsRef.current,
    Math.max(
      0,
      collection.totalMembers -
        (baselineMemberCountRef.current ?? 0) -
        materialisedSessionRows,
    ),
  );

  // Freeze the count only once the collection actually answers what was asked.
  // Edits land faster than collections arrive — change a filter's operator and
  // then type its value, and the collection built for the operator-only query
  // arrives when the query has already moved on. Recording ITS count against
  // the current query would freeze it for good: the collection that finally
  // answers carries the same query, so it would never be allowed to re-capture,
  // and the grid would keep rendering the previous filter's rows.
  //
  // The user may have typed a row before the collection answered (a slow
  // cold load); that row is already in the count, so it is not part of the
  // member baseline.
  if (
    ready &&
    answeredQuery === requestedQuery &&
    baselineMemberCountRef.current === null
  ) {
    baselineMemberCountRef.current = Math.max(
      0,
      collection.totalMembers -
        materialisedSessionRows -
        deletedSessionRowsRef.current,
    );
    baselineQueryKeyRef.current = requestedQuery;
  }

  // Before the collection is ready, track its live count so existing members
  // render as `TableRow`s during load (matching the old behaviour); once ready,
  // the frozen baseline takes over.
  //
  // Clamp to the collection's CURRENT size: when a filter shrinks the
  // collection the frozen baseline would otherwise exceed `totalMembers`, and
  // `getMemberWithIndex(index)` throws "Index out of bounds" for the now-
  // missing rows (surfacing as an unhandled rejection in
  // `useMemberFromCollection`). The clamp guards that instant; the filter
  // rebase effect below then recaptures a fresh baseline.
  // A row can also arrive from somewhere this session knows nothing about: a
  // paired peer, or another tab on the same drive. That grows the collection
  // without going through the new-row flow, so the frozen baseline never moves
  // and the grid keeps rendering the count it captured at load — the row is in
  // the collection, in the store, complete, and simply never drawn. Measured
  // against a paired node: `totalMembers` 8, `aria-setsize` 5.
  //
  // Freezing exists to stop a materialising session row from remounting; it was
  // never meant to hide other people's rows. So account for what this session
  // contributed — each materialised draft adds a member while still rendering
  // from `newRowSubjects` — and let anything beyond that raise the baseline.
  //
  // Only ever raises it. Shrink stays with `decrementMemberCount` and the clamp
  // below, and session rows keep their key through the index shift
  // (`itemKey` offsets by `memberCount`), so nothing remounts.
  if (baselineMemberCountRef.current !== null) {
    const accountedFor =
      baselineMemberCountRef.current +
      materialisedSessionRows +
      deletedSessionRowsRef.current;

    if (collection.totalMembers > accountedFor) {
      baselineMemberCountRef.current += collection.totalMembers - accountedFor;
    }
  }

  const memberCount = Math.min(
    baselineMemberCountRef.current ??
      Math.max(
        0,
        collection.totalMembers -
          materialisedSessionRows -
          deletedSessionRowsRef.current,
      ),
    collection.totalMembers,
  );

  // Applying a sort must visibly reorder the rows. Session rows render from
  // `newRowSubjects` in INSERTION order, bypassing the collection's sort, so a
  // sort would otherwise do nothing (the virtual rows ignore it). On a sort
  // change, "rebase" onto the freshly-sorted collection: clear the frozen
  // baseline (it re-captures from the re-sorted collection, so members render
  // in the new order) and reset the session to a single trailing placeholder.
  //
  // First, force-materialize any session row that has content but hasn't been
  // saved yet — otherwise dropping the session list would lose it. Once saved,
  // it joins the collection and reappears in its sorted position. Skips the
  // initial mount.
  const newRowSubjectsRef = useRef(newRowSubjects);
  newRowSubjectsRef.current = newRowSubjects;
  const rebaseInitialisedRef = useRef(false);

  // When the query changes (filter/sort/view edit — keyed on `queryKey`), the
  // collection rebuilds, so rebase the session: force-save any in-progress new
  // row, then reset to a single trailing placeholder. The baseline itself is
  // re-captured by the block above (NOT here — doing it here raced the
  // still-`ready` old collection and captured its count).
  useEffect(() => {
    if (!rebaseInitialisedRef.current) {
      rebaseInitialisedRef.current = true;

      return;
    }

    for (const subject of newRowSubjectsRef.current) {
      const row = store.getResourceLoading(subject);

      if (isUnsavedDraft(row) && hasUserContent(row)) {
        void row.save().catch(() => undefined);
      }
    }

    withSessionRow(Date.now(), subject => setNewRowSubjects([subject]));
  }, [queryKey, store, withSessionRow]);

  const decrementMemberCount = useCallback(() => {
    if (baselineMemberCountRef.current && baselineMemberCountRef.current > 0) {
      baselineMemberCountRef.current -= 1;
    }
  }, []);

  const incrementMemberCount = useCallback(() => {
    if (baselineMemberCountRef.current !== null) {
      baselineMemberCountRef.current += 1;
    }
  }, []);

  incrementMemberCountRef.current = incrementMemberCount;

  /**
   * Shift+Enter: insert a row directly below the given row.
   *
   * - Anchor is a persisted member: a row is created and saved immediately
   *   with a fractional `sortOrder` between its neighbors' keys (their
   *   explicit sortOrder or createdAt — the server sorts by the same
   *   fallback), so it materializes at exactly `index + 1`.
   * - Anchor is an unsaved session row: a fresh virtual row is spliced in
   *   below it, keyed between its neighbors' minted sort keys so the
   *   position also survives materialization.
   *
   * Returns false (= jump to the trailing empty row instead) under a column
   * sort, where a mid-table position has no meaning.
   */
  const handleInsertRowBelow = useCallback(
    (index: number): boolean => {
      // Rows hidden by the quick filter sit between the visible ones, so
      // "directly below" has no position to stand for.
      if (
        quickFilter.active ||
        sorting.prop !== dataBrowser.properties.sortOrder ||
        sorting.sortDesc
      ) {
        return false;
      }

      if (index >= memberCount) {
        const sessionIdx = index - memberCount;

        // Inserting below the trailing empty placeholder is meaningless.
        if (sessionIdx >= newRowSubjects.length - 1) {
          return false;
        }

        const anchor = newRowSubjects[sessionIdx];
        const anchorKey = sessionSortOrders.get(anchor);
        const nextKey = sessionSortOrders.get(newRowSubjects[sessionIdx + 1]);
        withSessionRow(computeSortOrder(anchorKey, nextKey), spliced =>
          setNewRowSubjects(prev => {
            const at = prev.indexOf(anchor) + 1;

            // The anchor row went away before the draft was ready.
            if (at === 0) return prev;

            return [...prev.slice(0, at), spliced, ...prev.slice(at)];
          }),
        );

        return true;
      }

      const insert = async () => {
        const anchorSubject = await collection.getMemberWithIndex(index);

        if (!anchorSubject) {
          return;
        }

        const nextSubject =
          index + 1 < memberCount
            ? await collection.getMemberWithIndex(index + 1)
            : undefined;

        const anchor = await store.getResource(anchorSubject);
        const next = nextSubject
          ? await store.getResource(nextSubject)
          : undefined;

        const row = await store.newResource({
          parent: resource.subject,
          isA: tableClass.subject,
          propVals: withRowDefaults(resource, {
            [dataBrowser.properties.sortOrder]: computeSortOrder(
              readSortKey(anchor),
              readSortKey(next),
            ),
          }),
        });

        // Table classes only `recommend` their columns, so an empty row is
        // valid to persist right away.
        await row.save();
        store.notifyResourceManuallyCreated(row);
        incrementMemberCount();
        // Refresh so the server-authoritative order (and the new member's
        // position at index + 1) lands promptly.
        await invalidateCollection();
      };

      insert().catch(error => {
        console.error('Failed to insert row:', error);
        toast.error('Failed to insert row');
      });

      return true;
    },
    [
      sorting,
      quickFilter.active,
      memberCount,
      newRowSubjects,
      sessionSortOrders,
      withSessionRow,
      collection,
      store,
      resource.subject,
      tableClass.subject,
      incrementMemberCount,
      invalidateCollection,
    ],
  );

  const addNewRow = useCallback(() => {
    withSessionRow(Date.now(), subject =>
      setNewRowSubjects(prev => [...prev, subject]),
    );
  }, [withSessionRow]);

  // What the grid draws. Under the quick filter: the matching rows and nothing
  // else — no session rows, since a row being typed would vanish the moment it
  // stopped matching. The session rows are kept, and come back on clearing.
  const gridMemberCount = quickFilter.active
    ? quickFilter.matches.length
    : memberCount;
  const gridNewRowSubjects = quickFilter.active ? NO_ROWS : newRowSubjects;

  const itemKey = useCallback(
    (index: number) => {
      if (quickFilter.active) {
        // By subject: the same row keeps its cells while the matches around it
        // come and go.
        return `match-${quickFilter.matches[index] ?? index}`;
      }

      if (index < memberCount) {
        return `member-${index}`;
      }

      return newRowSubjects[index - memberCount] ?? `new-row-fallback-${index}`;
    },
    [quickFilter.active, quickFilter.matches, memberCount, newRowSubjects],
  );

  // See `TablePageContextType.rowSource`. The SAME index→row mapping the grid
  // renders with, for the same reason `handleDeleteRow` repeats it: members
  // come from the collection, session rows from `newRowSubjects`. A session row
  // keeps its `_new:` key for its whole life here — materializing does not turn
  // it into a member — so resolving everything through the collection would
  // address the wrong row. Under the quick filter the grid draws the matches,
  // so this follows `rowCollection` and the grid's counts too.
  const rowSource = useCallback(
    (index: number): RowSource | undefined => {
      if (index < gridMemberCount) {
        return { kind: 'member', collection: rowCollection, index };
      }

      const key = gridNewRowSubjects[index - gridMemberCount];

      return key ? { kind: 'session', key } : undefined;
    },
    [rowCollection, gridMemberCount, gridNewRowSubjects],
  );

  const [showExpandedRowDialog, setShowExpandedRowDialog] = useState(false);
  const [expandedRowSubject, setExpandedRowSubject] = useState<string>();

  const handleRowExpand = useCallback(
    async (index: number) => {
      const row = await rowCollection.getMemberWithIndex(index);
      setExpandedRowSubject(row);
      setShowExpandedRowDialog(true);
    },
    [rowCollection],
  );

  // Rows ticked in the row header, by subject. A change of view, filter or
  // sorting changes which rows are visible, so the ticks would point at rows
  // the person can no longer see: they only count for the query they were made
  // under.
  const [selection, setSelection] = useState<{
    queryKey: string;
    rows: ReadonlySet<string>;
  }>({ queryKey, rows: new Set() });
  const selectedRows = useMemo<ReadonlySet<string>>(
    () => (selection.queryKey === queryKey ? selection.rows : new Set()),
    [selection, queryKey],
  );

  const toggleRowSelected = useCallback(
    (subject: string) => {
      setSelection(prev => {
        const next = new Set(prev.queryKey === queryKey ? prev.rows : []);

        if (!next.delete(subject)) {
          next.add(subject);
        }

        return { queryKey, rows: next };
      });
    },
    [queryKey],
  );

  const clearRowSelection = useCallback(
    () => setSelection({ queryKey, rows: new Set() }),
    [queryKey],
  );

  const deleteRowSubjects = useCallback(
    async (subjects: string[]) => {
      const resources = subjects
        .map(subject => store.getResourceLoading(subject))
        .filter(row => !isUnsavedDraft(row));

      clearRowSelection();

      // Rows added this session are drawn from `newRowSubjects`; drop them from
      // the render list right away, like `handleDeleteRow` does.
      const sessionSubjects = new Set(newRowSubjects);
      const doomed = new Set(subjects);

      for (const subject of sessionSubjects) {
        if (
          doomed.has(subject) &&
          isSavedDraft(store.getResourceLoading(subject))
        ) {
          deletedSessionRowsRef.current += 1;
        }
      }

      setNewRowSubjects(prev => prev.filter(s => !doomed.has(s)));

      if (resources.length === 0) {
        return;
      }

      // One undo step restores the whole batch.
      addItemsToHistoryStack(resources.map(createResourceDeletedHistoryItem));

      for (const row of resources) {
        await row.destroy();

        if (!sessionSubjects.has(row.subject)) {
          decrementMemberCount();
        }
      }
    },
    [
      newRowSubjects,
      store,
      clearRowSelection,
      addItemsToHistoryStack,
      decrementMemberCount,
    ],
  );

  const deleteSelectedRows = useCallback(
    () => deleteRowSubjects([...selectedRows]),
    [deleteRowSubjects, selectedRows],
  );

  // The subject of the row at a grid index: a collection member, or a row
  // added this session.
  const subjectAtRow = useCallback(
    async (index: number): Promise<string | undefined> =>
      index < memberCount
        ? await collection.getMemberWithIndex(index)
        : newRowSubjects[index - memberCount],
    [collection, memberCount, newRowSubjects],
  );

  const { openResourceMenu } = useResourceContextMenu();

  // Right-click on a row's header cell: the same resource menu a right-click on
  // one of its cells opens. The subject is looked up asynchronously, so keep
  // what the menu needs from the event.
  const handleRowContextMenu = useCallback(
    (index: number, e: React.MouseEvent) => {
      e.preventDefault();

      const { clientX, clientY } = e;

      void subjectAtRow(index).then(subject => {
        if (subject) {
          openResourceMenu(subject, {
            clientX,
            clientY,
            preventDefault: () => undefined,
            stopPropagation: () => undefined,
          } as React.MouseEvent);
        }
      });
    },
    [subjectAtRow, openResourceMenu],
  );

  const deleteRowsByIndex = useCallback(
    async (indexes: number[]) => {
      const subjects = await Promise.all(indexes.map(subjectAtRow));

      await deleteRowSubjects(
        subjects.filter((s): s is string => s !== undefined),
      );
    },
    [subjectAtRow, deleteRowSubjects],
  );

  const RowHeaderExtra = useCallback(
    ({ index }: { index: number }) => {
      if (!canWrite) {
        return null;
      }

      if (index < memberCount) {
        return <RowSelectCheckbox collection={collection} index={index} />;
      }

      // The trailing empty row is the entry placeholder, not a row yet.
      const newRowIndex = index - memberCount;
      const subject = newRowSubjects[newRowIndex];

      if (!subject || newRowIndex === newRowSubjects.length - 1) {
        return null;
      }

      return <RowSelectCheckbox subject={subject} index={index} />;
    },
    [canWrite, collection, memberCount, newRowSubjects],
  );

  const tablePageContext: TablePageContextType = useMemo(
    () => ({
      selectedRows,
      toggleRowSelected,
      clearRowSelection,
      deleteSelectedRows,
      tableSubject: resource.subject,
      tableClassSubject: tableClass.subject,
      sorting,
      setSortBy,
      filters,
      addFilter,
      setFilterValue,
      setFilterOperator,
      removeFilter,
      hideColumn,
      showColumn,
      splitLanguageSubjects: viewSplitLanguages,
      toggleSplitLanguages,
      classProperties: allColumns,
      rowActions: viewRowActions,
      addRowAction,
      updateRowAction,
      removeRowAction,
      aggregates: viewAggregates,
      aggregateOutcomes,
      // The rows on screen: under the quick filter, the ones that match.
      rowCount: rowCollection.totalMembers,
      rowsLoading: !ready,
      setColumnAggregate,
      removeAggregateRow,
      canWriteTable: canWrite,
      breakdownColumn: viewGroupByColumn,
      breakdownGranularity: viewGroupGranularity,
      setBreakdown,
      addDerivedColumn,
      updateDerivedColumn,
      removeDerivedColumn,
      addItemsToHistoryStack,
      rowSource,
      viewKind,
    }),
    [
      selectedRows,
      toggleRowSelected,
      clearRowSelection,
      deleteSelectedRows,
      resource.subject,
      tableClass.subject,
      sorting,
      setSortBy,
      filters,
      addFilter,
      setFilterValue,
      setFilterOperator,
      removeFilter,
      hideColumn,
      showColumn,
      viewSplitLanguages,
      toggleSplitLanguages,
      allColumns,
      viewAggregates,
      aggregateOutcomes,
      rowCollection.totalMembers,
      ready,
      setColumnAggregate,
      removeAggregateRow,
      canWrite,
      viewGroupByColumn,
      viewGroupGranularity,
      setBreakdown,
      addDerivedColumn,
      updateDerivedColumn,
      removeDerivedColumn,
      addItemsToHistoryStack,
      rowSource,
      viewKind,
    ],
  );

  const handleDeleteRow = useCallback(
    async (index: number) => {
      // Resolve the row by the SAME index→row mapping the grid renders with:
      // members come from the collection, session rows from `newRowSubjects`.
      // Using `collection.getMemberWithIndex` for everything would mis-resolve
      // session rows (they are drafts, not addressed by collection index
      // here).
      const isMember = index < gridMemberCount;
      const subject = isMember
        ? await rowCollection.getMemberWithIndex(index)
        : gridNewRowSubjects[index - gridMemberCount];

      if (!subject) {
        return;
      }

      // Drop a session row from the render list immediately (optimistic).
      if (!isMember) {
        if (isSavedDraft(store.getResourceLoading(subject))) {
          deletedSessionRowsRef.current += 1;
        }

        setNewRowSubjects(prev => prev.filter(s => s !== subject));
      }

      const rowResource = store.getResourceLoading(subject);

      // A draft that was never saved has no server resource to destroy —
      // removing it from `newRowSubjects` above is enough.
      if (isUnsavedDraft(rowResource)) {
        return;
      }

      addItemsToHistoryStack(createResourceDeletedHistoryItem(rowResource));

      await rowResource.destroy();

      if (isMember) {
        decrementMemberCount();
      }

      // No explicit invalidateCollection — `removeResource()` (called by
      // `destroy()`) emits `ResourceRemoved`, and `useCollection`'s listener
      // surgically strips the row from the cached page via
      // `applyResourceChange`. Calling `refresh()` here would re-fetch from
      // the local WASM DB (which still contains the just-destroyed row, since
      // `removeResource` doesn't tombstone there) and clobber the optimistic
      // update back to the pre-delete state.
    },
    [
      rowCollection,
      store,
      addItemsToHistoryStack,
      gridMemberCount,
      gridNewRowSubjects,
      decrementMemberCount,
    ],
  );

  // Presence: announce which cell (grid) or card (kanban) we're on,
  // learn which rows remote sessions are on (rendered by the cells and
  // cards via TablePresenceContext).
  const { presenceValue, handleSelectedCellChange } = useTablePresence(
    resource.subject,
    {
      collection: rowCollection,
      columns: columnProperties,
      memberCount: gridMemberCount,
      newRowSubjects: gridNewRowSubjects,
    },
  );

  const handleClearCells = useHandleClearCells(
    rowCollection,
    addItemsToHistoryStack,
  );

  const handleCopyCommandByProperty = useHandleCopyCommand(rowCollection);

  // The grid works in rendered (TableColumn) cells; the copy helper works
  // per property, so unwrap at the boundary.

  const handleCopyCommand = useCallback(
    (cells: CellIndex<TableColumn>[]) =>
      handleCopyCommandByProperty(
        // Virtual columns hold nothing to copy.
        cells
          .filter(([, column]) => column.property !== undefined)
          .map(([row, column]): CellIndex<Property> => [row, column.property!]),
      ),
    [handleCopyCommandByProperty],
  );

  const renderCellSelectionMenu = useCallback(
    (args: {
      cells: CellIndex<TableColumn>[];
      point: { x: number; y: number };
      onClose: () => void;
    }) =>
      canWrite ? (
        <CellSelectionMenu
          {...args}
          onClear={handleClearCells}
          onSetValue={handlePaste}
          onDeleteRows={deleteRowsByIndex}
        />
      ) : null,
    [canWrite, handleClearCells, handlePaste, deleteRowsByIndex],
  );

  const Row = useCallback(
    ({ index }: { index: number }) => {
      if (index < gridMemberCount) {
        return (
          <TableRow
            collection={rowCollection}
            index={index}
            columns={gridColumns}
            subject={
              quickFilter.active ? quickFilter.matches[index] : undefined
            }
          />
        );
      }

      // Only the trailing new row spawns a fresh empty placeholder when it
      // first gains content (keeping exactly one empty row at the bottom).
      const newRowIndex = index - memberCount;
      const isLastNewRow = newRowIndex === newRowSubjects.length - 1;

      return (
        <TableNewRow
          parent={resource}
          columns={gridColumns}
          index={index}
          subject={newRowSubjects[newRowIndex]}
          isLast={isLastNewRow}
          addNewRow={addNewRow}
          sortOrder={sessionSortOrders.get(newRowSubjects[newRowIndex])}
        />
      );
    },

    // Resource can update a lot but its internals are stable so removing it from the array saves a lot of rerenders and shouldn't cause issues.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      rowCollection,
      quickFilter.active,
      quickFilter.matches,
      gridColumns,
      gridMemberCount,
      memberCount,
      newRowSubjects,
      resource.subject,
      addNewRow,
    ],
  );

  return (
    <TablePageContext value={tablePageContext}>
      <TablePresenceContext value={presenceValue}>
        <TableCalendarRowContext value={calendarRow}>
          {!embedded && (
            <TableViewTabs
              rowClass={tableClass.subject}
              views={views}
              activeView={activeView}
              setActiveView={setActiveView}
              createView={createView}
              setViewKind={setViewKind}
              duplicateView={duplicateView}
              deleteView={deleteView}
              reorderViews={reorderViews}
              viewName={viewName}
              renameView={renameView}
              allColumns={allColumns}
              columns={uniqueColumnProperties}
              derivedColumns={derivedSpecs}
              showColumn={showColumn}
              hideColumn={hideColumn}
              lockedColumns={lockedColumns}
              lockedReason={lockedReason}
              canWrite={canWrite}
              quickAdd={viewQuickAdd}
              setQuickAdd={setViewQuickAdd}
              quickFilter={
                showsRows
                  ? { value: quickFilterText, onChange: setQuickFilterText }
                  : undefined
              }
            />
          )}
          {/* Above the view switch, not inside the table branch: the filter
           * dropdown in the tab bar is offered for every view kind, so a kanban /
           * calendar / timer view could add a filter that then had nowhere to
           * render its chip — the filter silently did nothing. */}
          {!embedded && (
            <TableFilterBar
              columns={uniqueColumnProperties}
              allColumns={allColumns}
              derivedColumns={derivedSpecs}
            />
          )}
          {quickFilter.active &&
            !quickFilter.loading &&
            quickFilter.matches.length === 0 && (
              <NoMatches role='status'>
                {`No rows show “${quickFilterQuery}”.`}
              </NoMatches>
            )}
          {/* Above the view switch on purpose: a grocery board wants its "Add
           *  item" as much as the list does. Writers only — a create button that
           *  will be rejected is worse than none. */}
          {viewQuickAdd && canWrite && (
            <QuickAddBar
              spec={viewQuickAdd}
              tableSubject={resource.subject}
              tableClass={tableClass}
              classProperties={allColumns}
              onRowCreated={notifyEntryCreated}
            />
          )}
          {appView !== undefined ? (
            // An app rendering this table's rows. It sits beside the Table tab
            // rather than in place of it: adding a way to look at rows never
            // takes one away, and the table is always one tab over.
            <AppViewWrapper>
              <AppFrame
                app={appView}
                drive={store.getDrive()!}
                table={resource.subject}
              />
            </AppViewWrapper>
          ) : viewKind === 'dashboard' && embedded ? (
            // A dashboard inside a dashboard block would render itself again,
            // forever. Say so instead of hanging the page.
            <p>
              Pick a table, board or calendar view; a dashboard can't be shown
              inside a dashboard.
            </p>
          ) : viewKind === 'dashboard' ? (
            <DashboardView dashboard={viewDashboard} />
          ) : viewKind === 'kanban' ? (
            <KanbanView
              tableSubject={resource.subject}
              tableClass={tableClass}
              allColumns={allColumns}
              columns={uniqueColumnProperties}
              collection={rowCollection}
              ready={ready}
              viewGroupBy={viewGroupBy}
              setViewGroupBy={setViewGroupBy}
              readOnly={!canWrite}
            />
          ) : viewKind === 'issues' ? (
            <IssuesView
              tableSubject={resource.subject}
              tableClass={tableClass}
              allColumns={allColumns}
              collection={rowCollection}
              ready={ready}
              viewGroupBy={viewGroupBy}
              setViewGroupBy={setViewGroupBy}
              readOnly={!canWrite}
            />
          ) : viewKind === 'calendar' ? (
            <CalendarView
              tableSubject={resource.subject}
              tableClass={tableClass}
              allColumns={allColumns}
              collection={rowCollection}
              ready={ready}
              viewGroupBy={viewGroupBy}
              setViewGroupBy={setViewGroupBy}
              readOnly={!canWrite}
            />
          ) : (
            <>
              {isTimer && timer.startProp && timer.endProp && (
                <TimerToolbar
                  tableSubject={resource.subject}
                  tableClass={tableClass}
                  collection={collection}
                  startProp={timer.startProp}
                  endProp={timer.endProp}
                  exclusive={viewTimerExclusive}
                  setExclusive={setViewTimerExclusive}
                  onEntryCreated={notifyEntryCreated}
                />
              )}
              <FancyTable
                readOnly={!canWrite}
                busy={!ready}
                columns={gridColumns}
                columnSizes={gridColumnSizes}
                // The session's empty entry row is local state: it needs
                // nothing from the collection, so it is not gated on `ready`.
                // Gating it made a fresh table wait for the collection's first
                // fetch, and when the socket is not authenticated yet that fetch
                // sits out a 3s `waitForServerConnected` grace period
                // (`Collection.fetchPage`) before an empty page lands — five
                // seconds with no row to type into. Members that arrive during
                // load shift the row's index, not its key (`itemKey` offsets by
                // `memberCount`), so nothing remounts.
                itemCount={gridMemberCount + gridNewRowSubjects.length}
                itemKey={itemKey}
                columnToKey={columnToKey}
                labelledBy={titleId}
                onClearRow={handleDeleteRow}
                onCellResize={handleColumnResize}
                onClearCells={handleClearCells}
                onCopyCommand={handleCopyCommand}
                onPasteCommand={handlePaste}
                onUndoCommand={undoLastItem}
                onColumnReorder={handleColumnReorder}
                onRowExpand={handleRowExpand}
                RowHeaderExtra={RowHeaderExtra}
                onRowContextMenu={handleRowContextMenu}
                renderCellSelectionMenu={renderCellSelectionMenu}
                onInsertRowBelow={handleInsertRowBelow}
                onSelectedCellChange={handleSelectedCellChange}
                RowHeaderAddonComponent={RowCommentButton}
                HeadingComponent={TableHeading}
                NewColumnButtonComponent={NewColumnButton}
                FooterComponent={TableTotalsFooter}
              >
                {Row}
              </FancyTable>
              {/* Under the grid, where a spreadsheet's totals live. The numbers
               *  come from the store, over every row the view matches (under
               *  a quick filter, over the rows that match it). Not
               *  mounted at all without totals: it resolves a title per column,
               *  and a table with no totals should pay nothing for that. */}
              {viewAggregates.length > 0 && viewGroupByColumn && (
                <TableSummaryBar
                  aggregates={viewAggregates}
                  outcomes={aggregateOutcomes}
                  classProperties={allColumns}
                  derivedColumns={derivedSpecs}
                  groupByColumn={viewGroupByColumn}
                  granularity={viewGroupGranularity}
                />
              )}
            </>
          )}
          <ExpandedRowDialog
            subject={expandedRowSubject ?? unknownSubject}
            open={showExpandedRowDialog}
            bindOpen={setShowExpandedRowDialog}
            calendar={calendarRow}
          />
        </TableCalendarRowContext>
      </TablePresenceContext>
    </TablePageContext>
  );
};

/**
 * Sizes the app tab the same way the Kanban and Calendar tabs size themselves:
 * fill the space under the title and view tabs, capped so the page chrome
 * stays reachable. An iframe cannot report how tall its document is, so the
 * box has to be decided out here.
 */
const NoMatches = styled.p`
  margin: 0;
  padding-block: 0.5rem;
  color: ${p => p.theme.colors.textLight};
`;

const AppViewWrapper = styled.div`
  display: flex;
  flex-direction: column;
  height: min(80vh, calc(100dvh - 13rem));
  min-height: 18rem;
`;
