import {
  core,
  dataBrowser,
  unknownSubject,
  type AggregateFunction,
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
  type TablePageContextType,
} from '@chunks/TablePage/tablePageContext';
import { TableNewRow, TableRow } from '@chunks/TablePage/TableRow';
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
import { TableViewTabs } from './TableViewTabs';
import { VIEW_KIND_LABELS } from './tableViewKinds';
import { ExpandedRowDialog } from './ExpandedRowDialog';
import { KanbanView } from './Kanban/KanbanView';
import { CalendarView } from './Calendar/CalendarView';
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
    collection,
    ready,
    invalidateCollection,
    viewKind,
    appView,
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
  } = useTableData(resource, viewSubject);

  const { columns, allColumns, hideColumn, showColumn } = useTableColumns(
    tableClass,
    viewColumns,
    setViewColumns,
    viewSplitLanguages,
  );

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

  // Totals ride their own query so they can be re-read on every edit without
  // clearing the grid's pages. See `useTableAggregates`.
  const aggregateOutcomes = useTableAggregates({
    property: core.properties.parent,
    value: resource.subject,
    filters: queryFilters,
    expressionFilters: queryExpressionFilters,
    aggregation: toAggregation(
      viewAggregates,
      viewGroupByColumn,
      viewGroupGranularity,
      derivedSpecs,
    ),
    drive: store.getDrive(),
    server: resource.subject.startsWith('http')
      ? new URL(resource.subject).origin
      : undefined,
  });

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

    // Kanban groups by it, calendar places days by it, timer starts from it.
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
    collection,
    tableClass,
    invalidateCollection,
    addItemsToHistoryStack,
  );

  // Each new row's `_new:` subject is minted ONCE, here in the parent, and
  // used as both its react-window key and the subject handed to `TableNewRow`.
  // This is what keeps row identity stable: react-window recycles/remounts row
  // components freely, so if `TableNewRow` minted its own subject via
  // `useState(createSubject)` a remount would orphan the typed data on the old
  // subject and show a fresh empty one. Binding subject↔key in the parent means
  // a remount reuses the same subject and the same (virtual) resource.
  const generateRowSubject = useCallback(
    () => store.createSubject(resource.subject),
    [store, resource.subject],
  );

  // Fractional order key per session row, minted with the subject. Seeded
  // into the draft (see TableNewRow) so a row's on-screen position persists
  // when it materializes — including rows spliced mid-session via
  // Shift+Enter, whose eventual `createdAt` (sign time) wouldn't match their
  // visual position.
  const [sessionSortOrders] = useState(() => new Map<string, number>());

  const mintSessionRow = useCallback(
    (sortOrder: number) => {
      const subject = generateRowSubject();
      sessionSortOrders.set(subject, sortOrder);

      return subject;
    },
    [generateRowSubject, sessionSortOrders],
  );

  const [newRowSubjects, setNewRowSubjects] = useState<string[]>(() => [
    mintSessionRow(Date.now()),
  ]);

  // `memberCount` is the number of rows the collection already had when it
  // FIRST finished loading — captured once, at `ready`. Those render as real
  // `TableRow` collection members (by index). Everything after them is a
  // this-session row from `newRowSubjects`, rendered as a `TableNewRow` keyed
  // by its stable `_new:` subject.
  //
  // Freezing the count (rather than tracking `collection.totalMembers` live) is
  // the whole point: a session row NEVER flips from `TableNewRow` to `TableRow`
  // when it materializes. It keeps its `_new:` key — which the store aliases to
  // the real `did:ad:` subject, so the cell resolves the persisted resource —
  // and react-window therefore never remounts it. That remount was the churn
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

  // Freeze the count only once the collection actually answers what was asked.
  // Edits land faster than collections arrive — change a filter's operator and
  // then type its value, and the collection built for the operator-only query
  // arrives when the query has already moved on. Recording ITS count against
  // the current query would freeze it for good: the collection that finally
  // answers carries the same query, so it would never be allowed to re-capture,
  // and the grid would keep rendering the previous filter's rows.
  if (
    ready &&
    answeredQuery === requestedQuery &&
    baselineMemberCountRef.current === null
  ) {
    baselineMemberCountRef.current = collection.totalMembers;
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
  // below, and session rows keep their `_new:` key through the index shift
  // (`itemKey` offsets by `memberCount`), so nothing remounts.
  if (baselineMemberCountRef.current !== null) {
    const materialisedSessionRows = newRowSubjects.filter(subject =>
      store.isAliased(subject),
    ).length;
    const accountedFor =
      baselineMemberCountRef.current + materialisedSessionRows;

    if (collection.totalMembers > accountedFor) {
      baselineMemberCountRef.current += collection.totalMembers - accountedFor;
    }
  }

  const memberCount = Math.min(
    baselineMemberCountRef.current ?? collection.totalMembers,
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

      if (row.subject.startsWith('_new:') && row.getEntries().length > 2) {
        void row.save().catch(() => undefined);
      }
    }

    setNewRowSubjects([mintSessionRow(Date.now())]);
  }, [queryKey, store, mintSessionRow]);

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
      if (
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

        const anchorKey = sessionSortOrders.get(newRowSubjects[sessionIdx]);
        const nextKey = sessionSortOrders.get(newRowSubjects[sessionIdx + 1]);
        const spliced = mintSessionRow(computeSortOrder(anchorKey, nextKey));
        setNewRowSubjects(prev => [
          ...prev.slice(0, sessionIdx + 1),
          spliced,
          ...prev.slice(sessionIdx + 1),
        ]);

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
          propVals: {
            [dataBrowser.properties.sortOrder]: computeSortOrder(
              readSortKey(anchor),
              readSortKey(next),
            ),
          },
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
      memberCount,
      newRowSubjects,
      sessionSortOrders,
      mintSessionRow,
      collection,
      store,
      resource.subject,
      tableClass.subject,
      incrementMemberCount,
      invalidateCollection,
    ],
  );

  const addNewRow = useCallback(() => {
    setNewRowSubjects(prev => [...prev, mintSessionRow(Date.now())]);
  }, [mintSessionRow]);

  const itemKey = useCallback(
    (index: number) => {
      if (index < memberCount) {
        return `member-${index}`;
      }

      return newRowSubjects[index - memberCount] ?? `new-row-fallback-${index}`;
    },
    [memberCount, newRowSubjects],
  );

  const [showExpandedRowDialog, setShowExpandedRowDialog] = useState(false);
  const [expandedRowSubject, setExpandedRowSubject] = useState<string>();

  const handleRowExpand = useCallback(
    async (index: number) => {
      const row = await collection.getMemberWithIndex(index);
      setExpandedRowSubject(row);
      setShowExpandedRowDialog(true);
    },
    [collection],
  );

  const tablePageContext: TablePageContextType = useMemo(
    () => ({
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
      rowCount: collection.totalMembers,
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
    }),
    [
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
      collection.totalMembers,
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
    ],
  );

  const handleDeleteRow = useCallback(
    async (index: number) => {
      // Resolve the row by the SAME index→row mapping the grid renders with:
      // members come from the collection, session rows from `newRowSubjects`.
      // Using `collection.getMemberWithIndex` for everything would mis-resolve
      // session rows (they keep their `_new:` identity and are not addressed by
      // collection index here).
      const isMember = index < memberCount;
      const subject = isMember
        ? await collection.getMemberWithIndex(index)
        : newRowSubjects[index - memberCount];

      if (!subject) {
        return;
      }

      // Drop a session row from the render list immediately (optimistic).
      if (!isMember) {
        setNewRowSubjects(prev => prev.filter(s => s !== subject));
      }

      const rowResource = store.getResourceLoading(subject);

      // A purely-virtual row that was never materialized has no server resource
      // to destroy — removing it from `newRowSubjects` above is enough.
      if (rowResource.subject.startsWith('_new:')) {
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
      collection,
      store,
      addItemsToHistoryStack,
      memberCount,
      newRowSubjects,
      decrementMemberCount,
    ],
  );

  // Presence: announce which cell (grid) or card (kanban) we're on,
  // learn which rows remote sessions are on (rendered by the cells and
  // cards via TablePresenceContext).
  const { presenceValue, handleSelectedCellChange } = useTablePresence(
    resource.subject,
    { collection, columns: columnProperties, memberCount, newRowSubjects },
  );

  const handleClearCells = useHandleClearCells(
    collection,
    addItemsToHistoryStack,
  );

  const handleCopyCommandByProperty = useHandleCopyCommand(collection);

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

  const Row = useCallback(
    ({ index }: { index: number }) => {
      if (index < memberCount) {
        return (
          <TableRow
            collection={collection}
            index={index}
            columns={gridColumns}
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
      collection,
      gridColumns,
      memberCount,
      newRowSubjects,
      resource.subject,
      addNewRow,
    ],
  );

  return (
    <TablePageContext value={tablePageContext}>
      <TablePresenceContext value={presenceValue}>
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
          />
        )}
        {/* Above the view switch, not inside the table branch: the filter
         * dropdown in the tab bar is offered for every view kind, so a kanban /
         * calendar / timer view could add a filter that then had nowhere to
         * render its chip — the filter silently did nothing. */}
        {!embedded && (
          <TableFilterBar
            columns={uniqueColumnProperties}
            derivedColumns={derivedSpecs}
          />
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
        ) : viewKind === 'kanban' ? (
          <KanbanView
            tableSubject={resource.subject}
            tableClass={tableClass}
            allColumns={allColumns}
            columns={uniqueColumnProperties}
            collection={collection}
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
            collection={collection}
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
              itemCount={memberCount + newRowSubjects.length}
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
              onInsertRowBelow={handleInsertRowBelow}
              onSelectedCellChange={handleSelectedCellChange}
              HeadingComponent={TableHeading}
              NewColumnButtonComponent={NewColumnButton}
              FooterComponent={TableTotalsFooter}
            >
              {Row}
            </FancyTable>
            {/* Under the grid, where a spreadsheet's totals live. The numbers
             *  come from the store, over every row the view matches. Not
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
        />
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
const AppViewWrapper = styled.div`
  display: flex;
  flex-direction: column;
  height: min(80vh, calc(100dvh - 13rem));
  min-height: 18rem;
`;
