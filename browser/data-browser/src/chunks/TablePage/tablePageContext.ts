import {
  unknownSubject,
  type AggregateFunction,
  type AggregateOutcome,
  type Collection,
  type Property,
} from '@tomic/react';
import { createContext } from 'react';
import { TableSorting } from './tableSorting';
import { AddItemToHistoryStack } from './helpers/useTableHistory';
import { TableFilter, FilterOperator } from './tableFiltering';
import type { DerivedColumnSpec } from './derivedColumns';
import type { RowActionSpec } from './rowActions';
import type { GroupGranularity, TableAggregate } from './tableAggregates';

/**
 * Which column a statistic describes: a stored property, or a column this view
 * computes (by its id). Exactly one of the two.
 */
export interface AggregateTarget {
  property?: string;
  derived?: string;
}

export interface TablePageContextType {
  /** Rows ticked in the row header, by subject ("select mode" while non-empty). */
  selectedRows: ReadonlySet<string>;
  toggleRowSelected: (subject: string) => void;
  clearRowSelection: () => void;
  /** Deletes every ticked row, as one undo step. */
  deleteSelectedRows: () => Promise<void>;
  tableSubject: string;
  tableClassSubject: string;
  sorting: TableSorting;
  setSortBy: React.Dispatch<string>;
  filters: TableFilter[];
  /** Keyed by `filterKey`: a property subject, or `derived:<id>` for a computed
   *  column. */
  addFilter: (key: string) => void;
  setFilterValue: (key: string, value: string) => void;
  setFilterOperator: (key: string, operator: FilterOperator) => void;
  removeFilter: (key: string) => void;
  hideColumn: (property: string) => void;
  /**
   * Adds a property to the active view's visible columns. Needed after creating
   * one: `view-columns` treats anything it doesn't list as hidden, so a brand
   * new property would otherwise land on the class and never show up.
   */
  showColumn: (property: string) => void;
  /** LocalizedText properties currently split into one column per language. */
  splitLanguageSubjects: string[];
  /** Toggle split-by-language for a LocalizedText property. */
  toggleSplitLanguages: (property: string) => void;
  /** Every property of the row class — what a computed column's arguments pick from. */
  classProperties: Property[];
  /** The statistics this view shows, as configured. */
  aggregates: TableAggregate[];
  /** What the store computed for them, over every matching row. */
  aggregateOutcomes: AggregateOutcome[];
  /** Total rows the view matches — what the footer says on the left. */
  rowCount: number;
  /** The rows have not arrived yet, so `rowCount` is not an answer. */
  rowsLoading: boolean;
  /**
   * Sets (or clears, with `undefined`) the statistic shown under a column, in
   * the given totals row (the first one by default).
   */
  setColumnAggregate: (
    target: AggregateTarget,
    fn: AggregateFunction | undefined,
    row?: number,
  ) => void;
  /** Drops a whole totals row, moving the ones below it up. */
  removeAggregateRow: (row: number) => void;
  /** Whether the viewer may change the table's configuration. */
  canWriteTable: boolean;
  /** The property the totals are broken down by, if any. */
  breakdownColumn: string | undefined;
  /** How a date/timestamp breakdown column is bucketed. */
  breakdownGranularity: GroupGranularity;
  /** Sets the breakdown (an empty column clears it). */
  setBreakdown: (config: {
    groupByColumn: string;
    granularity: GroupGranularity;
  }) => void;
  /** Add a computed column to the active view. */
  addDerivedColumn: (spec: DerivedColumnSpec) => void;
  /** Replace a computed column (matched on its id) in the active view. */
  updateDerivedColumn: (spec: DerivedColumnSpec) => void;
  /** Drop a computed column from the active view. */
  removeDerivedColumn: (id: string) => void;
  /** The buttons this view puts on each row. */
  rowActions: RowActionSpec[];
  /** Add a row action to the active view. */
  addRowAction: (spec: RowActionSpec) => void;
  /** Replace a row action (matched on its id) in the active view. */
  updateRowAction: (spec: RowActionSpec) => void;
  /** Drop a row action from the active view. */
  removeRowAction: (id: string) => void;
  addItemsToHistoryStack: AddItemToHistoryStack;
  /**
   * How the grid's row at `index` reaches its resource, mirroring what the grid
   * renders there (see `TablePage/TableRow.tsx`): a collection member, resolved
   * by index through the collection's pages, or a row added this session, which
   * keeps its local `_new:` key even after it materializes. `undefined` for an
   * index the grid draws nothing for.
   *
   * Row-scoped affordances rendered by the grid — the comment bubble in the
   * gutter — are handed nothing but an index, so this is how they reach the row
   * itself. The two cases need different hooks, so this reports which one it is
   * rather than resolving to a subject: a session row has no subject at all
   * until it materializes.
   */
  rowSource: (index: number) => RowSource | undefined;
  /** The kind of the active view ('table', 'calendar', …). */
  viewKind?: string;
}

export type RowSource =
  | { kind: 'member'; collection: Collection; index: number }
  | { kind: 'session'; key: string };

export const TablePageContext = createContext<TablePageContextType>({
  selectedRows: new Set(),
  toggleRowSelected: () => undefined,
  clearRowSelection: () => undefined,
  deleteSelectedRows: async () => undefined,
  tableSubject: unknownSubject,
  tableClassSubject: unknownSubject,
  sorting: {
    prop: '',
    sortDesc: true,
  },
  setSortBy: () => undefined,
  filters: [],
  addFilter: () => undefined,
  setFilterValue: () => undefined,
  setFilterOperator: () => undefined,
  removeFilter: () => undefined,
  hideColumn: () => undefined,
  showColumn: () => undefined,
  splitLanguageSubjects: [],
  toggleSplitLanguages: () => undefined,
  classProperties: [],
  aggregates: [],
  aggregateOutcomes: [],
  rowCount: 0,
  rowsLoading: false,
  setColumnAggregate: () => undefined,
  removeAggregateRow: () => undefined,
  canWriteTable: false,
  breakdownColumn: undefined,
  breakdownGranularity: 'day',
  setBreakdown: () => undefined,
  addDerivedColumn: () => undefined,
  updateDerivedColumn: () => undefined,
  removeDerivedColumn: () => undefined,
  rowActions: [],
  addRowAction: () => undefined,
  updateRowAction: () => undefined,
  removeRowAction: () => undefined,
  addItemsToHistoryStack: () => undefined,
  rowSource: () => undefined,
});
