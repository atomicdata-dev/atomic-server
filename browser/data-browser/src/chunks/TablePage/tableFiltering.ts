import { Datatype, type FilterOperator } from '@tomic/react';
import { useCallback, useState } from 'react';
import type { ExpressionFilter, PropVal } from '@tomic/react';
import {
  DERIVED_COLUMN_GENERATORS,
  toExpression,
  type DerivedColumnKind,
  type DerivedColumnSpec,
  type DerivedValueKind,
} from './derivedColumns';

export type { FilterOperator };

/**
 * A single table filter: an extra `(property, operator, value)` constraint
 * ANDed onto the table's `parent = <table>` query. One filter per property
 * (keyed by `property` subject). `value === ''` means "not set yet" — such
 * filters are kept in the UI (so the chip stays visible while editing) but
 * skipped by the query.
 */
export interface TableFilter {
  /** The stored property this constrains. Absent for a computed column. */
  property?: string;
  /**
   * The id of a computed column of this view, when the constraint is on a value
   * computed per row — "logged more than an hour", "due". The store evaluates the
   * column's expression over the rows the index narrows to, so paging and the
   * totals describe the filtered set.
   */
  derived?: string;
  operator: FilterOperator;
  value: string;
}

/**
 * How a filter is identified while it's being edited: a property subject, or a
 * computed column as `derived:<id>` — the same convention `view-column-order`
 * uses for the columns that aren't properties.
 *
 * A single key keeps the chips, the setters and the "already filtered" check
 * working for both kinds without every one of them growing a branch.
 */
export function filterKey(filter: TableFilter): string {
  return filter.derived
    ? derivedFilterKey(filter.derived)
    : (filter.property ?? '');
}

export function derivedFilterKey(id: string): string {
  return `derived:${id}`;
}

/** The target a key names: a stored property, or a computed column. */
export function parseFilterKey(
  key: string,
): Pick<TableFilter, 'property' | 'derived'> {
  return key.startsWith('derived:')
    ? { derived: key.slice('derived:'.length) }
    : { property: key };
}

/**
 * The operators a computed column offers. Its value is always a number, so the
 * comparisons are the numeric ones — no prefix or substring matching.
 */
export const DERIVED_FILTER_OPERATORS: FilterOperator[] = [
  'gte',
  'lte',
  'gt',
  'lt',
  'eq',
];

export interface UseTableFiltersResult {
  filters: TableFilter[];
  /** Add an empty filter for a property (no-op if one already exists). */
  addFilter: (property: string) => void;
  setFilterValue: (property: string, value: string) => void;
  setFilterOperator: (property: string, operator: FilterOperator) => void;
  removeFilter: (property: string) => void;
  clearFilters: () => void;
}

export function useTableFilters(): UseTableFiltersResult {
  const [filters, setFilters] = useState<TableFilter[]>([]);

  const addFilter = useCallback((property: string) => {
    setFilters(prev =>
      prev.some(f => f.property === property)
        ? prev
        : [...prev, { property, operator: 'eq', value: '' }],
    );
  }, []);

  const setFilterValue = useCallback((property: string, value: string) => {
    setFilters(prev =>
      prev.map(f => (f.property === property ? { ...f, value } : f)),
    );
  }, []);

  const setFilterOperator = useCallback(
    (property: string, operator: FilterOperator) => {
      setFilters(prev =>
        prev.map(f => (f.property === property ? { ...f, operator } : f)),
      );
    },
    [],
  );

  const removeFilter = useCallback((property: string) => {
    setFilters(prev => prev.filter(f => f.property !== property));
  }, []);

  const clearFilters = useCallback(() => setFilters([]), []);

  return {
    filters,
    addFilter,
    setFilterValue,
    setFilterOperator,
    removeFilter,
    clearFilters,
  };
}

const OPERATOR_LABELS: Record<FilterOperator, string> = {
  eq: 'is',
  gt: 'greater than',
  gte: 'at least',
  lt: 'less than',
  lte: 'at most',
  starts_with: 'starts with',
  contains: 'contains',
};

export function operatorLabel(operator: FilterOperator): string {
  return OPERATOR_LABELS[operator] ?? 'is';
}

/**
 * The operators offered for a property, by datatype. Only operators the query
 * index can currently honor are exposed (equality/membership, value
 * comparisons, prefix/substring). See `planning/table-view-filters.md`.
 */
export function operatorsForDatatype(datatype: Datatype): FilterOperator[] {
  switch (datatype) {
    case Datatype.INTEGER:
    case Datatype.FLOAT:
    case Datatype.DATE:
    case Datatype.TIMESTAMP:
      return ['eq', 'gt', 'gte', 'lt', 'lte'];
    case Datatype.STRING:
    case Datatype.MARKDOWN:
    case Datatype.SLUG:
      return ['eq', 'starts_with', 'contains'];
    case Datatype.RESOURCEARRAY:
      // Membership reads as "contains" but is the `eq` operator on the server.
      return ['eq'];
    default:
      // References, booleans, etc.: equality only.
      return ['eq'];
  }
}

/** For resource-array columns, `eq` reads as "contains" (membership). */
export function operatorLabelForColumn(
  operator: FilterOperator,
  datatype: Datatype,
): string {
  if (operator === 'eq' && datatype === Datatype.RESOURCEARRAY) {
    return 'contains';
  }

  return operatorLabel(operator);
}

/**
 * What a computed column's filter value means to a person, and how that becomes
 * the number the store compares against.
 *
 * A duration is milliseconds internally, and nobody filters durations in
 * milliseconds: the input asks for hours. A days-since is already days. A
 * next-due date is an instant, and the useful comparison is against *now* ("due"),
 * not against a date typed once and stale tomorrow — so `now` is a value the
 * filter can hold, resolved when the query is built.
 */
export interface DerivedFilterUnit {
  /** Shown after the input: "hours", "days", nothing for a plain number. */
  suffix: string;
  /** True when the value may be the literal `now` (a date-valued column). */
  allowsNow: boolean;
  /** The stored string → the number the store compares, or undefined if unusable. */
  toNumber: (value: string, now: number) => number | undefined;
}

const HOUR_MS = 3_600_000;

const UNITS: Record<DerivedValueKind, DerivedFilterUnit> = {
  duration: {
    suffix: 'hours',
    allowsNow: false,
    toNumber: value => {
      const hours = Number(value);

      return Number.isFinite(hours) ? hours * HOUR_MS : undefined;
    },
  },
  days: {
    suffix: 'days',
    allowsNow: false,
    toNumber: value => {
      const days = Number(value);

      return Number.isFinite(days) ? days : undefined;
    },
  },
  number: {
    suffix: '',
    allowsNow: false,
    toNumber: value => {
      const number = Number(value);

      return Number.isFinite(number) ? number : undefined;
    },
  },
  date: {
    suffix: '',
    allowsNow: true,
    toNumber: (value, now) => {
      if (value === NOW_VALUE) {
        return now;
      }

      const parsed = Date.parse(value);

      return Number.isNaN(parsed) ? undefined : parsed;
    },
  },
};

/** The value that means "the moment the query runs". */
export const NOW_VALUE = 'now';

export function derivedFilterUnit(kind: DerivedColumnKind): DerivedFilterUnit {
  return UNITS[DERIVED_COLUMN_GENERATORS[kind].valueKind];
}

/**
 * Splits the view's filters into the two things a query takes: `(property,
 * value)` constraints the index can answer, and constraints on computed values
 * the store has to evaluate per row.
 *
 * A filter with no value yet is skipped (its chip stays visible while you edit
 * it), as is one naming a computed column that is gone or still incomplete —
 * asking anyway would silently return an empty table.
 */
export function splitFilters(
  filters: TableFilter[],
  derivedColumns: DerivedColumnSpec[],
  now: number,
): { propVals: PropVal[]; expressionFilters: ExpressionFilter[] } {
  const specById = new Map(derivedColumns.map(spec => [spec.id, spec]));
  const propVals: PropVal[] = [];
  const expressionFilters: ExpressionFilter[] = [];

  for (const filter of filters) {
    if (filter.value === '') {
      continue;
    }

    if (filter.derived === undefined) {
      if (filter.property) {
        propVals.push({
          property: filter.property,
          value: filter.value,
          operator: filter.operator,
        });
      }

      continue;
    }

    const spec = specById.get(filter.derived);
    const expression = spec && toExpression(spec);

    if (!spec || !expression) {
      continue;
    }

    const value = derivedFilterUnit(spec.kind).toNumber(filter.value, now);

    if (value === undefined) {
      continue;
    }

    expressionFilters.push({
      expression,
      operator: filter.operator as ExpressionFilter['operator'],
      value,
      // The same instant for every constraint in the query, and quantized: this
      // is part of the query's identity, so a raw `Date.now()` would re-run it
      // on every render.
      ...(spec.kind === 'elapsed' || spec.kind === 'daysSince' || value === now
        ? { now_ms: now }
        : {}),
    });
  }

  return { propVals, expressionFilters };
}

/** How coarsely `now` is passed to the store, so a query has a stable identity. */
export const NOW_QUANTUM_MS = 60_000;

export function quantizedNow(): number {
  return Math.floor(Date.now() / NOW_QUANTUM_MS) * NOW_QUANTUM_MS;
}
