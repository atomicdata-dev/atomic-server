import { Property } from '@tomic/react';
import { useContext, useMemo, type JSX } from 'react';
import { styled } from 'styled-components';
import { FaPlus } from 'react-icons/fa6';
import type { DropdownItem } from '@components/Dropdown';
import { buildDefaultTrigger } from '@components/Dropdown/DefaultTrigger';
import { TablePageContext } from './tablePageContext';
import { TableFilterChip } from './TableFilterChip';
import { derivedFilterKey, filterKey } from './tableFiltering';
import type { DerivedColumnSpec } from './derivedColumns';
import { usePropertyTitles } from './helpers/usePropertyTitles';
import { ColumnFilterDropdown } from './ColumnFilterDropdown';

interface TableFilterBarProps {
  columns: Property[];
  /**
   * Every column of the table, hidden ones included. An active filter on a
   * hidden column keeps its chip, since it still excludes rows.
   */
  allColumns?: Property[];
  /** The view's computed columns — filterable like any other. */
  derivedColumns: DerivedColumnSpec[];
}

const AddFilterTrigger = buildDefaultTrigger(<FaPlus />, 'Add filter');

/**
 * The row of active filter chips shown above the table columns. Hidden when no
 * filters are set; filters are added either from a column's `…` menu or the
 * `+ Filter` button here.
 */
export function TableFilterBar({
  columns,
  allColumns = columns,
  derivedColumns,
}: TableFilterBarProps): JSX.Element | null {
  const { filters, addFilter } = useContext(TablePageContext);

  const columnBySubject = useMemo(
    () => new Map(allColumns.map(c => [c.subject, c])),
    [allColumns],
  );

  const derivedById = useMemo(
    () => new Map(derivedColumns.map(spec => [spec.id, spec])),
    [derivedColumns],
  );

  const titles = usePropertyTitles(columns);

  const addItems = useMemo((): DropdownItem[] => {
    const taken = new Set(filters.map(filterKey));

    return [
      ...columns
        .filter(c => !taken.has(c.subject))
        .map(c => ({
          id: c.subject,
          label: titles.get(c.subject)!,
          onClick: () => addFilter(c.subject),
        })),
      // A computed column is filterable too: the store evaluates it per row, so
      // "logged more than an hour" or "due" narrows the table like any value.
      ...derivedColumns
        .filter(spec => !taken.has(derivedFilterKey(spec.id)))
        .map(spec => ({
          id: derivedFilterKey(spec.id),
          label: spec.label,
          onClick: () => addFilter(derivedFilterKey(spec.id)),
        })),
    ];
  }, [columns, derivedColumns, filters, addFilter, titles]);

  if (filters.length === 0) {
    return null;
  }

  return (
    <Bar role='toolbar' aria-label='Table filters'>
      {filters.map(filter => {
        const key = filterKey(filter);
        const derived = filter.derived
          ? derivedById.get(filter.derived)
          : undefined;
        const column = filter.property
          ? columnBySubject.get(filter.property)
          : undefined;

        // A filter whose column is gone (a computed column that was
        // removed) renders nothing rather than an unlabelled chip.
        if (!column && !derived) {
          return null;
        }

        return (
          <TableFilterChip
            key={key}
            filter={filter}
            column={column}
            derived={derived}
          />
        );
      })}
      {addItems.length > 0 && (
        <ColumnFilterDropdown Trigger={AddFilterTrigger} items={addItems} />
      )}
    </Bar>
  );
}

const Bar = styled.div`
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
  padding-block: 0.5rem;
`;
