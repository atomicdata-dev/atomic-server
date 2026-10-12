import { type JSX } from 'react';
import { styled } from 'styled-components';
import { Datatype, type AggregateOutcome, type Property } from '@tomic/react';
import { ResourceInline } from '@views/ResourceInline';
import { usePropertyTitles } from './helpers/usePropertyTitles';
import type { DerivedColumnSpec } from './derivedColumns';
import {
  AGGREGATE_FUNCTION_LABELS,
  aggregateKey,
  BREAKDOWN_ROWS_ID,
  formatAggregateValue,
  formatGroupKey,
  type GroupGranularity,
  type TableAggregate,
} from './tableAggregates';

interface TableSummaryBarProps {
  /** The view's configured statistics, in display order. */
  aggregates: TableAggregate[];
  /** What the store computed for them, over every matching row. */
  outcomes: AggregateOutcome[];
  /** Every property of the row class, for labels and value formatting. */
  classProperties: Property[];
  /** The view's computed columns, for the statistics that describe one. */
  derivedColumns: DerivedColumnSpec[];
  /** The property the statistics are broken down by, if any. */
  groupByColumn: string | undefined;
  granularity: GroupGranularity;
}

/**
 * The per-group breakdown, under the grid: one row per bucket, a column per
 * total. The totals themselves live in the table's footer, each under its own
 * column — this is only the part that can't: a value per group.
 *
 * Computed by the store over every row the view matches, so a breakdown adds up
 * to the footer's totals.
 */
export function TableSummaryBar({
  aggregates,
  outcomes,
  classProperties,
  derivedColumns,
  groupByColumn,
  granularity,
}: TableSummaryBarProps): JSX.Element | null {
  const titles = usePropertyTitles(classProperties);

  if (aggregates.length === 0) {
    return null;
  }

  const byProperty = new Map(classProperties.map(p => [p.subject, p]));
  const byDerived = new Map(derivedColumns.map(spec => [spec.id, spec]));
  const byKey = new Map(outcomes.map(o => [aggregateKey(o), o]));

  const cell = (aggregate: TableAggregate, groupKey?: string) => {
    const outcome = byKey.get(aggregateKey(aggregate));
    const property = aggregate.property
      ? byProperty.get(aggregate.property)
      : undefined;

    const value =
      groupKey === undefined
        ? outcome?.value
        : outcome?.groups?.find(g => g.key === groupKey)?.value;

    // A bucket of a computed column formats the way the column does — an hour of
    // logged time reads as 1:00:00, not 3600000.
    return formatAggregateValue(
      value,
      aggregate.function,
      property,
      aggregate.derived ? byDerived.get(aggregate.derived) : undefined,
    );
  };

  const aggregateLabel = (aggregate: TableAggregate) => {
    const name = aggregate.derived
      ? byDerived.get(aggregate.derived)?.label
      : aggregate.property
        ? titles.get(aggregate.property)
        : undefined;

    return `${AGGREGATE_FUNCTION_LABELS[aggregate.function]}${name ? ` of ${name}` : ''}`;
  };

  // Buckets come from the row count: every aggregate is grouped by the same
  // property, but only the count sees every row, so it alone reports each
  // group's size (a sum's `count` is just the rows that had a number).
  const rowCounts = byKey.get(
    aggregateKey({ id: BREAKDOWN_ROWS_ID, function: 'count' }),
  );
  const groups = groupByColumn
    ? (rowCounts?.groups ?? outcomes[0]?.groups ?? [])
    : [];
  const truncated = outcomes.some(o => o.groups_truncated);
  const groupProperty = groupByColumn
    ? byProperty.get(groupByColumn)
    : undefined;
  const groupsAreSubjects =
    groupProperty?.datatype === Datatype.RESOURCEARRAY ||
    groupProperty?.datatype === Datatype.ATOMIC_URL;

  if (groups.length === 0) {
    return null;
  }

  return (
    <Wrapper data-testid='table-summary'>
      <Breakdown data-testid='table-breakdown'>
        <caption>Per {titles.get(groupByColumn!) ?? ''}</caption>
        {/* Without headings a bare 1 could be a sum, an average or a count. */}
        <thead>
          <tr>
            <th scope='col'>{titles.get(groupByColumn!) ?? ''}</th>
            {aggregates.map(aggregate => (
              <th scope='col' key={aggregate.id}>
                {aggregateLabel(aggregate)}
              </th>
            ))}
            <th scope='col'>Rows</th>
          </tr>
        </thead>
        <tbody>
          {groups.map(group => (
            <tr key={group.key} data-testid={`group-${group.key}`}>
              <GroupCell>
                {groupsAreSubjects && group.key !== '' ? (
                  <ResourceInline subject={group.key} />
                ) : (
                  formatGroupKey(group.key, granularity)
                )}
              </GroupCell>
              {aggregates.map(aggregate => (
                <ValueCell key={aggregate.id}>
                  {cell(aggregate, group.key)}
                </ValueCell>
              ))}
              <CountCell>{group.count.toLocaleString()} rows</CountCell>
            </tr>
          ))}
        </tbody>
        {truncated && (
          <tfoot>
            <tr>
              {/* Never let a cut-off breakdown read as a complete one. */}
              <TruncatedCell colSpan={aggregates.length + 2}>
                Only the largest groups are shown.
              </TruncatedCell>
            </tr>
          </tfoot>
        )}
      </Breakdown>
    </Wrapper>
  );
}

const Wrapper = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding-block: 0.5rem;
  border-top: 1px solid ${p => p.theme.colors.bg2};
`;

const Breakdown = styled.table`
  border-collapse: collapse;
  font-size: 0.9rem;
  max-width: 100%;

  caption {
    text-align: left;
    color: ${p => p.theme.colors.textLight};
    font-size: 0.8rem;
    padding-bottom: 0.2rem;
  }

  th {
    color: ${p => p.theme.colors.textLight};
    font-size: 0.8rem;
    font-weight: normal;
    padding: 0 0.75rem 0.15rem 0;
    text-align: right;
  }

  th:first-child {
    text-align: left;
  }

  td {
    padding: 0.15rem 0.75rem 0.15rem 0;
    border-top: 1px solid ${p => p.theme.colors.bg2};
  }
`;

const GroupCell = styled.td`
  max-width: 20rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const ValueCell = styled.td`
  font-variant-numeric: tabular-nums;
  text-align: right;
`;

const CountCell = styled.td`
  color: ${p => p.theme.colors.textLight};
  font-variant-numeric: tabular-nums;
  text-align: right;
`;

const TruncatedCell = styled.td`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.8rem;
`;
