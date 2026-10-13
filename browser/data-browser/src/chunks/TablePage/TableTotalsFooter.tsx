import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type JSX,
} from 'react';
import { styled } from 'styled-components';
import type { AggregateFunction, Property } from '@tomic/react';
import { DropdownMenu, type DropdownItem } from '@components/Dropdown';
import type {
  DropdownTriggerComponent,
  DropdownTriggerProps,
} from '@components/Dropdown/DropdownTrigger';
import { TableRow } from '@chunks/TableEditor/TableRow';
import { TableHeadingWrapper } from '@chunks/TableEditor/TableHeading';
import { TablePageContext, type AggregateTarget } from './tablePageContext';
import type { TableColumn } from './useTableColumns';
import { BreakdownDialog } from './BreakdownDialog';
import { useColumnLabel } from './helpers/useColumnLabel';
import type { DerivedColumnSpec } from './derivedColumns';
import {
  AGGREGATE_FUNCTION_LABELS,
  aggregateKey,
  aggregateRowCount,
  formatAggregateValue,
  functionsForDerived,
  isInstantProperty,
  isNumericProperty,
  type GroupGranularity,
  type TableAggregate,
} from './tableAggregates';

/**
 * What a footer cell's trigger button shows. Provided per cell, read by the ONE
 * trigger component below.
 *
 * The trigger has to be a stable component type: `DropdownMenu` mounts it and
 * holds a ref to it, so building a fresh component per render (the obvious way
 * to give each cell its own content) makes React remount the button on every
 * render — and the totals re-render on every store event, so a click landing in
 * that window did nothing at all.
 */
const CellTriggerContext = createContext<{
  content: React.ReactNode;
  title: string;
}>({ content: null, title: '' });

const CellTrigger: DropdownTriggerComponent = ({
  onClick,
  menuId,
  isActive,
  ref,
  id,
}: DropdownTriggerProps) => {
  const { content, title } = useContext(CellTriggerContext);

  return (
    <CellButton
      id={id}
      aria-controls={menuId}
      aria-expanded={isActive}
      aria-haspopup='menu'
      onClick={onClick}
      ref={ref}
      title={title}
      type='button'
    >
      {content}
    </CellButton>
  );
};

/** Which statistics make sense for a column, in menu order. */
function functionsFor(column: {
  property?: Property;
  derived?: DerivedColumnSpec;
}): AggregateFunction[] {
  if (column.derived) {
    return functionsForDerived(column.derived);
  }

  if (!column.property) {
    return [];
  }

  if (isNumericProperty(column.property)) {
    return ['sum', 'avg', 'min', 'max', 'count'];
  }

  if (isInstantProperty(column.property)) {
    return ['min', 'max', 'count'];
  }

  return ['count'];
}

/**
 * The rows under the rows: what this view's data adds up to.
 *
 * Each total sits in its own column, because that is the only place it means
 * anything — "615" under Amount needs no label to be understood. A column holds
 * one statistic per totals row, so adding a second row is how a table shows a
 * sum *and* an average under the same column.
 *
 * The numbers come from the store, computed over every row the view matches, so
 * they describe the whole (filtered) table rather than the page on screen — and
 * they follow edits.
 */
export function TableTotalsFooter({
  columns,
}: {
  columns: TableColumn[];
}): JSX.Element {
  const {
    aggregates,
    aggregateOutcomes,
    setColumnAggregate,
    removeAggregateRow,
    rowCount,
    rowsLoading,
    canWriteTable,
    classProperties,
    breakdownColumn,
    breakdownGranularity,
    setBreakdown,
  } = useContext(TablePageContext);

  const storedRows = aggregateRowCount(aggregates);
  // A row the user just added holds nothing yet, so there is nothing to store.
  // It becomes real as soon as a cell in it is set — which grows `storedRows`,
  // and the effect below then drops the placeholder.
  const [extraRows, setExtraRows] = useState(0);
  useEffect(() => setExtraRows(0), [storedRows]);

  const totalRows = storedRows + extraRows;

  const outcomeByKey = useMemo(
    () =>
      new Map(
        aggregateOutcomes.map(outcome => [aggregateKey(outcome), outcome]),
      ),
    [aggregateOutcomes],
  );

  /** The statistic configured for a column in a given totals row. */
  const configuredAt = (
    column: TableColumn,
    row: number,
  ): TableAggregate | undefined => {
    const target = targetOf(column);

    if (!target) {
      return undefined;
    }

    return aggregates.find(
      aggregate =>
        aggregate.property === target.property &&
        aggregate.derived === target.derived &&
        (aggregate.row ?? 0) === row,
    );
  };

  return (
    <>
      {Array.from({ length: totalRows }, (_, row) => (
        <FooterRow
          key={row}
          data-testid={row === 0 ? 'table-totals' : `table-totals-${row}`}
        >
          <LeadCell
            aria-colindex={1}
            row={row}
            rowCount={rowCount}
            rowsLoading={rowsLoading}
            totalRows={totalRows}
            canWrite={canWriteTable}
            classProperties={classProperties}
            breakdownColumn={breakdownColumn}
            breakdownGranularity={breakdownGranularity}
            setBreakdown={setBreakdown}
            addRow={() => setExtraRows(extra => extra + 1)}
            removeRow={() =>
              row < storedRows ? removeAggregateRow(row) : setExtraRows(0)
            }
          />
          {columns.map((column, index) => {
            const target = targetOf(column);

            return (
              <TotalCell
                key={column.key}
                aria-colindex={index + 2}
                column={column}
                configured={configuredAt(column, row)}
                outcomeByKey={outcomeByKey}
                onPick={fn => target && setColumnAggregate(target, fn, row)}
                readOnly={!canWriteTable}
              />
            );
          })}
          <FillerCell aria-colindex={columns.length + 2} />
        </FooterRow>
      ))}
    </>
  );
}

/** The leftmost cell: how many rows, plus the menu for the totals rows. */
function LeadCell({
  row,
  rowCount,
  rowsLoading,
  totalRows,
  canWrite,
  classProperties,
  breakdownColumn,
  breakdownGranularity,
  setBreakdown,
  addRow,
  removeRow,
  ...rest
}: {
  row: number;
  rowCount: number;
  rowsLoading: boolean;
  totalRows: number;
  canWrite: boolean;
  classProperties: Property[];
  breakdownColumn: string | undefined;
  breakdownGranularity: GroupGranularity;
  setBreakdown: (config: {
    groupByColumn: string;
    granularity: GroupGranularity;
  }) => void;
  addRow: () => void;
  removeRow: () => void;
}): JSX.Element {
  const [showBreakdown, setShowBreakdown] = useState(false);

  const items: DropdownItem[] = [
    { id: 'add-row', label: 'Add a totals row', onClick: addRow },
    ...(totalRows > 1
      ? [
          {
            id: 'remove-row',
            label: 'Remove this totals row',
            onClick: removeRow,
          },
        ]
      : []),
    {
      id: 'breakdown',
      label: breakdownColumn ? 'Change breakdown…' : 'Break down by…',
      onClick: () => setShowBreakdown(true),
    },
    ...(breakdownColumn
      ? [
          {
            id: 'clear-breakdown',
            label: 'Clear breakdown',
            onClick: () =>
              setBreakdown({
                groupByColumn: '',
                granularity: breakdownGranularity,
              }),
          },
        ]
      : []),
  ];

  // The count describes the table, not a particular totals row.
  // While the rows are on their way "0" would be a claim, not a count.
  const label = row === 0 && !rowsLoading ? rowCount.toLocaleString() : '';

  if (!canWrite) {
    return (
      <CountCell {...rest} title={`${rowCount} rows`}>
        {label}
      </CountCell>
    );
  }

  return (
    <CountCell {...rest}>
      <CellTriggerContext
        value={{ content: label, title: `${rowCount} rows — the totals menu` }}
      >
        <DropdownMenu Trigger={CellTrigger} items={items} />
      </CellTriggerContext>
      <BreakdownDialog
        open={showBreakdown}
        bindShow={setShowBreakdown}
        classProperties={classProperties}
        groupByColumn={breakdownColumn}
        granularity={breakdownGranularity}
        onSave={setBreakdown}
      />
    </CountCell>
  );
}

function TotalCell({
  column,
  configured,
  outcomeByKey,
  onPick,
  readOnly,
  ...rest
}: {
  column: TableColumn;
  configured?: TableAggregate;
  outcomeByKey: Map<string, { value: number | null; count: number }>;
  onPick: (fn: AggregateFunction | undefined) => void;
  readOnly: boolean;
}): JSX.Element {
  const functions = functionsFor(column);
  const propertyLabel = useColumnLabel(column.property);

  // A column that is neither stored nor computed — the timer's Start/Stop button
  // — has nothing to add up. Say so rather than swallowing the click: a dead cell
  // in a row of live ones reads as a bug.
  if (functions.length === 0) {
    return (
      <Cell {...rest}>
        <Unavailable title='This column holds an action, not a value, so there is nothing to total.'>
          –
        </Unavailable>
      </Cell>
    );
  }

  const label = column.derived?.label ?? propertyLabel;

  const outcome = configured
    ? outcomeByKey.get(aggregateKey(configured))
    : undefined;

  const value = configured ? (
    <Value>
      <Label>{AGGREGATE_FUNCTION_LABELS[configured.function]}</Label>
      <Amount>
        {formatAggregateValue(
          outcome?.value,
          configured.function,
          column.property,
          column.derived,
        )}
      </Amount>
    </Value>
  ) : undefined;

  if (readOnly) {
    return <Cell {...rest}>{value}</Cell>;
  }

  const items: DropdownItem[] = [
    { id: 'none', label: 'None', onClick: () => onPick(undefined) },
    ...functions.map(fn => ({
      id: fn,
      label: AGGREGATE_FUNCTION_LABELS[fn],
      onClick: () => onPick(fn),
    })),
  ];

  return (
    <Cell {...rest}>
      <CellTriggerContext
        value={{
          content: value ?? <Hint data-hint='true'>Σ</Hint>,
          title: configured
            ? `${AGGREGATE_FUNCTION_LABELS[configured.function]} of ${label} — click to change`
            : 'Total this column',
        }}
      >
        <DropdownMenu Trigger={CellTrigger} items={items} />
      </CellTriggerContext>
    </Cell>
  );
}

/**
 * What a column's statistic would describe: its property, or the computed column
 * itself. Undefined for a column that is neither (a row action).
 */
function targetOf(column: TableColumn): AggregateTarget | undefined {
  if (column.property) {
    return { property: column.property.subject };
  }

  return column.derived ? { derived: column.derived.id } : undefined;
}

/**
 * Reads as a summary, not as another row of data: its own raised background and
 * a firm line above it, with the row borders `TableRow` draws suppressed.
 *
 * Hovering anywhere along a row reveals every column's affordance at once, so
 * the totals stay discoverable without a permanent line of symbols under an
 * otherwise quiet table.
 */
const FooterRow = styled(TableRow)`
  background-color: ${p => p.theme.colors.bg1};

  & > div {
    border-bottom: none;
    border-right: 1px solid ${p => p.theme.colors.bg2};

    &:last-child {
      border-right: none;
    }
  }

  /* Each extra totals row is separated from the one above it. */
  & + & > div {
    border-top: 1px solid ${p => p.theme.colors.bg2};
  }

  span[data-hint='true'] {
    opacity: 0;
  }

  &:hover span[data-hint='true'] {
    opacity: 0.6;
  }

  & > div:hover span[data-hint='true'] {
    opacity: 1;
  }
`;

const Cell = styled(TableHeadingWrapper)`
  background-color: transparent;
  font-weight: normal;
  padding: 0;
  overflow: hidden;
`;

/** Fills its cell so the whole area is the click target. */
const CellButton = styled.button`
  all: unset;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  width: 100%;
  height: 100%;
  padding-inline: var(--table-inner-padding);
  cursor: pointer;
  overflow: hidden;

  &:focus-visible {
    outline: 2px solid ${p => p.theme.colors.main};
    outline-offset: -2px;
  }
`;

const CountCell = styled(TableHeadingWrapper)`
  background-color: transparent;
  font-weight: normal;
  white-space: nowrap;
  font-size: 0.8rem;
  justify-content: flex-end;
  padding: 0;
  color: ${p => p.theme.colors.textLight};
`;

const FillerCell = styled(TableHeadingWrapper)`
  background-color: transparent;
`;

const Value = styled.span`
  display: flex;
  align-items: baseline;
  gap: 0.4rem;
  overflow: hidden;
  white-space: nowrap;
`;

const Label = styled.span`
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  /* textLight, not textLight2: in dark mode the latter is darkened almost to
   * the background, which left this label unreadable. */
  color: ${p => p.theme.colors.textLight};
`;

const Amount = styled.span`
  font-variant-numeric: tabular-nums;
  font-weight: bold;
  color: ${p => p.theme.colors.text};
`;

/** A column that cannot carry a total, marked as such on hover. */
const Unavailable = styled.span`
  color: ${p => p.theme.colors.textLight};
  opacity: 0;
  transition: opacity 0.1s;
  padding-inline: var(--table-inner-padding);
  cursor: help;

  [role='row']:hover & {
    opacity: 0.45;
  }
`;

const Hint = styled.span`
  transition: opacity 0.1s;
  color: ${p => p.theme.colors.textLight};
`;
