import { Property, unknownSubject, useResource, useTitle } from '@tomic/react';
import { useContext, useState, type JSX } from 'react';
import * as RadixPopover from '@radix-ui/react-popover';
import { styled } from 'styled-components';
import { FaXmark } from 'react-icons/fa6';
import { Popover } from '@components/Popover';
import { Row, Column } from '@components/Row';
import { BasicSelect } from '@components/forms/BasicSelect';
import { ResourceInline } from '@views/ResourceInline';
import { TablePageContext } from './tablePageContext';
import {
  DERIVED_FILTER_OPERATORS,
  derivedFilterUnit,
  filterKey,
  NOW_VALUE,
  operatorLabel,
  operatorLabelForColumn,
  operatorsForDatatype,
  type DerivedFilterUnit,
  type FilterOperator,
  type TableFilter,
} from './tableFiltering';
import type { DerivedColumnSpec } from './derivedColumns';
import { InputStyled, InputWrapper } from '@components/forms/InputStyles';
import { TableFilterValueInput } from './TableFilterValueInput';

interface TableFilterChipProps {
  filter: TableFilter;
  /** The stored column this constrains, when it constrains one. */
  column?: Property;
  /** The computed column this constrains instead. Exactly one of the two. */
  derived?: DerivedColumnSpec;
}

export function TableFilterChip({
  filter,
  column,
  derived,
}: TableFilterChipProps): JSX.Element {
  const { setFilterValue, setFilterOperator, removeFilter } =
    useContext(TablePageContext);
  // A computed column has no property resource to read a title from.
  const propResource = useResource(column?.subject ?? unknownSubject);
  const [title] = useTitle(propResource);
  // Newly added filters (no value yet) open their editor straight away.
  const [open, setOpen] = useState(filter.value === '');
  const key = filterKey(filter);

  const label = derived ? derived.label : title || column!.shortname;
  const operators = derived
    ? DERIVED_FILTER_OPERATORS
    : operatorsForDatatype(column!.datatype);
  const chipOperator = derived
    ? operatorLabel(filter.operator)
    : operatorLabelForColumn(filter.operator, column!.datatype);
  const unit = derived ? derivedFilterUnit(derived.kind) : undefined;

  return (
    <Popover
      // Editing an operator/value changes the anchor width while this is open.
      // Track that rectangle on frames instead of resizing/repositioning the
      // popover inside the anchor's ResizeObserver delivery.
      updatePositionStrategy='always'
      open={open}
      onOpenChange={setOpen}
      Trigger={
        <ChipTrigger $active={filter.value !== ''} data-testid='filter-chip'>
          <ChipLabel>{label}</ChipLabel>
          <ChipOperator>{chipOperator}</ChipOperator>
          <ChipValue>
            {filter.value === '' ? (
              <Placeholder>…</Placeholder>
            ) : (
              <FilterValueSummary value={filter.value} suffix={unit?.suffix} />
            )}
          </ChipValue>
        </ChipTrigger>
      }
    >
      <PopoverInner>
        <Row center justify='space-between' gap='1rem'>
          <Header>{label}</Header>
          <RemoveButton
            onClick={() => removeFilter(key)}
            title='Remove filter'
            type='button'
          >
            <FaXmark />
          </RemoveButton>
        </Row>
        {operators.length > 1 && (
          <BasicSelect
            value={filter.operator}
            aria-label='Filter operator'
            onChange={e =>
              setFilterOperator(key, e.target.value as FilterOperator)
            }
          >
            {operators.map(op => (
              <option key={op} value={op}>
                {derived
                  ? operatorLabel(op)
                  : operatorLabelForColumn(op, column!.datatype)}
              </option>
            ))}
          </BasicSelect>
        )}
        {derived && unit ? (
          <DerivedValueInput
            unit={unit}
            value={filter.value}
            onChange={value => setFilterValue(key, value)}
          />
        ) : (
          <TableFilterValueInput
            property={column!}
            value={filter.value}
            autoFocus
            onChange={value => setFilterValue(key, value)}
          />
        )}
      </PopoverInner>
    </Popover>
  );
}

/** Renders the chosen value: a resource link for references, raw text else. */
function FilterValueSummary({
  value,
  suffix,
}: {
  value: string;
  suffix?: string;
}): JSX.Element {
  if (value.startsWith('http') || value.startsWith('did:')) {
    return <ResourceInline subject={value} untabbable />;
  }

  return <span>{suffix ? `${value} ${suffix}` : value}</span>;
}

/**
 * The value side of a computed column's filter, in the unit a person thinks in:
 * hours for a duration, days for a days-since, and for a date the choice between
 * a fixed day and `now` — "due" has to mean *now* when the query runs, or it goes
 * stale tomorrow.
 */
function DerivedValueInput({
  unit,
  value,
  onChange,
}: {
  unit: DerivedFilterUnit;
  value: string;
  onChange: (value: string) => void;
}): JSX.Element {
  const isNow = value === NOW_VALUE;

  return (
    <Column gap='0.5rem'>
      {unit.allowsNow && (
        <BasicSelect
          aria-label='Compare against'
          value={isNow ? NOW_VALUE : 'date'}
          onChange={e =>
            onChange(e.target.value === NOW_VALUE ? NOW_VALUE : '')
          }
        >
          <option value={NOW_VALUE}>now</option>
          <option value='date'>a date</option>
        </BasicSelect>
      )}
      {!isNow && (
        <Row center gap='0.5ch'>
          <InputWrapper>
            <InputStyled
              autoFocus
              data-testid='derived-filter-value'
              onChange={e => onChange(e.target.value)}
              placeholder={unit.allowsNow ? 'yyyy-mm-dd' : '0'}
              step='any'
              type={unit.allowsNow ? 'date' : 'number'}
              value={value}
            />
          </InputWrapper>
          {unit.suffix && <Suffix>{unit.suffix}</Suffix>}
        </Row>
      )}
    </Column>
  );
}

const Suffix = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.85rem;
  white-space: nowrap;
`;

const ChipTrigger = styled(RadixPopover.Trigger)<{ $active: boolean }>`
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  max-width: 24rem;
  padding: 0.1rem 0.5rem;
  height: 1.75rem;
  border: 1px solid ${p => p.theme.colors.bg2};
  border-radius: ${p => p.theme.radius};
  background-color: ${p =>
    p.$active ? p.theme.colors.bg1 : p.theme.colors.bg};
  color: ${p => p.theme.colors.text};
  cursor: pointer;
  font-size: 0.85rem;
  white-space: nowrap;

  &:hover {
    border-color: ${p => p.theme.colors.main};
  }
`;

const ChipLabel = styled.span`
  font-weight: bold;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const ChipOperator = styled.span`
  color: ${p => p.theme.colors.textLight};
`;

const ChipValue = styled.span`
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 12rem;
`;

const Placeholder = styled.span`
  color: ${p => p.theme.colors.textLight};
`;

const PopoverInner = styled(Column)`
  padding: ${p => p.theme.size()};
  gap: ${p => p.theme.size()};
  min-width: 18rem;
`;

const Header = styled.span`
  font-weight: bold;
`;

const RemoveButton = styled.button`
  background: none;
  border: none;
  color: ${p => p.theme.colors.textLight};
  cursor: pointer;
  display: flex;
  align-items: center;
  padding: 0.25rem;
  border-radius: ${p => p.theme.radius};

  &:hover {
    color: ${p => p.theme.colors.alert};
    background-color: ${p => p.theme.colors.bg1};
  }
`;
