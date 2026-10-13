import { useEffectiveConstraint, type Constraint } from '@tomic/react';
import { styled } from 'styled-components';
import { InlineFormattedResourceList } from '../../../components/InlineFormattedResourceList';
import { ResourceInline } from '../../ResourceInline';
import { optionSubjects } from '../../../helpers/withConstraint';

import type { JSX } from 'react';

const RANGES: [
  'value' | 'length' | 'items',
  keyof Constraint,
  keyof Constraint,
][] = [
  ['value', 'minimum', 'maximum'],
  ['length', 'minLength', 'maxLength'],
  ['items', 'minItems', 'maxItems'],
];

const range = (min: unknown, max: unknown): string =>
  `${String(min ?? '…')} to ${String(max ?? '…')}`;

interface ClassConstraintSummaryProps {
  classSubject: string;
  propertySubject: string;
}

/** What a class requires of one of its properties, read-only. Empty when nothing. */
export function ClassConstraintSummary({
  classSubject,
  propertySubject,
}: ClassConstraintSummaryProps): JSX.Element | null {
  const constraint = useEffectiveConstraint([classSubject], propertySubject);
  const options = optionSubjects(constraint);
  const ranges = RANGES.filter(
    ([, min, max]) =>
      constraint[min] !== undefined || constraint[max] !== undefined,
  );

  if (
    options.length === 0 &&
    ranges.length === 0 &&
    !constraint.class &&
    !constraint.pattern
  ) {
    return null;
  }

  return (
    <Summary data-testid='constraint-summary'>
      {constraint.class && (
        <div>
          Links to <ResourceInline subject={constraint.class} />
        </div>
      )}
      {options.length > 0 && (
        <div>
          Allows only: <InlineFormattedResourceList subjects={options} />
        </div>
      )}
      {ranges.map(([label, min, max]) => (
        <div key={label}>
          {label === 'value'
            ? 'Value'
            : label === 'length'
              ? 'Length'
              : 'Items'}
          : {range(constraint[min], constraint[max])}
        </div>
      ))}
      {constraint.pattern && <div>Pattern: {constraint.pattern.source}</div>}
    </Summary>
  );
}

const Summary = styled.div`
  grid-column: 1 / -1;
  color: ${p => p.theme.colors.textLight};
`;
