import type { JSX } from 'react';
import { styled } from 'styled-components';

interface ChoiceBarsProps {
  /** `[option, count]` pairs, rendered in the given order. */
  counts: Array<[string, number]>;
  /** Denominator for the percentage label (number of respondents). */
  answered: number;
}

/**
 * Horizontal bar per option: label, track with a single-hue fill, count +
 * percentage at the tip. Bars scale against the largest count so the ranking
 * is readable even when percentages are small.
 */
export function ChoiceBars({ counts, answered }: ChoiceBarsProps): JSX.Element {
  const maxCount = Math.max(1, ...counts.map(([, count]) => count));

  return (
    <Rows>
      {counts.map(([option, count]) => (
        <li key={option}>
          <OptionLabel>{option}</OptionLabel>
          <BarRow>
            <Track>
              <Fill style={{ width: `${(count / maxCount) * 100}%` }} />
            </Track>
            <ValueLabel>
              {count}
              {answered > 0 && (
                <Percentage>
                  {' '}
                  ({Math.round((count / answered) * 100)}%)
                </Percentage>
              )}
            </ValueLabel>
          </BarRow>
        </li>
      ))}
    </Rows>
  );
}

const Rows = styled.ul`
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: ${p => p.theme.size(2)};
`;

const OptionLabel = styled.div`
  color: ${p => p.theme.colors.text};
  font-size: 0.85rem;
  margin-bottom: 0.2rem;
  overflow-wrap: anywhere;
`;

const BarRow = styled.div`
  display: flex;
  align-items: center;
  gap: ${p => p.theme.size(2)};
`;

const Track = styled.div`
  flex: 1;
  height: 12px;
  background: ${p => p.theme.colors.bg1};
  border-radius: 4px;
  overflow: hidden;
`;

const Fill = styled.div`
  height: 100%;
  background: ${p => p.theme.colors.main};
  /* Rounded at the data end, square at the baseline. */
  border-radius: 0 4px 4px 0;
`;

const ValueLabel = styled.div`
  color: ${p => p.theme.colors.text};
  font-size: 0.8rem;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
  min-width: 4.5rem;
`;

const Percentage = styled.span`
  color: ${p => p.theme.colors.textLight};
`;
