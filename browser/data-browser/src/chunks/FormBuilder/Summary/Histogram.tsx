import type { JSX } from 'react';
import { styled } from 'styled-components';
import type { HistogramBin } from './types';

interface HistogramProps {
  bins: HistogramBin[];
  min?: number;
  max?: number;
  mean?: number;
}

const formatNumber = new Intl.NumberFormat(undefined, {
  maximumFractionDigits: 2,
}).format;

/**
 * Column histogram over the server-computed bins. Counts sit on the column
 * caps (few bins, so direct labels replace a y-axis); bin start values label
 * the x-axis, with the final bin's end closing the scale.
 */
export function Histogram({
  bins,
  min,
  max,
  mean,
}: HistogramProps): JSX.Element {
  const maxCount = Math.max(1, ...bins.map(bin => bin.count));

  return (
    <div>
      <Plot>
        {bins.map(bin => (
          <ColumnSlot key={bin.min}>
            <CountLabel>{bin.count}</CountLabel>
            <Column
              style={{ height: `${(bin.count / maxCount) * 100}%` }}
              $empty={bin.count === 0}
            />
          </ColumnSlot>
        ))}
      </Plot>
      <Axis>
        {bins.map(bin => (
          <TickLabel key={bin.min}>{formatNumber(bin.min)}</TickLabel>
        ))}
        <EndTickLabel>{formatNumber(bins[bins.length - 1].max)}</EndTickLabel>
      </Axis>
      {min !== undefined && max !== undefined && mean !== undefined && (
        <Stats>
          min {formatNumber(min)} · mean {formatNumber(mean)} · max{' '}
          {formatNumber(max)}
        </Stats>
      )}
    </div>
  );
}

const Plot = styled.div`
  display: flex;
  align-items: flex-end;
  /* The 2px surface gap between touching columns. */
  gap: 2px;
  height: 9rem;
  border-bottom: 1px solid ${p => p.theme.colors.bg2};
`;

const ColumnSlot = styled.div`
  flex: 1;
  height: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: flex-end;
  min-width: 0;
`;

const CountLabel = styled.div`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.7rem;
  font-variant-numeric: tabular-nums;
  margin-bottom: 0.2rem;
`;

const Column = styled.div<{ $empty: boolean }>`
  width: 100%;
  max-width: 24px;
  background: ${p => p.theme.colors.main};
  /* Rounded at the data end, square at the baseline. */
  border-radius: 4px 4px 0 0;
  min-height: ${p => (p.$empty ? '0' : '2px')};
`;

const Axis = styled.div`
  position: relative;
  display: flex;
  /* Match the plot's column gap so tick labels align with column edges. */
  gap: 2px;
  margin-top: 0.25rem;
`;

const TickLabel = styled.div`
  flex: 1;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.7rem;
  font-variant-numeric: tabular-nums;
  text-align: left;
  overflow: hidden;
  white-space: nowrap;
`;

const EndTickLabel = styled.div`
  position: absolute;
  right: 0;
  color: ${p => p.theme.colors.textLight};
  font-size: 0.7rem;
  font-variant-numeric: tabular-nums;
  background: ${p => p.theme.colors.bg};
  padding-left: 0.2rem;
`;

const Stats = styled.div`
  color: ${p => p.theme.colors.textLight};
  font-size: 0.8rem;
  margin-top: ${p => p.theme.size(2)};
  font-variant-numeric: tabular-nums;
`;
