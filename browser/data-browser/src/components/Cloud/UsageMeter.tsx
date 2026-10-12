import type { ReactNode } from 'react';
import { styled } from 'styled-components';
import { CARD_SUB_FONT } from '../cardSurface';
import { formatBytes } from '../../helpers/formatBytes';

/**
 * How much of a plan's space a service uses: a bar and "X MB of Y GB".
 *
 * One component for Cloud Vault and Cloud Server, so the two rows draw their
 * usage the same way. Without a quota there is no share to draw, so only the
 * amount is shown.
 */
export function UsageMeter({
  usedBytes,
  quotaBytes,
  facts,
  note,
  backedUp = false,
  ...props
}: {
  usedBytes: number;
  quotaBytes?: number | null;
  /** Size facts that lead the line, such as "42 resources". */
  facts?: string[];
  /** Sits right behind the amount, such as a link to where the space goes. */
  note?: ReactNode;
  /** Say "backed up" instead of "used" when there is no quota to compare with. */
  backedUp?: boolean;
  [data: `data-${string}`]: string | number | undefined;
}) {
  const percent =
    quotaBytes && quotaBytes > 0
      ? Math.min(100, Math.round((usedBytes / quotaBytes) * 100))
      : null;
  const amount = quotaBytes
    ? `${formatBytes(usedBytes)} of ${formatBytes(quotaBytes)}`
    : backedUp
      ? `${formatBytes(usedBytes)} backed up`
      : `${formatBytes(usedBytes)} used`;
  // One line for every service: size facts, then the amount, then a link.
  const text = [...(facts ?? []), amount].join(' · ');

  return (
    <Wrapper {...props}>
      {percent !== null && (
        <Bar
          role='progressbar'
          aria-label='Storage used'
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={percent}
          title={`${percent}% used`}
        >
          <Fill style={{ width: `${percent}%` }} />
        </Bar>
      )}
      <Text data-testid='usage-meter-text'>
        {text}
        {note && <> · {note}</>}
      </Text>
    </Wrapper>
  );
}

const Wrapper = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
  min-width: 0;
`;

const Bar = styled.div`
  height: 6px;
  border-radius: 3px;
  background: ${p => p.theme.colors.bg2};
  overflow: hidden;
`;

const Fill = styled.div`
  height: 100%;
  border-radius: 3px;
  background: ${p => p.theme.colors.main};
  transition: width 0.3s ease;
`;

const Text = styled.span`
  color: ${p => p.theme.colors.text};
  font-size: ${CARD_SUB_FONT};
`;
