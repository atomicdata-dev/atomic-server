import { useEffect, useRef, type JSX } from 'react';
import { Link } from '@tanstack/react-router';
import { styled } from 'styled-components';
import { FaCircleExclamation } from 'react-icons/fa6';
import { Button } from './Button';
import { focusConnectDevice } from './ConnectDevice';
import { cardSurface, CARD_SUB_FONT } from './cardSurface';
import { compactButtons } from './Cloud/ServiceRow';
import { paths } from '../routes/paths';
import type { SyncProblem } from '../helpers/syncProblem';

/** The sidebar's warning icon links here. */
export const SYNC_PROBLEM_ID = 'sync-problem';

/** Bring the Devices section into view, and the sync switch in it if shown. */
function reviewSync(): void {
  const devices = document.getElementById('sync-devices');

  devices?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  document.getElementById('workspace-server-sync')?.focus({
    preventScroll: true,
  });
}

/**
 * Why this workspace is not syncing, and what to do about it.
 *
 * Sits at the top of the Sync page, which is where the sidebar's warning icon
 * leads. It says plainly whose problem it is: ours (we are told, press Try
 * again) or the person's (the remedy is a button that goes there).
 */
export function SyncProblemBanner({
  problem,
  notified,
  retrying,
  onTryAgain,
}: {
  problem: SyncProblem;
  /** Error reporting is on, so "we have been notified" is true. */
  notified: boolean;
  retrying: boolean;
  onTryAgain: () => void;
}): JSX.Element {
  const ref = useRef<HTMLDivElement>(null);

  // Arriving from the sidebar icon: the banner appears after the page loads
  // its status, so the browser's own hash scroll has nothing to land on yet.
  useEffect(() => {
    if (window.location.hash === `#${SYNC_PROBLEM_ID}`) {
      ref.current?.scrollIntoView({ block: 'start' });
    }
  }, []);

  const mine = problem.cause === 'ours';

  return (
    <Banner
      ref={ref}
      id={SYNC_PROBLEM_ID}
      role={problem.cause === 'offline' ? 'status' : 'alert'}
      data-testid='sync-problem'
      data-cause={problem.cause}
      $cause={problem.cause}
    >
      <Icon aria-hidden>
        <FaCircleExclamation />
      </Icon>
      <Body>
        <Title>{problem.title}</Title>
        <Text>
          {problem.body}
          {mine && notified && ' We have been notified.'}
        </Text>
        {problem.detail && <Detail>{problem.detail}</Detail>}
        {problem.actions.length > 0 && (
          <Actions>
            {problem.actions.map(action => {
              switch (action) {
                case 'try-again':
                  return (
                    <Button
                      key={action}
                      data-testid='sync-problem-retry'
                      onClick={onTryAgain}
                      disabled={retrying}
                    >
                      {retrying ? 'Trying again…' : 'Try again'}
                    </Button>
                  );
                case 'connect-device':
                  return (
                    <Button key={action} onClick={focusConnectDevice}>
                      Connect a device
                    </Button>
                  );
                case 'review-sync':
                  return (
                    <Button key={action} subtle onClick={reviewSync}>
                      Turn off server sync
                    </Button>
                  );
                case 'storage':
                  return (
                    <StorageLink key={action} to={paths.storage}>
                      See where space goes
                    </StorageLink>
                  );
              }
            })}
          </Actions>
        )}
      </Body>
    </Banner>
  );
}

const Banner = styled.div<{ $cause: SyncProblem['cause'] }>`
  ${cardSurface}
  margin-bottom: 1.5rem;
  scroll-margin-top: 1rem;
  border-color: ${p =>
    p.$cause === 'offline' ? p.theme.colors.bg2 : p.theme.colors.warning};
  background: ${p =>
    p.$cause === 'offline' ? p.theme.colors.bg : `${p.theme.colors.warning}14`};
`;

const Icon = styled.span`
  flex-shrink: 0;
  display: inline-flex;
  margin-top: 0.15rem;
  color: ${p => p.theme.colors.warning};
`;

const Body = styled.div`
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
`;

const Title = styled.strong`
  font-size: 0.95rem;
`;

const Text = styled.p`
  margin: 0;
  font-size: ${CARD_SUB_FONT};
  color: ${p => p.theme.colors.text};
`;

const Detail = styled.code`
  font-size: 0.75rem;
  color: ${p => p.theme.colors.textLight};
  overflow-wrap: anywhere;
`;

const Actions = styled.div`
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
  margin-top: 0.3rem;
  ${compactButtons}
`;

const StorageLink = styled(Link)`
  color: ${p => p.theme.colors.main};
  font-size: ${CARD_SUB_FONT};
`;
