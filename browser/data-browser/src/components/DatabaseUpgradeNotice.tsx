import { useSyncExternalStore, type JSX } from 'react';
import { styled } from 'styled-components';
import {
  getIndexMigration,
  subscribeIndexMigration,
  type IndexMigrationProgress,
} from '@tomic/lib';
import { ProgressBar } from './ProgressBar';

const subscribe = (onChange: () => void) => subscribeIndexMigration(onChange);

/**
 * Covers the app while the local database rebuilds its indexes, or packs old
 * chat messages into logs, after an update. Nothing can be read from the database until that is done, so the
 * person waits here instead of at a blank page.
 */
export function DatabaseUpgradeNotice(): JSX.Element | null {
  const progress = useSyncExternalStore<IndexMigrationProgress | undefined>(
    subscribe,
    getIndexMigration,
  );

  if (!progress) return null;

  const counted = progress.total > 0;

  return (
    <Cover role='alertdialog' aria-modal='true' aria-labelledby='db-upgrade'>
      <Card>
        <Title id='db-upgrade'>Updating your local data</Title>
        {progress.phase === 'messages' ? (
          <p>
            Chat messages are being packed into compact logs. This is needed
            once after an update and can take a while for a big chat. Keep this
            tab open.
          </p>
        ) : (
          <p>
            This is needed once after an update and takes a moment. Keep this
            tab open.
          </p>
        )}
        <Bar>
          <ProgressBar
            value={
              counted ? Math.round((progress.done / progress.total) * 100) : 0
            }
          />
        </Bar>
        {counted && (
          <Count aria-live='polite'>
            {progress.done} of {progress.total}
          </Count>
        )}
      </Card>
    </Cover>
  );
}

const Cover = styled.div`
  position: fixed;
  inset: 0;
  z-index: 1000;
  display: grid;
  place-items: center;
  padding: 1rem;
  background-color: ${p => p.theme.colors.bg};
`;

const Card = styled.div`
  display: flex;
  flex-direction: column;
  gap: 1rem;
  width: min(26rem, 100%);
  color: ${p => p.theme.colors.text};
`;

const Title = styled.h1`
  margin: 0;
  font-size: 1.4rem;
`;

const Bar = styled.div`
  display: flex;
`;

const Count = styled.span`
  color: ${p => p.theme.colors.textLight};
  font-variant-numeric: tabular-nums;
`;
