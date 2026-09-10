import { NewInstanceButton } from '../../components/NewInstanceButton';
import { Card } from '../../components/Card';
import { server } from '@tomic/react';
import { styled } from 'styled-components';
import { useSettings } from '../../helpers/AppSettings';
import { DriveRow } from './DriveRow';

import type { JSX } from 'react';

export interface DriveCardProps {
  drives: string[];
  labels?: Record<string, string>;
  /** Lets a test name this list, since two of them render on the same page. */
  testId?: string;
  /** Which of these, if any, is the user's private drive. */
  privateDrive?: string;
  showNewOption?: boolean;
  hideFavorite?: boolean;
  onDriveSelect: (drive: string) => void;
  onDriveRemove?: (drive: string) => void;
}

/**
 * The list of drives, one of which is the one you are on.
 *
 * Lays out its own rows rather than reaching for CardRow, which is built for
 * blocks of content and pads accordingly — two rows of one word each came out
 * taller than the heading above them. CardInsideFull then pulled the rows wider
 * than their own padding, so the dividing line stopped short at both ends.
 */
export function DrivesCard({
  drives,
  labels,
  testId,
  privateDrive,
  showNewOption,
  hideFavorite,
  onDriveSelect,
  onDriveRemove,
}: DriveCardProps): JSX.Element {
  const { drive } = useSettings();

  if (drives.length === 0 && !showNewOption) {
    return <span data-testid={testId}>Nothing to show</span>;
  }

  return (
    <ContainerCard data-testid={testId}>
      <List role='radiogroup' aria-label='Drives'>
        {drives.map(subject => (
          <DriveRow
            key={subject}
            subject={subject}
            label={labels?.[subject]}
            selected={subject === drive}
            isPrivate={subject === privateDrive}
            // Never unstarrable: it is not in the list by choice, and a star
            // that removes your home is a trap.
            hideFavorite={hideFavorite || subject === privateDrive}
            onRemove={onDriveRemove}
            onClick={onDriveSelect}
          />
        ))}
      </List>
      {showNewOption && (
        <NewRow>
          <StyledNewInstanceButton
            klass={server.classes.drive}
            subtle
            icon
            label='New Drive'
          />
        </NewRow>
      )}
    </ContainerCard>
  );
}

const ContainerCard = styled(Card)`
  container-type: inline-size;
  padding: 0;
  overflow: hidden;
`;

/**
 * Rows divide themselves, so the line runs the full width of the card. Nothing
 * here sets inline padding: each row pays its own, which is what lets a row's
 * hover state reach both edges.
 */
const List = styled.div`
  display: flex;
  flex-direction: column;

  > * + * {
    border-top: solid 1px ${p => p.theme.colors.bg2};
  }
`;

const NewRow = styled.div`
  border-top: solid 1px ${p => p.theme.colors.bg2};
  padding: 0.5rem 0.75rem;
`;

const StyledNewInstanceButton = styled(NewInstanceButton)`
  border: none;
  box-shadow: none;
  padding: 0;

  &&:hover,
  &&:focus {
    box-shadow: none;
  }
`;
