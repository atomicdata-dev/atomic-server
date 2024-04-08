import { NewInstanceButton } from '../../components/NewInstanceButton';
import { Card, CardInsideFull, CardRow } from '../../components/Card';
import { server } from '@tomic/react';
import { styled } from 'styled-components';
import { useSettings } from '../../helpers/AppSettings';
import { DriveRow } from './DriveRow';

export interface DriveCardProps {
  drives: string[];
  showNewOption?: boolean;
  onDriveSelect: (drive: string) => void;
  onDriveRemove?: (drive: string) => void;
}

export function DrivesCard({
  drives,
  showNewOption,
  onDriveSelect,
  onDriveRemove,
}: DriveCardProps): JSX.Element {
  const { drive } = useSettings();

  if (drives.length === 0) {
    return <span>Nothing to show</span>;
  }

  return (
    <ContainerCard>
      <CardInsideFull>
        {drives.map((subject, i) => {
          return (
            <CardRow key={subject} noBorder={i === 0}>
              <DriveRow
                subject={subject}
                disabled={subject === drive}
                onRemove={onDriveRemove}
                onClick={onDriveSelect}
              />
            </CardRow>
          );
        })}
        {showNewOption && (
          <CardRow>
            <StyledNewInstanceButton
              klass={server.classes.drive}
              subtle
              icon
              label='New Drive'
            />
          </CardRow>
        )}
      </CardInsideFull>
    </ContainerCard>
  );
}

const ContainerCard = styled(Card)`
  container-type: inline-size;
  padding-block: 0;
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
