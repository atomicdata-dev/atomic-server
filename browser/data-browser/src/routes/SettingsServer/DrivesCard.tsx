import React from 'react';
import NewIntanceButton from '../../components/NewInstanceButton';
import { Card, CardInsideFull, CardRow } from '../../components/Card';
import { urls } from '@tomic/react';
import styled from 'styled-components';
import { useSettings } from '../../helpers/AppSettings';
import { DriveRow } from './DriveRow';

export interface DriveCardProps {
  drives: string[];
  onDriveSelect: (drive: string) => void;
  showNewOption?: boolean;
}

export function DrivesCard({
  drives,
  onDriveSelect,
  showNewOption,
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
                onClick={onDriveSelect}
                disabled={subject === drive}
              />
            </CardRow>
          );
        })}
        {showNewOption && (
          <CardRow>
            <StyledNewInstanceButton
              klass={urls.classes.drive}
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
  padding-top: 0;
`;

const StyledNewInstanceButton = styled(NewIntanceButton)`
  border: none;
  box-shadow: none;
  padding: 0;

  &&:hover,
  &&:focus {
    box-shadow: none;
  }
`;
