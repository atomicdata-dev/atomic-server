import { core, useArray, useResource, useString } from '@tomic/react';

import { PropertyLineRead } from '../Property/PropertyLineRead';
import { styled } from 'styled-components';
import { FaCube } from 'react-icons/fa6';
import { Column, Row } from '../../../components/Row';
import Markdown from '../../../components/datatypes/Markdown';
import { AtomicLink } from '../../../components/AtomicLink';
import { NewClassInstanceButton } from './NewClassInstanceButton';

import type { JSX } from 'react';
import { TargetableCard } from '../TargetableCard';

interface ClassCardReadProps {
  subject: string;
}

export function ClassCardRead({ subject }: ClassCardReadProps): JSX.Element {
  const resource = useResource(subject);
  const [description] = useString(resource, core.properties.description);
  const [requires] = useArray(resource, core.properties.requires);
  const [recommends] = useArray(resource, core.properties.recommends);

  return (
    <TargetableCard subject={subject}>
      <Column>
        <Row center justify='space-between'>
          <StyledH3>
            <FaCube />
            <AtomicLink subject={subject}>{resource.title}</AtomicLink>
          </StyledH3>
          <NewClassInstanceButton resource={resource} />
        </Row>
        <Markdown text={description ?? ''} maxLength={1500} />
        <StyledH4>Requires</StyledH4>
        <StyledTable>
          {requires.length > 0 ? (
            requires.map(s => (
              <PropertyLineRead key={s} subject={s} classSubject={subject} />
            ))
          ) : (
            <span>none</span>
          )}
        </StyledTable>
        <StyledH4>Recommends</StyledH4>
        <StyledTable>
          {recommends.length > 0 ? (
            recommends.map(s => (
              <PropertyLineRead key={s} subject={s} classSubject={subject} />
            ))
          ) : (
            <span>none</span>
          )}
        </StyledTable>
      </Column>
    </TargetableCard>
  );
}

const StyledH3 = styled.h3`
  display: flex;
  align-items: center;
  gap: 1ch;
  margin-bottom: 0px;
  font-size: 1.5rem;
`;

const StyledH4 = styled.h4`
  margin-bottom: 0px;
`;

const StyledTable = styled.div``;
