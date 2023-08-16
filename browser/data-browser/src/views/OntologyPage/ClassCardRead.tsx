import { urls, useArray, useResource, useString } from '@tomic/react';
import React from 'react';
import { Card } from '../../components/Card';
import { PropertyLineRead } from './PropertyLineRead';
import styled from 'styled-components';
import { FaCube } from 'react-icons/fa';
import { Column } from '../../components/Row';
import Markdown from '../../components/datatypes/Markdown';
import { AtomicLink } from '../../components/AtomicLink';

interface ClassCardReadProps {
  subject: string;
}

export function ClassCardRead({ subject }: ClassCardReadProps): JSX.Element {
  const resource = useResource(subject);
  const [description] = useString(resource, urls.properties.description);
  const [requires] = useArray(resource, urls.properties.requires);
  const [recommends] = useArray(resource, urls.properties.recommends);

  return (
    <StyledLi>
      <StyledCard>
        <Column>
          <StyledH3 id={`list-item-${subject}`}>
            <FaCube />
            <AtomicLink subject={subject}>{resource.title}</AtomicLink>
          </StyledH3>
          <Markdown text={description ?? ''} maxLength={1500} />
          <StyledH4>Requires</StyledH4>
          <StyledTable>
            {requires.length > 0 ? (
              requires.map(s => <PropertyLineRead key={s} subject={s} />)
            ) : (
              <span>none</span>
            )}
          </StyledTable>
          <StyledH4>Recommends</StyledH4>
          <StyledTable>
            {recommends.length > 0 ? (
              recommends.map(s => <PropertyLineRead key={s} subject={s} />)
            ) : (
              <span>none</span>
            )}
          </StyledTable>
        </Column>
      </StyledCard>
    </StyledLi>
  );
}

const StyledCard = styled(Card)`
  padding-bottom: ${p => p.theme.margin}rem;
`;

const StyledLi = styled.li`
  margin-left: 0px;
  list-style: none;
`;

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

const StyledTable = styled.table`
  border-collapse: collapse;
`;
