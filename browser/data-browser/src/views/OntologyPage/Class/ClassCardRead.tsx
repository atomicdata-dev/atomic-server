import { core, useArray, useResource, useString } from '@tomic/react';

import { Card } from '../../../components/Card';
import { PropertyLineRead } from '../Property/PropertyLineRead';
import { styled } from 'styled-components';
import { FaCube } from 'react-icons/fa';
import { Column, Row } from '../../../components/Row';
import Markdown from '../../../components/datatypes/Markdown';
import { AtomicLink } from '../../../components/AtomicLink';
import { toAnchorId } from '../toAnchorId';
import { ViewTransitionProps } from '../../../helpers/ViewTransitionProps';
import { transitionName } from '../../../helpers/transitionName';
import { NewClassInstanceButton } from './NewClassInstanceButton';

interface ClassCardReadProps {
  subject: string;
}

export function ClassCardRead({ subject }: ClassCardReadProps): JSX.Element {
  const resource = useResource(subject);
  const [description] = useString(resource, core.properties.description);
  const [requires] = useArray(resource, core.properties.requires);
  const [recommends] = useArray(resource, core.properties.recommends);

  return (
    <StyledCard subject={subject}>
      <Column>
        <Row center justify='space-between'>
          <StyledH3 id={toAnchorId(subject)}>
            <FaCube />
            <AtomicLink subject={subject}>{resource.title}</AtomicLink>
          </StyledH3>
          <NewClassInstanceButton resource={resource} />
        </Row>
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
  );
}

const StyledCard = styled(Card)<ViewTransitionProps>`
  padding-bottom: ${p => p.theme.margin}rem;
  ${props => transitionName('resource-page', props.subject)};
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
