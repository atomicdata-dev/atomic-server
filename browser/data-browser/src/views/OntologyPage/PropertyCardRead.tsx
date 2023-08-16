import React from 'react';
import { Card } from '../../components/Card';
import { urls, useArray, useResource, useString } from '@tomic/react';
import { FaHashtag } from 'react-icons/fa';
import styled from 'styled-components';
import Markdown from '../../components/datatypes/Markdown';
import { Column, Row } from '../../components/Row';
import { InlineFormattedResourceList } from '../../components/InlineFormattedResourceList';
import { InlineDatatype } from './InlineDatatype';
import { AtomicLink } from '../../components/AtomicLink';

interface PropertyCardReadProps {
  subject: string;
}

export function PropertyCardRead({
  subject,
}: PropertyCardReadProps): JSX.Element {
  const resource = useResource(subject);
  const [description] = useString(resource, urls.properties.description);
  const [allowsOnly] = useArray(resource, urls.properties.allowsOnly);

  return (
    <StyledCard id={`list-item-${subject}`}>
      <Column>
        <Row center justify='space-between'>
          <Heading>
            <FaHashtag />
            <AtomicLink subject={subject}>{resource.title}</AtomicLink>
          </Heading>
          <InlineDatatype resource={resource} />
        </Row>
        <Markdown text={description ?? ''} />
        {allowsOnly.length > 0 && (
          <>
            <SubHeading>Allows only:</SubHeading>
            <div>
              <InlineFormattedResourceList subjects={allowsOnly} />
            </div>
          </>
        )}
      </Column>
    </StyledCard>
  );
}

const Heading = styled.h3`
  display: flex;
  align-items: center;
  gap: 1ch;
  margin-bottom: 0px;
  font-size: 1.5rem;
`;

const SubHeading = styled.h4`
  margin-bottom: 0px;
`;

const StyledCard = styled(Card)`
  padding-bottom: ${p => p.theme.margin}rem;
`;
