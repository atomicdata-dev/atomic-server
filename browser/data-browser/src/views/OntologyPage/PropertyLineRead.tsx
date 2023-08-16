import { urls, useResource, useString } from '@tomic/react';
import React from 'react';
import styled from 'styled-components';
import Markdown from '../../components/datatypes/Markdown';
import { InlineDatatype } from './InlineDatatype';

interface PropertyLineReadProps {
  subject: string;
}

export function PropertyLineRead({
  subject,
}: PropertyLineReadProps): JSX.Element {
  const resource = useResource(subject);
  const [description] = useString(resource, urls.properties.description);

  return (
    <tr>
      <StyledTd>{resource.title}</StyledTd>
      <StyledTd>
        <InlineDatatype resource={resource} />
      </StyledTd>
      <StyledTd>
        <Markdown text={description ?? ''} />
      </StyledTd>
    </tr>
  );
}

const StyledTd = styled.td`
  padding-inline: 0.5rem;
  padding-block: 0.4rem;
  vertical-align: top;
`;
