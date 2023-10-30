import { urls, useResource, useString } from '@tomic/react';
import React from 'react';
import { styled } from 'styled-components';
import Markdown from '../../../components/datatypes/Markdown';
import { InlineDatatype } from '../InlineDatatype';
import { ErrorLook } from '../../../components/ErrorLook';

interface PropertyLineReadProps {
  subject: string;
}

export function PropertyLineRead({
  subject,
}: PropertyLineReadProps): JSX.Element {
  const resource = useResource(subject);
  const [description] = useString(resource, urls.properties.description);

  if (resource.error) {
    return (
      <tr>
        <ErrorLook>Property does not exist anymore</ErrorLook>
      </tr>
    );
  }

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
