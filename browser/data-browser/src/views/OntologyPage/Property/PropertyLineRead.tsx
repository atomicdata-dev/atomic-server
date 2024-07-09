import { urls, useResource, useString } from '@tomic/react';

import { styled } from 'styled-components';
import Markdown from '../../../components/datatypes/Markdown';
import { InlineDatatype } from '../InlineDatatype';
import { ErrorLook } from '../../../components/ErrorLook';
import { CARD_CONTAINER } from '../../../helpers/containers';

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
    <SubGrid>
      <PropTitle>{resource.title}</PropTitle>
      <DatatypeSlot>
        <InlineDatatype resource={resource} />
      </DatatypeSlot>
      <MarkdownWrapper>
        <Markdown text={description ?? ''} />
      </MarkdownWrapper>
    </SubGrid>
  );
}

const SubGrid = styled.div`
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 1rem;
  padding: ${p => p.theme.size()};
  border-radius: ${p => p.theme.radius};

  @container ${CARD_CONTAINER} (inline-size < 400px) {
    grid-template-columns: 1fr;
  }

  &:nth-child(odd) {
    background-color: ${p => p.theme.colors.bg1};
  }
`;

const MarkdownWrapper = styled.span`
  @container ${CARD_CONTAINER} (inline-size > 400px) {
    grid-column: 1 / 3;
  }

  color: ${({ theme }) => theme.colors.textLight};
  padding-bottom: 0.5rem;
`;

const PropTitle = styled.span`
  font-weight: bold;
`;

const DatatypeSlot = styled.span`
  @container ${CARD_CONTAINER} (inline-size > 400px) {
    justify-self: end;
  }
`;
