import { useResource, useTitle } from '@tomic/react';
import React from 'react';

import { AtomicLink } from './AtomicLink';
import { styled } from 'styled-components';

interface FilePillProps {
  subject: string;
}

/** Small preview of a file */
function FilePill({ subject }: FilePillProps): JSX.Element {
  const resource = useResource(subject);
  const [title] = useTitle(resource);

  return (
    <FilePillStyled data-test='file-pill'>
      <AtomicLink subject={resource.getSubject()}>
        <span>{title}</span>
      </AtomicLink>
    </FilePillStyled>
  );
}

const FilePillStyled = styled.div`
  display: inline-flex;
  border: solid 1px ${t => t.theme.colors.main};
  border-radius: ${t => t.theme.radius};
  padding: 0.4rem;
  margin-bottom: ${t => t.theme.margin}rem;
  margin-right: ${t => t.theme.margin}rem;
`;

export default FilePill;
