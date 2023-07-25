import React from 'react';
import { Resource } from '@tomic/react';
import AllProps from '../AllProps';
import styled from 'styled-components';

type Props = {
  resource: Resource;
};

/** Renders a Date value */
function Nestedresource({ resource }: Props): JSX.Element {
  return (
    <NestedWrapper>
      <AllProps resource={resource} />
    </NestedWrapper>
  );
}

const NestedWrapper = styled.div`
  margin-left: ${p => p.theme.margin}rem;
`;

export default Nestedresource;
