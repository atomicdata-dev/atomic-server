import React from 'react';
import styled from 'styled-components';
import { AllPropsSimple } from '../../../components/AllPropsSimple';
import { GridItemViewProps } from './GridItemViewProps';

export function DefaultGridItem({ resource }: GridItemViewProps): JSX.Element {
  return (
    <DefaultGridWrapper>
      <AllPropsSimple resource={resource} />
    </DefaultGridWrapper>
  );
}

const DefaultGridWrapper = styled.div`
  padding: ${p => p.theme.margin}rem;
  pointer-events: none;
`;
