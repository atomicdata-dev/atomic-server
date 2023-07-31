import { useDroppable } from '@dnd-kit/core';
import React from 'react';
import styled from 'styled-components';
import { transition } from '../../helpers/transition';
import { transparentize } from 'polished';

interface ReorderDropAreaProps {
  index: number;
}

export function ReorderDropArea({ index }: ReorderDropAreaProps) {
  const { setNodeRef, isOver } = useDroppable({
    id: `droppable-${index}`,
    data: { index },
  });

  return <ReorderDropZone ref={setNodeRef} hover={isOver} />;
}

const ReorderDropZone = styled.div<{ hover: boolean }>`
  --dropzone-width: 0.4rem;
  position: absolute;
  background-color: ${p => p.theme.colors.main};
  opacity: 0.4;
  width: var(--dropzone-width);
  height: min(
    var(--table-height),
    var(--table-content-height) + var(--table-row-height)
  );
  top: 0;
  left: calc(var(--dropzone-width) * 0.5 * -1);
  z-index: 10;
  box-shadow: 0 0 7px 0 ${p => transparentize(0.3, p.theme.colors.main)};
  transform: scaleX(${p => (p.hover ? 1 : 0)});
  ${transition('transform', 'opacity')}
`;
