import { useDndMonitor, useDroppable } from '@dnd-kit/core';
import { styled } from 'styled-components';
import { useState } from 'react';
import { transition } from '../../../helpers/transition';
import { SideBarDropData } from '../useSidebarDnd';
import { useCanWrite, useResource } from '@tomic/react';
import { SIDEBAR_WIDTH_PROP } from '../SidebarCSSVars';

interface DropEdgeProps {
  parentHierarchy: string[];
  position: number;
}

export function DropEdge({
  parentHierarchy,
  position,
}: DropEdgeProps): React.JSX.Element {
  if (parentHierarchy.length === 0) {
    throw new Error('renderedHierargy should not be empty');
  }

  const [activeDraggedSubject, setDraggingSubject] = useState<string>();

  const parent = parentHierarchy.at(-1)!;

  const parentResource = useResource(parent);

  const [canWrite] = useCanWrite(parentResource);
  useDndMonitor({
    onDragStart: event => setDraggingSubject(event.active.id as string),
    onDragEnd: () => setDraggingSubject(undefined),
  });

  const data: SideBarDropData = {
    parent,
    position,
  };

  const { setNodeRef, isOver } = useDroppable({
    id: `${parent}-${position}`,
    data,
  });

  if (!canWrite) {
    return <></>;
  }

  const shouldRender =
    !!activeDraggedSubject && !parentHierarchy.includes(activeDraggedSubject);

  return (
    <DropEdgeElement ref={setNodeRef} active={isOver} visible={shouldRender} />
  );
}

const DropEdgeElement = styled.div<{ visible: boolean; active: boolean }>`
  display: ${p => (p.visible ? 'block' : 'none')};
  position: absolute;
  left: 0;
  height: 3px;
  border-radius: 1.5px;
  transform: scaleX(${p => (p.active ? 1 : 0.9)});
  background: ${p => p.theme.colors.main};
  opacity: ${p => (p.active ? 1 : 0)};
  z-index: 2;
  width: calc(var(${SIDEBAR_WIDTH_PROP}) - 2rem);

  ${transition('opacity', 'transform')}
`;
