import React, { useState, type JSX, type ReactNode } from 'react';
import { styled } from 'styled-components';
import {
  DndContext,
  DragEndEvent,
  useDraggable,
  useDroppable,
} from '@dnd-kit/core';
import { FaGripVertical } from 'react-icons/fa6';
import { useDragSensors } from '../TableEditor/hooks/useDragSensors';
import { transition } from '../../helpers/transition';

interface ReorderableListProps {
  subjects: string[];
  onReorder: (next: string[]) => void;
  renderItem: (subject: string, index: number) => ReactNode;
  disabled?: boolean;
  orientation?: 'vertical' | 'horizontal';
}

/**
 * Drag-handle + drop-edge reordering for a plain list of subjects, following
 * the same idiom as `InputResourceArray` (the only drag-and-drop pattern used
 * anywhere in this codebase) but content-agnostic so it can back both the
 * page tab bar and the field list.
 */
export function ReorderableList({
  subjects,
  onReorder,
  renderItem,
  disabled,
  orientation = 'vertical',
}: ReorderableListProps): JSX.Element {
  const [draggingSubject, setDraggingSubject] = useState<string>();
  const sensors = useDragSensors();

  const handleDragEnd = ({ active, over }: DragEndEvent) => {
    setDraggingSubject(undefined);

    if (!over) {
      return;
    }

    const oldPos = subjects.indexOf(active.id as string);
    const newPos = over.id as number;

    if (oldPos === -1 || oldPos === newPos) {
      return;
    }

    const next = [...subjects];
    const [removed] = next.splice(oldPos, 1);
    next.splice(newPos > oldPos ? newPos - 1 : newPos, 0, removed);
    onReorder(next);
  };

  return (
    <DndContext
      sensors={sensors}
      onDragStart={event => setDraggingSubject(event.active.id as string)}
      onDragCancel={() => setDraggingSubject(undefined)}
      onDragEnd={handleDragEnd}
    >
      <RelativeContainer $orientation={orientation}>
        <DropEdge
          visible={!!draggingSubject}
          index={0}
          orientation={orientation}
        />
        {subjects.map((subject, index) => (
          <React.Fragment key={subject}>
            <DraggableRow
              subject={subject}
              disabled={disabled}
              dragging={draggingSubject === subject}
              orientation={orientation}
            >
              {renderItem(subject, index)}
            </DraggableRow>
            <DropEdge
              visible={!!draggingSubject}
              index={index + 1}
              orientation={orientation}
            />
          </React.Fragment>
        ))}
      </RelativeContainer>
    </DndContext>
  );
}

interface DraggableRowProps {
  subject: string;
  disabled?: boolean;
  dragging: boolean;
  orientation: 'vertical' | 'horizontal';
  children: ReactNode;
}

function DraggableRow({
  subject,
  disabled,
  dragging,
  orientation,
  children,
}: DraggableRowProps): JSX.Element {
  const { attributes, listeners, setNodeRef } = useDraggable({
    id: subject,
    disabled,
  });

  return (
    <RowWrapper
      ref={setNodeRef}
      $dragging={dragging}
      $orientation={orientation}
    >
      {!disabled && (
        <DragHandle
          {...listeners}
          {...attributes}
          type="button"
          title="Move item"
        >
          <FaGripVertical />
        </DragHandle>
      )}
      <RowContent $orientation={orientation}>{children}</RowContent>
    </RowWrapper>
  );
}

interface DropEdgeProps {
  index: number;
  visible: boolean;
  orientation: 'vertical' | 'horizontal';
}

function DropEdge({ index, visible, orientation }: DropEdgeProps): JSX.Element {
  const { setNodeRef, isOver } = useDroppable({ id: index });

  return (
    <DropEdgeElement
      ref={setNodeRef}
      active={isOver}
      visible={visible}
      $orientation={orientation}
    />
  );
}

const RelativeContainer = styled.div<{
  $orientation: 'vertical' | 'horizontal';
}>`
  position: relative;
  display: flex;
  flex-direction: ${p => (p.$orientation === 'horizontal' ? 'row' : 'column')};
  ${p => p.$orientation === 'horizontal' && 'align-items: center;'}
  gap: ${p => (p.$orientation === 'horizontal' ? '0' : '0.5rem')};
`;

const RowWrapper = styled.div<{
  $dragging: boolean;
  $orientation: 'vertical' | 'horizontal';
}>`
  display: flex;
  align-items: center;
  gap: 0.4rem;
  opacity: ${p => (p.$dragging ? 0.4 : 1)};
  ${p => (p.$orientation === 'vertical' ? 'width: 100%;' : '')}
`;

const RowContent = styled.div<{ $orientation: 'vertical' | 'horizontal' }>`
  ${p => (p.$orientation === 'vertical' ? 'flex: 1;' : '')}
  min-width: 0;
`;

const DragHandle = styled.button`
  display: flex;
  align-items: center;
  cursor: grab;
  appearance: none;
  background: transparent;
  border: none;
  flex-shrink: 0;

  &:active {
    cursor: grabbing;
  }

  svg {
    color: ${p => p.theme.colors.textLight2};
  }

  &:hover svg {
    color: ${p => p.theme.colors.textLight};
  }
`;

const DropEdgeElement = styled.div<{
  visible: boolean;
  active: boolean;
  $orientation: 'vertical' | 'horizontal';
}>`
  display: ${p => (p.visible ? 'block' : 'none')};
  flex-shrink: 0;
  border-radius: 1.5px;
  background: ${p => p.theme.colors.main};
  opacity: ${p => (p.active ? 1 : 0)};

  ${p =>
    p.$orientation === 'horizontal'
      ? `
    width: 3px;
    height: 1.8rem;
    margin: 0 0.15rem;
    transform: scaleY(${p.active ? 1.1 : 1});
  `
      : `
    height: 3px;
    width: 100%;
    transform: scaleX(${p.active ? 1.1 : 1});
  `}

  ${transition('opacity', 'transform')}
`;
