import React, { useState, type CSSProperties, type JSX, type ReactNode } from 'react';
import { styled } from 'styled-components';
import { createPortal } from 'react-dom';
import {
  DndContext,
  DragEndEvent,
  DragOverlay,
  DragStartEvent,
  closestCenter,
} from '@dnd-kit/core';
import {
  SortableContext,
  arrayMove,
  horizontalListSortingStrategy,
  useSortable,
  verticalListSortingStrategy,
} from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import { FaGripVertical } from 'react-icons/fa6';
import { useDragSensors } from '../TableEditor/hooks/useDragSensors';

interface ReorderableListProps {
  subjects: string[];
  onReorder: (next: string[]) => void;
  renderItem: (subject: string, index: number) => ReactNode;
  disabled?: boolean;
  orientation?: 'vertical' | 'horizontal';
}

/**
 * Drag-handle reordering for a plain list of subjects, built on
 * `@dnd-kit/sortable` so the rest of the list smoothly slides out of the way
 * to preview where the dragged item will land, and a floating `DragOverlay`
 * previews the item being picked up. Backs both the page tab bar and the
 * field list.
 */
export function ReorderableList({
  subjects,
  onReorder,
  renderItem,
  disabled,
  orientation = 'vertical',
}: ReorderableListProps): JSX.Element {
  const [activeSubject, setActiveSubject] = useState<string>();
  const [activeWidth, setActiveWidth] = useState<number>();
  const sensors = useDragSensors();

  const handleDragStart = ({ active }: DragStartEvent) => {
    setActiveSubject(active.id as string);
    setActiveWidth(active.rect.current.initial?.width);
  };

  const handleDragCancel = () => {
    setActiveSubject(undefined);
    setActiveWidth(undefined);
  };

  const handleDragEnd = ({ active, over }: DragEndEvent) => {
    setActiveSubject(undefined);
    setActiveWidth(undefined);

    if (!over || active.id === over.id) {
      return;
    }

    const oldPos = subjects.indexOf(active.id as string);
    const newPos = subjects.indexOf(over.id as string);

    if (oldPos === -1 || newPos === -1) {
      return;
    }

    onReorder(arrayMove(subjects, oldPos, newPos));
  };

  return (
    <DndContext
      sensors={sensors}
      collisionDetection={closestCenter}
      onDragStart={handleDragStart}
      onDragCancel={handleDragCancel}
      onDragEnd={handleDragEnd}
    >
      <SortableContext
        items={subjects}
        strategy={
          orientation === 'horizontal'
            ? horizontalListSortingStrategy
            : verticalListSortingStrategy
        }
      >
        <ListContainer $orientation={orientation}>
          {subjects.map((subject, index) => (
            <SortableRow
              key={subject}
              subject={subject}
              disabled={disabled}
              orientation={orientation}
            >
              {renderItem(subject, index)}
            </SortableRow>
          ))}
        </ListContainer>
      </SortableContext>
      {createPortal(
        <DragOverlay dropAnimation={null}>
          {activeSubject && (
            <DragPreview
              $orientation={orientation}
              style={
                orientation === 'vertical' && activeWidth
                  ? { width: activeWidth }
                  : undefined
              }
            >
              <DragHandle type="button" tabIndex={-1}>
                <FaGripVertical />
              </DragHandle>
              <RowContent $orientation={orientation}>
                {renderItem(activeSubject, subjects.indexOf(activeSubject))}
              </RowContent>
            </DragPreview>
          )}
        </DragOverlay>,
        document.body,
      )}
    </DndContext>
  );
}

interface SortableRowProps {
  subject: string;
  disabled?: boolean;
  orientation: 'vertical' | 'horizontal';
  children: ReactNode;
}

function SortableRow({
  subject,
  disabled,
  orientation,
  children,
}: SortableRowProps): JSX.Element {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition: sortTransition,
    isDragging,
  } = useSortable({ id: subject, disabled });

  const style: CSSProperties = {
    transform: CSS.Transform.toString(transform),
    transition: sortTransition,
    zIndex: isDragging ? 1 : undefined,
  };

  return (
    <RowWrapper
      ref={setNodeRef}
      style={style}
      $dragging={isDragging}
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

const ListContainer = styled.div<{
  $orientation: 'vertical' | 'horizontal';
}>`
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

const DragPreview = styled.div<{ $orientation: 'vertical' | 'horizontal' }>`
  display: flex;
  align-items: center;
  gap: 0.4rem;
  cursor: grabbing;
  pointer-events: none;
  filter: drop-shadow(0 4px 10px rgba(0, 0, 0, 0.15));

  ${DragHandle} svg {
    color: ${p => p.theme.colors.textLight};
  }
`;
