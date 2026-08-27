import React, {
  useState,
  type CSSProperties,
  type JSX,
  type ReactNode,
} from 'react';
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

/**
 * Handed to `renderItem` so an item can host its own grip instead of the
 * external one. Only used when `handle` is `'custom'`.
 */
export interface ItemDragProps {
  /**
   * Spread on the element that acts as the visible grip. Carries the keyboard
   * activator and the ARIA wiring, so keyboard reordering keeps working even
   * when the grip is only revealed on hover.
   */
  handleProps: Record<string, unknown>;
  /**
   * Spread on the item as a whole so it can be dragged from anywhere. Pointer
   * activators only: a pointer press on the grip bubbles up to here, so the
   * drag activates exactly once whichever of the two was pressed.
   */
  itemProps: Record<string, unknown>;
  isDragging: boolean;
}

const OVERLAY_DRAG_PROPS: ItemDragProps = {
  handleProps: {},
  itemProps: {},
  isDragging: true,
};

interface ReorderableListProps {
  subjects: string[];
  onReorder: (next: string[]) => void;
  renderItem: (
    subject: string,
    index: number,
    drag: ItemDragProps,
  ) => ReactNode;
  disabled?: boolean;
  orientation?: 'vertical' | 'horizontal';
  /**
   * `'external'` puts an always-visible grip next to the item. `'custom'`
   * renders no grip at all and hands the drag props to `renderItem`, letting
   * the item place (and hide) its own.
   */
  handle?: 'external' | 'custom';
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
  handle = 'external',
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
              handle={handle}
            >
              {drag => renderItem(subject, index, drag)}
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
              {handle === 'external' && (
                <DragHandle type='button' tabIndex={-1}>
                  <FaGripVertical />
                </DragHandle>
              )}
              <RowContent $orientation={orientation}>
                {renderItem(
                  activeSubject,
                  subjects.indexOf(activeSubject),
                  OVERLAY_DRAG_PROPS,
                )}
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
  handle: 'external' | 'custom';
  children: (drag: ItemDragProps) => ReactNode;
}

function SortableRow({
  subject,
  disabled,
  orientation,
  handle,
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

  const drag: ItemDragProps = {
    handleProps: { ...attributes, onKeyDown: listeners?.onKeyDown },
    itemProps: {
      onMouseDown: listeners?.onMouseDown,
      onTouchStart: listeners?.onTouchStart,
    },
    isDragging,
  };

  return (
    <RowWrapper
      ref={setNodeRef}
      style={style}
      $dragging={isDragging}
      $orientation={orientation}
    >
      {handle === 'external' && !disabled && (
        <DragHandle
          {...listeners}
          {...attributes}
          type='button'
          title='Move item'
        >
          <FaGripVertical />
        </DragHandle>
      )}
      <RowContent $orientation={orientation}>{children(drag)}</RowContent>
    </RowWrapper>
  );
}

const ListContainer = styled.div<{
  $orientation: 'vertical' | 'horizontal';
}>`
  display: flex;
  flex-direction: ${p => (p.$orientation === 'horizontal' ? 'row' : 'column')};
  ${p => p.$orientation === 'horizontal' && 'align-items: stretch;'}
  gap: ${p => (p.$orientation === 'horizontal' ? '0' : '0.5rem')};
`;

const RowWrapper = styled.div<{
  $dragging: boolean;
  $orientation: 'vertical' | 'horizontal';
}>`
  display: flex;
  align-items: ${p => (p.$orientation === 'horizontal' ? 'stretch' : 'center')};
  gap: ${p => (p.$orientation === 'horizontal' ? '0' : '0.4rem')};
  opacity: ${p => (p.$dragging ? 0.4 : 1)};
  ${p => (p.$orientation === 'vertical' ? 'width: 100%;' : '')}
`;

const RowContent = styled.div<{ $orientation: 'vertical' | 'horizontal' }>`
  ${p => (p.$orientation === 'vertical' ? 'flex: 1;' : 'display: flex;')}
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
