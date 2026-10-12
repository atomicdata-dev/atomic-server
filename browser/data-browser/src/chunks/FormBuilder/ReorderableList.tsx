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
  /** Space between items. Vertical lists only. */
  gap?: string;
  /**
   * Where the external grip sits on a vertical item. `'center'` (the default)
   * centers it against the whole item; `'start'` pins it to the item's first
   * input row, for items that grow taller than one line.
   */
  align?: 'center' | 'start';
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
  gap,
  align = 'center',
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
        <ListContainer $orientation={orientation} $gap={gap}>
          {subjects.map((subject, index) => (
            <SortableRow
              key={subject}
              subject={subject}
              disabled={disabled}
              orientation={orientation}
              handle={handle}
              align={align}
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
              $align={align}
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
  align: 'center' | 'start';
  children: (drag: ItemDragProps) => ReactNode;
}

function SortableRow({
  subject,
  disabled,
  orientation,
  handle,
  align,
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
      $align={align}
    >
      {handle === 'external' && !disabled && (
        <DragHandle
          $align={align}
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
  $gap?: string;
}>`
  display: flex;
  flex-direction: ${p => (p.$orientation === 'horizontal' ? 'row' : 'column')};
  ${p => p.$orientation === 'horizontal' && 'align-items: stretch;'}
  gap: ${p => (p.$orientation === 'horizontal' ? '0' : (p.$gap ?? '0.5rem'))};
`;

const RowWrapper = styled.div<{
  $dragging: boolean;
  $orientation: 'vertical' | 'horizontal';
  $align: 'center' | 'start';
}>`
  display: flex;
  align-items: ${p =>
    p.$orientation === 'horizontal'
      ? 'stretch'
      : p.$align === 'start'
        ? 'flex-start'
        : 'center'};
  gap: ${p => (p.$orientation === 'horizontal' ? '0' : '0.4rem')};
  opacity: ${p => (p.$dragging ? 0.4 : 1)};
  ${p => (p.$orientation === 'vertical' ? 'width: 100%;' : '')}
`;

const RowContent = styled.div<{ $orientation: 'vertical' | 'horizontal' }>`
  ${p => (p.$orientation === 'vertical' ? 'flex: 1;' : 'display: flex;')}
  min-width: 0;
`;

const DragHandle = styled.button<{ $align?: 'center' | 'start' }>`
  display: flex;
  align-items: center;
  /* Matches the height of a single input row, so a grip pinned to the start of
     a multi-line item still lines up with that item's first input. */
  ${p => p.$align === 'start' && 'height: 2rem;'}
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

const DragPreview = styled.div<{
  $orientation: 'vertical' | 'horizontal';
  $align: 'center' | 'start';
}>`
  display: flex;
  align-items: ${p => (p.$align === 'start' ? 'flex-start' : 'center')};
  gap: 0.4rem;
  cursor: grabbing;
  pointer-events: none;
  filter: drop-shadow(0 4px 10px rgba(0, 0, 0, 0.15));

  ${DragHandle} svg {
    color: ${p => p.theme.colors.textLight};
  }
`;
