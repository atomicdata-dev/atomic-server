import React, { useCallback } from 'react';
import { styled } from 'styled-components';
import {
  TableHeading,
  TableHeadingDummy,
  TableHeadingWrapper,
} from './TableHeading';
import { TableRow } from './TableRow';
import {
  DragEndEvent,
  DragOverlay,
  DragStartEvent,
  useDndMonitor,
} from '@dnd-kit/core';
import { createPortal } from 'react-dom';
import { ColumnReorderHandler } from './types';
import { ReorderDropArea } from './ReorderDropArea';

export type TableHeadingComponent<T> = ({
  column,
}: {
  column: T;
}) => JSX.Element;

export interface TableHeaderProps<T> {
  columns: T[];
  onResize: (index: number, size: string) => void;
  columnToKey: (column: T) => string;
  onColumnReorder?: ColumnReorderHandler;
  HeadingComponent: TableHeadingComponent<T>;
  NewColumnButtonComponent: React.ComponentType;
  headerRef: React.Ref<HTMLDivElement>;
}

/** The entire first row of an Editable Table. */
export function TableHeader<T>({
  columns,
  onResize,
  columnToKey,
  onColumnReorder,
  HeadingComponent,
  NewColumnButtonComponent,
  headerRef,
}: TableHeaderProps<T>): JSX.Element {
  const [activeIndex, setActiveIndex] = React.useState<number | undefined>();

  const handleDragStart = useCallback(
    (event: DragStartEvent) => {
      const key = columns.map(columnToKey).indexOf(event.active.id as string);
      setActiveIndex(key);

      document.body.style.cursor = 'grabbing';
    },
    [columns, columnToKey],
  );

  const handleDragEnd = useCallback(
    ({ active, over }: DragEndEvent) => {
      setActiveIndex(undefined);
      document.body.style.cursor = 'unset';

      if (over) {
        const draggableIndex = active.data.current!.index as number;
        let droppapleIndex = over.data.current!.index as number;

        if (
          draggableIndex === droppapleIndex ||
          draggableIndex + 1 === droppapleIndex
        ) {
          return;
        }

        if (droppapleIndex > draggableIndex) {
          droppapleIndex -= 1;
        }

        onColumnReorder?.(draggableIndex, droppapleIndex);
      }
    },
    [onColumnReorder],
  );

  // We use the DndMonitor here instead of the DndContext because the
  // context creates an aria - live element that is not allowed inside something with role = 'grid'
  useDndMonitor({
    onDragStart: handleDragStart,
    onDragEnd: handleDragEnd,
  });

  return (
    <div role='rowgroup'>
      <StyledTableRow ref={headerRef} aria-rowindex={1}>
        <TableHeadingWrapper align='end' aria-colindex={1} role='columnheader'>
          #
        </TableHeadingWrapper>
        {columns.map((column, index) => (
          <TableHeading
            key={columnToKey(column)}
            dragKey={columnToKey(column)}
            index={index}
            onResize={onResize}
            isReordering={activeIndex !== undefined}
          >
            <HeadingComponent column={column} />
          </TableHeading>
        ))}
        <TableHeadingWrapper aria-colindex={columns.length + 2}>
          <ReorderDropArea index={columns.length} />
          <NewColumnButtonComponent />
        </TableHeadingWrapper>
      </StyledTableRow>
      {createPortal(
        <StyledDragOverlay>
          {activeIndex !== undefined && (
            <TableHeadingDummy>
              <HeadingComponent column={columns[activeIndex]} />
            </TableHeadingDummy>
          )}
        </StyledDragOverlay>,
        document.body,
      )}
    </div>
  );
}

const StyledTableRow = styled(TableRow)`
  z-index: 10;
  position: relative;
`;

const StyledDragOverlay = styled(DragOverlay)`
  box-shadow: ${p => p.theme.boxShadowSoft};
  background-color: ${p => p.theme.colors.bg};
  display: flex;
  align-items: center;
  border-radius: ${p => p.theme.radius};
  padding-inline: ${p => p.theme.margin}rem;
  opacity: 0.88;
`;
