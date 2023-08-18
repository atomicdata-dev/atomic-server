import React, { useCallback, useEffect } from 'react';
import { styled } from 'styled-components';
import { DragAreaBase, useResizable } from '../../hooks/useResizable';
import { useTableEditorContext } from './TableEditorContext';
import { useDraggable } from '@dnd-kit/core';
import { ReorderDropArea } from './ReorderDropArea';
import { transparentize } from 'polished';
import { DEFAULT_SIZE_PX } from './hooks/useCellSizes';

interface TableHeadingProps {
  index: number;
  dragKey: string;
  onResize: (index: number, size: string) => void;
  isReordering: boolean;
}

/** A single column header, mostly used to render Properties */
export function TableHeading({
  children,
  dragKey,
  index,
  isReordering,
  onResize,
}: React.PropsWithChildren<TableHeadingProps>): JSX.Element {
  const {
    attributes,
    listeners,
    setNodeRef,
    isDragging: isReorderingThisNode,
  } = useDraggable({
    id: dragKey,
    data: { index },
  });

  const { targetRef, dragAreaRef, isDragging } = useResizable<HTMLDivElement>({
    initialSize: DEFAULT_SIZE_PX,
    minSize: 100,
    onResize: size => onResize(index, `${size}px`),
  });

  const { setIsDragging } = useTableEditorContext();

  useEffect(() => {
    setIsDragging(isDragging);
  }, [isDragging]);

  const setRef = useCallback((node: HTMLDivElement) => {
    setNodeRef(node);
    // @ts-ignore
    targetRef.current = node;
  }, []);

  return (
    <TableHeadingWrapper
      ref={setRef}
      reordering={isReorderingThisNode}
      role='columnheader'
      aria-colindex={index + 2}
    >
      {children}
      <ReorderHandle {...listeners} {...attributes} title='Reorder column' />
      {isReordering && <ReorderDropArea index={index} />}
      <ResizeHandle isDragging={isDragging} ref={dragAreaRef} />
    </TableHeadingWrapper>
  );
}

export function TableHeadingDummy({ children }: React.PropsWithChildren) {
  return <TableHeadingWrapperDummy>{children}</TableHeadingWrapperDummy>;
}

export interface TableHeadingWrapperProps {
  align?: 'start' | 'end';
  reordering?: boolean;
}

export const TableHeadingWrapper = styled.div<TableHeadingWrapperProps>`
  position: relative;
  background-color: ${p =>
    p.reordering
      ? transparentize(0.5, p.theme.colors.bg)
      : p.theme.colors.bgBody};
  display: flex;
  width: 100%;
  align-items: center;
  justify-content: ${p => p.align ?? 'start'};
  padding-inline: var(--table-inner-padding);
  font-weight: bold;
  white-space: nowrap;
  isolation: isolate;
  color: ${p =>
    p.reordering
      ? transparentize(0.5, p.theme.colors.textLight)
      : p.theme.colors.textLight};
`;

const TableHeadingWrapperDummy = styled(TableHeadingWrapper)`
  cursor: grabbing;
`;

const ResizeHandle = styled(DragAreaBase)`
  --handle-margin: 4px;
  right: -2px;
  top: 0;
  height: calc(var(--table-row-height) - (var(--handle-margin) * 2));
  width: 4px;
  margin-top: var(--handle-margin);
  z-index: 10;
  position: absolute;
`;

const ReorderHandle = styled.button`
  border: none;
  background: none;
  position: absolute;
  inset: 0;
  cursor: grab;
  z-index: -1;
`;
