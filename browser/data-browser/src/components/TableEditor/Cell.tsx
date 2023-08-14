import React, { useCallback, useEffect, useLayoutEffect, useRef } from 'react';
import styled from 'styled-components';
import {
  CursorMode,
  TableEvent,
  useTableEditorContext,
} from './TableEditorContext';
import { FaExpandAlt } from 'react-icons/fa';
import { IconButton } from '../IconButton/IconButton';

export enum CellAlign {
  Start = 'flex-start',
  End = 'flex-end',
  Center = 'center',
}

export interface CellProps {
  rowIndex: number;
  columnIndex: number;
  className?: string;
  disabled?: boolean;
  align?: CellAlign;
  role?: string;
  onClearCell?: () => void;
  onEnterEditModeWithCharacter?: (key: string) => void;
}

interface IndexCellProps extends CellProps {
  onExpand: (rowIndex: number) => void;
}

export function Cell({
  rowIndex,
  columnIndex,
  className,
  children,
  disabled,
  align,
  role,
  onEnterEditModeWithCharacter = () => undefined,
}: React.PropsWithChildren<CellProps>): JSX.Element {
  const ref = useRef<HTMLDivElement>(null);

  const {
    selectedRow,
    selectedColumn,
    multiSelectCornerRow,
    multiSelectCornerColumn,
    cursorMode,
    setActiveCell,
    setMultiSelectCorner,
    activeCellRef,
    multiSelectCornerCellRef,
    setCursorMode,
    registerEventListener,
  } = useTableEditorContext();

  const isActive = rowIndex === selectedRow && columnIndex === selectedColumn;
  const isActiveCorner =
    rowIndex === multiSelectCornerRow &&
    columnIndex === multiSelectCornerColumn;

  const handleClick = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      // When Shift is pressed, enter multi-select mode
      if (e.shiftKey) {
        e.stopPropagation();
        setCursorMode(CursorMode.MultiSelect);
        setMultiSelectCorner(rowIndex, columnIndex);

        return;
      }

      // When the user clicks on the 'add' row
      if (columnIndex === Infinity || rowIndex === Infinity) {
        setActiveCell(undefined, undefined);

        return;
      }

      // @ts-ignore
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'BUTTON') {
        // If the user clicked on an input don't enter edit mode. (Necessary for normal checkbox behavior)
        return;
      }

      if (isActive && columnIndex !== 0) {
        // Enter edit mode when clicking on a higlighted cell, except when it's the index column.
        return setCursorMode(CursorMode.Edit);
      }

      setCursorMode(CursorMode.Visual);
      setActiveCell(rowIndex, columnIndex);
    },
    [setActiveCell, isActive, columnIndex],
  );

  useLayoutEffect(() => {
    if (!ref.current) {
      return;
    }

    if (isActiveCorner) {
      multiSelectCornerCellRef.current = ref.current;
    }
  }, [isActiveCorner]);

  useEffect(() => {
    if (!ref.current) {
      return;
    }

    if (isActive) {
      if (!ref.current.contains(document.activeElement)) {
        ref.current.focus({ preventScroll: true });
      }

      activeCellRef.current = ref.current;

      const unregister = registerEventListener(
        TableEvent.EnterEditModeWithCharacter,
        onEnterEditModeWithCharacter,
      );

      return () => {
        unregister();
      };
    }
  }, [isActive, onEnterEditModeWithCharacter]);

  return (
    <CellWrapper
      aria-colindex={columnIndex + 1}
      ref={ref}
      disabled={disabled}
      role={role ?? 'gridcell'}
      className={className}
      onClick={handleClick}
      allowUserSelect={cursorMode === CursorMode.Edit}
      align={align}
      tabIndex={isActive ? 0 : -1}
    >
      {children}
    </CellWrapper>
  );
}

export function IndexCell({
  children,
  onExpand,
  ...props
}: React.PropsWithChildren<IndexCellProps>): JSX.Element {
  return (
    <StyledIndexCell role='rowheader' {...props}>
      <IconButton
        title='Open resource'
        onClick={() => onExpand(props.rowIndex)}
      >
        <FaExpandAlt />
      </IconButton>
      <IndexNumber>{children}</IndexNumber>
    </StyledIndexCell>
  );
}

const IndexNumber = styled.span``;

const StyledIndexCell = styled(Cell)`
  justify-content: flex-end !important;
  color: ${p => p.theme.colors.textLight};

  & button {
    display: none;
  }

  &:hover ${IndexNumber}, &:focus-within ${IndexNumber} {
    display: none;
  }

  &:hover button,
  &:focus-within button {
    display: block;
  }
`;

export interface CellWrapperProps {
  align?: CellAlign;
  allowUserSelect?: boolean;
  disabled?: boolean;
}

export const CellWrapper = styled.div<CellWrapperProps>`
  background-color: ${p =>
    p.disabled ? p.theme.colors.bg1 : p.theme.colors.bg};
  cursor: ${p => (p.disabled ? 'not-allowed' : 'pointer')};
  display: flex;
  width: 100%;
  justify-content: ${p => p.align ?? 'flex-start'};
  align-items: center;
  user-select: ${p => (p.allowUserSelect ? 'text' : 'none')};
  padding-inline: var(--table-inner-padding);
  white-space: nowrap;
  text-overflow: ellipsis;
  position: relative;
  outline: none;
`;
