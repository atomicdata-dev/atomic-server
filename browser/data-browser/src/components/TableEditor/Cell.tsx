import React, { useCallback, useEffect, useLayoutEffect, useRef } from 'react';
import { styled } from 'styled-components';
import {
  CursorMode,
  TableEvent,
  useTableEditorContext,
} from './TableEditorContext';
import { FaExpandAlt } from 'react-icons/fa';
import { IconButton } from '../IconButton/IconButton';
import { KeyboardInteraction } from './helpers/keyboardHandlers';

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
  onEditNextRow?: () => void;
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
  onEditNextRow,
}: React.PropsWithChildren<CellProps>): JSX.Element {
  const ref = useRef<HTMLDivElement>(null);

  const {
    mouseDown,
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
    disabledKeyboardInteractions,
    setMouseDown,
  } = useTableEditorContext();

  const isActive = rowIndex === selectedRow && columnIndex === selectedColumn;
  const isActiveCorner =
    rowIndex === multiSelectCornerRow &&
    columnIndex === multiSelectCornerColumn;

  const handleMouseUp = useCallback(() => {
    setMouseDown(false);
  }, []);

  const handleMouseEnter = useCallback(() => {
    if (mouseDown) {
      setMultiSelectCorner(rowIndex, columnIndex);
      setCursorMode(CursorMode.MultiSelect);
    }
  }, [mouseDown, rowIndex, columnIndex]);

  const handleMouseDown = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      setMouseDown(true);

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
        setMultiSelectCorner(undefined, undefined);

        return setCursorMode(CursorMode.Edit);
      }

      if (disabledKeyboardInteractions.has(KeyboardInteraction.ExitEditMode)) {
        return;
      }

      setCursorMode(CursorMode.Visual);
      setActiveCell(rowIndex, columnIndex);
    },
    [setActiveCell, isActive, columnIndex, disabledKeyboardInteractions],
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

      const unregisters = [
        registerEventListener(
          TableEvent.EnterEditModeWithCharacter,
          onEnterEditModeWithCharacter,
        ),
        registerEventListener(TableEvent.InteractionsFired, interactions => {
          if (
            interactions.includes(KeyboardInteraction.EditNextRow) &&
            isActive
          ) {
            onEditNextRow?.();
          }
        }),
      ];

      return () => {
        for (const unregister of unregisters) {
          unregister();
        }
      };
    }
  }, [isActive, onEnterEditModeWithCharacter, onEditNextRow]);

  return (
    <CellWrapper
      aria-colindex={columnIndex + 1}
      ref={ref}
      disabled={disabled}
      role={role ?? 'gridcell'}
      className={className}
      allowUserSelect={cursorMode === CursorMode.Edit}
      align={align}
      tabIndex={isActive ? 0 : -1}
      onMouseDown={handleMouseDown}
      onMouseUp={handleMouseUp}
      onMouseEnter={handleMouseEnter}
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
