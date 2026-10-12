import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type JSX,
} from 'react';
import { styled } from 'styled-components';
import {
  CursorMode,
  TableEvent,
  useTableEditorContext,
} from './TableEditorContext';
import { FaUpRightAndDownLeftFromCenter } from 'react-icons/fa6';
import { isInMultiSelection } from './helpers/selectionBounds';
import { IconButton } from '@components/IconButton/IconButton';
import { KeyboardInteraction } from './helpers/keyboardHandlers';
import { CSSVar } from '@helpers/CSSVar';

export const CELL_WIDTH = new CSSVar('table-cell-width');

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
  /** Supplementary position/context info (e.g. "name, row 1"). Exposed as
   * `aria-description`, NOT `aria-label` — an aria-label would override the
   * cell's own content as its accessible name, hiding the actual value from
   * both screen readers and role-based queries. */
  ariaDescription?: string;
  onClearCell?: () => void;
  onEnterEditModeWithCharacter?: (key: string) => void;
  onEditNextRow?: () => void;
  onContextMenu?: (e: React.MouseEvent<HTMLDivElement>) => void;
}

interface IndexCellProps extends CellProps {
  onExpand: (rowIndex: number) => void;
  /** Rendered before the expand button, e.g. a row-select tick box. */
  Extra?: React.ComponentType<{ index: number }>;
  /**
   * Rendered in the gutter at the start of the row, left of the row number —
   * where a row-scoped affordance belongs (the table view hangs its comment
   * bubble here). See {@link FancyTableProps.RowHeaderAddonComponent}.
   */
  RowHeaderAddonComponent?: React.ComponentType<{ rowIndex: number }>;
}

export function Cell({
  rowIndex,
  columnIndex,
  className,
  children,
  disabled,
  align,
  role,
  ariaDescription,
  onEnterEditModeWithCharacter = () => undefined,
  onEditNextRow,
  onContextMenu,
}: React.PropsWithChildren<CellProps>): JSX.Element {
  const ref = useRef<HTMLDivElement>(null);

  const [markEnterEditMode, setMarkEnterEditMode] = useState(false);

  const {
    readOnly,
    mouseDown,
    selectedRow,
    selectedColumn,
    multiSelectCornerRow,
    multiSelectCornerColumn,
    cursorMode,
    setActiveCell,
    setMultiSelectCorner,
    updateActiveCellRef,
    updateMultiSelectCornerCellRef,
    setCursorMode,
    registerEventListener,
    disabledKeyboardInteractions,
    setMouseDown,
    openSelectionMenu,
  } = useTableEditorContext();

  const isActive = rowIndex === selectedRow && columnIndex === selectedColumn;
  const isActiveCorner =
    rowIndex === multiSelectCornerRow &&
    columnIndex === multiSelectCornerColumn;

  const inMultiSelection = isInMultiSelection(
    cursorMode,
    selectedRow,
    selectedColumn,
    multiSelectCornerRow,
    multiSelectCornerColumn,
    rowIndex,
    columnIndex,
  );

  // Right-clicking inside a multi-cell selection acts on all of it, so it
  // opens the selection's own menu rather than the cell's.
  const handleContextMenu = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      if (inMultiSelection) {
        openSelectionMenu(e);

        return;
      }

      onContextMenu?.(e);
    },
    [inMultiSelection, openSelectionMenu, onContextMenu],
  );

  const handleMouseUp = useCallback(() => {
    setMouseDown(false);
  }, [setMouseDown]);

  const handleMouseEnter = useCallback(() => {
    // Drag-select: only enter MultiSelect when the mouse leaves the
    // initially-clicked cell while still held. Without the diff-check, the
    // mouseenter that fires *during the initial mousedown* (e.g. the way
    // playwright dispatches click sequences in newer versions) leaves the
    // cell in MultiSelect mode after a plain click, so no Visual-mode
    // keyboard handler — Enter, character-typing, arrows — fires.
    if (
      mouseDown &&
      (rowIndex !== selectedRow || columnIndex !== selectedColumn)
    ) {
      setMultiSelectCorner(rowIndex, columnIndex);
      setCursorMode(CursorMode.MultiSelect);
    }
  }, [
    mouseDown,
    rowIndex,
    columnIndex,
    selectedRow,
    selectedColumn,
    setMultiSelectCorner,
    setCursorMode,
  ]);

  const shouldEnterEditMode = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      const target = e.target as HTMLElement;

      if (target.tagName === 'INPUT' || target.tagName === 'BUTTON') {
        // If the user clicked on an input don't enter edit mode. (Necessary for normal checkbox behavior)
        return false;
      }

      // Enter edit mode when clicking on a higlighted cell, except when it's the index column.
      return isActive && columnIndex !== 0;
    },
    [isActive, columnIndex],
  );

  const handleMouseDown = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      if ((e.target as HTMLElement).tagName === 'BUTTON') {
        return;
      }

      if (disabledKeyboardInteractions.has(KeyboardInteraction.ExitEditMode)) {
        return;
      }

      // A right-click inside the selection must not collapse it: the context
      // menu that follows is for the whole selection.
      if (e.button === 2 && inMultiSelection) {
        return;
      }

      setMouseDown(true);

      // Stop the browser starting its own text selection for this drag.
      // `user-select: none` on the cell is not enough: it governs what can be
      // selected, not whether a drag begins, so dragging across cells still
      // paints a native selection over the grid (and, in the desktop webview,
      // leaves it behind after mouseup). Not called when entering Edit mode
      // below, where selecting text is the point.
      if (cursorMode !== CursorMode.Edit) {
        e.preventDefault();
      }

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

      if (!readOnly && shouldEnterEditMode(e)) {
        setMarkEnterEditMode(true);

        return;
      }

      if (isActive && cursorMode === CursorMode.Edit) {
        return;
      }

      setCursorMode(CursorMode.Visual);
      setActiveCell(rowIndex, columnIndex);
    },
    [
      readOnly,
      setActiveCell,
      columnIndex,
      shouldEnterEditMode,
      cursorMode,
      isActive,
      inMultiSelection,
      disabledKeyboardInteractions,
      setCursorMode,
      setMouseDown,
      setMultiSelectCorner,
      rowIndex,
    ],
  );

  const handleClick = useCallback(() => {
    if (disabledKeyboardInteractions.has(KeyboardInteraction.ExitEditMode)) {
      return;
    }

    if (markEnterEditMode) {
      setMultiSelectCorner(undefined, undefined);
      setMouseDown(false);

      setCursorMode(CursorMode.Edit);
      setMarkEnterEditMode(false);
    }
  }, [
    markEnterEditMode,
    disabledKeyboardInteractions,
    setMultiSelectCorner,
    setMouseDown,
    setCursorMode,
  ]);

  useLayoutEffect(() => {
    if (!ref.current) {
      return;
    }

    if (isActiveCorner) {
      updateMultiSelectCornerCellRef(ref.current);
    }
  }, [isActiveCorner, updateMultiSelectCornerCellRef]);

  useEffect(() => {
    if (!ref.current) {
      return;
    }

    if (isActive) {
      if (!ref.current.contains(document.activeElement)) {
        ref.current.focus({ preventScroll: true });
      }

      updateActiveCellRef(ref.current);

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
  }, [
    isActive,
    onEnterEditModeWithCharacter,
    onEditNextRow,
    updateActiveCellRef,
    registerEventListener,
  ]);

  return (
    <CellWrapper
      index={columnIndex}
      aria-colindex={columnIndex + 1}
      ref={ref}
      disabled={disabled}
      role={role ?? 'gridcell'}
      aria-description={ariaDescription}
      className={className}
      allowUserSelect={cursorMode === CursorMode.Edit}
      align={align}
      tabIndex={isActive ? 0 : -1}
      onMouseDown={handleMouseDown}
      onMouseUp={handleMouseUp}
      onClick={handleClick}
      onMouseEnter={handleMouseEnter}
      onContextMenu={handleContextMenu}
    >
      {children}
    </CellWrapper>
  );
}

export function IndexCell({
  children,
  onExpand,
  Extra,
  RowHeaderAddonComponent,
  ...props
}: React.PropsWithChildren<IndexCellProps>): JSX.Element {
  const { markings } = useTableEditorContext();

  const marking = markings.get(props.rowIndex);

  return (
    <StyledIndexCell role='rowheader' {...props} hasMarking={!!marking}>
      {(Extra || RowHeaderAddonComponent) && (
        <AddonSlot>
          {Extra && <Extra index={props.rowIndex} />}
          {RowHeaderAddonComponent && (
            <RowHeaderAddonComponent rowIndex={props.rowIndex} />
          )}
        </AddonSlot>
      )}
      <IconButton
        title='Open resource'
        onClick={() => onExpand(props.rowIndex)}
      >
        <FaUpRightAndDownLeftFromCenter />
      </IconButton>
      {marking ? marking : <IndexNumber>{children}</IndexNumber>}
    </StyledIndexCell>
  );
}

const IndexNumber = styled.span``;

/**
 * Holds the gutter affordance at the start of the row. It keeps its box even
 * when empty, so a row number never shifts sideways as the affordance appears
 * and disappears on hover.
 */
const AddonSlot = styled.span`
  margin-inline-end: auto;
  display: flex;
  align-items: center;
  gap: ${p => p.theme.size(1)};
`;

/* The addon's buttons (`data-row-affordance`) are
 * row-scoped and are revealed from the row itself (see TableRow); only the
 * expand button is shown and hidden by this cell's own hover rules. */
const StyledIndexCell = styled(Cell)<{ hasMarking: boolean }>`
  justify-content: flex-end !important;
  /* Tighter than a data cell: the gutter fits two controls side by side. */
  padding-inline: 0.25rem;
  gap: ${p => p.theme.size(1)};
  color: ${p => p.theme.colors.textLight};

  /* The row-select tick box sits in the slot pinned left, so it doesn't move
     when the number swaps for the expand button under a hovering or tapping
     pointer. */
  & [data-row-select] {
    display: flex;
    align-items: center;
  }

  & [data-row-select]:not([data-active='true']) {
    display: none;
  }

  /* No hover on touch: without this there'd be no way to start selecting. */
  @media (hover: none) {
    & [data-row-select] {
      display: flex !important;
    }
  }

  &:hover [data-row-select],
  &:focus-within [data-row-select] {
    display: flex;
  }

  /* Only the expand button: the tick box and the addon's buttons live in the
     slot and are shown by their own rules. */
  & > button {
    display: none;
  }

  &:hover ${IndexNumber}, &:is(:focus, :has(> button:focus)) ${IndexNumber} {
    display: none;
  }

  &:not([data-hasmarking='true']):hover > button,
  &:not([data-hasmarking='true']):is(:focus, :has(> button:focus)) > button {
    display: ${p => (p.hasMarking ? 'none' : 'block')};
  }
`;

export interface CellWrapperProps {
  align?: CellAlign;
  allowUserSelect?: boolean;
  disabled?: boolean;
  index: number;
}

export const CellWrapper = styled.div.attrs<CellWrapperProps>(p => ({
  style: {
    [CELL_WIDTH.raw]: `var(--cell-width-${p.index})`,
  } as Record<string, string>,
}))`
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
