import { CursorMode, TableEditorContext } from '../TableEditorContext';

const triggerCharacters =
  'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+-=[]{};:"|,./<>?`~ø';

export enum KeyboardInteraction {
  ExitEditMode,
  EditNextRow,
  InsertRowBelow,
  EditNextCell,
  EditPreviousCell,
  ExpandRow,
  Copy,
  DeleteCell,
  DeleteRow,
  MoveCursorUp,
  MoveCursorDown,
  MoveCursorLeft,
  MoveCursorRight,
  EnterEditModeWithEnter,
  EnterEditModeByTyping,
  MoveMultiSelectCornerUp,
  MoveMultiSelectCornerDown,
  MoveMultiSelectCornerLeft,
  MoveMultiSelectCornerRight,
  Undo,
}

export type TableCommands = {
  copy?: () => void;
  undo?: () => void;
  expand?: (row: number) => void;
  /**
   * Create a new row below the given row index. Returns true when the row is
   * inserted at that position (the caller moves the cursor one row down), or
   * false when it was appended at the bottom instead (e.g. under a column
   * sort, where a mid-table position has no meaning).
   */
  insertRowBelow?: (row: number) => boolean;
};

export type HandlerContext = {
  tableContext: TableEditorContext;
  event: React.KeyboardEvent | KeyboardEvent;
  tableRef: React.RefObject<HTMLDivElement | null>;
  translateCursor: (row: number, column: number) => void;
  columnCount: number;
  rowCount: number;
} & TableCommands;

export interface KeyboardHandler {
  id: KeyboardInteraction;
  keys: Set<string>;
  cursorMode: Set<CursorMode>;
  preventDefault?: boolean;
  disabledInReadOnly?: boolean;
  shift?: boolean;
  /**
   * When true, Ctrl/Cmd must be held. When false or omitted, the handler
   * only matches *without* Ctrl/Cmd. Omitted used to mean "either", which
   * made ArrowUp swallow Cmd/Ctrl+ArrowUp (go to parent).
   */
  mod?: boolean;
  condition?: (context: HandlerContext) => boolean;

  handler: (context: HandlerContext) => void;
}

/** True when the handler's `mod` flag matches the event's Ctrl/Cmd state. */
export function handlerMatchesModifier(
  handler: Pick<KeyboardHandler, 'mod'>,
  event: { metaKey: boolean; ctrlKey: boolean },
  isMac = typeof navigator !== 'undefined' &&
    navigator.platform.includes('Mac'),
): boolean {
  return (handler.mod ?? false) === (isMac ? event.metaKey : event.ctrlKey);
}

const getMultiSelectStartPosition = ({
  cursorMode,
  multiSelectCornerRow,
  multiSelectCornerColumn,
  selectedRow,
  selectedColumn,
}: TableEditorContext) => {
  const row =
    (cursorMode === CursorMode.MultiSelect
      ? multiSelectCornerRow
      : selectedRow) ?? 0;

  const col =
    (cursorMode === CursorMode.MultiSelect
      ? multiSelectCornerColumn
      : selectedColumn) ?? 0;

  return { row, col };
};

const relativePositionToMultiSelectCorner = ({
  multiSelectCornerColumn,
  multiSelectCornerRow,
  selectedColumn,
  selectedRow,
}: TableEditorContext) => {
  const row = (multiSelectCornerRow ?? selectedRow ?? 0) - (selectedRow ?? 0);
  const col =
    (multiSelectCornerColumn ?? selectedColumn ?? 0) - (selectedColumn ?? 0);

  return [row, col];
};

const createCursorHandler =
  (rowMod: number, columnMod: number) =>
  ({ translateCursor, tableContext }: HandlerContext) => {
    let rowTranslation = rowMod;
    let columnTranslation = columnMod;

    if (tableContext.cursorMode === CursorMode.MultiSelect) {
      const [relativeRow, relativeColumn] =
        relativePositionToMultiSelectCorner(tableContext);
      rowTranslation += relativeRow;
      columnTranslation += relativeColumn;

      tableContext.setMultiSelectCorner(undefined, undefined);
    }

    tableContext.setCursorMode(CursorMode.Visual);
    translateCursor(rowTranslation, columnTranslation);
  };

const editNextRow: KeyboardHandler = {
  id: KeyboardInteraction.EditNextRow,
  keys: new Set(['Enter']),
  shift: false,
  cursorMode: new Set([CursorMode.Edit]),
  disabledInReadOnly: true,
  preventDefault: true,
  handler: ({ translateCursor }) => {
    translateCursor(1, 0);
  },
};

const insertRowBelow: KeyboardHandler = {
  id: KeyboardInteraction.InsertRowBelow,
  keys: new Set(['Enter']),
  shift: true,
  cursorMode: new Set([CursorMode.Visual, CursorMode.Edit]),
  disabledInReadOnly: true,
  preventDefault: true,
  condition: ({ insertRowBelow: command, tableContext }) =>
    command !== undefined && tableContext.selectedRow !== undefined,
  handler: context => {
    const { tableContext, translateCursor, rowCount } = context;
    const row = tableContext.selectedRow!;
    const positional = context.insertRowBelow!(row);

    tableContext.setCursorMode(CursorMode.Visual);

    if (positional) {
      // The new row materializes at row + 1; the cursor is already there
      // when it lands.
      translateCursor(1, 0);
    } else {
      // Appended: jump to the trailing empty row.
      translateCursor(rowCount - 1 - row, 0);
    }
  },
};

const editNextCell: KeyboardHandler = {
  id: KeyboardInteraction.EditNextCell,
  keys: new Set(['Tab']),
  shift: false,
  cursorMode: new Set([CursorMode.Edit]),
  disabledInReadOnly: true,
  preventDefault: true,
  handler: ({ translateCursor }) => {
    translateCursor(0, 1);
  },
};

const editPreviousCell: KeyboardHandler = {
  id: KeyboardInteraction.EditPreviousCell,
  keys: new Set(['Tab']),
  shift: true,
  cursorMode: new Set([CursorMode.Edit]),
  disabledInReadOnly: true,
  preventDefault: true,
  handler: ({ translateCursor }) => {
    translateCursor(0, -1);
  },
};

const copyCommand: KeyboardHandler = {
  id: KeyboardInteraction.Copy,
  keys: new Set(['c']),
  mod: true,
  cursorMode: new Set([CursorMode.Visual, CursorMode.MultiSelect]),
  condition: ({ tableContext }) =>
    tableContext.selectedColumn !== undefined &&
    tableContext.selectedRow !== undefined,

  handler: ({ event, copy }) => {
    event.preventDefault();
    copy?.();
  },
};

const undoCommand: KeyboardHandler = {
  id: KeyboardInteraction.Undo,
  keys: new Set(['z']),
  mod: true,
  cursorMode: new Set([CursorMode.Visual, CursorMode.MultiSelect]),
  disabledInReadOnly: true,
  condition: () => document.activeElement?.tagName !== 'INPUT',
  handler: ({ undo }) => {
    undo?.();
  },
};

const deleteCell: KeyboardHandler = {
  id: KeyboardInteraction.DeleteCell,
  keys: new Set(['Delete', 'Backspace']),
  cursorMode: new Set([CursorMode.Visual, CursorMode.MultiSelect]),
  disabledInReadOnly: true,
  condition: ({ tableContext }) =>
    tableContext.selectedColumn !== 0 &&
    tableContext.selectedColumn !== undefined &&
    tableContext.selectedRow !== undefined,

  handler: ({ tableContext }) => {
    tableContext.clearCell();
  },
};

const deleteRow: KeyboardHandler = {
  id: KeyboardInteraction.DeleteRow,
  keys: new Set(['Delete', 'Backspace']),
  cursorMode: new Set([CursorMode.Visual]),
  disabledInReadOnly: true,
  condition: ({ tableContext }) =>
    tableContext.selectedColumn === 0 &&
    tableContext.selectedColumn !== undefined &&
    tableContext.selectedRow !== undefined,

  handler: ({ tableContext }) => {
    tableContext.clearRow(tableContext.selectedRow!);
  },
};

const moveCursorUp: KeyboardHandler = {
  id: KeyboardInteraction.MoveCursorUp,
  keys: new Set(['ArrowUp']),
  shift: false,
  cursorMode: new Set([CursorMode.Visual, CursorMode.MultiSelect]),

  preventDefault: true,
  handler: createCursorHandler(-1, 0),
};

const moveCursorDown: KeyboardHandler = {
  id: KeyboardInteraction.MoveCursorDown,
  keys: new Set(['ArrowDown']),
  shift: false,
  cursorMode: new Set([CursorMode.Visual, CursorMode.MultiSelect]),

  preventDefault: true,
  handler: createCursorHandler(1, 0),
};

const moveCursorLeft: KeyboardHandler = {
  id: KeyboardInteraction.MoveCursorLeft,
  keys: new Set(['ArrowLeft']),
  shift: false,
  cursorMode: new Set([CursorMode.Visual, CursorMode.MultiSelect]),

  preventDefault: true,
  handler: createCursorHandler(0, -1),
};

const moveCursorRight: KeyboardHandler = {
  id: KeyboardInteraction.MoveCursorRight,
  keys: new Set(['ArrowRight']),
  shift: false,
  cursorMode: new Set([CursorMode.Visual, CursorMode.MultiSelect]),

  preventDefault: true,
  handler: createCursorHandler(0, 1),
};

const enterEditModeWithEnter: KeyboardHandler = {
  id: KeyboardInteraction.EnterEditModeWithEnter,
  keys: new Set(['Enter']),
  shift: false,
  cursorMode: new Set([CursorMode.Visual]),
  disabledInReadOnly: true,
  condition: ({ tableContext }) =>
    tableContext.selectedColumn !== undefined &&
    tableContext.selectedColumn !== 0 &&
    tableContext.selectedRow !== undefined,

  handler: ({ tableContext }) => {
    tableContext.setCursorMode(CursorMode.Edit);
  },
};

const expandRow: KeyboardHandler = {
  id: KeyboardInteraction.ExpandRow,
  cursorMode: new Set([CursorMode.Visual]),
  keys: new Set(['Enter']),
  shift: false,
  condition: ({ tableContext }) => tableContext.selectedColumn === 0,
  handler: ({ expand, tableContext }) => {
    expand?.(tableContext.selectedRow!);
  },
};

const enterEditModeByTyping: KeyboardHandler = {
  id: KeyboardInteraction.EnterEditModeByTyping,
  keys: new Set(triggerCharacters.split('')),
  cursorMode: new Set([CursorMode.Visual]),
  disabledInReadOnly: true,
  mod: false,
  condition: ({ tableContext }) =>
    tableContext.selectedColumn !== undefined &&
    tableContext.selectedColumn !== 0 &&
    tableContext.selectedRow !== undefined,

  preventDefault: true,
  handler: ({ tableContext, event }) => {
    tableContext.enterEditModeWithCharacter(event.key);
    tableContext.setCursorMode(CursorMode.Edit);
  },
};

const moveMultiSelectCornerUp: KeyboardHandler = {
  id: KeyboardInteraction.MoveMultiSelectCornerUp,
  keys: new Set(['ArrowUp']),
  cursorMode: new Set([CursorMode.Visual, CursorMode.MultiSelect]),
  shift: true,

  preventDefault: true,
  handler: ({ tableContext }) => {
    const { row, col } = getMultiSelectStartPosition(tableContext);
    tableContext.setMultiSelectCorner(Math.max(0, row - 1), col);
    tableContext.setCursorMode(CursorMode.MultiSelect);
  },
};

const moveMultiSelectCornerDown: KeyboardHandler = {
  id: KeyboardInteraction.MoveMultiSelectCornerDown,
  keys: new Set(['ArrowDown']),
  cursorMode: new Set([CursorMode.Visual, CursorMode.MultiSelect]),
  shift: true,

  preventDefault: true,
  handler: ({ tableContext }) => {
    const { row, col } = getMultiSelectStartPosition(tableContext);
    tableContext.setMultiSelectCorner(Math.max(0, row + 1), col);
    tableContext.setCursorMode(CursorMode.MultiSelect);
  },
};

const moveMultiSelectCornerLeft: KeyboardHandler = {
  id: KeyboardInteraction.MoveMultiSelectCornerLeft,
  keys: new Set(['ArrowLeft']),
  cursorMode: new Set([CursorMode.Visual, CursorMode.MultiSelect]),
  shift: true,

  preventDefault: true,
  handler: ({ tableContext, columnCount }) => {
    const { row, col } = getMultiSelectStartPosition(tableContext);
    tableContext.setMultiSelectCorner(
      row,
      Math.min(Math.max(col - 1, 0), columnCount),
    );
    tableContext.setCursorMode(CursorMode.MultiSelect);
  },
};

const moveMultiSelectCornerRight: KeyboardHandler = {
  id: KeyboardInteraction.MoveMultiSelectCornerRight,
  keys: new Set(['ArrowRight']),
  cursorMode: new Set([CursorMode.Visual, CursorMode.MultiSelect]),
  shift: true,

  preventDefault: true,
  handler: ({ tableContext, columnCount }) => {
    const { row, col } = getMultiSelectStartPosition(tableContext);
    tableContext.setMultiSelectCorner(
      row,
      Math.min(Math.max(col + 1, 0), columnCount),
    );
    tableContext.setCursorMode(CursorMode.MultiSelect);
  },
};

export const tableKeyboardHandlers = [
  editNextRow,
  insertRowBelow,
  editNextCell,
  editPreviousCell,
  expandRow,
  copyCommand,
  undoCommand,
  deleteCell,
  deleteRow,
  moveCursorUp,
  moveCursorDown,
  moveCursorLeft,
  moveCursorRight,
  enterEditModeWithEnter,
  enterEditModeByTyping,
  moveMultiSelectCornerUp,
  moveMultiSelectCornerDown,
  moveMultiSelectCornerLeft,
  moveMultiSelectCornerRight,
];
