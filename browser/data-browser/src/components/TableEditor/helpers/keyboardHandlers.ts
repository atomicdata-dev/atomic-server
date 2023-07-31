import { CursorMode, TableEditorContext } from '../TableEditorContext';

const triggerCharacters =
  'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+-=[]{};:"|,./<>?`~ø';

export enum KeyboardInteraction {
  ExitEditMode,
  EditNextRow,
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
};

export type HandlerContext = {
  tableContext: TableEditorContext;
  event: React.KeyboardEvent;
  tableRef: React.RefObject<HTMLDivElement>;
  translateCursor: (row: number, column: number) => void;
  columnCount: number;
} & TableCommands;

export interface KeyboardHandler {
  id: KeyboardInteraction;
  keys: Set<string>;
  cursorMode: Set<CursorMode>;
  preventDefault?: boolean;
  shift?: boolean;
  mod?: boolean;
  condition?: (context: HandlerContext) => boolean;

  handler: (context: HandlerContext) => void;
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

const exitEditMode: KeyboardHandler = {
  id: KeyboardInteraction.ExitEditMode,
  keys: new Set(['Escape']),
  cursorMode: new Set([CursorMode.Edit]),

  handler: ({ tableContext, tableRef }) => {
    tableContext.setCursorMode(CursorMode.Visual);
    tableRef.current?.focus();
  },
};

const editNextRow: KeyboardHandler = {
  id: KeyboardInteraction.EditNextRow,
  keys: new Set(['Enter']),
  shift: false,
  cursorMode: new Set([CursorMode.Edit]),
  preventDefault: true,
  handler: ({ translateCursor }) => {
    translateCursor(1, 0);
  },
};

const editNextCell: KeyboardHandler = {
  id: KeyboardInteraction.EditNextCell,
  keys: new Set(['Tab']),
  shift: false,
  cursorMode: new Set([CursorMode.Edit]),
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
  condition: () => document.activeElement?.tagName !== 'INPUT',
  handler: ({ undo }) => {
    undo?.();
  },
};

const deleteCell: KeyboardHandler = {
  id: KeyboardInteraction.DeleteCell,
  keys: new Set(['Delete', 'Backspace']),
  cursorMode: new Set([CursorMode.Visual, CursorMode.MultiSelect]),
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
  cursorMode: new Set([CursorMode.Visual]),
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
  condition: ({ tableContext }) => tableContext.selectedColumn === 0,
  handler: ({ expand, tableContext }) => {
    expand?.(tableContext.selectedRow!);
  },
};

const enterEditModeByTyping: KeyboardHandler = {
  id: KeyboardInteraction.EnterEditModeByTyping,
  keys: new Set(triggerCharacters.split('')),
  cursorMode: new Set([CursorMode.Visual]),
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
  exitEditMode,
  editNextRow,
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
