import { useCallback } from 'react';
import {
  HandlerContext,
  handlerMatchesModifier,
  KeyboardHandler,
  TableCommands,
  tableKeyboardHandlers,
} from '../helpers/keyboardHandlers';
import { useTableEditorContext } from '../TableEditorContext';
import { useHasControlLock } from '../../../hooks/useControlLock';

const matchShift = (
  handler: KeyboardHandler,
  event: React.KeyboardEvent<HTMLDivElement> | KeyboardEvent,
) => handler.shift === undefined || handler.shift === event.shiftKey;

const matchModifier = (
  handler: KeyboardHandler,
  event: React.KeyboardEvent<HTMLDivElement> | KeyboardEvent,
) => handlerMatchesModifier(handler, event);

const matchCondition = (handler: KeyboardHandler, context: HandlerContext) =>
  handler.condition === undefined || handler.condition(context);

const tableHeaderHasFocus = (
  headerRef: React.RefObject<HTMLDivElement | null>,
) => headerRef.current?.contains(document.activeElement);

export function useTableEditorKeyboardNavigation(
  columnCount: number,
  rowCount: number,
  tableRef: React.RefObject<HTMLDivElement | null>,
  headerRef: React.RefObject<HTMLDivElement | null>,
  commands: TableCommands,
) {
  const tableContext = useTableEditorContext();
  const {
    readOnly,
    disabledKeyboardInteractions,
    selectedRow,
    selectedColumn,
    setActiveCell,
    listRef,
    emitInteractionsFired,
  } = tableContext;

  const hasControlLock = useHasControlLock();

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLDivElement> | KeyboardEvent) => {
      if (hasControlLock || tableHeaderHasFocus(headerRef)) {
        return;
      }

      const translateCursor = (r: number, c: number) => {
        let row = (selectedRow ?? 0) + r;
        let column = (selectedColumn ?? 0) + c;

        if (column < 0) {
          row -= 1;
          column = columnCount;
        }

        if (column > columnCount) {
          row += 1;
          column = 1;
        }

        // Cursor target may legitimately be outside [0, rowCount) — e.g.
        // pressing Enter on the last row pre-emptively targets the next
        // row before the new row exists. react-window v1's `scrollToItem`
        // silently clamped that; v2's `scrollToRow` throws a RangeError
        // (`Invalid index specified: N`) and the whole keystroke is lost.
        // Clamp the scroll target ourselves; setActiveCell already clamps.
        const clampedRow = Math.min(Math.max(row, 0), rowCount - 1);

        if (listRef.current && rowCount > 0) {
          listRef.current.scrollToRow({ index: clampedRow, align: 'auto' });
        }

        setActiveCell(clampedRow, column);
      };

      const context: HandlerContext = {
        tableContext,
        event: e,
        tableRef,
        columnCount,
        rowCount,
        ...commands,
        translateCursor,
      };

      const handlers = tableKeyboardHandlers.filter(
        h =>
          !disabledKeyboardInteractions.has(h.id) &&
          h.keys.has(e.key) &&
          h.cursorMode.has(tableContext.cursorMode) &&
          (readOnly ? !h.disabledInReadOnly : true) &&
          matchShift(h, e) &&
          matchModifier(h, e) &&
          matchCondition(h, context),
      );

      for (const handler of handlers) {
        if (handler.preventDefault) {
          e.preventDefault();
        }

        handler.handler(context);
      }

      emitInteractionsFired(handlers.map(h => h.id));
    },
    [
      commands,
      listRef,
      setActiveCell,
      columnCount,
      rowCount,
      tableRef,
      headerRef,
      readOnly,
      disabledKeyboardInteractions,
      selectedRow,
      selectedColumn,
      tableContext,
      hasControlLock,
      emitInteractionsFired,
    ],
  );

  return handleKeyDown;
}
