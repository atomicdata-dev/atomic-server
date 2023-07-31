import React, { useCallback } from 'react';
import {
  HandlerContext,
  KeyboardHandler,
  TableCommands,
  tableKeyboardHandlers,
} from '../helpers/keyboardHandlers';
import { useTableEditorContext } from '../TableEditorContext';
import { useHasControlLock } from '../../../hooks/useControlLock';

const matchShift = (
  handler: KeyboardHandler,
  event: React.KeyboardEvent<HTMLDivElement>,
) => handler.shift === undefined || handler.shift === event.shiftKey;

const matchModifier = (
  handler: KeyboardHandler,
  event: React.KeyboardEvent<HTMLDivElement>,
) =>
  handler.mod === undefined ||
  handler.mod ===
    (navigator.platform.includes('Mac') ? event.metaKey : event.ctrlKey);

const matchCondition = (handler: KeyboardHandler, context: HandlerContext) =>
  handler.condition === undefined || handler.condition(context);

const tableHeaderHasFocus = (headerRef: React.RefObject<HTMLDivElement>) =>
  headerRef.current?.contains(document.activeElement);

export function useTableEditorKeyboardNavigation(
  columnCount: number,
  rowCount: number,
  tableRef: React.RefObject<HTMLDivElement>,
  headerRef: React.RefObject<HTMLDivElement>,
  commands: TableCommands,
) {
  const tableContext = useTableEditorContext();
  const {
    disabledKeyboardInteractions,
    selectedRow,
    selectedColumn,
    multiSelectCornerRow,
    multiSelectCornerColumn,
    setActiveCell,
    listRef,
  } = tableContext;

  const hasControlLock = useHasControlLock();

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLDivElement>) => {
      if (hasControlLock || tableHeaderHasFocus(headerRef)) {
        console.warn('Control lock enabled, can not use keyboard.');

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

        if (listRef.current) {
          listRef.current.scrollToItem(row, 'auto');
        }

        setActiveCell(Math.min(Math.max(row, 0), rowCount - 1), column);
      };

      const context: HandlerContext = {
        tableContext,
        event: e,
        tableRef,
        columnCount,
        ...commands,
        translateCursor,
      };

      const handlers = tableKeyboardHandlers.filter(
        h =>
          !disabledKeyboardInteractions.has(h.id) &&
          h.keys.has(e.key) &&
          h.cursorMode.has(tableContext.cursorMode) &&
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
    },
    [
      disabledKeyboardInteractions,
      selectedRow,
      selectedColumn,
      multiSelectCornerRow,
      multiSelectCornerColumn,
      tableContext,
      commands.copy,
      commands.undo,
      commands.expand,
      hasControlLock,
    ],
  );

  return handleKeyDown;
}
