import { CursorMode } from '../TableEditorContext';

/**
 * Whether a cell sits inside the rectangle the person has selected with
 * shift+click or a drag. Column 0 is the row header: a selection that touches
 * it spans whole rows.
 */
export function isInMultiSelection(
  cursorMode: CursorMode,
  selectedRow: number | undefined,
  selectedColumn: number | undefined,
  cornerRow: number | undefined,
  cornerColumn: number | undefined,
  rowIndex: number,
  columnIndex: number,
): boolean {
  if (
    cursorMode !== CursorMode.MultiSelect ||
    selectedRow === undefined ||
    selectedColumn === undefined ||
    cornerRow === undefined ||
    cornerColumn === undefined
  ) {
    return false;
  }

  const wholeRows = selectedColumn === 0 || cornerColumn === 0;

  return (
    rowIndex >= Math.min(selectedRow, cornerRow) &&
    rowIndex <= Math.max(selectedRow, cornerRow) &&
    (wholeRows ||
      (columnIndex >= Math.min(selectedColumn, cornerColumn) &&
        columnIndex <= Math.max(selectedColumn, cornerColumn)))
  );
}
