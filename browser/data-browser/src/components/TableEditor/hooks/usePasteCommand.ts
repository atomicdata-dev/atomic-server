import { useCallback } from 'react';
import { parseHTMLTable } from '../helpers/clipboard';
import { useTableEditorContext } from '../TableEditorContext';
import { CellPasteData } from '../types';

const matrixToCellPasteData = <T>(
  matrix: string[][],
  columns: T[],
  offsetRow: number,
  offsetCol: number,
): CellPasteData<T>[] => {
  const cellPasteData: CellPasteData<T>[] = [];

  for (const [rowIndex, row] of matrix.entries()) {
    for (const [colIndex, cell] of row.entries()) {
      cellPasteData.push({
        index: [
          rowIndex + offsetRow,
          columns[colIndex + Math.max(0, offsetCol - 1)],
        ],
        data: cell,
      });
    }
  }

  return cellPasteData;
};

export function usePasteCommand<T>(
  columns: T[],
  onPaste?: (pasteData: CellPasteData<T>[]) => void,
) {
  const { selectedRow, selectedColumn } = useTableEditorContext();

  const triggerPaste = useCallback(
    async (event: ClipboardEvent) => {
      if (selectedColumn === undefined || selectedRow === undefined) {
        return;
      }

      // Don't use custom paste logic when the user is focussed on an input
      if (document.activeElement?.tagName === 'INPUT') {
        return;
      }

      const htmlData = event.clipboardData?.getData('text/html');

      if (htmlData) {
        const parsedData = parseHTMLTable(htmlData);
        const cellPasteData = matrixToCellPasteData(
          parsedData,
          columns,
          selectedRow,
          selectedColumn,
        );

        onPaste?.(cellPasteData);
      }
    },
    [selectedRow, selectedColumn, onPaste],
  );

  return triggerPaste;
}
