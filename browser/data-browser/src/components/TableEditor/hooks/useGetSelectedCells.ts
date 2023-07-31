import { useCallback } from 'react';
import { CursorMode, useTableEditorContext } from '../TableEditorContext';
import { CellIndex, Corner } from '../types';

const getCornersVisualMode = (
  selectedRow: number,
  selectedColumn: number,
  columns: unknown[],
): [Corner, Corner] => {
  if (selectedColumn === 0) {
    return [
      [selectedRow, 0],
      [selectedRow, columns.length - 1],
    ];
  }

  const c: Corner = [selectedRow, selectedColumn - 1];

  return [[...c], [...c]];
};

const getCornersMultiSelectMode = (
  selectedRow: number,
  selectedColumn: number,
  multiSelectCornerRow: number,
  multiSelectCornerColumn: number,
  columns: unknown[],
): [Corner, Corner] => {
  if (selectedColumn === 0 || multiSelectCornerColumn === 0) {
    return [
      [Math.min(selectedRow, multiSelectCornerRow), 0],
      [Math.max(selectedRow, multiSelectCornerRow), columns.length - 1],
    ];
  }

  const c1: Corner = [selectedRow, selectedColumn - 1];
  const c2: Corner = [multiSelectCornerRow, multiSelectCornerColumn - 1];

  return [c1, c2];
};

function getAllCellsBetweenCorners<T>(
  [row1, col1]: Corner,
  [row2, col2]: Corner,
  columns: T[],
): CellIndex<T>[] {
  const cells: CellIndex<T>[] = [];

  for (let x = Math.min(col1, col2); x <= Math.max(col1, col2); x++) {
    for (let y = Math.min(row1, row2); y <= Math.max(row1, row2); y++) {
      cells.push([y, columns[x]]);
    }
  }

  return cells;
}

export function useGetSelectedCells<T>(columns: T[]): () => CellIndex<T>[] {
  const {
    selectedRow,
    selectedColumn,
    multiSelectCornerRow,
    multiSelectCornerColumn,
    cursorMode,
  } = useTableEditorContext();

  return useCallback(() => {
    if (selectedColumn === undefined || selectedRow === undefined) {
      return [];
    }

    const [c1, c2] =
      cursorMode === CursorMode.MultiSelect
        ? getCornersMultiSelectMode(
            selectedRow,
            selectedColumn,
            multiSelectCornerRow!,
            multiSelectCornerColumn!,
            columns,
          )
        : getCornersVisualMode(selectedRow, selectedColumn, columns);

    return getAllCellsBetweenCorners(c1, c2, columns);
  }, [
    selectedRow,
    selectedColumn,
    multiSelectCornerRow,
    multiSelectCornerColumn,
    cursorMode,
    columns,
  ]);
}
