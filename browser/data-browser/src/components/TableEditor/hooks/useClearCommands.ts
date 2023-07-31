import { useEffect } from 'react';
import { TableEvent, useTableEditorContext } from '../TableEditorContext';
import { CellIndex } from '../types';
import { useGetSelectedCells } from './useGetSelectedCells';

export function useClearCommands<T>(
  columns: T[],
  onClearRow?: (index: number) => void,
  onClearCells?: (cells: CellIndex<T>[]) => void,
) {
  const { registerEventListener } = useTableEditorContext();
  const getSelectedCells = useGetSelectedCells(columns);

  useEffect(() => {
    if (onClearRow) {
      return registerEventListener(TableEvent.ClearRow, onClearRow);
    }
  }, [onClearRow, registerEventListener]);

  useEffect(() => {
    if (!onClearCells) {
      return;
    }

    const clearCells = () => {
      const cells = getSelectedCells();
      onClearCells?.(cells);
    };

    return registerEventListener(TableEvent.ClearCell, clearCells);
  }, [registerEventListener, onClearCells, getSelectedCells]);
}
