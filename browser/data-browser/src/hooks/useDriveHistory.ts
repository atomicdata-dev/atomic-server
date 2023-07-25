import { useLocalStorage } from '@tomic/react';
import { useCallback, useMemo } from 'react';
import { useSavedDrives } from './useSavedDrives';

const MAX_DRIVE_HISTORY = 5;

export function useDriveHistory(
  filter: string[] = [],
  limit = Number.MAX_VALUE,
): [
  driveHistory: string[],
  addDriveToHistory: (drive: string) => void,
  removeFromHistory: (drive: string) => void,
] {
  const [savedDrives] = useSavedDrives();
  const [driveHistory, setDriveHistory] = useLocalStorage<string[]>(
    'driveHistory',
    [],
  );

  const addDriveToHistory = useCallback(
    (drive: string) => {
      setDriveHistory(prev => {
        if (prev[0] === drive) {
          return prev;
        }

        return [drive, ...prev.filter(d => d !== drive)].slice(
          0,
          MAX_DRIVE_HISTORY,
        );
      });
    },
    [savedDrives, setDriveHistory],
  );

  const removeFromHistory = useCallback(
    (drive: string) => {
      setDriveHistory(prev => prev.filter(d => d !== drive));
    },
    [setDriveHistory],
  );

  const slicedAndFilteredHistory = useMemo(
    () => driveHistory.slice(0, limit).filter(d => !filter.includes(d)),
    [driveHistory, filter],
  );

  return [slicedAndFilteredHistory, addDriveToHistory, removeFromHistory];
}
