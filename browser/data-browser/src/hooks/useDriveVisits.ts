import { useCallback } from 'react';
import { canonicalizeScheme } from '@tomic/lib';
import { useLocalStorage } from './useLocalStorage';

/** Last visit time (ms) per drive, keyed by canonical subject. */
export function useDriveVisits(): [
  driveVisits: Record<string, number>,
  recordVisit: (subject: string) => void,
] {
  const [driveVisits, setDriveVisits] = useLocalStorage<Record<string, number>>(
    'driveVisits',
    {},
  );

  const recordVisit = useCallback(
    (subject: string) => {
      setDriveVisits(prev => ({
        ...prev,
        [canonicalizeScheme(subject)]: Date.now(),
      }));
    },
    [setDriveVisits],
  );

  return [driveVisits, recordVisit];
}
