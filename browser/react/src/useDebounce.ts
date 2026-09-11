import { Resource } from '@tomic/lib';
import { useCallback, useEffect, useMemo, useState } from 'react';

import { useSaveState, useStore } from './hooks.js';

// T is a generic type for value parameter, our case this will be string
export function useDebounce<T>(value: T, delay: number): T {
  // State and setters for debounced value
  const [debouncedValue, setDebouncedValue] = useState<T>(value);

  useEffect(
    () => {
      // Update debounced value after delay
      const handler = setTimeout(() => {
        setDebouncedValue(value);
      }, delay);

      // Cancel the timeout if value changes (also on delay change or unmount)
      // This is how we prevent debounced value from updating if value is changed ...
      // .. within the delay period. Timeout gets cleared and restarted.
      return () => {
        clearTimeout(handler);
      };
    },
    [value, delay], // Only re-call effect if value or delay changes
  );

  return debouncedValue;
}

export function useDebouncedSave(
  resource: Resource,
  timeout: number,
  onError?: (error: Error) => void,
): [save: () => void, savePending: boolean] {
  const store = useStore();
  const stable = resource.__internalObject;
  const scheduler = useMemo(
    () => store.createSaveScheduler(stable),
    [store, stable],
  );
  useEffect(() => {
    scheduler.setErrorHandler(onError ?? (error => store.notifyError(error)));
  }, [scheduler, onError, store]);
  useEffect(
    () => () => {
      void scheduler.flush();
    },
    [scheduler],
  );
  const save = useCallback(
    () => scheduler.schedule(timeout),
    [scheduler, timeout],
  );
  const state = useSaveState(stable);

  return [save, state.kind === 'scheduled' || state.kind === 'saving'];
}
