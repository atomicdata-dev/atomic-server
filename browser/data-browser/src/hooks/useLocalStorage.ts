import { useCallback, useEffect, useState } from 'react';

const listeners = new Map<
  string,
  Set<(value: React.SetStateAction<unknown>) => void>
>();

export type SetLocalStorageValue<T> = (value: T | ((val: T) => T)) => void;

export function useLocalStorage<T>(
  key: string,
  initialValue: T,
): [T, SetLocalStorageValue<T>] {
  // State to store our value
  // Pass initial state function to useState so logic is only executed once
  const [storedValue, setStoredValue] = useState<T>(() => {
    try {
      // Get from local storage by key
      const item = window.localStorage.getItem(key);

      if (item === 'undefined') {
        return initialValue;
      }

      // Parse stored json or if none return initialValue
      return item ? JSON.parse(item) : initialValue;
    } catch (error) {
      // If error also return initialValue
      console.error(`Error finding ${key} in localStorage:`, error);

      return initialValue;
    }
  });

  // Return a wrapped version of useState's setter function that
  // persists the new value to localStorage.
  const setValue = useCallback(
    (value: T | ((val: T) => T)) => {
      try {
        // Allow value to be a function so we have same API as useState
        const valueToStore =
          value instanceof Function ? value(storedValue) : value;

        // Save state
        for (const listener of listeners.get(key) || []) {
          listener(valueToStore);
        }

        // Save to local storage
        window.localStorage.setItem(key, JSON.stringify(valueToStore));
      } catch (error) {
        // A more advanced implementation would handle the error case
        console.error(error);
      }
    },
    [storedValue, key],
  );

  useEffect(() => {
    if (!listeners.has(key)) {
      listeners.set(key, new Set());
    }

    listeners.get(key)?.add(setStoredValue as (value: unknown) => void);

    return () => {
      listeners.get(key)?.delete(setStoredValue as (value: unknown) => void);
    };
  }, [key]);

  return [storedValue, setValue];
}
