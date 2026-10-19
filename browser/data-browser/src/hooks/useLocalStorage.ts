import { useCallback, useEffect, useRef, useState } from 'react';

const listeners = new Map<
  string,
  Set<(value: React.SetStateAction<unknown>) => void>
>();

export type SetLocalStorageValue<T> = (value: T | ((val: T) => T)) => void;

export function useLocalStorage<T>(
  key: string,
  initialValue: T,
  storage: Storage = window.localStorage,
): [T, SetLocalStorageValue<T>] {
  // State to store our value
  // Pass initial state function to useState so logic is only executed once
  const [storedValue, setStoredValue] = useState<T>(() => {
    try {
      // Get from local storage by key
      const item = storage.getItem(key);

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

  // The latest value, kept in a ref so `setValue` keeps one identity. A setter
  // that changed after every write made effects depending on it loop (#2212).
  const valueRef = useRef(storedValue);

  // Return a wrapped version of useState's setter function that
  // persists the new value to localStorage.
  const setValue = useCallback(
    (value: T | ((val: T) => T)) => {
      try {
        // Allow value to be a function so we have same API as useState
        const valueToStore =
          value instanceof Function ? value(valueRef.current) : value;

        // Save state
        for (const listener of listeners.get(key) || []) {
          listener(valueToStore);
        }

        // Save to local storage
        storage.setItem(key, JSON.stringify(valueToStore));
      } catch (error) {
        // A more advanced implementation would handle the error case
        console.error(error);
      }
    },
    [key, storage],
  );

  useEffect(() => {
    if (!listeners.has(key)) {
      listeners.set(key, new Set());
    }

    const listener = (value: unknown) => {
      valueRef.current = value as T;
      setStoredValue(value as T);
    };

    listeners.get(key)?.add(listener);

    return () => {
      listeners.get(key)?.delete(listener);
    };
  }, [key]);

  return [storedValue, setValue];
}

/** Write a value to storage and notify all `useLocalStorage` subscribers for that key (same tab). */
export function setLocalStorageValue<T>(
  key: string,
  value: T,
  storage: Storage = window.localStorage,
): void {
  try {
    for (const listener of listeners.get(key) || []) {
      listener(value);
    }

    storage.setItem(key, JSON.stringify(value));
  } catch (error) {
    console.error(error);
  }
}
