import { useCallback, useEffect, useRef, useState } from 'react';

type Callback =
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  | ((...args: any[]) => void)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  | ((...args: any[]) => Promise<void>);

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

export function useDebouncedCallback<F extends Callback>(
  func: F,
  time: number,
  deps: unknown[],
): [debouncedFunction: (...args: Parameters<F>) => void, isWaiting: boolean] {
  const timeoutId = useRef<ReturnType<typeof setTimeout>>();
  const [isWaiting, setIsWaiting] = useState(false);

  const memoizedFunction = useCallback(
    (...args: Parameters<F>) => {
      if (timeoutId.current) {
        clearTimeout(timeoutId.current);
      }

      const id = setTimeout(async () => {
        await func(...args);
        timeoutId.current = undefined;
        setIsWaiting(false);
      }, time);
      setIsWaiting(true);
      timeoutId.current = id;
    },
    [...deps, time, timeoutId],
  );

  return [memoizedFunction, isWaiting];
}
