import { useState, useDeferredValue, useCallback, useEffect } from 'react';

export function useDeferredUpdate<T>(
  onDeferredUpdate: (value: T) => void,
  initialValue: T,
) {
  const [started, setStarted] = useState(false);
  const [realValue, setInnerValue] = useState<T>(initialValue);
  const deferredValue = useDeferredValue(realValue);

  const update = useCallback((value: T) => {
    setInnerValue(value);
    setStarted(true);
  }, []);

  useEffect(() => {
    if (started) {
      onDeferredUpdate(deferredValue);
    }
  }, [started, deferredValue, onDeferredUpdate]);

  return update;
}
