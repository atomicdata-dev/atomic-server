import { useEffect, useRef } from 'react';

/** Logic is called only once - also in React 18! */
export function useEffectOnce(effect: () => (() => void) | void) {
  const called = useRef(false);
  useEffect(() => {
    if (!called.current) {
      called.current = true;

      return effect();
    }
  }, []);
}
