import { useEffect, useRef } from 'react';

export function useLifecycleWithDependencies(
  onMount: () => void,
  onCleanup: () => void,
) {
  const mountRef = useRef(onMount);
  const cleanupRef = useRef(onCleanup);

  mountRef.current = onMount;
  cleanupRef.current = onCleanup;

  useEffect(() => {
    mountRef.current();

    return () => {
      cleanupRef.current();
    };
  }, []);
}
