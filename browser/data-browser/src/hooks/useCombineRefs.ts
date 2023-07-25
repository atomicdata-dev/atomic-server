import React, { useCallback } from 'react';

/**
 * Returns a callback ref that sets all given refs to the same passed in node.
 * Usefull if you want multiple refs to reference the same dom element.
 */
export function useCombineRefs<T>(
  refs: React.MutableRefObject<T>[],
  deps: unknown[] = [],
): (node: T) => void {
  return useCallback((node: T) => {
    for (const ref of refs) {
      ref.current = node;
    }
  }, deps);
}
