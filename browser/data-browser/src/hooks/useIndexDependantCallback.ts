import { useMemo } from 'react';
import { GenericFunction } from '../helpers/genericTypes';

/**
 * A hook that builds a list of callbacks that recieve the index of the item in the dependant array.
 * Usefull for buttons in a list that need to know which item they are acting on but should also be memoized.
 * @param callbackFactory A function that takes an index and returns the actual callback.
 * @param dependantArray This array determines the amount of callbacks that will be created.
 * @param dependancies Any values the callback depends on (same as a useCallback dependancy array).
 */
export function useIndexDependantCallback<CB extends GenericFunction>(
  callbackFactory: (index: number) => CB,
  dependantArray: unknown[],
  dependancies: unknown[],
): CB[] {
  return useMemo(() => {
    return dependantArray.map((_, i) => callbackFactory(i));
  }, [dependantArray, ...dependancies]);
}
