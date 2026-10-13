import {
  getEffectiveConstraint,
  ResourceEvents,
  type Constraint,
} from '@tomic/lib';
import { useCallback, useMemo, useRef, useSyncExternalStore } from 'react';
import { useStore } from './hooks.js';

/**
 * The constraint that applies to a property for instances of the given classes:
 * the merged class `constraints` maps, falling back per keyword to the
 * Property's legacy `allowsOnly`, `classtype` and `min`/`max`.
 * See {@link getEffectiveConstraint}.
 *
 * Re-renders when any of the classes or the property changes, including edits
 * that have not been saved yet. The object is the `useSyncExternalStore`
 * snapshot: it is rebuilt after each of those changes and stays the same
 * between them. It must come out of the store hook rather than be computed
 * from the hook's arguments: the React Compiler (data-browser compiles this
 * package, which is linked from outside `node_modules`) caches anything that
 * only depends on `store`, the class subjects and the property subject, and
 * the resources behind them mutate in place, so the editor would keep showing
 * the first value it read.
 */
export function useEffectiveConstraint(
  classSubjects: string[] | undefined,
  propertySubject: string | undefined,
): Constraint {
  const store = useStore();
  const key = (classSubjects ?? []).join('\n');
  const stableSubjects = useMemo(() => (key ? key.split('\n') : []), [key]);
  const watched = useMemo(
    () =>
      propertySubject ? [...stableSubjects, propertySubject] : stableSubjects,
    [stableSubjects, propertySubject],
  );

  // The resources mutate in place, so a counter stands in for their state.
  const version = useRef(0);
  const cache = useRef<
    | {
        version: number;
        key: string;
        propertySubject: string | undefined;
        store: unknown;
        value: Constraint;
      }
    | undefined
  >(undefined);
  const subscribe = useCallback(
    (callback: () => void) => {
      const bump = () => {
        version.current += 1;
        callback();
      };

      // `store.subscribe` covers loads and commits; `LocalChange` covers
      // `set()` before it is saved.
      const unsubscribers = watched.flatMap(subject => [
        store.subscribe(subject, bump),
        store
          .getResourceLoading(subject)
          .stable.on(ResourceEvents.LocalChange, bump),
      ]);

      return () => unsubscribers.forEach(unsubscribe => unsubscribe());
    },
    [store, watched],
  );
  const getSnapshot = useCallback((): Constraint => {
    const hit = cache.current;

    if (
      hit &&
      hit.version === version.current &&
      hit.key === key &&
      hit.propertySubject === propertySubject &&
      hit.store === store
    ) {
      return hit.value;
    }

    const value = propertySubject
      ? getEffectiveConstraint(store, stableSubjects, propertySubject)
      : {};
    cache.current = {
      version: version.current,
      key,
      propertySubject,
      store,
      value,
    };

    return value;
  }, [store, key, stableSubjects, propertySubject]);

  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}
