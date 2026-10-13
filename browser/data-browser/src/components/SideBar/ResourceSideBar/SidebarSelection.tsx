import {
  createContext,
  useContext,
  useLayoutEffect,
  useState,
  type ReactNode,
} from 'react';
import { useSyncExternalStore } from 'react';

interface Selection {
  /** The subject the app is showing. */
  current: string | undefined;
  /** Ancestors of that resource, nearest first (the resource itself is first). */
  ancestry: string[];
}

class SelectionStore {
  private selection: Selection;
  private listeners = new Set<() => void>();

  public constructor(initial: Selection) {
    this.selection = initial;
  }

  public get = (): Selection => this.selection;

  public subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);

    return () => {
      this.listeners.delete(listener);
    };
  };

  public set(next: Selection): void {
    if (
      next.current === this.selection.current &&
      next.ancestry === this.selection.ancestry
    ) {
      return;
    }

    this.selection = next;
    this.listeners.forEach(listener => listener());
  }
}

const SelectionContext = createContext<SelectionStore | undefined>(undefined);

const noSubscribe = () => () => undefined;

/**
 * Tells the sidebar rows below which resource is open and what its ancestors
 * are, without making every row listen to the router.
 *
 * A row used to read the location itself and take the ancestry as a prop, so
 * each navigation re-rendered every row of the tree (800 rows: over three
 * seconds a click in a dev build). Rows now subscribe to the one fact they
 * need, whether they are the open resource and whether they are one of its
 * ancestors, and only the rows whose answer changed render.
 */
export function SidebarSelectionProvider({
  current,
  ancestry,
  children,
}: Selection & { children: ReactNode }): React.JSX.Element {
  const [store] = useState(() => new SelectionStore({ current, ancestry }));

  useLayoutEffect(() => {
    store.set({ current, ancestry });
  }, [store, current, ancestry]);

  return (
    <SelectionContext.Provider value={store}>
      {children}
    </SelectionContext.Provider>
  );
}

/** Whether `subject` is the resource the app is showing. Re-renders its
 *  caller only when that answer changes. */
export function useIsCurrentSubject(subject: string): boolean {
  const store = useContext(SelectionContext);

  return useSyncExternalStore(
    store?.subscribe ?? noSubscribe,
    () => store?.get().current === subject,
  );
}

/** The ancestry of the open resource when `subject` is one of its ancestors,
 *  else `undefined`. Re-renders its caller only for such rows. */
export function useAncestryIfAncestor(subject: string): string[] | undefined {
  const store = useContext(SelectionContext);

  return useSyncExternalStore(store?.subscribe ?? noSubscribe, () => {
    const ancestry = store?.get().ancestry;

    return ancestry?.includes(subject) && ancestry[0] !== subject
      ? ancestry
      : undefined;
  });
}
