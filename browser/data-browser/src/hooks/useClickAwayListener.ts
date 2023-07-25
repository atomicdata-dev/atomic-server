import { useEffect } from 'react';

type RefList = Array<React.RefObject<HTMLElement | null>>;
type SupportedEvents = 'click' | 'mouseout' | 'mousedown';

const elementsContainTarget = (refs: RefList, target: HTMLElement) =>
  refs
    .filter(r => r.current)
    .some(ref => ref.current === target || ref.current?.contains(target));

const addListeners = (
  types: SupportedEvents[],
  hanlder: (e: MouseEvent) => void,
) => {
  types.forEach(type => window.addEventListener(type, hanlder));
};

const removeListeners = (
  types: SupportedEvents[],
  hanlder: (e: MouseEvent) => void,
) => {
  types.forEach(type => window.removeEventListener(type, hanlder));
};

/**
 * Detects when a user clicks outside of any of the given elements.
 *
 * @param refs List of element refs that will not trigger the listener when clicked.
 * @param onClickAway Callback that will be called when the user clicks outside
 *   of any of the given elements.
 * @param shouldListen When false the callback will not be called.
 * @param eventTypes List of events that will trigger the listener.
 */
export const useClickAwayListener = (
  refs: RefList,
  onClickAway: () => void,
  shouldListen = true,
  eventTypes: SupportedEvents[] = ['mousedown'],
): void => {
  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (
        shouldListen &&
        !elementsContainTarget(refs, e.target as HTMLElement)
      ) {
        e.preventDefault();
        onClickAway();
        removeListeners(eventTypes, onClick);
      }
    };

    addListeners(eventTypes, onClick);

    return () => {
      removeListeners(eventTypes, onClick);
    };
  }, [refs, onClickAway, shouldListen]);
};
