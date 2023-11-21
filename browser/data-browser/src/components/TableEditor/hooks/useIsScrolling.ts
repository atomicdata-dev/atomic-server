import { useCallback, useEffect, useRef } from 'react';

/**
 * Sets a ref to true when the user is scrolling the given element.
 * @param ref The element to attach the scroll listener to.
 * @param isScrollingRef The ref that is modified to reflect if the user is scrolling.
 * @param pollingRate After how many milliseconds the hook should check if the user is still scrolling.
 */
export function useIsScrolling<T extends HTMLElement>(
  ref: React.RefObject<T | null>,
  isScrollingRef: React.MutableRefObject<boolean>,
  pollingRate = 100,
): void {
  const scrollLeft = useRef(0);
  const scrollTop = useRef(0);
  const timeoutID = useRef<number | undefined>();

  const scrollPositionChanged = (): boolean => {
    const node = ref.current;

    return (
      !!node &&
      node.scrollLeft !== scrollLeft.current &&
      node.scrollTop !== scrollTop.current
    );
  };

  const checkIfScrollEnded = useCallback(() => {
    if (ref.current === null) {
      return;
    }

    if (scrollPositionChanged()) {
      // The user is still scrolling.
      scrollLeft.current = ref.current.scrollLeft;
      scrollTop.current = ref.current.scrollTop;

      timeoutID.current = setTimeout(
        checkIfScrollEnded,
        pollingRate,
      ) as unknown as number;
    } else {
      // The user has stopped scrolling.
      isScrollingRef.current = false;
      timeoutID.current = undefined;
    }
  }, [ref, pollingRate]);

  const handleScroll = useCallback(() => {
    if (ref.current === null) {
      return;
    }

    if (!isScrollingRef.current) {
      isScrollingRef.current = true;
      scrollLeft.current = ref.current.scrollLeft;
      scrollTop.current = ref.current.scrollTop;
    }

    if (timeoutID.current !== undefined) {
      clearTimeout(timeoutID.current);
    }

    timeoutID.current = setTimeout(
      checkIfScrollEnded,
      pollingRate,
    ) as unknown as number;
  }, [ref, pollingRate, checkIfScrollEnded]);

  useEffect(() => {
    if (ref.current === null) {
      return;
    }

    const listener = () => {
      requestAnimationFrame(() => {
        handleScroll();
      });
    };

    ref.current.addEventListener('scroll', listener);

    return () => ref.current?.removeEventListener('scroll', listener);
  }, [ref]);
}
