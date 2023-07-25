import { RefObject, useEffect, useRef, useState } from 'react';

// hook returns tuple(array) with type [any, boolean]
// T - could be any type of HTML element like: HTMLDivElement, HTMLParagraphElement and etc.
export function useHover<T extends HTMLElement>(
  disabled: boolean,
): [RefObject<T>, boolean] {
  const [value, setValue] = useState<boolean>(false);

  const ref = useRef<T>(null);

  useEffect(() => {
    const handleMouseOver = (): void => setValue(true);
    const handleMouseOut = (): void => setValue(false);

    // eslint-disable-next-line
    const node = ref.current;

    // This could be expensive, and triggers re-renders for some reasons.
    // That's why it's disabled as much as possible.
    if (!disabled && node) {
      node.addEventListener('mouseover', handleMouseOver);
      node.addEventListener('mouseout', handleMouseOut);

      return () => {
        node.removeEventListener('mouseover', handleMouseOver);
        node.removeEventListener('mouseout', handleMouseOut);
      };
    }
  }, [disabled]);

  // don't hover on touch screen devices
  if (window.matchMedia('(pointer: coarse)').matches) {
    return [ref, false];
  }

  return [ref, value];
}
