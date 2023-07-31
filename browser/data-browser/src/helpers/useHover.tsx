import { RefObject, useCallback, useMemo, useRef, useState } from 'react';

type Listeners = {
  onMouseOver?: React.MouseEventHandler;
  onMouseOut?: React.MouseEventHandler;
  onFocus?: React.FocusEventHandler;
  onBlur?: React.FocusEventHandler;
};

export function useHover<T extends HTMLElement>(): [
  ref: RefObject<T>,
  isHovering: boolean,
  listeners: Listeners,
] {
  const [value, setValue] = useState<boolean>(false);

  const ref = useRef<T>(null);

  const onMouseOver = useCallback(() => setValue(true), []);
  const onMouseOut = useCallback(() => setValue(false), []);

  const onFocus = useCallback((e: React.FocusEvent) => {
    if (ref.current?.contains(e.target)) {
      setValue(true);
    }
  }, []);

  const onBlur = useCallback(() => {
    if (!ref.current?.contains(document.activeElement)) {
      setValue(false);
    }
  }, []);

  const listeners = useMemo(
    () => ({
      onMouseOver,
      onMouseOut,
      onFocus,
      onBlur,
    }),
    [onMouseOver, onMouseOut, onFocus, onBlur],
  );

  // don't hover on touch screen devices
  if (window.matchMedia('(pointer: coarse)').matches) {
    return [ref, false, {}];
  }

  return [ref, value, listeners];
}
