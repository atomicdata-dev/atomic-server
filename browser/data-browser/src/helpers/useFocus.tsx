import { useRef } from 'react';

/** Hook for programmaticall setting focus */
export const useFocus = (): [React.RefObject<unknown>, () => void] => {
  const htmlElRef = useRef<HTMLElement>(null);

  const setFocus = () => {
    htmlElRef.current?.focus();
  };

  return [htmlElRef, setFocus];
};
