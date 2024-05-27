import { useEffect, useRef, useState } from 'react';

export function useHTMLFormFieldValidation(): [
  valid: boolean,
  ref: React.RefObject<HTMLInputElement>,
] {
  const [valid, setValid] = useState(false);

  const ref = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!ref.current) return;

    const callback = (e: Event) => {
      const target = e.target as HTMLInputElement;
      // For some reason setting the state directly causes the browser to skip the users input so we wait for an idle frame.
      requestAnimationFrame(() => setValid(target.validity.valid));
    };

    ref.current.addEventListener('input', callback);

    return () => ref.current?.removeEventListener('input', callback);
  }, []);

  return [valid, ref];
}
