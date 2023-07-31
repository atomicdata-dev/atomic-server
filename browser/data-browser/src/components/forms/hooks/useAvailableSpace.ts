import { useDeferredValue, useLayoutEffect, useRef, useState } from 'react';

export function useAvailableSpace<T extends HTMLElement>(trigger: boolean) {
  const ref = useRef<T>(null);
  const [space, setSpace] = useState({ above: 0, below: 0, width: 0 });

  const deferredTrigger = useDeferredValue(trigger);

  useLayoutEffect(() => {
    if (trigger) {
      const { top, bottom, width } = ref.current!.getBoundingClientRect();
      const { innerHeight } = window;
      setSpace({ above: top, below: innerHeight - bottom, width });
    }
  }, [deferredTrigger]);

  return {
    ref,
    above: space.above,
    below: space.below,
    width: space.width,
  };
}
