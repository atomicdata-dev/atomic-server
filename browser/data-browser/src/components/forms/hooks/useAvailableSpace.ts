import { useDeferredValue, useLayoutEffect, useState } from 'react';

export function useAvailableSpace<T extends HTMLElement>(
  trigger: boolean,
  ref: React.RefObject<T>,
) {
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
    above: space.above,
    below: space.below,
    width: space.width,
  };
}
