import { useState } from 'react';

export function useOnValueChange(callback: () => void, dependants: unknown[]) {
  const [deps, setDeps] = useState(dependants);

  if (deps.some((d, i) => d !== dependants[i])) {
    setDeps(dependants);
    callback();
  }
}
