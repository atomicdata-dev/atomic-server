import { ServerSupports, useStore } from './index.js';
import { useEffect, useState } from 'react';

export function useServerSupports(): ServerSupports {
  const store = useStore();
  const [supports, setSupports] = useState<ServerSupports>({
    emailRegister: false,
  });

  useEffect(() => {
    async function check() {
      const res = await store.getServerSupports();
      setSupports(res);
    }

    check();
  }, [store]);

  return supports;
}
