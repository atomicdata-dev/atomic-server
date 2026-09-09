import { useEffect } from 'react';
import { useStore } from '@tomic/react';
import { useSettings } from '../helpers/AppSettings';
import { resumePeerLinks, stopPeerLinks } from '../helpers/browserPeerSync';

/** Keep enabled peer links alive across route changes, scoped to this identity. */
export function BrowserPeerWatcher() {
  const store = useStore();
  const { agent } = useSettings();
  useEffect(() => {
    const timer = setInterval(() => resumePeerLinks(store), 2000);
    resumePeerLinks(store);

    return () => {
      clearInterval(timer);
      stopPeerLinks(store);
    };
  }, [store, agent]);

  return null;
}
