import { useEffect } from 'react';
import { useStore } from '@tomic/react';
import { useSettings } from '../helpers/AppSettings';
import {
  discoverPeerDrives,
  resumePeerLinks,
  stopPeerLinks,
} from '../helpers/browserPeerSync';

/** Keep enabled peer links alive across route changes, scoped to this identity. */
export function BrowserPeerWatcher() {
  const store = useStore();
  const { agent } = useSettings();
  useEffect(() => {
    const resume = () => {
      resumePeerLinks(store);
      void discoverPeerDrives(store);
    };

    const timer = setInterval(resume, 2000);
    resume();

    return () => {
      clearInterval(timer);
      stopPeerLinks(store);
    };
  }, [store, agent]);

  return null;
}
