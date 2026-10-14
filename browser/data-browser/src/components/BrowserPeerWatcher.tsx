import { useEffect } from 'react';
import { useStore } from '@tomic/react';
import { useSettings } from '../helpers/AppSettings';
import {
  discoverPeerDrives,
  resumePeerLinks,
  stopPeerLinks,
} from '../helpers/browserPeerSync';

/** A tab hidden this long leaves the room, so it stops taking up a slot. */
const IDLE_LEAVE_MS = 2 * 60 * 1000;

/** Keep enabled peer links alive across route changes, scoped to this identity. */
export function BrowserPeerWatcher() {
  const store = useStore();
  const { agent } = useSettings();
  useEffect(() => {
    let hiddenSince: number | null = null;

    const idle = () => {
      if (!document.hidden) {
        hiddenSince = null;

        return false;
      }

      hiddenSince ??= Date.now();

      return Date.now() - hiddenSince >= IDLE_LEAVE_MS;
    };

    const resume = () => {
      // A background tab nobody is looking at would otherwise hold one of the
      // few places in the room. It rejoins as soon as it is visible again.
      if (idle()) {
        stopPeerLinks(store);

        return;
      }

      resumePeerLinks(store);
      void discoverPeerDrives(store);
    };

    // A closing or reloading tab never runs the cleanup below, and its peer
    // sessions live in the leader tab's database until that tab closes.
    // Stop them while the page is going away; the interval resumes them if
    // it comes back from the back/forward cache.
    const leave = () => stopPeerLinks(store);
    window.addEventListener('pagehide', leave);
    const timer = setInterval(resume, 2000);
    resume();

    return () => {
      window.removeEventListener('pagehide', leave);
      clearInterval(timer);
      stopPeerLinks(store);
    };
  }, [store, agent]);

  return null;
}
