import { useStore } from '@tomic/react';
import { useEffect, useState } from 'react';
import { useSettings } from '../helpers/AppSettings';
import { fetchPrivateDriveSubject } from '../helpers/privateDrive';

/**
 * Resolves the signed-in agent's personal (private) home drive.
 * Uses `initialDrive` optimistically while fetching authoritative value from the server.
 */
export function usePrivateDrive(): {
  privateDrive: string | undefined;
  loading: boolean;
} {
  const store = useStore();
  const { agent } = useSettings();
  const [resolvedHome, setResolvedHome] = useState(() => ({
    agent,
    store,
    privateDrive: agent?.initialDrive,
    loading: !!agent,
  }));

  useEffect(() => {
    if (!agent) return;

    let cancelled = false;

    void fetchPrivateDriveSubject(store, agent).then(resolved => {
      if (!cancelled) {
        setResolvedHome({
          agent,
          store,
          privateDrive: resolved,
          loading: false,
        });
      }
    });

    return () => {
      cancelled = true;
    };
  }, [store, agent]);

  // Effects run after render. Never lend the previous identity's resolved
  // home to consumers (Inbox, subscriptions) while the new one is loading.
  return resolvedHome.agent === agent && resolvedHome.store === store
    ? resolvedHome
    : { privateDrive: agent?.initialDrive, loading: !!agent };
}
