import { useEffect, useState } from 'react';
import {
  getHostedAIStatus,
  HOSTED_AI_USAGE_EVENT,
  type HostedAIStatus,
} from '@helpers/managed/ai';
import { hasManagedApi } from '@helpers/managed/api';
import {
  hasManagedSession,
  onManagedLogout,
  onManagedSessionChanged,
} from '@helpers/managed/session';

/** Delays before asking again while the status could not be read. */
export const HOSTED_AI_RETRY_DELAYS_MS = [1500, 4000, 10_000, 30_000];

export function useHostedAI() {
  const [status, setStatus] = useState<HostedAIStatus>();
  useEffect(() => {
    let generation = 0;
    let active = true;
    let settlementRefresh: ReturnType<typeof setTimeout> | undefined;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;

    const refresh = async () => {
      const request = ++generation;
      clearTimeout(retryTimer);
      let known = false;
      // Without a session there is nothing to wait for: a sign-in announces
      // itself (`onManagedSessionChanged`), and a return to the tab refreshes.
      let signedIn = true;

      try {
        const next = await getHostedAIStatus();
        if (active && generation === request) setStatus(next);
        known = next !== undefined;
        if (!known) signedIn = await hasManagedSession().catch(() => true);
      } catch {
        // Preserve an existing balance during a transient outage. Requests are
        // always authorized and metered by the server, never by this display.
      }

      if (known || !signedIn) {
        attempt = 0;

        return;
      }

      // One failed or too-early read must not be final: the session cookie can
      // still be settling right after sign-in, and until a status arrives the
      // chat falls back to the bring-your-own-key path. Only a build that has
      // a control plane to ask keeps trying; FOSS has nothing to retry.
      const delay = HOSTED_AI_RETRY_DELAYS_MS[attempt];

      if (
        active &&
        generation === request &&
        delay !== undefined &&
        hasManagedApi()
      ) {
        attempt++;
        retryTimer = setTimeout(() => void refresh(), delay);
      }
    };

    const refreshUsage = () => {
      void refresh();
      clearTimeout(settlementRefresh);
      // The server finishes metering even after the SDK cancels its stream.
      settlementRefresh = setTimeout(() => void refresh(), 1000);
    };

    void refresh();
    window.addEventListener(HOSTED_AI_USAGE_EVENT, refreshUsage);

    const refreshOnFocus = () => {
      attempt = 0;
      void refresh();
    };

    window.addEventListener('focus', refreshOnFocus);

    const removeSessionChanged = onManagedSessionChanged(refreshOnFocus);

    const removeLogout = onManagedLogout(() => {
      generation++;
      clearTimeout(settlementRefresh);
      clearTimeout(retryTimer);
      setStatus(undefined);
    });

    return () => {
      active = false;
      clearTimeout(settlementRefresh);
      clearTimeout(retryTimer);
      removeLogout();
      removeSessionChanged();
      window.removeEventListener(HOSTED_AI_USAGE_EVENT, refreshUsage);
      window.removeEventListener('focus', refreshOnFocus);
    };
  }, []);

  return { hostedAI: status, setHostedAI: setStatus };
}
