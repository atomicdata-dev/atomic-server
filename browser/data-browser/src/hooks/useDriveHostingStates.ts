import { useCallback, useEffect, useRef, useState } from 'react';
import { useStore } from '@tomic/react';
import {
  managedFetch,
  getRememberedManagedPortalUrl,
} from '../helpers/managed/api';
import { getManagedPortalUrl } from '../helpers/managed/cloudSync';
import type { ManagedEnrollmentSummary } from '../helpers/managed/enrollmentApi';
import {
  listVaultDrives,
  type VaultEnrollment,
} from '../helpers/managed/vault';
import { getManagedAccount } from '../helpers/managed/session';
import { driveHostingState } from '../helpers/managed/driveHostingState';

type Services = {
  agent: string | undefined;
  servers: ManagedEnrollmentSummary[];
  vaults: VaultEnrollment[];
};

/** Fetch once per menu opening, never once per drive. Unknown is not Off. */
export function useDriveHostingStates() {
  const store = useStore();
  const agent = store.getAgent()?.subject;
  const [services, setServices] = useState<Services | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const generation = useRef(0);
  const offered = !!(getManagedPortalUrl() || getRememberedManagedPortalUrl());
  const refresh = useCallback(async () => {
    if (!offered) return;

    const request = ++generation.current;

    try {
      if (!(await getManagedAccount())) {
        if (request !== generation.current) return;
        setServices({ servers: [], vaults: [], agent });
        setUnavailable(false);

        return;
      }

      const [response, vaults] = await Promise.all([
        managedFetch('/sync-enrollments', {}),
        listVaultDrives(),
      ]);

      if (!response.ok) throw new Error('Hosting status unavailable');

      const body = await response.json();
      const servers = Array.isArray(body) ? body : body.enrollments;

      if (!Array.isArray(servers)) throw new Error('Invalid hosting status');
      if (request !== generation.current) return;

      setServices({ servers, vaults, agent });
      setUnavailable(false);
    } catch {
      if (request !== generation.current) return;

      setServices(null);
      setUnavailable(true);
    }
  }, [offered, agent]);

  useEffect(() => {
    void refresh();
    window.addEventListener('focus', refresh);

    return () => {
      generation.current++;
      window.removeEventListener('focus', refresh);
    };
  }, [refresh, agent]);

  const current = services?.agent === agent ? services : null;

  return {
    refresh,
    states: (subject: string) => {
      const labels = driveHostingState(
        store.isLocalOnlyDrive(subject),
        current?.servers.find(e => e.drive_subject === subject),
        current?.vaults.find(e => e.drive_subject === subject),
      );

      if (offered && !current)
        labels.push(unavailable ? 'Cloud unknown' : 'Checking cloud…');

      return labels.join(' · ');
    },
  };
}
