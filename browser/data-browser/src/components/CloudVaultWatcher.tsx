import { useEffect } from 'react';
import { useStore } from '@tomic/react';
import { useSettings } from '../helpers/AppSettings';
import { deviceHasDriveData } from '../helpers/driveData';
import { fetchPrivateDriveSubject } from '../helpers/privateDrive';
import {
  AUTO_BACKUP_RETRY_MS,
  ensureVaultBackup,
  watchForVaultBackups,
} from '../helpers/managed/vaultAutoBackup';

/**
 * Keeps the signed-in account's personal drive backed up in Cloud Vault while
 * the app is open. Renders nothing.
 *
 * Two jobs. At boot, and whenever the agent changes, it enrols the personal
 * drive and backs it up once — which is how an account that predates automatic
 * backup, or that only ever signs in on this device, gets covered without
 * going through sign-in again. After that it backs the open drive up again a
 * while after each edit. Periodic retries cover late account linking and data
 * arriving after startup. Both paths require an eligible account session.
 */
export function CloudVaultWatcher() {
  const store = useStore();
  const { agent } = useSettings();
  const subject = agent?.subject;

  useEffect(() => watchForVaultBackups(store), [store]);

  useEffect(() => {
    if (!subject || !agent) return;

    let cancelled = false;

    let checking = false;

    const check = async () => {
      if (checking || cancelled) return;
      checking = true;

      try {
        const drive = await fetchPrivateDriveSubject(store, agent).catch(
          () => undefined,
        );

        if (cancelled || !drive) return;

        // Nothing to back up from a device that does not hold the drive — and
        // sign-in handles that device by restoring instead.
        if (!(await deviceHasDriveData(store, drive))) return;

        if (!cancelled) await ensureVaultBackup(store, drive);
      } finally {
        checking = false;
      }
    };

    void check();
    // Account linking, restored data and connectivity can arrive after mount.
    const retry = setInterval(() => void check(), AUTO_BACKUP_RETRY_MS);
    const onOnline = () => void check();
    window.addEventListener('online', onOnline);

    return () => {
      cancelled = true;
      clearInterval(retry);
      window.removeEventListener('online', onOnline);
    };
    // `agent` is a new object on every settings render; its subject is what
    // identifies a sign-in.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [store, subject]);

  return null;
}
