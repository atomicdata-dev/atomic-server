import { useCallback, useEffect, useRef, useState } from 'react';
import {
  agentVaultProof,
  disableVault,
  getVaultState,
  listVaultDrives,
  recoverDriveKey,
  restoreDrive,
  runVaultBackup,
  setUpVaultForDrive,
  type DriveKeyHandle,
  type RestoreOutcome,
  type VaultCapableDb,
  type VaultDriveState,
  type VaultEnrollment,
  type VaultKeyOps,
  type VaultProofSigner,
} from './vault';
import { onVaultChanged, setVaultOptOut } from './vaultAutoBackup';

/**
 * Cloud Vault state for one drive, ready to bind to a UI.
 *
 * The drive key is held in memory for the session and never persisted here.
 * Its durable home is the wrapped envelope on the control plane, which only the
 * account's agent secret opens — so a reload simply fetches and unwraps it
 * again rather than keeping a decrypted copy anywhere a script could reach.
 */
export type VaultStatus =
  | { state: 'loading' }
  | { state: 'unavailable'; reason: string }
  | { state: 'off' }
  | { state: 'on'; enrollment: VaultEnrollment; details: VaultDriveState };

export type UseVaultBackup = {
  status: VaultStatus;
  busy: boolean;
  error: string | null;
  enable: () => Promise<void>;
  disable: () => Promise<void>;
  backupNow: () => Promise<void>;
  restore: () => Promise<RestoreOutcome | null>;
  /** 0–1 while a restore is downloading, otherwise null. */
  restoreProgress: number | null;
  /**
   * Re-read the enrollment and vault state. For a screen that knows something
   * changed on the control-plane side that no store event reports — a session
   * that did not exist when the first read said `unavailable`.
   */
  refresh: () => Promise<void>;
};

/**
 * What the vault is still waiting on, in words a reader can act on.
 *
 * Each of these is a legitimate "not yet" for a moment and a permanent state
 * after that — a server that serves no wasm bundle, a signed-out store, a
 * drive that never resolves. The panel rendered nothing for either case, so a
 * device that would never be ready looked identical to one still starting,
 * forever, with nothing on screen to say so.
 *
 * Pure and exported so the wording is testable without rendering a hook.
 */
export function describeMissingVaultInputs(inputs: {
  db: unknown;
  keys: unknown;
  driveSubject: unknown;
  agentSubject: unknown;
  signer: unknown;
  devicePubkey: unknown;
}): string[] {
  return [
    !inputs.db && 'no local database',
    !inputs.keys && 'the encryption keys did not load',
    !inputs.driveSubject && 'no drive is open',
    !(inputs.agentSubject && inputs.signer) && 'not signed in',
    !inputs.devicePubkey && 'this device has no identity yet',
  ].filter(Boolean) as string[];
}

/**
 * How long the inputs get to arrive before the panel says so instead.
 *
 * Generous: the wasm bundle and the device id are async on a cold load, and a
 * panel that flashed an error before settling would be worse than the silence
 * it replaces.
 */
const READINESS_GRACE_MS = 6_000;

export function useVaultBackup({
  db,
  keys,
  driveSubject,
  agentSubject,
  signer,
  proofMessage,
  devicePubkey,
}: {
  db: VaultCapableDb | null;
  keys: VaultKeyOps | null;
  driveSubject: string | null;
  agentSubject: string | null;
  /** Signs the derivation message. The private key is never handled here. */
  signer: VaultProofSigner | null;
  proofMessage: Uint8Array | null;
  devicePubkey: string | null;
}): UseVaultBackup {
  const [status, setStatus] = useState<VaultStatus>({ state: 'loading' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [restoreProgress, setRestoreProgress] = useState<number | null>(null);

  // Kept in a ref rather than state: it is not rendered, and putting a key in
  // state would put it in React DevTools for anyone with the page open.
  const driveKey = useRef<DriveKeyHandle | null>(null);

  const ready = Boolean(
    db &&
    keys &&
    driveSubject &&
    agentSubject &&
    signer &&
    proofMessage &&
    devicePubkey,
  );

  const missing = describeMissingVaultInputs({
    db,
    keys,
    driveSubject,
    agentSubject,
    signer,
    devicePubkey,
  });

  const refresh = useCallback(async () => {
    if (!driveSubject) return;

    try {
      const drives = await listVaultDrives();
      const enrollment = drives.find(d => d.drive_subject === driveSubject);

      if (!enrollment) {
        setStatus({ state: 'off' });

        return;
      }

      setStatus({
        state: 'on',
        enrollment,
        details: await getVaultState(enrollment.drive_pseudonym),
      });
    } catch (e) {
      // Not signed in, no portal configured, offline. All of these mean "we
      // cannot say", which is different from "backup is off" — showing an
      // enable button here would produce a confusing failure on click.
      setStatus({ state: 'unavailable', reason: (e as Error).message });
    }
  }, [driveSubject]);

  // The automatic path (sign-in, the boot watcher) may enrol this drive after
  // the first read came back "off"; re-read when it says so.
  useEffect(
    () =>
      onVaultChanged(changed => {
        if (changed === driveSubject) void refresh();
      }),
    [driveSubject, refresh],
  );

  useEffect(() => {
    if (ready) {
      void refresh();

      return;
    }

    setStatus({ state: 'loading' });

    // Stop calling it "loading" once it plainly is not. Everything `ready`
    // waits on either arrives within a second or two or never does, and
    // "loading" forever is indistinguishable from a feature that does not
    // exist — which is how the panel came to be invisible on a device with a
    // perfectly good local drive.
    const timer = setTimeout(() => {
      setStatus({
        state: 'unavailable',
        reason: `Cloud Vault is not available here: ${missing.join(', ')}.`,
      });
    }, READINESS_GRACE_MS);

    return () => clearTimeout(timer);
    // `missing` is derived from the same inputs as `ready`; listing it would
    // reset the timer on every render for no gain.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, refresh]);

  /** Make sure we hold the drive key, fetching and unwrapping if needed. */
  const ensureKey = useCallback(
    async (drivePseudonym: string): Promise<DriveKeyHandle> => {
      if (driveKey.current) return driveKey.current;

      const recovered = await recoverDriveKey({
        keys: keys!,
        drivePseudonym,
        agentSecret: await agentVaultProof(signer!, proofMessage!),
      });
      driveKey.current = recovered;

      return recovered;
    },
    [keys, signer, proofMessage],
  );

  /** Drop the cached key and fetch the drive's current envelope. */
  const refreshKey = useCallback(
    async (drivePseudonym: string): Promise<DriveKeyHandle> => {
      driveKey.current = null;

      return ensureKey(drivePseudonym);
    },
    [ensureKey],
  );

  /** Run an action with a single busy flag and a readable error. */
  const run = useCallback(
    async <T>(action: () => Promise<T>): Promise<T | null> => {
      setBusy(true);
      setError(null);

      try {
        return await action();
      } catch (e) {
        setError((e as Error).message);

        return null;
      } finally {
        setBusy(false);
      }
    },
    [],
  );

  const enable = useCallback(async () => {
    await run(async () => {
      const {
        enrollment,
        driveKey: key,
        keyEpoch,
      } = await setUpVaultForDrive({
        keys: keys!,
        driveSubject: driveSubject!,
        agentSubject: agentSubject!,
        agentSecret: await agentVaultProof(signer!, proofMessage!),
      });
      driveKey.current = { driveKey: key, keyEpoch };
      // Turning it on by hand lifts an earlier opt-out, so automatic backups
      // resume as well.
      setVaultOptOut(driveSubject!, false);
      // First backup immediately, so enabling produces something restorable
      // rather than an empty vault waiting on a tick the user cannot see.
      await runVaultBackup({
        db: db!,
        driveSubject: driveSubject!,
        drivePseudonym: enrollment.drive_pseudonym,
        devicePubkey: devicePubkey!,
        driveKey: key,
        driveKeyEpoch: keyEpoch,
        refreshDriveKey: () => refreshKey(enrollment.drive_pseudonym),
      });
      await refresh();
    });
  }, [
    run,
    refreshKey,
    keys,
    driveSubject,
    agentSubject,
    signer,
    proofMessage,
    db,
    devicePubkey,
    refresh,
  ]);

  const disable = useCallback(async () => {
    if (status.state !== 'on') return;

    await run(async () => {
      await disableVault(status.enrollment.drive_pseudonym);
      driveKey.current = null;
      // Backup is on for everyone by default; switching it off here must not
      // be undone by the next sign-in (see vaultAutoBackup.ts).
      setVaultOptOut(driveSubject!, true);
      await refresh();
    });
  }, [run, status, driveSubject, refresh]);

  const backupNow = useCallback(async () => {
    if (status.state !== 'on') return;

    await run(async () => {
      const key = await ensureKey(status.enrollment.drive_pseudonym);
      await runVaultBackup({
        db: db!,
        driveSubject: driveSubject!,
        drivePseudonym: status.enrollment.drive_pseudonym,
        devicePubkey: devicePubkey!,
        driveKey: key.driveKey,
        driveKeyEpoch: key.keyEpoch,
        refreshDriveKey: () => refreshKey(status.enrollment.drive_pseudonym),
      });
      await refresh();
    });
  }, [
    run,
    status,
    ensureKey,
    refreshKey,
    db,
    driveSubject,
    devicePubkey,
    refresh,
  ]);

  const restore = useCallback(async () => {
    if (status.state !== 'on') return null;

    return run(async () => {
      const key = await ensureKey(status.enrollment.drive_pseudonym);
      setRestoreProgress(0);

      try {
        return await restoreDrive({
          db: db!,
          drivePseudonym: status.enrollment.drive_pseudonym,
          // This device's lane, so the import can record which *other* lanes it
          // now provably holds. That is what lets a checkpoint published from
          // here later claim coverage for them — the only way a lane belonging
          // to a device that is gone ever becomes prunable.
          devicePubkey: devicePubkey!,
          driveKey: key.driveKey,
          onProgress: (done, total) =>
            setRestoreProgress(total === 0 ? 1 : done / total),
        });
      } finally {
        setRestoreProgress(null);
      }
    });
  }, [run, status, ensureKey, db, devicePubkey]);

  return {
    status,
    busy,
    error,
    enable,
    disable,
    backupNow,
    restore,
    restoreProgress,
    refresh,
  };
}
