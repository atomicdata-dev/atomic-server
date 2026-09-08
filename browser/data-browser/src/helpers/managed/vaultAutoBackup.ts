import { driveDisplayMetadata } from './driveDisplayMetadata';
import { StoreEvents, type Store } from '@tomic/lib';
import {
  VaultSessionEndedError,
  agentVaultProof,
  canEnrollVault,
  getVaultState,
  listVaultDrives,
  recoverDriveKey,
  restoreDrive,
  runVaultBackup,
  setUpVaultForDrive,
  vaultLaneId,
  type BackupOutcome,
  type DriveKeyHandle,
  type RestoreOutcome,
  type VaultCapableDb,
  type VaultKeyOps,
} from './vault';
import { loadVaultKeyOps } from './vaultKeyOps';
import { getOrCreateDeviceId } from './devices';
import { getManagedAccount, onManagedLogout } from './session';
import { evaluateIdentityReconciliation } from './reconcile';
import { nodeVault } from './nodeVault';
import { isRunningInTauri } from '../tauri';

/**
 * Cloud Vault without a button.
 *
 * Every account on a managed origin gets an encrypted backup of its personal
 * drive, free, whether it asked or not. Before this, backup was something a new
 * identity received during onboarding and everyone else had to find on the Sync
 * page — so an account that signed in with its secret on a second browser found
 * nothing, and was told its data lived "on another device". For someone on the
 * free tier there is no other device: the drive is local-only, and the browser
 * profile that made it is the only copy. A backup nobody has to think about is
 * what makes that case answerable.
 *
 * Three moments, one module:
 *
 * - {@link ensureVaultBackup}: enrol the drive (idempotent) and back it up now.
 *   Called at sign-in and at boot, so existing accounts are covered too.
 * - {@link watchForVaultBackups}: back the drive up again a while after the
 *   last edit, and when the tab goes to the background.
 * - {@link restoreFromVault}: pull the backup down on a device that has none of
 *   the data, without a click.
 *
 * All of it is best-effort. The vault needs a control-plane session, the wasm
 * bundle, and a device id; missing any of those makes every call here a quiet
 * no-op rather than an error the user has to read. A workspace with backup
 * switched off is a working workspace; onboarding and sign-in must never block
 * on this.
 */

export type VaultAutoBackupDeps = {
  /** Whether a control-plane session exists. Nothing here works without one. */
  hasAccount: () => Promise<boolean>;
  canEnroll?: typeof canEnrollVault;
  /** Enrollment must wait until the local identity matches the portal account. */
  identityMatches?: (agentSubject: string) => Promise<boolean>;
  loadKeys: () => Promise<VaultKeyOps & { proofMessage: Uint8Array }>;
  /** The lane this device writes to, or null when it has no identity yet. */
  laneId: () => Promise<string | null>;
  /**
   * The local store the drive lives in, once it is attached — or null when
   * this build has none. Async because the ClientDb attaches a few hundred ms
   * after sign-in, and a restore or first backup asked for in that window
   * must wait for it rather than conclude there is nothing to write to.
   */
  db: (store: Store) => Promise<VaultCapableDb | null>;
  setUpVaultForDrive: typeof setUpVaultForDrive;
  runVaultBackup: typeof runVaultBackup;
  listVaultDrives: typeof listVaultDrives;
  getVaultState: typeof getVaultState;
  recoverDriveKey: typeof recoverDriveKey;
  restoreDrive: typeof restoreDrive;
  /** Whether the user switched backup off for this drive on purpose. */
  optedOut: (driveSubject: string) => boolean;
};

const OPT_OUT_KEY = 'atomic.vault.optOut';

/**
 * Drives whose owner turned Cloud Vault off by hand.
 *
 * The control plane cannot tell us: a disabled enrollment is simply absent from
 * the list, exactly like one that never existed, and re-enrolling is how the
 * server implements "enable". So the choice is remembered here — per browser,
 * which is the scope the choice was made in. Without this, every sign-in would
 * switch back on the thing the user just switched off.
 */
function readOptOuts(): Set<string> {
  try {
    const raw = localStorage.getItem(OPT_OUT_KEY);

    return new Set(raw ? (JSON.parse(raw) as string[]) : []);
  } catch {
    return new Set();
  }
}

export function setVaultOptOut(driveSubject: string, optedOut: boolean): void {
  const drives = readOptOuts();

  if (optedOut) drives.add(driveSubject);
  else drives.delete(driveSubject);

  try {
    localStorage.setItem(OPT_OUT_KEY, JSON.stringify([...drives]));
  } catch {
    // Storage disabled: the choice lasts the session, which is all we can do.
  }
}

export function isVaultOptedOut(driveSubject: string): boolean {
  return readOptOuts().has(driveSubject);
}

const defaultDeps: VaultAutoBackupDeps = {
  canEnroll: canEnrollVault,
  identityMatches: async subject =>
    (await evaluateIdentityReconciliation(subject)).ok,
  // A self-hosted server answers `/api/me` with whatever it likes; that is
  // "no account", not a failure worth logging.
  hasAccount: async () =>
    (await getManagedAccount().catch(() => null)) !== null,
  loadKeys: loadVaultKeyOps,
  laneId: async () => {
    const deviceId = getOrCreateDeviceId();

    return deviceId ? vaultLaneId(deviceId) : null;
  },
  // Same choice `useDriveVault` makes: the desktop and Android apps keep the
  // drive in their embedded node and have no ClientDb.
  db: async store => {
    if (isRunningInTauri()) return nodeVault;

    await store.waitForClientDb(CLIENT_DB_WAIT_MS);

    return store.getClientDb() ?? null;
  },
  setUpVaultForDrive,
  runVaultBackup,
  listVaultDrives,
  getVaultState,
  recoverDriveKey,
  restoreDrive,
  optedOut: isVaultOptedOut,
};

/**
 * Drives this session has enrolled, with their keys.
 *
 * In memory only, for the same reason `useVaultBackup` keeps its key in a ref:
 * the durable copy is the wrapped envelope on the control plane, and a page
 * that persisted the plaintext key would be persisting the one thing the vault
 * is designed never to hold. A reload recovers it by signing the proof message
 * again, which costs one round trip.
 */
const enrolled = new Map<
  string,
  { drivePseudonym: string; metadata?: string } & DriveKeyHandle
>();

/** Only in tests. */
export function forgetEnrolledVaults(): void {
  enrolled.clear();
}

export type EnsureVaultOutcome =
  | { status: 'skipped'; reason: string }
  | { status: 'failed'; error: Error }
  | BackupOutcome;

/**
 * Enrol `driveSubject` in Cloud Vault if it is not yet, and back it up now.
 *
 * Idempotent: the control plane returns the existing enrollment for a drive
 * this account already has, and `setUpVaultForDrive` adopts the stored key
 * rather than minting a second one. So this is safe to call on every sign-in,
 * which is the point — an account that never went through onboarding here gets
 * its backup the next time it signs in.
 *
 * Backs up straight away rather than only enrolling, for the reason
 * onboarding does: an enrollment with nothing in it reports a protection the
 * account does not have.
 */
export function ensureVaultBackup(
  store: Store,
  driveSubject: string,
  deps: VaultAutoBackupDeps = defaultDeps,
): Promise<EnsureVaultOutcome> {
  // Sign-in and the boot watcher both ask for the same drive within the same
  // second. `runVaultBackup` already shares an in-flight pass, but enrolling
  // and unwrapping the key twice is still two round trips for nothing.
  const existing = ensuring.get(driveSubject);

  if (existing) return existing;

  const pass = ensureVaultBackupOnce(store, driveSubject, deps)
    .then(outcome => {
      // Skips are by design, but the reason is exactly what someone looking
      // at a Sync page that still says "off" needs to see.
      if (outcome.status === 'skipped') {
        console.info('[cloud-vault] backup skipped:', outcome.reason);
      }

      return outcome;
    })
    .finally(() => {
      ensuring.delete(driveSubject);
    });
  ensuring.set(driveSubject, pass);

  return pass;
}

const ensuring = new Map<string, Promise<EnsureVaultOutcome>>();

/**
 * How long to wait for the ClientDb to attach after sign-in. Deriving the
 * database name and unwrapping the agent's key takes a few hundred ms on a
 * laptop; a phone with a slow key unwrap wants a generous ceiling.
 */
const CLIENT_DB_WAIT_MS = 20_000;

type VaultChangeListener = (driveSubject: string) => void;
const vaultChangeListeners = new Set<VaultChangeListener>();

/**
 * Called when a drive's enrollment or backup changed through the automatic
 * path, so a screen that shows the vault's status (the Sync page) re-reads it
 * rather than keeping the "off" it rendered a moment earlier.
 */
export function onVaultChanged(listener: VaultChangeListener): () => void {
  vaultChangeListeners.add(listener);

  return () => {
    vaultChangeListeners.delete(listener);
  };
}

function notifyVaultChanged(driveSubject: string): void {
  for (const listener of vaultChangeListeners) listener(driveSubject);
}

async function ensureVaultBackupOnce(
  store: Store,
  driveSubject: string,
  deps: VaultAutoBackupDeps,
): Promise<EnsureVaultOutcome> {
  const agent = store.getAgent();

  if (!agent?.subject) return { status: 'skipped', reason: 'not signed in' };

  if (deps.optedOut(driveSubject)) {
    return { status: 'skipped', reason: 'backup switched off for this drive' };
  }

  const controller = new AbortController();
  const { signal } = controller;
  const stop = () => controller.abort();
  const offAgent = store.on(StoreEvents.AgentChanged, next => {
    if (next?.subject !== agent.subject) stop();
  });
  const offLogout = onManagedLogout(stop);
  if (typeof window !== 'undefined') window.addEventListener('pagehide', stop);

  try {
    // Cached keys do not imply that the account session is still valid.
    if (!(await deps.hasAccount())) {
      return { status: 'skipped', reason: 'no account session' };
    }

    signal.throwIfAborted();
    const db = await deps.db(store);
    signal.throwIfAborted();
    const lane = await deps.laneId();

    if (!db || !lane) {
      return { status: 'skipped', reason: 'no local database or device id' };
    }

    let known = enrolled.get(driveSubject);

    // Display metadata is shared with SaaS; read it from the local drive.
    const metadata = await driveDisplayMetadata(store, driveSubject);
    const metadataKey = JSON.stringify(metadata);

    if (!known || (known.metadata ?? '{}') !== metadataKey) {
      if (
        deps.identityMatches &&
        !(await deps.identityMatches(agent.subject))
      ) {
        return {
          status: 'skipped',
          reason: 'account identity needs reconciliation',
        };
      }

      signal.throwIfAborted();

      if (deps.canEnroll && !(await deps.canEnroll(driveSubject, signal))) {
        return {
          status: 'skipped',
          reason: 'drive backup belongs to another account',
        };
      }

      const keys = await deps.loadKeys();
      const proof = await agentVaultProof(agent, keys.proofMessage);

      if (store.getAgent()?.subject !== agent.subject) {
        return {
          status: 'skipped',
          reason: 'identity changed during backup setup',
        };
      }

      signal.throwIfAborted();
      const { enrollment, driveKey, keyEpoch } = await deps.setUpVaultForDrive({
        signal,
        keys,
        driveSubject,
        metadata,
        agentSubject: agent.subject,
        // The agent signs a fixed message; its key is never read. That is what
        // keeps non-extractable and hardware-backed keys usable here.
        agentSecret: proof,
      });
      known = {
        drivePseudonym: enrollment.drive_pseudonym,
        driveKey,
        keyEpoch,
        metadata: metadataKey,
      };
      enrolled.set(driveSubject, known);
    }

    if (store.getAgent()?.subject !== agent.subject) {
      return {
        status: 'skipped',
        reason: 'identity changed during backup setup',
      };
    }

    signal.throwIfAborted();
    const held = known;
    const agentSubject = agent.subject;
    const outcome = await deps.runVaultBackup({
      signal,
      db,
      driveSubject,
      drivePseudonym: held.drivePseudonym,
      devicePubkey: lane,
      driveKey: held.driveKey,
      driveKeyEpoch: held.keyEpoch,
      beforeNetworkWrite: async () => {
        signal.throwIfAborted();

        if (
          !(await deps.hasAccount()) ||
          (deps.identityMatches && !(await deps.identityMatches(agentSubject)))
        ) {
          controller.abort();
        }

        signal.throwIfAborted();
      },
      // The drive was re-keyed since this key was cached: fetch the current
      // envelope, and remember it so the next tick does not refetch.
      refreshDriveKey: async () => {
        const keys = await deps.loadKeys();
        const fresh = await deps.recoverDriveKey({
          keys,
          drivePseudonym: held.drivePseudonym,
          agentSecret: await agentVaultProof(agent, keys.proofMessage),
        });
        enrolled.set(driveSubject, {
          drivePseudonym: held.drivePseudonym,
          ...fresh,
        });

        return fresh;
      },
    });
    signal.throwIfAborted();
    notifyVaultChanged(driveSubject);

    return outcome;
  } catch (error) {
    // A stale key or enrollment must not be reused after a failure; the next
    // attempt re-derives both from the control plane.
    enrolled.delete(driveSubject);

    if (signal.aborted || error instanceof VaultSessionEndedError) {
      return {
        status: 'skipped',
        reason: 'backup cancelled by account change',
      };
    }

    console.warn('[cloud-vault] backup failed', error);

    return {
      status: 'failed',
      error: error instanceof Error ? error : new Error(String(error)),
    };
  } finally {
    offAgent();
    offLogout();
    if (typeof window !== 'undefined')
      window.removeEventListener('pagehide', stop);
  }
}

/** Incremental packs make short idle backups cheap; unchanged drives upload nothing. */
export const AUTO_BACKUP_IDLE_MS = 5_000;
export const AUTO_BACKUP_MAX_WAIT_MS = 30_000;
export const AUTO_BACKUP_RETRY_MS = 60_000;

export type VaultRestoreOutcome =
  | { status: 'restored'; outcome: RestoreOutcome }
  | { status: 'no-backup'; reason: string }
  | { status: 'failed'; error: Error };

/**
 * Bring `driveSubject` back from its vault, if there is one to bring.
 *
 * `no-backup` covers every case where restoring is not possible rather than
 * broken — no session, no enrollment, an enrollment with nothing confirmed in
 * it — so a caller can fall through to its other routes without showing an
 * error for a device that simply has nothing to restore.
 */
export async function restoreFromVault(
  store: Store,
  driveSubject: string,
  deps: VaultAutoBackupDeps = defaultDeps,
): Promise<VaultRestoreOutcome> {
  const agent = store.getAgent();

  if (!agent?.subject) return { status: 'no-backup', reason: 'not signed in' };

  try {
    // Session first: one quick request, against a database wait of up to
    // `CLIENT_DB_WAIT_MS`. Sign-in calls this on every device that holds no
    // data, and a browser that never signed in to the account — the common
    // case for a fresh one — should not sit on "Restoring…" for twenty seconds
    // to be told there was nothing to ask.
    if (!(await deps.hasAccount())) {
      return { status: 'no-backup', reason: 'no account session' };
    }

    const db = await deps.db(store);

    if (!db) return { status: 'no-backup', reason: 'no local database' };

    const enrollment = (await deps.listVaultDrives()).find(
      e => e.drive_subject === driveSubject && e.status === 'active',
    );

    if (!enrollment) {
      return { status: 'no-backup', reason: 'drive is not backed up' };
    }

    const state = await deps.getVaultState(enrollment.drive_pseudonym);

    // An empty vault restores zero resources, which on screen is
    // indistinguishable from a failed restore.
    if (state.confirmed_objects === 0) {
      return { status: 'no-backup', reason: 'the vault is empty' };
    }

    // This device's lane. A restore records which other lanes it imported, so a
    // checkpoint published from here later can claim coverage for them — the
    // only route by which a lane belonging to a device that is gone for good
    // ever becomes prunable.
    const lane = await deps.laneId();

    if (!lane) {
      return { status: 'no-backup', reason: 'this device has no identity yet' };
    }

    const keys = await deps.loadKeys();
    const { driveKey, keyEpoch } = await deps.recoverDriveKey({
      keys,
      drivePseudonym: enrollment.drive_pseudonym,
      agentSecret: await agentVaultProof(agent, keys.proofMessage),
    });
    const outcome = await deps.restoreDrive({
      db,
      drivePseudonym: enrollment.drive_pseudonym,
      devicePubkey: lane,
      driveKey,
    });

    // The device now holds the drive and the key; later edits here should go
    // back up without a second enrollment round trip.
    enrolled.set(driveSubject, {
      drivePseudonym: enrollment.drive_pseudonym,
      driveKey,
      keyEpoch,
    });
    notifyVaultChanged(driveSubject);

    return { status: 'restored', outcome };
  } catch (error) {
    console.warn('[cloud-vault] restore failed', error);

    return {
      status: 'failed',
      error: error instanceof Error ? error : new Error(String(error)),
    };
  }
}

/** Local Tauri data lives in its embedded node, not the browser's local-only registry. */
export function isEmbeddedVaultDrive(store: Store): boolean {
  if (!isRunningInTauri()) return false;

  return ['localhost', '127.0.0.1', '[::1]'].includes(
    new URL(store.getServerUrl()).hostname,
  );
}

/**
 * Incremental backups while the app is running. Keep every edited drive queued,
 * cap the debounce, and retry after account/network recovery without another edit.
 * Remote drives are only backed up when already enrolled with this account.
 */
export function watchForVaultBackups(
  store: Store,
  deps: VaultAutoBackupDeps = defaultDeps,
  options: {
    idleMs?: number;
    maxWaitMs?: number;
    retryMs?: number;
    window?: Window | null;
  } = {},
): () => void {
  const idleMs = options.idleMs ?? AUTO_BACKUP_IDLE_MS;
  const maxWaitMs = options.maxWaitMs ?? AUTO_BACKUP_MAX_WAIT_MS;
  const win =
    options.window === undefined
      ? typeof window === 'undefined'
        ? null
        : window
      : options.window;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let deadline: ReturnType<typeof setTimeout> | undefined;
  let stopped = false;
  let generation = 0;
  const pending = new Set<string>();

  const flush = () => {
    clearTimeout(timer);
    clearTimeout(deadline);
    timer = deadline = undefined;
    const drives = [...pending];
    pending.clear();
    const identity = store.getAgent()?.subject;
    const passGeneration = generation;

    if (!identity) return;

    void (async () => {
      // Avoid enrollment discovery requests when signed out. Keep work queued
      // so a reconnect or periodic retry can finish it later.
      const retry = (drive: string) => {
        if (
          !stopped &&
          passGeneration === generation &&
          store.getAgent()?.subject === identity
        )
          pending.add(drive);
      };

      try {
        if (!drives.length || stopped || !(await deps.hasAccount())) {
          drives.forEach(retry);

          return;
        }

        const remote = drives.filter(
          drive =>
            !store.isLocalOnlyDrive(drive) &&
            !enrolled.has(drive) &&
            !isEmbeddedVaultDrive(store),
        );
        const existing = remote.length ? await deps.listVaultDrives() : [];

        for (const drive of drives) {
          if (
            stopped ||
            passGeneration !== generation ||
            store.getAgent()?.subject !== identity
          )
            return;
          if (
            remote.includes(drive) &&
            !existing.some(item => item.drive_subject === drive)
          )
            continue;
          const outcome = await ensureVaultBackup(store, drive, deps);
          if (outcome.status === 'failed' || outcome.status === 'skipped')
            retry(drive);
        }
      } catch {
        // Discovery can fail offline; the next bounded retry rechecks it.
        drives.forEach(retry);
      }
    })();
  };

  const schedule = () => {
    const drive = store.getDrive();
    if (!drive || stopped) return;
    pending.add(drive);
    clearTimeout(timer);
    timer = setTimeout(flush, idleMs);
    deadline ??= setTimeout(flush, maxWaitMs);
  };

  const resume = () => {
    schedule();
    flush();
  };

  const onVisibility = () => {
    if (win?.document.visibilityState === 'hidden') flush();
    else resume();
  };

  const reset = () => {
    generation++;
    enrolled.clear();
    pending.clear();
    clearTimeout(timer);
    clearTimeout(deadline);
    timer = deadline = undefined;
    schedule();
  };

  const unsubscribe = [
    store.on(StoreEvents.ResourceSaved, schedule),
    store.on(StoreEvents.ResourceRemoved, schedule),
    store.on(StoreEvents.ResourceManuallyCreated, schedule),
    store.on(StoreEvents.DriveChanged, schedule),
    store.on(StoreEvents.AgentChanged, reset),
    onManagedLogout(reset),
  ];
  // Also catches native-node changes that do not emit browser Store events,
  // and accounts linked after the initial mount. No-change passes upload nothing.
  const periodic = setInterval(resume, options.retryMs ?? AUTO_BACKUP_RETRY_MS);
  win?.document.addEventListener('visibilitychange', onVisibility);
  win?.addEventListener('online', resume);
  schedule();

  return () => {
    stopped = true;
    clearTimeout(timer);
    clearTimeout(deadline);
    clearInterval(periodic);
    pending.clear();
    unsubscribe.forEach(off => off());
    win?.document.removeEventListener('visibilitychange', onVisibility);
    win?.removeEventListener('online', resume);
  };
}
