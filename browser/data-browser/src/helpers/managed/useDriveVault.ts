import { driveDisplayMetadata } from './driveDisplayMetadata';
import { useCallback, useEffect, useState } from 'react';
import { useStore } from '@tomic/react';
import { reopenRestoredDrive } from '../driveData';
import { loadVaultKeyOps } from './vaultKeyOps';
import { vaultLaneId, type VaultKeyOps } from './vault';
import { getOrCreateDeviceId } from './devices';
import { nodeVault } from './nodeVault';
import { isRunningInTauri } from '../tauri';
import { useVaultBackup, type UseVaultBackup } from './useVaultBackup';

/**
 * Cloud Vault for one drive, with its prerequisites resolved.
 *
 * {@link useVaultBackup} takes the key ops, the agent, the proof message and
 * this install's lane id as inputs; getting them involves the wasm bundle, an
 * async device id and the store's agent. That assembly is the same everywhere
 * the vault is offered, and duplicating it is how two screens end up disagreeing
 * about whether a vault exists — so it lives here once.
 *
 * Every input is allowed to be missing. A server that serves no wasm bundle, a
 * signed-out store, a drive that hasn't resolved yet: all of them leave the
 * returned status at `loading`/`unavailable`, which callers render as nothing
 * rather than as an offer that cannot work.
 */
export function useDriveVault(driveSubject: string | null): UseVaultBackup {
  const store = useStore();
  const [keys, setKeys] = useState<VaultKeyOps | null>(null);
  const [proofMessage, setProofMessage] = useState<Uint8Array | null>(null);
  const [laneId, setLaneId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      try {
        const loaded = await loadVaultKeyOps();
        const deviceId = getOrCreateDeviceId();

        if (cancelled || !deviceId) return;

        setKeys(loaded);
        setProofMessage(loaded.proofMessage);
        setLaneId(await vaultLaneId(deviceId));
      } catch {
        // No wasm bundle (a server that doesn't serve one, an old build).
        // Leaving these null keeps the vault reported as unavailable.
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  const agent = store.getAgent();

  const getDisplayMetadata = useCallback(
    () =>
      driveSubject
        ? driveDisplayMetadata(store, driveSubject)
        : Promise.resolve({}),
    [store, driveSubject],
  );

  const vault = useVaultBackup({
    getDisplayMetadata,
    // Whichever local store this build actually keeps the drive in. A browser
    // has the ClientDb; the desktop and Android apps have the embedded node and
    // deliberately no ClientDb, since a second copy of the same drive is the
    // thing that arrangement exists to avoid. Both reach the same Rust.
    db: isRunningInTauri() ? nodeVault : (store.getClientDb() ?? null),
    keys,
    driveSubject,
    agentSubject: agent?.subject ?? null,
    // The agent signs; its key is never read here. That is what keeps
    // hardware-backed and non-extractable keys possible.
    signer: agent ?? null,
    proofMessage,
    devicePubkey: laneId,
  });

  // A restore writes to the local database, which the store does not watch.
  // Three screens offer the restore; one of them used to refetch the drive
  // afterwards and the other two navigated straight into the cached "could
  // not open" that had brought the user there. Done here, so an offer cannot
  // forget.
  const { restore: importFromVault } = vault;
  const restore = useCallback(async () => {
    const outcome = await importFromVault();

    if (outcome && driveSubject) {
      await reopenRestoredDrive(store, driveSubject);
    }

    return outcome;
  }, [importFromVault, driveSubject, store]);

  return { ...vault, restore };
}
