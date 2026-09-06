// @wc-ignore-file
// Cloud Vault against this device's embedded node, for the desktop and Android
// apps.
//
// In a browser the vault runs inside the WASM ClientDb, because that *is* the
// local database there. These apps have no ClientDb: the embedded server
// already persists everything, and running an OPFS copy alongside would mean
// two databases holding the same drive. So the same `atomic_lib::vault`
// functions run natively against the node's own store, and this file is only
// the shape that lets `backupDrive` / `restoreDrive` call them without knowing
// which one they got.
//
// Only sealing lives on the other side of this. The network half — presigned
// URLs, uploads, the agent-signed proof — stays in `vault.ts`, where the
// agent's key already is. See `desktop/src/lib.rs`.
import { decodeB64, encodeB64 } from '@tomic/lib';
import { invoke } from '@tauri-apps/api/core';
import type { RestoreOutcome, SegmentKind, VaultCapableDb } from './vault';

/**
 * Bytes cross the IPC boundary base64-encoded rather than as arrays.
 *
 * A `Uint8Array` does not survive the trip as itself — it arrives as a plain
 * number array, and `serde` on the other side takes it as one. That is
 * precisely how a stringified byte array once ended up stored in every vault
 * object, uploaded and confirmed, unreadable. A string has one obvious
 * meaning on both sides.
 */
type SealedObject = { objectKey: string; sealed: string };

export const nodeVault: VaultCapableDb = {
  async vaultExport(
    driveSubject,
    key,
    keyEpoch,
    drivePseudonym,
    devicePubkey,
    segment,
    checkpointN,
    driveHasCheckpoint,
    observedLanes,
  ) {
    const result = await invoke<
      | (Omit<SealedObject, 'objectKey'> & {
          objectKey: string;
          kind: SegmentKind;
          resources: number;
          unchanged: number;
          tombstones: number;
          coverage: Record<string, number>;
        })
      | null
    >('vault_export', {
      driveSubject,
      key: encodeB64(key),
      keyEpoch,
      drivePseudonym,
      devicePubkey,
      segment,
      checkpointN,
      driveHasCheckpoint,
      observedLanes,
    });

    // Null is a real answer, not a failure: nothing has changed since this
    // lane's cursor, so there is nothing to upload.
    if (!result) return null;

    return {
      objectKey: result.objectKey,
      sealed: decodeB64(result.sealed),
      kind: result.kind,
      resources: result.resources,
      unchanged: result.unchanged,
      tombstones: result.tombstones,
      coverage: result.coverage,
    };
  },

  async vaultImport(
    key,
    keyEpoch,
    drivePseudonym,
    devicePubkey,
    objects,
  ): Promise<RestoreOutcome> {
    return invoke<RestoreOutcome>('vault_import', {
      key: encodeB64(key),
      keyEpoch,
      drivePseudonym,
      devicePubkey,
      // The importer plans its own order from the newest checkpoint's coverage
      // and observed maps, so this list is what the vault holds rather than a
      // sequence to apply verbatim. See `plan_restore` in the Rust side.
      objects: objects.map(
        (o): SealedObject => ({
          objectKey: o.objectKey,
          sealed: encodeB64(o.sealed),
        }),
      ),
    });
  },

  async vaultCommitSegment(drivePseudonym, devicePubkey, segment) {
    await invoke('vault_commit_segment', {
      drivePseudonym,
      devicePubkey,
      segment,
    });
  },
};
