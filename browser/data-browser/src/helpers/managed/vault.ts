import { AGENT_VAULT_PROOF_MESSAGE, decodeB64 } from '@tomic/lib';
import { managedFetch } from './api';

/**
 * Cloud Vault client: encrypted, blind backup of a drive.
 *
 * The division of labour is deliberate. **WASM does crypto and format, this
 * file does the network.** `vaultExport` hands back bytes that are already
 * sealed; everything here only ever moves ciphertext around. The control plane
 * brokers presigned URLs and never sees a payload, and object bytes go straight
 * to storage rather than through the API — which is why a backup of a large
 * drive does not cost us bandwidth.
 *
 * What that means for reading this file: nothing here can leak drive contents,
 * because nothing here can read them. The security-critical code is in
 * `atomic_lib::vault`; this is plumbing.
 */

/** Signs the fixed derivation message. Satisfied by `@tomic/lib`'s `Agent`. */
export type VaultProofSigner = {
  signBytes(data: Uint8Array): Promise<string>;
  /** The proof computed from the raw key at sign-in, if the agent carries it. */
  vaultProof?: string;
  /** Whether `signBytes` is reproducible. Absent means unknown. */
  signsDeterministically?: boolean;
};

/**
 * The agent's proof, from which its vault key-encryption key is derived.
 *
 * A signature over a fixed message, not the private key. The browser's
 * `CryptoProvider` exposes signing rather than key bytes — deliberately, so
 * hardware-backed and non-extractable keys stay possible. RFC 8032 Ed25519
 * signatures are deterministic, which is what lets every device holding the
 * agent reproduce the same proof and therefore the same key — but that is a
 * property of the implementation, and WebKit's WebCrypto randomizes the nonce.
 * A Safari session signing live got a fresh proof every call: enrolling there
 * wrote a wrapper no device could open, and restoring there failed with "no
 * wrapper in this envelope accepted that credential" against a backup made
 * anywhere else.
 *
 * So the proof the agent computed from its raw key at sign-in wins when it has
 * one. Without it, a live signature is only trusted once it has reproduced
 * itself; a signer that cannot is refused rather than handed a key it will
 * never derive again.
 *
 * It also has exactly one representation, unlike "the agent secret", which in
 * this codebase means the base64 blob, the `privateKey` inside it, or the
 * decoded seed depending on who is asking. Wrapping under one of those and
 * unwrapping with another produced an envelope nothing could open.
 */
export async function agentVaultProof(
  signer: VaultProofSigner,
  proofMessage: Uint8Array,
): Promise<Uint8Array> {
  if (
    signer.vaultProof &&
    bytesEqual(proofMessage, AGENT_VAULT_PROOF_MESSAGE)
  ) {
    return checkedSignature(signer.vaultProof);
  }

  const first = await signer.signBytes(proofMessage);

  if (signer.signsDeterministically === false) {
    const second = await signer.signBytes(proofMessage);

    if (second !== first) {
      throw new Error(
        'This browser signs differently every time, so it cannot reproduce ' +
          'the credential your backups are wrapped under. Sign in with your ' +
          'recovery code or secret again on this browser to fix that.',
      );
    }
  }

  return checkedSignature(first);
}

function checkedSignature(signatureB64: string): Uint8Array {
  const signature = new Uint8Array(decodeB64(signatureB64));

  if (signature.length !== 64) {
    throw new Error(
      `Expected a 64-byte agent signature, got ${signature.length} bytes.`,
    );
  }

  return signature;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

/**
 * This install's lane identifier, as 64 hex characters.
 *
 * Each device appends only to its own lane, so the id only has to be stable and
 * distinct — the control plane validates the shape, not that it is a real
 * public key. Per-device *keys* are deliberately out of v1 scope
 * (`CLOUD_VAULT_ARCHITECTURE.md`, decision 7): they add ceremony without a v1
 * win, and the lane exists to avoid write contention rather than to prove
 * authorship.
 *
 * Derived from the existing per-install device id, so it survives reloads. If
 * local storage is cleared the device gets a new id and therefore a new lane —
 * harmless, because a fresh lane simply starts at segment 1 and restore spans
 * every lane in the drive.
 */
export async function vaultLaneId(deviceId: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(`atomic-vault-lane:${deviceId}`),
  );

  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** One confirmed object, from `GET /api/cloud-vault/{drive}/objects`. */
export type VaultObject = {
  object_id: string;
  object_key: string;
  kind: string;
  size_bytes: number;
  key_epoch: number;
  lane_device_pubkey: string | null;
  segment: number | null;
};

type UploadUrl = {
  already_stored?: boolean;
  object_id: string;
  object_key: string;
  url: string;
  method: string;
  headers: [string, string][];
  size_bytes: number;
};

type DownloadUrl = {
  object_id: string;
  object_key: string;
  url: string;
};

export type VaultEnrollment = {
  drive_name?: string | null;
  drive_emoji?: string | null;
  id: string;
  drive_subject: string;
  /** The agent that enrolled it; an account may hold several agents' drives. */
  agent_subject?: string;
  drive_pseudonym: string;
  status: string;
  used_bytes: number;
  quota_bytes: number;
  last_backup_at: number | null;
  /**
   * The key epoch this drive's uploads must be sealed under. Bumped by a
   * re-key; the control plane refuses objects declaring any other epoch.
   *
   * Optional only for the deploy window in which a control plane predating
   * epoch tracking is still answering — callers read it as `?? 1`, the epoch
   * every drive started at.
   */
  key_epoch?: number;
};

export type BackupOutcome =
  | { status: 'nothing-to-do' }
  | {
      status: 'backed-up';
      /** `'pack'` for an incremental delta, `'checkpoint'` for a fresh anchor. */
      kind: SegmentKind;
      resources: number;
      /**
       * Resources this pass skipped because they had not changed since the last
       * one. On a healthy incremental pass this is nearly the whole drive.
       */
      unchanged: number;
      bytes: number;
      objectKey: string;
    };

export type SegmentKind = 'pack' | 'checkpoint';

export type RestoreOutcome = {
  packsRead: number;
  resourcesRestored: number;
  tombstonesApplied: number;
  /** Objects the newest checkpoint subsumed, so they were never read. */
  objectsSkipped: number;
  /**
   * Objects that would not open. Non-zero means part of the vault is corrupt or
   * foreign — everything else still restored, and reporting a clean restore
   * without mentioning this would be a lie.
   */
  objectsUnreadable: number;
};

/** What a `VaultCheckpointRecord` looks like on the wire. */
export type VaultCheckpoint = {
  checkpoint_n: number;
  /** Device pubkey → last inclusive segment this checkpoint provably holds. */
  coverage: Record<string, number>;
  checkpoint_object_id: string;
  created_at: number;
};

/**
 * The subset of the WASM `ClientDb` this module needs.
 *
 * Declared structurally rather than imported so this file does not depend on
 * which wasm binding module the host wires up — the worker and the tests pass
 * different ones.
 */
export type VaultCapableDb = {
  vaultExport(
    driveSubject: string,
    key: Uint8Array,
    keyEpoch: number,
    drivePseudonym: string,
    devicePubkey: string,
    segment: number,
    checkpointN: number,
    driveHasCheckpoint: boolean,
    observedLanes: Record<string, number>,
  ): Promise<{
    objectKey: string;
    sealed: Uint8Array;
    kind: SegmentKind;
    resources: number;
    unchanged: number;
    tombstones: number;
    /** Checkpoints only; published verbatim to the control plane. */
    coverage: Record<string, number>;
  } | null>;
  vaultImport(
    key: Uint8Array,
    keyEpoch: number,
    drivePseudonym: string,
    devicePubkey: string,
    objects: { objectKey: string; sealed: Uint8Array }[],
  ): Promise<RestoreOutcome>;
  /** Marks a sealed segment as durably stored. See `backupDrive`. */
  vaultCommitSegment(
    drivePseudonym: string,
    devicePubkey: string,
    segment: number,
  ): Promise<void> | void;
};

async function api<T>(
  path: string,
  init?: RequestInit & { body?: string },
): Promise<T> {
  const response = await managedFetch(`${path}`, {
    ...init,
    headers: init?.body
      ? { 'Content-Type': 'application/json', ...(init?.headers ?? {}) }
      : init?.headers,
  });

  if (!response.ok) {
    // The control plane answers 402 when a plan does not cover this, and the
    // body carries an upgrade URL. Surfacing the server's own message beats a
    // generic failure, which is what a user would otherwise see for a billing
    // problem.
    const body = await response.json().catch(() => null);
    throw new Error(
      body?.error ?? `Cloud Vault request failed (${response.status})`,
    );
  }

  return (await response.json()) as T;
}

export async function enrollVault(
  driveSubject: string,
  agentSubject: string,
  metadata?: { name?: string; emoji?: string },
  signal?: AbortSignal,
): Promise<VaultEnrollment> {
  const created = await api<{ enrollment: VaultEnrollment }>(
    '/cloud-vault/enroll',
    {
      signal,
      method: 'POST',
      body: JSON.stringify({
        drive_subject: driveSubject,
        agent_subject: agentSubject,
        drive_name: metadata?.name,
        drive_emoji: metadata?.emoji,
      }),
    },
  );

  return created.enrollment;
}

export async function listVaultDrives(): Promise<VaultEnrollment[]> {
  return api<VaultEnrollment[]>('/cloud-vault/drives');
}

export async function disableVault(drivePseudonym: string): Promise<void> {
  await api(`/cloud-vault/${drivePseudonym}/disable`, {
    method: 'POST',
    body: '{}',
  });
}

/**
 * Store this drive's wrapped vault key.
 *
 * The envelope is sealed under the account's agent secret, which never leaves
 * the browser — the control plane holds ciphertext it cannot open, the same
 * boundary as the recovery-secret blob. Storing it is what makes a wiped device
 * recoverable, and it is why enabling backup asks the user to remember nothing.
 */
export async function putVaultKeyEnvelope(
  drivePseudonym: string,
  envelope: string,
  { replace = false, signal }: { replace?: boolean; signal?: AbortSignal } = {},
): Promise<void> {
  await api(`/cloud-vault/${drivePseudonym}/key`, {
    signal,
    method: 'PUT',
    body: JSON.stringify({ envelope, replace }),
  });
}

/**
 * Fetch this drive's wrapped vault key, or null if none was ever stored.
 *
 * `204` rather than `404` when absent, so a caller can tell "no key yet" from
 * "no such drive" — the first is a drive that has never been backed up, the
 * second is a mistake.
 */
export async function getVaultKeyEnvelope(
  drivePseudonym: string,
): Promise<string | null> {
  const record = await getVaultKeyEnvelopeRecord(drivePseudonym);

  return record?.envelope ?? null;
}

/** A drive key in hand, and the epoch its envelope wrapped it at. */
export type DriveKeyHandle = {
  driveKey: Uint8Array;
  /**
   * The drive's key epoch when this key was unwrapped. Compared with the
   * epoch the drive reports before every upload: a mismatch means someone
   * re-keyed, and this key must not seal anything new.
   */
  keyEpoch: number;
};

/**
 * The stored envelope together with the epoch it wraps. `key_epoch` is
 * optional on the wire only for a control plane predating epoch tracking; it
 * reads as 1, the epoch every drive started at.
 */
export async function getVaultKeyEnvelopeRecord(
  drivePseudonym: string,
  signal?: AbortSignal,
): Promise<{ envelope: string; keyEpoch: number } | null> {
  signal?.throwIfAborted();
  const response = await managedFetch(`/cloud-vault/${drivePseudonym}/key`, {
    signal,
    credentials: 'include',
  });

  if (response.status === 204) return null;

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(
      body?.error ?? `Could not fetch the vault key (${response.status})`,
    );
  }

  const record = (await response.json()) as {
    envelope?: unknown;
    key_epoch?: unknown;
  };

  // A present-but-unusable envelope must not read as "no key yet": the caller
  // would mint a second key and overwrite the real one, making every existing
  // backup permanently undecryptable.
  if (typeof record.envelope !== 'string' || record.envelope.length === 0) {
    throw new Error('The stored vault key is malformed.');
  }

  return {
    envelope: record.envelope,
    keyEpoch: typeof record.key_epoch === 'number' ? record.key_epoch : 1,
  };
}

/** What `GET /api/cloud-vault/{drive}/state` reports. */
export type VaultDriveState = {
  enrollment: VaultEnrollment;
  /** Device pubkey → last segment number written to that lane. */
  lanes: Record<string, number>;
  checkpoints: VaultCheckpoint[];
  pending_uploads: number;
  confirmed_objects: number;
  /**
   * Confirmed objects still sealed under an epoch before the drive's current
   * one. Non-zero after a re-key means that much history is still readable
   * with the old key, until this client re-seals and drops it.
   */
  stale_epoch_objects?: number;
};

/**
 * The checkpoint number this device should claim next.
 *
 * Taken from the server so two devices do not both mint number 1 over an
 * anchorless vault. They still can — the read and the publish are not atomic —
 * and `publish_checkpoint` rejects the loser rather than letting two records
 * claim different coverage over one set of stored bytes.
 */
export function nextCheckpointFor(state: VaultDriveState): number {
  return (
    state.checkpoints.reduce((max, c) => Math.max(max, c.checkpoint_n), 0) + 1
  );
}

/** Read enrollment eligibility without attempting to claim another account's drive. */
export async function canEnrollVault(
  driveSubject: string,
  signal?: AbortSignal,
): Promise<boolean> {
  const result = await api<{ can_enroll: boolean }>(
    '/cloud-vault/eligibility',
    {
      method: 'POST',
      signal,
      body: JSON.stringify({ drive_subject: driveSubject }),
    },
  );

  return result.can_enroll;
}

export async function getVaultState(
  drivePseudonym: string,
  signal?: AbortSignal,
): Promise<VaultDriveState> {
  return api<VaultDriveState>(`/cloud-vault/${drivePseudonym}/state`, {
    signal,
  });
}

/**
 * The segment number this device should write next.
 *
 * Taken from the server's lane state rather than anything local: a device that
 * cleared its storage has no memory of what it wrote, and reusing a segment
 * number would overwrite a pack that is still the only copy of some history.
 */
export function nextSegmentFor(
  state: VaultDriveState,
  devicePubkey: string,
): number {
  return (state.lanes[devicePubkey] ?? 0) + 1;
}

export async function listVaultObjects(
  drivePseudonym: string,
): Promise<VaultObject[]> {
  return api<VaultObject[]>(`/cloud-vault/${drivePseudonym}/objects`);
}

/**
 * Back a drive up: seal locally, upload straight to storage, then tell the
 * control plane what landed.
 *
 * The order matters. The object is confirmed only *after* storage accepted it,
 * so a failed upload leaves a reservation that expires rather than usage the
 * user never consumed. Confirming first would make quota drift upward on every
 * dropped connection.
 *
 * The pass may produce either an incremental **pack** or a **checkpoint**, and
 * `vaultExport` decides which — the cadence lives in Rust so every host makes
 * the same call. A checkpoint takes one extra step: it is *published* after it
 * is confirmed, which is what tells the control plane it may prune the chain
 * the anchor now subsumes. Uploading one without publishing it stores bytes
 * that free nothing.
 */
export async function backupDrive({
  db,
  signal,
  driveSubject,
  drivePseudonym,
  devicePubkey,
  driveKey,
  keyEpoch = 1,
  segment,
  checkpointN,
  driveHasCheckpoint,
  observedLanes,
  collisionRetries = 0,
}: {
  db: VaultCapableDb;
  collisionRetries?: number;
  signal?: AbortSignal;
  driveSubject: string;
  drivePseudonym: string;
  devicePubkey: string;
  driveKey: Uint8Array;
  keyEpoch?: number;
  segment: number;
  checkpointN: number;
  driveHasCheckpoint: boolean;
  observedLanes: Record<string, number>;
}): Promise<BackupOutcome> {
  signal?.throwIfAborted();
  const sealedPack = await db.vaultExport(
    driveSubject,
    driveKey,
    keyEpoch,
    drivePseudonym,
    devicePubkey,
    segment,
    checkpointN,
    driveHasCheckpoint,
    observedLanes,
  );

  signal?.throwIfAborted();
  // An untouched drive produces nothing. Since incremental cursors landed this
  // is the ordinary outcome for an idle device rather than a rare one: a pass
  // whose version vectors all match the lane cursor writes no object at all.
  if (!sealedPack) return { status: 'nothing-to-do' };

  const isCheckpoint = sealedPack.kind === 'checkpoint';

  const { uploads } = await api<{ uploads: UploadUrl[] }>(
    `/cloud-vault/${drivePseudonym}/upload-urls`,
    {
      method: 'POST',
      signal,
      body: JSON.stringify({
        objects: [
          isCheckpoint
            ? {
                kind: 'checkpoint',
                size_bytes: sealedPack.sealed.length,
                key_epoch: keyEpoch,
                checkpoint_n: checkpointN,
              }
            : {
                kind: 'pack',
                size_bytes: sealedPack.sealed.length,
                key_epoch: keyEpoch,
                lane_device_pubkey: devicePubkey,
                segment,
              },
        ],
      }),
    },
  );

  const upload = uploads?.[0];

  if (!upload) {
    throw new Error('The control plane issued no upload URL for this object.');
  }

  // The server decides where an object lives; the client never picks its own
  // location. A mismatch means the two sides disagree about the key layout,
  // which would otherwise only surface as a restore that comes up short.
  if (upload.object_key !== sealedPack.objectKey) {
    throw new Error(
      `Vault key mismatch: control plane issued ${upload.object_key}, client sealed ${sealedPack.objectKey}`,
    );
  }

  if (upload.already_stored) {
    // A cancelled pass may have confirmed bytes without publishing its anchor.
    // Those bytes need not match this export. Never overwrite them, publish
    // this export's coverage over them, or advance this export's cursor.
    if (collisionRetries >= 8) {
      throw new Error(
        'Vault backup could not reserve a fresh object after 8 collisions.',
      );
    }

    return backupDrive({
      db,
      signal,
      driveSubject,
      drivePseudonym,
      devicePubkey,
      driveKey,
      keyEpoch,
      driveHasCheckpoint,
      observedLanes,
      checkpointN: isCheckpoint ? checkpointN + 1 : checkpointN,
      segment: isCheckpoint ? segment : segment + 1,
      collisionRetries: collisionRetries + 1,
    });
  }

  // Guard the type rather than assert it. `fetch` accepts any value as `body`
  // and stringifies whatever it does not recognise, so a plain number array —
  // which is what `serde_wasm_bindgen` produces for a `Vec<u8>` unless the
  // boundary is explicit — uploads as the text "1,1,0,0,..." instead of
  // ciphertext. That stores fine, counts fine, and is unrestorable: exactly
  // the kind of success this vault must never report.
  if (!(sealedPack.sealed instanceof Uint8Array)) {
    throw new Error(
      'Vault export returned non-binary data; refusing to upload a corrupt object.',
    );
  }

  const put = await fetch(upload.url, {
    method: 'PUT',
    signal,
    body: sealedPack.sealed as BodyInit,
    headers: Object.fromEntries(
      // Content-Length is set by the browser and cannot be assigned; passing it
      // through would throw before the request is made.
      upload.headers.filter(
        ([name]) => name.toLowerCase() !== 'content-length',
      ),
    ),
  });

  if (!put.ok) {
    throw new Error(`Vault upload failed (${put.status})`);
  }

  await api(`/cloud-vault/${drivePseudonym}/confirm-upload`, {
    method: 'POST',
    signal,
    body: JSON.stringify({
      confirmations: [
        { object_id: upload.object_id, size_bytes: sealedPack.sealed.length },
      ],
    }),
  });

  // Publishing is what makes a checkpoint an anchor. Until this lands the
  // control plane has bytes it cannot prune against, so a checkpoint that
  // uploaded and never published costs storage and frees none.
  //
  // A rejection here means another device published this number first. Its
  // anchor is just as good as ours, so the pass still counts as backed up and
  // the next one picks the next number.
  if (isCheckpoint) {
    try {
      await api(`/cloud-vault/${drivePseudonym}/checkpoint`, {
        method: 'POST',
        signal,
        body: JSON.stringify({
          checkpoint_n: checkpointN,
          coverage: sealedPack.coverage,
          checkpoint_object_id: upload.object_id,
        }),
      });
    } catch (error) {
      signal?.throwIfAborted();
      console.warn(
        `Vault checkpoint ${checkpointN} was not published; another device likely won the race.`,
        error,
      );
    }
  }

  // Only now is the lane's progress official. Sealing parked it; if the upload
  // above had failed, the next pass would retry against the same view of what
  // has been backed up rather than one that assumed success. That matters more
  // than it did before cursors existed: an advanced cursor whose object never
  // landed leaves ops no later delta would ever ship again.
  signal?.throwIfAborted();
  await db.vaultCommitSegment(drivePseudonym, devicePubkey, segment);

  return {
    status: 'backed-up',
    kind: sealedPack.kind,
    resources: sealedPack.resources,
    unchanged: sealedPack.unchanged,
    bytes: sealedPack.sealed.length,
    objectKey: sealedPack.objectKey,
  };
}

/**
 * Restore a drive from its vault into this device's store.
 *
 * Objects are listed from the control plane rather than guessed: keys are
 * reconstructible from the format, but the ids `download-urls` needs are not,
 * so a device that lost its local state can only learn them by asking.
 *
 * The list arrives ordered by key and is applied in that order. Out of order, a
 * later segment's deletion would be applied before the earlier pack that
 * re-creates the resource, and the delete would be undone.
 */
export async function restoreDrive({
  db,
  drivePseudonym,
  devicePubkey,
  driveKey,
  keyEpoch = 1,
  onProgress,
}: {
  db: VaultCapableDb;
  drivePseudonym: string;
  devicePubkey: string;
  driveKey: Uint8Array;
  keyEpoch?: number;
  onProgress?: (downloaded: number, total: number) => void;
}): Promise<RestoreOutcome> {
  const objects = await listVaultObjects(drivePseudonym);

  if (objects.length === 0) {
    return {
      packsRead: 0,
      resourcesRestored: 0,
      tombstonesApplied: 0,
      objectsSkipped: 0,
      objectsUnreadable: 0,
    };
  }

  const { downloads } = await api<{ downloads: DownloadUrl[] }>(
    `/cloud-vault/${drivePseudonym}/download-urls`,
    {
      method: 'POST',
      body: JSON.stringify({ object_ids: objects.map(o => o.object_id) }),
    },
  );

  // Preserve the server's ordering: `download-urls` answers per request and is
  // not required to echo the order back.
  const urlByKey = new Map(downloads.map(d => [d.object_key, d.url]));
  const fetched: { objectKey: string; sealed: Uint8Array }[] = [];

  for (const [index, object] of objects.entries()) {
    const url = urlByKey.get(object.object_key);

    if (!url) {
      throw new Error(`No download URL issued for ${object.object_key}`);
    }

    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(
        `Vault download failed for ${object.object_key} (${response.status})`,
      );
    }

    fetched.push({
      objectKey: object.object_key,
      sealed: new Uint8Array(await response.arrayBuffer()),
    });
    onProgress?.(index + 1, objects.length);
  }

  // Every lane, not just this device's: each device appends only to its own,
  // so importing one would silently drop the rest of the drive's history.
  //
  // The order this list arrives in is not the order it is applied in. The
  // importer reads the newest checkpoint first, then uses its coverage and
  // observed maps to decide what to replay and when — see `plan_restore` in
  // `lib/src/vault/sync.rs`. Passing everything and letting it choose is what
  // keeps that decision in one place rather than duplicated here in JS.
  return db.vaultImport(
    driveKey,
    keyEpoch,
    drivePseudonym,
    devicePubkey,
    fetched,
  );
}

/**
 * The key-management half of the client.
 *
 * Kept separate from the transport above because it is where the "no second
 * secret" promise is actually kept: a drive key is generated once, wrapped
 * under the agent secret, and handed to the control plane as ciphertext. From
 * then on any device that can sign in as this account can get it back.
 */
export type VaultKeyOps = {
  vaultGenerateKey(): Uint8Array;
  vaultWrapKey(driveKey: Uint8Array, agentSecret: Uint8Array): string;
  vaultUnwrapKey(envelope: string, agentSecret: Uint8Array): Uint8Array;
};

/**
 * Turn Cloud Vault on for a drive and make sure its key is recoverable.
 *
 * Enrolls, then generates and stores a wrapped key — but only if the drive does
 * not already have one. Re-running on a drive that is already set up returns
 * the existing key rather than minting a new one: a second key would leave
 * every object written under the first permanently unreadable, which is the
 * worst thing this module could do.
 */
export async function setUpVaultForDrive({
  keys,
  driveSubject,
  agentSubject,
  agentSecret,
  metadata,
  signal,
}: {
  signal?: AbortSignal;
  metadata?: { name?: string; emoji?: string };
  keys: VaultKeyOps;
  driveSubject: string;
  agentSubject: string;
  agentSecret: Uint8Array;
}): Promise<{ enrollment: VaultEnrollment } & DriveKeyHandle> {
  signal?.throwIfAborted();
  const enrollment = await enrollVault(
    driveSubject,
    agentSubject,
    metadata,
    signal,
  );
  const existing = await getVaultKeyEnvelopeRecord(
    enrollment.drive_pseudonym,
    signal,
  );

  signal?.throwIfAborted();

  if (existing) {
    return {
      enrollment,
      driveKey: keys.vaultUnwrapKey(existing.envelope, agentSecret),
      keyEpoch: existing.keyEpoch,
    };
  }

  const driveKey = keys.vaultGenerateKey();

  try {
    // Stored before anything is backed up. A key that exists only in memory
    // when the first upload happens would leave objects nobody can open if the
    // tab closed in between.
    await putVaultKeyEnvelope(
      enrollment.drive_pseudonym,
      keys.vaultWrapKey(driveKey, agentSecret),
      { signal },
    );
  } catch {
    signal?.throwIfAborted();
    // Create-only, so this means another client won the race and stored its
    // own key between our read and our write. Theirs is authoritative: adopting
    // it is the only outcome where both clients can read each other's backups.
    // Ours has sealed nothing yet, so discarding it costs nothing.
    const winner = await getVaultKeyEnvelopeRecord(
      enrollment.drive_pseudonym,
      signal,
    );

    if (!winner) throw new Error('Could not store or recover a vault key.');

    return {
      enrollment,
      driveKey: keys.vaultUnwrapKey(winner.envelope, agentSecret),
      keyEpoch: winner.keyEpoch,
    };
  }

  return { enrollment, driveKey, keyEpoch: enrollment.key_epoch ?? 1 };
}

/**
 * Recover a drive's key on a device that has none.
 *
 * This is the step that makes "clear site data, sign in, restore" work: the
 * envelope comes from the control plane, the agent secret comes from signing
 * in, and neither alone is enough.
 */
export async function recoverDriveKey({
  keys,
  drivePseudonym,
  agentSecret,
}: {
  keys: VaultKeyOps;
  drivePseudonym: string;
  agentSecret: Uint8Array;
}): Promise<DriveKeyHandle> {
  const record = await getVaultKeyEnvelopeRecord(drivePseudonym);

  if (!record) {
    throw new Error(
      'This drive has no stored vault key, so its backups cannot be decrypted.',
    );
  }

  return {
    driveKey: keys.vaultUnwrapKey(record.envelope, agentSecret),
    keyEpoch: record.keyEpoch,
  };
}

/**
 * Run one backup pass for a drive.
 *
 * Picks the segment from the server's lane state, so a device that lost its
 * local storage does not overwrite a pack that is still the only copy of some
 * history.
 *
 * **Single-flight per drive.** Two passes running at once would both read the
 * same "next" segment and race to write it, and the loser's history would be
 * silently overwritten. Concurrent callers share the in-flight promise instead
 * of starting a second pass.
 *
 * That guard is per JavaScript context, which is enough only because exactly
 * one context is meant to run this. The ClientDb worker is that context — a
 * SharedWorker fans every tab into one inner worker, so the store has a single
 * writer. Driving backups from individual tabs instead would reintroduce the
 * race across tabs, where an in-process lock cannot see it.
 */
const inFlight = new Map<string, Promise<BackupOutcome>>();

export function runVaultBackup(args: {
  signal?: AbortSignal;
  db: VaultCapableDb;
  driveSubject: string;
  drivePseudonym: string;
  devicePubkey: string;
  driveKey: Uint8Array;
  /**
   * The epoch `driveKey` was unwrapped at. Read as 1 when absent: a drive
   * that was never re-keyed has only ever had epoch 1.
   */
  driveKeyEpoch?: number;
  /**
   * Fetch and unwrap the drive's current envelope. Called when the drive
   * reports an epoch other than `driveKeyEpoch`, which means someone re-keyed
   * since this key was obtained. Without it a re-keyed drive cannot be backed
   * up from here: sealing with the old key while declaring the new epoch
   * would pass the server's check and produce objects the new key cannot
   * read, which is the exact hole the epoch exists to close.
   */
  refreshDriveKey?: () => Promise<DriveKeyHandle>;
}): Promise<BackupOutcome> {
  const existing = inFlight.get(args.drivePseudonym);

  if (existing) return existing;

  const pass = (async () => {
    args.signal?.throwIfAborted();
    const state = await getVaultState(args.drivePseudonym, args.signal);
    args.signal?.throwIfAborted();

    // A suspended vault refuses uploads; asking anyway would just produce an
    // error per tick and bury anything else in the log.
    if (state.enrollment.status !== 'active') {
      return { status: 'nothing-to-do' } as BackupOutcome;
    }

    // The epoch comes from the state just read, never from the caller. The
    // key has to match it: a long-lived caller holding the key it started
    // with is exactly the client that would keep sealing under a key someone
    // was just removed from.
    const currentEpoch = state.enrollment.key_epoch ?? 1;
    let { driveKey } = args;
    let heldEpoch = args.driveKeyEpoch ?? 1;

    if (heldEpoch !== currentEpoch) {
      if (!args.refreshDriveKey) {
        throw new Error(
          `This drive was re-keyed (epoch ${currentEpoch}, key in hand is epoch ${heldEpoch}); fetch the current key envelope before backing up.`,
        );
      }

      ({ driveKey, keyEpoch: heldEpoch } = await args.refreshDriveKey());

      if (heldEpoch !== currentEpoch) {
        throw new Error(
          `The stored key envelope wraps epoch ${heldEpoch} but the drive is at epoch ${currentEpoch}; the re-key did not finish, so nothing can be sealed safely.`,
        );
      }
    }

    return backupDrive({
      ...args,
      driveKey,
      keyEpoch: currentEpoch,
      segment: nextSegmentFor(state, args.devicePubkey),
      checkpointN: nextCheckpointFor(state),
      driveHasCheckpoint: state.checkpoints.length > 0,
      // What the vault held when this pass started. A checkpoint records it so
      // a restore can tell which segments predate the anchor and must be
      // replayed before it.
      observedLanes: state.lanes,
    });
  })().finally(() => {
    inFlight.delete(args.drivePseudonym);
  });

  inFlight.set(args.drivePseudonym, pass);

  return pass;
}
