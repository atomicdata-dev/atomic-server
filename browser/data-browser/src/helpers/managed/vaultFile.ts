import {
  downloadVaultObjects,
  listVaultObjects,
  restoreDrive,
  type RestoreOutcome,
  type RestoreSource,
  type SealedObject,
  type VaultCapableDb,
  type VaultObject,
} from './vault';

/**
 * The `.atomic-vault` backup file: a drive's sealed Cloud Vault objects in one
 * file on the person's own device.
 *
 * Nothing in it is readable without the drive key: every object is sealed on
 * the device that made it, exactly as it is stored in the cloud, and the file
 * adds only a header that names them. A restore from the file goes through the
 * same import as a restore from the cloud.
 *
 * Layout (all integers big-endian):
 *
 *   bytes 0..8    magic, the ASCII text `ATMVAULT`
 *   bytes 8..12   u32 `headerLength`
 *   next headerLength bytes
 *                 UTF-8 JSON {@link VaultFileHeader}
 *   rest          the sealed objects back to back, in `header.objects` order,
 *                 each exactly `size` bytes
 *
 * The object order is the order the cloud listed them in (sorted by key), which
 * is the order a restore hands them to the importer.
 */
export const VAULT_FILE_EXTENSION = '.atomic-vault';
export const VAULT_FILE_VERSION = 1;

const MAGIC = new TextEncoder().encode('ATMVAULT');
const PREAMBLE = MAGIC.length + 4;
/** A header larger than this is not one of ours; stops a bad file allocating. */
const MAX_HEADER_BYTES = 64 * 1024 * 1024;

export type VaultFileObject = {
  objectKey: string;
  /** `pack`, `checkpoint`, `blob`, … as the control plane names it. */
  kind: string;
  /** Pack only: the device lane it belongs to. */
  lane: string | null;
  /** Pack only: its segment number in that lane. */
  segment: number | null;
  /** Checkpoint only: its number. */
  checkpointN: number | null;
  keyEpoch: number;
  /** Length of the sealed bytes. */
  size: number;
  /** Lowercase hex SHA-256 of the sealed bytes. */
  contentHash: string;
};

export type VaultFileHeader = {
  version: number;
  /** When the file was made, Unix milliseconds. */
  createdAt: number;
  drivePseudonym: string;
  keyEpoch: number;
  objects: VaultFileObject[];
};

export type VaultFileProblem =
  | 'notAVaultFile'
  | 'incomplete'
  | 'badHeader'
  | 'newerVersion'
  | 'extraData'
  | 'badChecksum'
  | 'otherDrive'
  | 'otherKey'
  | 'mismatch';

/** What each problem says to the reader. Here so the texts are translated. */
function describeProblem(problem: VaultFileProblem): string {
  switch (problem) {
    case 'notAVaultFile':
      return 'This is not an Atomic vault backup file. Pick a file ending in .atomic-vault.';
    case 'incomplete':
      return 'This backup file is incomplete. Download it again.';
    case 'badHeader':
      return 'The header of this backup file is damaged.';
    case 'newerVersion':
      return 'This backup file was made by a newer version of the app. Update the app to restore it.';
    case 'extraData':
      return 'This backup file has extra data at the end and cannot be trusted.';
    case 'badChecksum':
      return 'This backup file is damaged: an object does not match its checksum.';
    case 'otherDrive':
      return 'This backup file is from a different workspace than the one you are restoring.';
    case 'otherKey':
      return 'This backup file was sealed under a different encryption key than this workspace uses now, so it cannot be opened.';
    case 'mismatch':
      return 'The list of objects and their contents do not match.';
  }
}

/** Thrown for a file that is not a usable backup; the message is for the reader. */
export class VaultFileError extends Error {
  readonly problem: VaultFileProblem;

  constructor(problem: VaultFileProblem) {
    super(describeProblem(problem));
    this.name = /* @wc-ignore */ 'VaultFileError';
    this.problem = problem;
  }
}

/** A finished file: the leading bytes, then the sealed bodies to append. */
export type VaultFileBuild = {
  header: VaultFileHeader;
  head: Uint8Array;
  bodies: Blob[];
  totalBytes: number;
};

export async function sha256Hex(data: Blob | Uint8Array): Promise<string> {
  const bytes =
    data instanceof Blob ? await data.arrayBuffer() : (data as BufferSource);
  const digest = await crypto.subtle.digest('SHA-256', bytes);

  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** `ckpt-000012.loro` → 12. Null for any other key. */
export function checkpointNumberFromKey(objectKey: string): number | null {
  const match = /\/ckpt-(\d+)\.loro$/.exec(objectKey);

  return match ? Number(match[1]) : null;
}

/**
 * Assemble a file from objects and their sealed bodies.
 *
 * Bodies stay `Blob`s so the browser can keep them off the JS heap; each is
 * read once, for its hash.
 */
export async function buildVaultFile({
  drivePseudonym,
  objects,
  bodies,
  now = Date.now(),
}: {
  drivePseudonym: string;
  objects: VaultObject[];
  bodies: Blob[];
  now?: number;
}): Promise<VaultFileBuild> {
  if (objects.length !== bodies.length) {
    throw new VaultFileError('mismatch');
  }

  const entries: VaultFileObject[] = [];

  for (let i = 0; i < objects.length; i++) {
    const o = objects[i];
    entries.push({
      objectKey: o.object_key,
      kind: o.kind,
      lane: o.lane_device_pubkey ?? null,
      segment: o.segment ?? null,
      checkpointN: checkpointNumberFromKey(o.object_key),
      keyEpoch: o.key_epoch,
      size: bodies[i].size,
      contentHash: await sha256Hex(bodies[i]),
    });
  }

  const header: VaultFileHeader = {
    version: VAULT_FILE_VERSION,
    createdAt: now,
    drivePseudonym,
    keyEpoch: entries.reduce((max, e) => Math.max(max, e.keyEpoch), 1),
    objects: entries,
  };
  const json = new TextEncoder().encode(JSON.stringify(header));
  const head = new Uint8Array(PREAMBLE + json.length);
  head.set(MAGIC, 0);
  new DataView(head.buffer).setUint32(MAGIC.length, json.length, false);
  head.set(json, PREAMBLE);

  return {
    header,
    head,
    bodies,
    totalBytes: head.length + bodies.reduce((sum, b) => sum + b.size, 0),
  };
}

/** The whole file as one Blob. */
export function vaultFileBlob(build: VaultFileBuild): Blob {
  return new Blob([build.head as BlobPart, ...build.bodies], {
    type: 'application/octet-stream',
  });
}

function isObjectEntry(value: unknown): value is VaultFileObject {
  const o = value as Record<string, unknown> | null;

  return (
    typeof o === 'object' &&
    o !== null &&
    typeof o.objectKey === 'string' &&
    o.objectKey.length > 0 &&
    typeof o.kind === 'string' &&
    (o.lane === null || typeof o.lane === 'string') &&
    (o.segment === null || Number.isInteger(o.segment)) &&
    (o.checkpointN === null || Number.isInteger(o.checkpointN)) &&
    Number.isInteger(o.keyEpoch) &&
    Number.isInteger(o.size) &&
    (o.size as number) >= 0 &&
    typeof o.contentHash === 'string' &&
    /^[0-9a-f]{64}$/.test(o.contentHash)
  );
}

export type ParsedVaultFile = {
  header: VaultFileHeader;
  /** Read and verify the sealed bytes of object `index`. */
  read(index: number): Promise<Uint8Array>;
};

/**
 * Check a file's structure and return a reader for its objects.
 *
 * Rejects files that are not ours, are from a newer version, or are cut short
 * or padded: the sizes in the header must add up to the file's length exactly.
 * Object bytes are only checked against their hashes when read.
 */
export async function parseVaultFile(file: Blob): Promise<ParsedVaultFile> {
  const wrong = () => new VaultFileError('notAVaultFile');

  if (file.size < PREAMBLE) throw wrong();

  const preamble = new Uint8Array(await file.slice(0, PREAMBLE).arrayBuffer());

  if (!MAGIC.every((byte, i) => preamble[i] === byte)) throw wrong();

  const headerLength = new DataView(preamble.buffer).getUint32(
    MAGIC.length,
    false,
  );

  if (headerLength > MAX_HEADER_BYTES || PREAMBLE + headerLength > file.size) {
    throw new VaultFileError('incomplete');
  }

  let header: VaultFileHeader;

  try {
    header = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(
        await file.slice(PREAMBLE, PREAMBLE + headerLength).arrayBuffer(),
      ),
    );
  } catch {
    throw new VaultFileError('badHeader');
  }

  if (typeof header !== 'object' || header === null) {
    throw new VaultFileError('badHeader');
  }

  if (!Number.isInteger(header.version) || header.version < 1) {
    throw new VaultFileError('badHeader');
  }

  if (header.version > VAULT_FILE_VERSION) {
    throw new VaultFileError('newerVersion');
  }

  if (
    typeof header.drivePseudonym !== 'string' ||
    header.drivePseudonym === '' ||
    !Number.isInteger(header.keyEpoch) ||
    !Array.isArray(header.objects) ||
    !header.objects.every(isObjectEntry)
  ) {
    throw new VaultFileError('badHeader');
  }

  const offsets: number[] = [];
  let cursor = PREAMBLE + headerLength;

  for (const object of header.objects) {
    offsets.push(cursor);
    cursor += object.size;
  }

  if (cursor > file.size) {
    throw new VaultFileError('incomplete');
  }

  if (cursor < file.size) {
    throw new VaultFileError('extraData');
  }

  return {
    header,
    async read(index) {
      const object = header.objects[index];
      const bytes = new Uint8Array(
        await file
          .slice(offsets[index], offsets[index] + object.size)
          .arrayBuffer(),
      );

      if ((await sha256Hex(bytes)) !== object.contentHash) {
        throw new VaultFileError('badChecksum');
      }

      return bytes;
    },
  };
}

/**
 * A parsed file as a restore source, in header order, verifying every object.
 * Nothing is sent anywhere.
 */
export function fileRestoreSource(parsed: ParsedVaultFile): RestoreSource {
  return async onProgress => {
    const total = parsed.header.objects.length;
    const out: SealedObject[] = [];

    for (let i = 0; i < total; i++) {
      out.push({
        objectKey: parsed.header.objects[i].objectKey,
        sealed: await parsed.read(i),
      });
      onProgress?.(i + 1, total);
    }

    return out;
  };
}

/** Where a finished file goes. */
export type VaultFileTarget = { save(build: VaultFileBuild): Promise<void> };

type SaveHandle = {
  createWritable(): Promise<{
    write(data: BlobPart): Promise<void>;
    close(): Promise<void>;
  }>;
};

export function suggestedFileName(drivePseudonym: string, now = new Date()) {
  const day = now.toISOString().slice(0, 10);

  return `atomic-vault-${drivePseudonym.slice(0, 8)}-${day}${VAULT_FILE_EXTENSION}`;
}

/**
 * Ask where to save, before any slow work: the browser only allows the picker
 * straight after a click. Uses the File System Access API where there is one
 * (the file is streamed to disk), else a normal browser download. Resolves to
 * null if the person cancels.
 */
export async function pickVaultFileTarget(
  fileName: string,
): Promise<VaultFileTarget | null> {
  const picker = (
    window as unknown as {
      showSaveFilePicker?: (options: unknown) => Promise<SaveHandle>;
    }
  ).showSaveFilePicker;

  if (picker) {
    let handle: SaveHandle;

    try {
      handle = await picker.call(window, {
        suggestedName: fileName,
        types: [
          {
            description: 'Atomic vault backup',
            accept: { 'application/octet-stream': [VAULT_FILE_EXTENSION] },
          },
        ],
      });
    } catch (e) {
      if ((e as Error).name === /* @wc-ignore */ 'AbortError') return null;

      throw e;
    }

    return {
      async save(build) {
        const writable = await handle.createWritable();

        await writable.write(build.head as BlobPart);

        for (const body of build.bodies) await writable.write(body);

        await writable.close();
      },
    };
  }

  return {
    async save(build) {
      const url = URL.createObjectURL(vaultFileBlob(build));
      const link = document.createElement('a');
      link.href = url;
      link.download = fileName;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    },
  };
}

/**
 * Fetch every confirmed object of a drive from the cloud vault and assemble a
 * file. Needs no drive key: the objects stay sealed.
 */
export async function fetchVaultBackupFile(
  drivePseudonym: string,
  onProgress?: (done: number, total: number) => void,
): Promise<VaultFileBuild | null> {
  const objects = await listVaultObjects(drivePseudonym);

  if (objects.length === 0) return null;

  const bodies = await downloadVaultObjects(
    drivePseudonym,
    objects,
    response => response.blob(),
    onProgress,
  );

  return buildVaultFile({ drivePseudonym, objects, bodies });
}

/**
 * Restore from a file through {@link restoreDrive}'s own import. Checks the
 * file belongs to this drive and to the key held before anything is read.
 */
export async function restoreDriveFromFile({
  file,
  drivePseudonym,
  keyEpoch,
  ...rest
}: {
  file: Blob;
  drivePseudonym: string;
  /** The epoch of the drive key in hand; the file must be sealed under it. */
  keyEpoch: number;
  db: VaultCapableDb;
  devicePubkey: string;
  driveKey: Uint8Array;
  onProgress?: (done: number, total: number) => void;
}): Promise<RestoreOutcome> {
  const parsed = await parseVaultFile(file);

  if (parsed.header.drivePseudonym !== drivePseudonym) {
    throw new VaultFileError('otherDrive');
  }

  if (parsed.header.keyEpoch !== keyEpoch) {
    throw new VaultFileError('otherKey');
  }

  return restoreDrive({
    ...rest,
    drivePseudonym,
    source: fileRestoreSource(parsed),
  });
}
