import { atomicWasmSource, wasmJsUrl } from '../wasmUrls';
import { getManagedAccount } from './session';
import { loadVaultKeyOps } from './vaultKeyOps';
import {
  agentVaultProof,
  downloadVaultObjects,
  listVaultObjects,
  recoverDriveKey,
  type DriveKeyHandle,
  type VaultEnrollment,
  type VaultObject,
  type VaultProofSigner,
} from './vault';

export type PackInspection = {
  entries: {
    subject: string;
    name?: string;
    updateBytes: number;
    envelopeBytes: number;
    blobHashes: string[];
  }[];
  blobs: { hash: string; content_id: string; size: number; chunks: number }[];
  structureBytes: number;
};
export type ContentItem = {
  id: string;
  name: string;
  subjects: string[];
  kind: 'resource' | 'file' | 'structure' | 'unreadable' | 'other';
  bytes: number;
  updateBytes: number;
  envelopeBytes: number;
  copies: number;
  error?: string;
};
export type VaultContents = {
  items: ContentItem[];
  storedBytes: number;
  objects: number;
  unreadable: number;
};

/** Use the account's stable identifier, not its display address. */
export async function requireStorageAccount(
  accountId: string,
  signal?: AbortSignal,
) {
  const account = await getManagedAccount({ fresh: true });
  signal?.throwIfAborted();
  if (account?.email !== accountId)
    throw new Error('Account changed. Refresh before continuing.');
}

/** No OPFS, store writes or restore calls. The worker dies with the scan. */
async function openInspector(key: DriveKeyHandle, signal: AbortSignal) {
  const source = await atomicWasmSource();
  signal.throwIfAborted();
  const worker = new Worker(
    new URL('./vaultInspect.worker.ts', import.meta.url),
    { type: 'module' },
  );
  const pending = new Map<
    number,
    {
      resolve: (result: PackInspection) => void;
      reject: (error: Error) => void;
    }
  >();
  let next = 0;
  let closed = false;

  const close = () => {
    closed = true;
    worker.terminate();
    for (const request of pending.values())
      request.reject(new Error('Inspection stopped.'));
    pending.clear();
    signal.removeEventListener('abort', close);
  };

  worker.onmessage = ({ data }) => {
    const request = pending.get(data.id);
    pending.delete(data.id);
    if (data.error) request?.reject(new Error(data.error));
    else request?.resolve(data.result);
  };

  worker.onerror = close;
  signal.addEventListener('abort', close, { once: true });
  worker.postMessage({ key, source, jsUrl: wasmJsUrl() });

  return {
    close,
    inspect: (sealed: Uint8Array) =>
      new Promise<PackInspection>((resolve, reject) => {
        signal.throwIfAborted();
        if (closed)
          throw new Error(
            'Inspection worker is unavailable. Retry the inspection.',
          );
        const id = next++;
        pending.set(id, { resolve, reject });
        worker.postMessage({ id, sealed }, [sealed.buffer]);
      }),
  };
}

export async function inspectVaultContents(
  enrollment: VaultEnrollment,
  accountId: string,
  signer: VaultProofSigner,
  signal: AbortSignal,
  onProgress: (done: number, total: number) => void,
): Promise<VaultContents> {
  await requireStorageAccount(accountId, signal);
  const keys = await loadVaultKeyOps();
  const key = await recoverDriveKey({
    keys,
    drivePseudonym: enrollment.drive_pseudonym,
    agentSecret: await agentVaultProof(signer, keys.proofMessage),
  });
  let inspector: Awaited<ReturnType<typeof openInspector>> | undefined;

  try {
    signal.throwIfAborted();
    const objects = await listVaultObjects(enrollment.drive_pseudonym, signal);
    const packs = objects.filter(
      o => o.kind === 'pack' || o.kind === 'checkpoint',
    );
    inspector = await openInspector(key, signal);
    const reader = inspector;
    const results = await downloadVaultObjects<PackInspection | string>(
      enrollment.drive_pseudonym,
      packs,
      async (response, object) => {
        const bytes = new Uint8Array(await response.arrayBuffer());
        if (bytes.length !== object.size_bytes)
          throw new Error(
            'Downloaded size differs from the inventory. Refresh and inspect again.',
          );

        return reader.inspect(bytes);
      },
      onProgress,
      error => (error instanceof Error ? error.message : String(error)),
      signal,
    );
    await requireStorageAccount(accountId, signal);

    return summarizeVaultContents(
      objects,
      new Map(packs.map((object, i) => [object.object_id, results[i]])),
    );
  } finally {
    key.driveKey.fill(0);
    inspector?.close();
  }
}

/** All tiles sum to the measured inventory. Shared format bytes stay separate;
 * repeated copies count repeatedly because they really occupy stored bytes. */
export function summarizeVaultContents(
  objects: VaultObject[],
  packs: Map<string, PackInspection | string>,
): VaultContents {
  const items = new Map<string, ContentItem>();
  const names = new Map<string, string>();
  const refs = new Map<string, Set<string>>();
  const blobHashes = new Map<string, string>();

  const add = (
    id: string,
    kind: ContentItem['kind'],
    name: string,
    bytes: number,
    subjects: string[] = [],
  ) => {
    let item = items.get(id);

    if (!item) {
      item = {
        id,
        kind,
        name,
        bytes: 0,
        subjects,
        updateBytes: 0,
        envelopeBytes: 0,
        copies: 0,
      };
      items.set(id, item);
    }

    item.bytes += bytes;

    return item;
  };

  let unreadable = 0;

  for (const object of objects) {
    if (object.kind !== 'pack' && object.kind !== 'checkpoint') continue;
    const pack = packs.get(object.object_id);

    if (!pack || typeof pack === 'string') {
      const item = add(
        object.object_id,
        'unreadable',
        'Unreadable backup object',
        object.size_bytes,
      );
      item.error = pack || 'Object was not inspected.';
      unreadable++;
      continue;
    }

    const measured =
      pack.structureBytes +
      pack.entries.reduce((sum, e) => sum + e.updateBytes + e.envelopeBytes, 0);
    if (measured !== object.size_bytes)
      throw new Error('Inspected sizes do not match the inventory.');
    add(
      'structure',
      'structure',
      'Backup structure and encryption',
      pack.structureBytes,
    );

    for (const entry of pack.entries) {
      if (entry.name) names.set(entry.subject, entry.name);
      const item = add(
        `resource:${entry.subject}`,
        'resource',
        entry.subject,
        entry.updateBytes + entry.envelopeBytes,
        [entry.subject],
      );
      item.updateBytes += entry.updateBytes;
      item.envelopeBytes += entry.envelopeBytes;
      item.copies++;

      for (const hash of entry.blobHashes) {
        if (!refs.has(hash)) refs.set(hash, new Set());
        refs.get(hash)!.add(entry.subject);
      }
    }

    for (const blob of pack.blobs) blobHashes.set(blob.content_id, blob.hash);
  }

  for (const object of objects) {
    if (object.kind === 'pack' || object.kind === 'checkpoint') continue;
    if (object.kind === 'blob') {
      const id =
        object.object_key.split('/blobs/')[1]?.split('/')[0] ??
        object.object_id;
      const subjects = [...(refs.get(blobHashes.get(id) ?? '') ?? [])];
      add(
        `file:${id}`,
        'file',
        subjects.length ? 'Attached file bytes' : 'Unattributed file bytes',
        object.size_bytes,
        subjects,
      );
    } else add(object.object_id, 'other', object.kind, object.size_bytes);
  }

  for (const item of items.values()) {
    if (item.kind === 'resource')
      item.name = names.get(item.subjects[0]) ?? item.subjects[0];
    if (item.kind === 'file' && item.subjects.length === 1)
      item.name = `${names.get(item.subjects[0]) ?? item.subjects[0]} (file bytes)`;
  }

  return {
    items: [...items.values()]
      .filter(item => item.bytes > 0)
      .sort((a, b) => b.bytes - a.bytes),
    storedBytes: objects.reduce((sum, object) => sum + object.size_bytes, 0),
    objects: objects.length,
    unreadable,
  };
}
