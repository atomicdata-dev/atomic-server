import type { ClientDbWorker } from './client-db.js';
import type { Item } from './rbsr.js';

/** Verify every readable remote resource and its content-addressed attachment.
 * A root snapshot or matching resource count is not proof of a complete copy. */
export async function verifyLocalDriveCopy(
  db: ClientDbWorker,
  drive: string,
  remote: Item[],
): Promise<void> {
  if (!remote.some(item => item.subject === drive))
    throw new Error('The server did not provide a complete drive inventory.');
  await db.flush();
  const local = await db.getVersionVectorsForDrive(drive);

  for (const item of remote) {
    const vv = local[item.subject];
    if (
      !vv ||
      Object.entries(item.vv).some(
        ([peer, counter]) =>
          !Number.isSafeInteger(counter) ||
          counter < 0 ||
          (vv[peer] ?? 0) < counter,
      )
    )
      throw new Error(
        'Some resources are not fully stored on this device yet. Keep the server connected and retry after syncing.',
      );
    const { jsonAd, snapshot } = await db.getResourceWithSnapshot(item.subject);
    if (!jsonAd || !snapshot?.length)
      throw new Error(
        'A resource is missing its local history. Keep the server connected.',
      );
    const blob = JSON.parse(jsonAd)['https://atomicdata.dev/properties/blob'];
    if (blob === undefined || blob === null) continue;
    if (typeof blob !== 'string' || !/^did:ad:blob:[0-9a-f]{64}$/.test(blob))
      throw new Error(
        'An attachment is not stored as a portable blob. Keep the server connected.',
      );
    const hash = Uint8Array.from(
      blob.slice('did:ad:blob:'.length).match(/../g)!,
      part => parseInt(part, 16),
    );
    const bytes = await db.getBlob(hash);
    if (!bytes)
      throw new Error(
        'An attachment is missing on this device. Open it to download it, then retry.',
      );
    const actual = await db.blake3Hash(bytes);
    if (
      actual.length !== hash.length ||
      actual.some((byte, index) => byte !== hash[index])
    )
      throw new Error(
        'An attachment could not be verified. Keep the server connected.',
      );
  }
}
