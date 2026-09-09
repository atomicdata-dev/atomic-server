import type { Store } from '@tomic/lib';
import { isOriginWithoutNode } from './originNode';

/**
 * Make a drive that a vault restore just put into local storage show up.
 *
 * The store still holds whatever fetch sent the user to the restore offer:
 * on a node-backed origin a 401, fetched as the public agent before they
 * signed in; on an origin without a node a "not available locally". Left
 * alone, that cached answer is what the workspace renders after the restore
 * — "Unauthorized" as the drive title, over a sidebar that already lists the
 * restored folders — so look again, local database first, now that the data
 * is there.
 *
 * On an origin with no node the restored drive lives only on this device,
 * like one made here; without registering it as such every later commit
 * would park in the outbox waiting for a server that does not exist.
 *
 * The pack also carries the drive's agent — the profile with the name typed
 * on the first device — which the store looked up the same way, before it was
 * there. Reloaded too, so settings shows the person and not an empty field.
 */
export async function reopenRestoredDrive(
  store: Store,
  drive: string,
): Promise<void> {
  if (isOriginWithoutNode(store.getServerUrl())) {
    store.registerLocalOnlyDrive(drive);
  }

  await store.reloadResource(drive);

  const agent = store.getAgent()?.subject;

  if (agent) {
    await store.reloadResource(agent);
  }
}

/**
 * Whether this device can actually load the drive.
 *
 * False on a device that just signed in with a secret: it holds the identity
 * but none of the account's data, which still lives wherever it was created.
 * Resolves locally first, so a local-only drive that never touched a server
 * still counts as present.
 *
 * Pass `refresh` once something should have changed — a peer sync landed, say.
 * The store cached the failed fetch that reported the drive missing in the
 * first place, and left alone would go on reporting it missing.
 */
export async function deviceHasDriveData(
  store: Store,
  drive: string,
  options?: { refresh?: boolean },
): Promise<boolean> {
  try {
    if (options?.refresh) {
      if (
        isOriginWithoutNode(store.getServerUrl()) ||
        store.isLocalOnlyDrive(drive)
      ) {
        await store.reloadResource(drive);
      } else {
        await store.fetchResourceFromServer(drive);
      }

      return !store.getResourceLoading(drive).error;
    }

    const resource = await store.getResource(drive);

    return !resource.error;
  } catch {
    return false;
  }
}
