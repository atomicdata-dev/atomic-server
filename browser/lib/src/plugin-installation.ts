import type { Store } from './store.js';

/** Server-executed apps need their workspace on that server before creating anything. */
export async function requireInstallationServer(
  store: Pick<Store, 'isLocalOnlyDrive' | 'fetchResourceFromServer'>,
  drive: string,
): Promise<void> {
  if (store.isLocalOnlyDrive(drive)) {
    throw new Error(
      'Sync this workspace with AtomicServer before connecting this app.',
    );
  }

  try {
    const resource = await store.fetchResourceFromServer(drive, {
      noWebSocket: true,
    });
    if (resource.error) throw resource.error;
  } catch {
    throw new Error(
      'This workspace is not available on AtomicServer. Check your connection and workspace sync, then try again.',
    );
  }
}
