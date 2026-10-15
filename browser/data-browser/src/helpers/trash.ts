import type { Store } from '@tomic/react';
import { removeRecentResource } from './recentResources';

/**
 * Parks a resource in the drive's Trash (see `store.trash`) and forgets it in
 * the recents list when something was actually moved.
 */
export async function moveToTrash(
  store: Store,
  subject: string,
  drive: string,
): Promise<boolean> {
  const moved = await store.trash(subject, drive);

  if (moved) {
    removeRecentResource(drive, subject);
  }

  return moved;
}
