import {
  isNotAvailableLocally,
  isNotFound,
  type Resource,
  type Store,
} from '@tomic/react';
import { isInTrash } from './trash';

/**
 * Why `resource` should be left out of lists the user picks from (the command
 * palette, @ mentions). `gone`: destroyed, in the Trash (directly or under a
 * trashed folder), or failed to load because it no longer exists. `uncached`:
 * merely not available locally (offline or still syncing), so it may come back.
 * The in-memory destroyed set only knows this session's deletes, so the rest is
 * read off the resource itself.
 */
export type UnavailableReason = 'gone' | 'uncached';

export const unavailableReason = (
  store: Store,
  drive: string | undefined,
  resource: Resource,
): UnavailableReason | undefined => {
  if (
    store.isDestroyed(resource.subject) ||
    isNotFound(resource.error) ||
    isInTrash(store, drive, resource, true)
  ) {
    return 'gone';
  }

  if (isNotAvailableLocally(resource.error)) {
    return 'uncached';
  }

  return undefined;
};

export const isUnavailableResource = (
  store: Store,
  drive: string | undefined,
  resource: Resource,
): boolean => unavailableReason(store, drive, resource) !== undefined;

/**
 * Splits `subjects` into the ones to show (`available`, order kept, unknown
 * ones included) and the `gone` ones. Uncached subjects are in neither: hidden
 * for now, but not safe to forget.
 */
export const withoutUnavailable = (
  store: Store,
  drive: string | undefined,
  subjects: string[],
  resources: Map<string, Resource>,
): { available: string[]; gone: string[] } => {
  const available: string[] = [];
  const gone: string[] = [];

  for (const subject of subjects) {
    const resource = resources.get(subject);
    const reason = resource && unavailableReason(store, drive, resource);

    if (!reason) {
      available.push(subject);
    } else if (reason === 'gone') {
      gone.push(subject);
    }
  }

  return { available, gone };
};
