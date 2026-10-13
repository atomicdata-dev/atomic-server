import {
  core,
  isNotAvailableLocally,
  isNotFound,
  type Resource,
  type Store,
} from '@tomic/react';
import { readTrashFolder } from './trash';

const MAX_ANCESTOR_DEPTH = 8;

/**
 * Whether `resource` should be left out of lists the user picks from (the
 * command palette, @ mentions): destroyed, in the Trash (directly or under a
 * trashed folder), or failed to load because it no longer exists. The
 * in-memory destroyed set only knows this session's deletes, so the rest is
 * read off the resource itself.
 */
export const isUnavailableResource = (
  store: Store,
  drive: string | undefined,
  resource: Resource,
): boolean => {
  if (store.isDestroyed(resource.subject)) {
    return true;
  }

  if (isNotFound(resource.error) || isNotAvailableLocally(resource.error)) {
    return true;
  }

  const trash = drive ? readTrashFolder(store.getResourceLoading(drive)) : '';

  if (!trash) {
    return false;
  }

  // Walk up through ancestors until the Trash folder or the top.
  let parent = resource.get(core.properties.parent) as string | undefined;

  for (let depth = 0; parent && depth < MAX_ANCESTOR_DEPTH; depth++) {
    if (parent === trash) {
      return true;
    }

    parent = store.getResourceLoading(parent).get(core.properties.parent) as
      | string
      | undefined;
  }

  return false;
};

/** `subjects` minus those whose resource in `resources` is unavailable. */
export const withoutUnavailable = (
  store: Store,
  drive: string | undefined,
  subjects: string[],
  resources: Map<string, Resource>,
): string[] =>
  subjects.filter(subject => {
    const resource = resources.get(subject);

    return !resource || !isUnavailableResource(store, drive, resource);
  });
