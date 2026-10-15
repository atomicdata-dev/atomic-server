import { getOrCreateDriveLocation } from './drive-location.js';
import { core } from './ontologies/core.js';
import { dataBrowser } from './ontologies/dataBrowser.js';
import type { Resource } from './resource.js';
import type { Store } from './store.js';
import { isPropertySubject } from './subject.js';

/** The drive's Trash folder, if one was ever created. */
export const readTrashFolder = (drive: Resource): string | undefined =>
  drive.get(dataBrowser.properties.trashFolder) as string | undefined;

/**
 * The drive's Trash folder as far as the store already knows. Menus ask this
 * at every render, so it must not start a fetch: a drive that is not loaded
 * has no known Trash folder, and nothing is lost by saying so.
 */
export const peekTrashFolder = (
  store: Store,
  drive: string | undefined,
): string | undefined => {
  const loaded = drive
    ? (store.resources.get(drive) ??
      store.resources.get(store.normalizeSubject(drive)))
    : undefined;

  return loaded ? readTrashFolder(loaded) : undefined;
};

/** The drive's Trash folder, created on first use. */
export const getOrCreateTrashFolder = (
  store: Store,
  drive: string,
): Promise<string> =>
  getOrCreateDriveLocation(store, drive, dataBrowser.properties.trashFolder, {
    isA: dataBrowser.classes.folder,
    name: 'Trash',
  });

export type IsTrashedOptions = {
  /** Also true when any ancestor sits in the Trash. Default: direct parent only. */
  deep?: boolean;
};

/**
 * Whether the resource sits directly in the drive's Trash folder. With
 * `deep`, also when any ancestor does. The deep walk only reads ancestors
 * that are already loaded (`getResourceLoading`), so an unloaded ancestor
 * ends it with `false`. A visited set ends parent cycles.
 */
export const isTrashed = (
  store: Store,
  subjectOrResource: string | Resource,
  drive: string | undefined,
  { deep = false }: IsTrashedOptions = {},
): boolean => {
  const trash = peekTrashFolder(store, drive);

  if (!trash) {
    return false;
  }

  const resource =
    typeof subjectOrResource === 'string'
      ? store.getResourceLoading(subjectOrResource)
      : subjectOrResource;

  const visited = new Set<string>([resource.subject]);
  let parent = resource.get(core.properties.parent) as string | undefined;

  while (parent && !visited.has(parent)) {
    if (parent === trash) {
      return true;
    }

    if (!deep) {
      return false;
    }

    visited.add(parent);
    parent = store.getResourceLoading(parent).get(core.properties.parent) as
      | string
      | undefined;
  }

  return false;
};

/**
 * Parks a resource in the drive's Trash folder (created on first use) and
 * remembers where it came from so {@link restoreFromTrash} can put it back.
 * Nothing is destroyed. Resolves to false when there was nothing to do.
 */
export async function moveToTrash(
  store: Store,
  subject: string,
  drive: string,
): Promise<boolean> {
  // A content-addressed property's parent is part of its ID: it cannot move.
  if (isPropertySubject(subject)) {
    throw new Error("A property can't be moved to the trash.");
  }

  const trash = await getOrCreateTrashFolder(store, drive);
  const resource = await store.getResource(subject);
  const parent = resource.get(core.properties.parent) as string | undefined;

  // Already in the trash (or the trash itself): dropping again is a no-op.
  if (subject === trash || parent === trash) {
    return false;
  }

  if (parent) {
    await resource.set(dataBrowser.properties.trashedFrom, parent);
  }

  await resource.set(core.properties.parent, trash);
  await resource.save();

  return true;
}

/**
 * Moves a trashed resource back to the parent it came from. Falls back to the
 * drive root when that parent is gone or itself unreadable.
 */
export async function restoreFromTrash(
  store: Store,
  subject: string,
  drive: string,
): Promise<void> {
  const resource = await store.getResource(subject);
  const from = resource.get(dataBrowser.properties.trashedFrom) as
    | string
    | undefined;
  let target = drive;

  if (from && !store.isDestroyed(from)) {
    const candidate = await store.getResource(from);

    if (!candidate.error) {
      target = from;
    }
  }

  await resource.set(core.properties.parent, target);
  resource.remove(dataBrowser.properties.trashedFrom);
  await resource.save();
}
