import { core, dataBrowser, type Resource, type Store } from '@tomic/react';
import { isContentAddressed } from './propertyIdentity';
import { getOrCreateTrashFolder } from './standardLocations';

/** The drive's Trash folder, if one was ever created. */
export const readTrashFolder = (drive: Resource): string | undefined =>
  drive.get(dataBrowser.properties.trashFolder) as string | undefined;

/** Whether `resource` sits directly in the drive's Trash folder. */
export const isInTrash = (
  store: Store,
  drive: string | undefined,
  resource: Resource,
): boolean => {
  if (!drive) {
    return false;
  }

  const trash = readTrashFolder(store.getResourceLoading(drive));

  return !!trash && resource.get(core.properties.parent) === trash;
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
  if (isContentAddressed(subject)) {
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
