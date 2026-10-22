import {
  copyResource,
  core,
  IDENTITY_PROPS,
  RIGHTS_PROPS,
  server,
  type Resource,
  type Store,
} from '@tomic/react';
import { isContentAddressed } from './propertyIdentity';
import { moveToTrash } from './trash';

/**
 * Why `subject` cannot be re-parented under `target`, or undefined when it can.
 * Walks the loaded `parent` chain of the target: a cycle ends the walk.
 */
export function moveBlockedReason(
  store: Pick<Store, 'getResourceLoading' | 'driveOfSubject'>,
  subject: string,
  target: string,
): string | undefined {
  if (isContentAddressed(subject)) {
    return "A property can't be moved to another parent.";
  }

  const seen = new Set<string>();

  for (let at: string | undefined = target; at && !seen.has(at); ) {
    if (at === subject) {
      return at === target
        ? "A resource can't be moved into itself."
        : "A resource can't be moved into something inside it.";
    }

    seen.add(at);
    at = store.getResourceLoading(at).get(core.properties.parent) as
      | string
      | undefined;
  }

  return undefined;
}

/**
 * Copies a resource and everything below it (children via `parent`) under
 * `targetParent`, which may be in another drive. Every copy gets a fresh
 * genesis id; resource-valued properties that point inside the copied set are
 * rewritten to the new ids, other references stay as they were. Files are
 * copied by value: the blob is content-addressed (`internalId`, `blob`,
 * `downloadUrl` carry a hash), so the copy points at the same bytes.
 * Returns the new subject of `subject`.
 */
export async function copyResourceTree(
  store: Store,
  subject: string,
  targetParent: string,
): Promise<string> {
  const originals: Resource[] = [];
  const parentOf = new Map<string, string>();

  for (const queue = [subject]; queue.length; ) {
    const resource = await store.getResource(queue.shift()!);

    if (isContentAddressed(resource.subject)) {
      throw new Error("Properties can't be copied to another drive.");
    }

    originals.push(resource);
    const children = await (
      await resource.getChildrenCollection(1000)
    ).getAllMembers();

    for (const child of children) {
      parentOf.set(child, resource.subject);
      queue.push(child);
    }
  }

  // Mint every id first, so references between the copies can be rewritten.
  const copies = new Map<string, Resource>();
  const subjects = new Map<string, string>();

  for (const original of originals) {
    const parent = parentOf.get(original.subject);
    const copy = await store.newResource({
      parent: parent ? subjects.get(parent)! : targetParent,
      isA: original.getClasses(),
      deferGenesis: true,
    });

    copies.set(original.subject, copy);
    subjects.set(original.subject, copy.subject);
  }

  for (const original of originals) {
    await copyResource(store, original, {
      copy: copies.get(original.subject),
      subjects,
    });
  }

  // Parents first: a child's genesis is checked against its parent.
  for (const original of originals) {
    await copies.get(original.subject)!.save();
  }

  return copies.get(subject)!.subject;
}

/**
 * Turns `resource` into a `Redirect` to `destination`. Parent, drive, genesis
 * and rights stay as they were, so the old link still resolves for whoever
 * could read it; everything else is dropped, except what names the row in the
 * sidebar (`Resource.title`), so the Redirect keeps the old name.
 */
export async function replaceWithRedirect(
  resource: Resource,
  destination: string,
): Promise<void> {
  const keep = new Set([
    ...IDENTITY_PROPS,
    ...RIGHTS_PROPS,
    core.properties.name,
    core.properties.shortname,
    server.properties.filename,
  ]);

  for (const prop of Object.keys(resource.getPropVals())) {
    if (!keep.has(prop)) resource.remove(prop);
  }

  await resource.set(core.properties.isA, [server.classes.redirect], false);
  await resource.set(server.properties.destination, destination, false);
  await resource.save();
}

/**
 * Sends the children of `subject` (a Redirect now) to its drive's Trash. Trash
 * moves a subtree, so the grandchildren go along. Call it only after the copy
 * saved: the originals are parked, not destroyed.
 */
export async function trashDescendants(
  store: Store,
  subject: string,
): Promise<void> {
  const drive = store.driveOfSubject(subject);
  const children = await (
    await (await store.getResource(subject)).getChildrenCollection(1000)
  ).getAllMembers();

  for (const child of children) {
    await moveToTrash(store, child, drive);
  }
}
