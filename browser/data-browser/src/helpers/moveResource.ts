import {
  core,
  server,
  type AtomicValue,
  type Resource,
  type Store,
} from '@tomic/react';
import { isContentAddressed } from './propertyIdentity';

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

const P = 'https://atomicdata.dev/properties/';
/** Identity and access: a copy gets its own (rights follow the new parent). */
const IDENTITY = [
  core.properties.parent,
  `${P}drive`,
  `${P}genesis`,
  `${P}lastCommit`,
  `${P}createdAt`,
  server.properties.createdBy,
];
const RIGHTS = [core.properties.read, core.properties.write, `${P}append`];
const NOT_COPIED = new Set([
  ...IDENTITY,
  ...RIGHTS,
  core.properties.isA,
  core.properties.localId,
]);

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

  for (const original of originals) {
    const parent = parentOf.get(original.subject);

    copies.set(
      original.subject,
      await store.newResource({
        parent: parent ? copies.get(parent)!.subject : targetParent,
        isA: original.getClasses(),
        deferGenesis: true,
      }),
    );
  }

  const rewrite = (value: AtomicValue): AtomicValue =>
    typeof value === 'string'
      ? (copies.get(value)?.subject ?? value)
      : Array.isArray(value)
        ? (value.map(v => rewrite(v as AtomicValue)) as AtomicValue)
        : value;

  for (const original of originals) {
    const copy = copies.get(original.subject)!;
    const identity = copy.getPropVals();
    const content = Object.entries(original.getPropVals()).filter(
      ([prop]) => !NOT_COPIED.has(prop),
    );

    // A rich-text body lives in the Loro doc, not in propvals. Seeding it
    // overwrites the copy's propvals with the original's, so re-assert ours.
    if (original.hasLoroBody()) {
      copy.seedLoroBodyFrom(original);

      for (const [prop, value] of Object.entries(identity)) {
        await copy.set(prop, value, false);
      }
    }

    for (const [prop, value] of content) {
      await copy.set(prop, rewrite(value), false);
    }

    const keep = new Set([...Object.keys(identity), ...content.map(c => c[0])]);

    for (const prop of Object.keys(copy.getPropVals())) {
      if (!keep.has(prop)) copy.remove(prop);
    }
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
 * could read it; everything else is dropped.
 */
export async function replaceWithRedirect(
  resource: Resource,
  destination: string,
): Promise<void> {
  const keep = new Set([...IDENTITY, ...RIGHTS]);

  for (const prop of Object.keys(resource.getPropVals())) {
    if (!keep.has(prop)) resource.remove(prop);
  }

  await resource.set(core.properties.isA, [server.classes.redirect], false);
  await resource.set(server.properties.destination, destination, false);
  await resource.save();
}
