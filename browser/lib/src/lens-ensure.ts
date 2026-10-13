import { core } from './ontologies/core.js';
import { CollectionBuilder } from './collectionBuilder.js';
import { lensId, parseTransform, type Transform } from './lens.js';
import type { Resource } from './resource.js';
import type { Store } from './store.js';
import { canonicalizeScheme } from './subject.js';

export interface LensInput {
  /** The property the lens reads. */
  from: string;
  /** The property the lens writes. The lens belongs to the ontology that owns it. */
  to: string;
  transform: Transform;
}

/**
 * Makes a Lens real: `from` and `to` are two properties and the transform says
 * how a value under one becomes a value under the other. Values stored under
 * `from` then show up under `to` (and back, when the transform allows it)
 * without touching any data. See `docs/src/schema/lenses.md`.
 *
 * The lens is created in the ontology that owns `to` (its `parent`), under the
 * content-addressed ID `atomic:lens:{hash}`. Idempotent: the same input always
 * names the same Lens, and an existing one is returned without a write.
 *
 * Throws when the transform is invalid or `to` has no parent to own the lens.
 */
export async function ensureLens(
  store: Store,
  input: LensInput,
): Promise<Resource> {
  const transform = parseTransform(input.transform);
  const from = canonicalizeScheme(input.from);
  const to = canonicalizeScheme(input.to);
  const id = lensId(from, to, transform);

  const target = await store.getResource(to);
  const parent = target.get(core.properties.parent);

  if (typeof parent !== 'string') {
    throw new Error(`Property ${to} has no parent to own a lens`);
  }

  const lens = await store.newResource({
    parent,
    isA: [core.classes.lens],
    propVals: {
      [core.properties.lensFrom]: from,
      [core.properties.lensTo]: to,
      [core.properties.lensTransform]: transform,
    },
    contentAddressedLens: true,
  });

  if (lens.subject !== id) {
    throw new Error(`Lens ID mismatch: expected ${id}, got ${lens.subject}`);
  }

  // Not `if (lens.new)`: signing the genesis commit already clears `new`
  // while the commit stays parked on the resource until `save()`. Gating on it
  // left the lens unsaved, so it only worked until the next reload. `save()`
  // is a no-op for a lens that is already known and clean.
  await lens.save();

  // It applies in this session from now on, and to what is already loaded.
  await store.activateLens(lens);

  return lens;
}

/**
 * Brings the lenses of a drive into the store, so resources loaded afterwards
 * show derived values. The store learns of a lens as its resource loads;
 * nothing else loads them. Resources already loaded are re-derived as each
 * lens arrives.
 */
export async function loadLenses(store: Store, drive?: string): Promise<void> {
  const builder = new CollectionBuilder(store)
    .setProperty(core.properties.isA)
    .setValue(core.classes.lens);

  if (drive) builder.setDrive(drive);

  const collection = await builder.buildAndFetch();

  for (const subject of await collection.getAllMembers()) {
    await store.getResource(subject);
  }
}
