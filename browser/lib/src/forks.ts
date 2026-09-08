import { core } from './ontologies/core.js';
import { forks } from './ontologies/forks.js';
import type { AtomicValue } from './value.js';
import type { JSONValue } from './value.js';
import type { Resource } from './resource.js';
import type { Store } from './store.js';

/**
 * Properties that say *who* a resource is and *who may reach it*, as opposed to
 * what it says. Neither a fork nor a merge may carry these across.
 *
 * Identity: writing the fork's `parent` onto the original would move it, and its
 * `genesis` would claim the original was created by the fork's signature.
 *
 * Authority (`read` / `write` / `append`): a fork must inherit its privacy from
 * the folder it lands in, never from the resource it forked. Copying them would
 * mean a fork of a *published* page carries that page's `read: [PUBLIC_AGENT]`
 * grant and is therefore itself public — which is exactly the thing forks exist
 * to prevent. For the same reason a merge must not push the fork's ACL onto the
 * original: publishing is a move, not a copied grant.
 *
 * `isA` and the fork's own bookkeeping are excluded here too, and handled
 * explicitly by the merge.
 */
const NON_CONTENT_PROPS: ReadonlySet<string> = new Set<string>([
  core.properties.parent,
  core.properties.isA,
  core.properties.localId,
  core.properties.read,
  core.properties.write,
  'https://atomicdata.dev/properties/append',
  'https://atomicdata.dev/properties/drive',
  'https://atomicdata.dev/properties/genesis',
  'https://atomicdata.dev/properties/lastCommit',
  forks.properties.originalSubject,
  forks.properties.forkBase,
  forks.properties.forkVersion,
]);

const contentPropsOf = (resource: Resource): Record<string, AtomicValue> =>
  Object.fromEntries(
    Object.entries(resource.getPropVals()).filter(
      ([prop]) => !NON_CONTENT_PROPS.has(prop),
    ),
  );

/** Content classes, i.e. everything the resource `isA` except the Fork marker. */
const contentClassesOf = (resource: Resource): string[] =>
  resource.getClasses().filter(c => c !== forks.classes.fork);

const valuesEqual = (a: AtomicValue | undefined, b: AtomicValue | undefined) =>
  JSON.stringify(a ?? null) === JSON.stringify(b ?? null);

/**
 * The forked-from content stored on the fork. A JSON-datatype property comes
 * back as a serialized string once it has round-tripped through a commit, but as
 * a live object before its first save — accept either.
 */
function readForkBase(fork: Resource): Record<string, AtomicValue> {
  const raw = fork.get(forks.properties.forkBase);

  if (typeof raw === 'string') {
    try {
      return JSON.parse(raw) as Record<string, AtomicValue>;
    } catch {
      return {};
    }
  }

  return (raw ?? {}) as Record<string, AtomicValue>;
}

/**
 * One property the fork changed relative to the version it forked from. `base`
 * is the value at fork time, `fork` the value now, `original` the value on the
 * live original. `conflict` is true when the original moved away from `base`
 * too — both sides edited this property since the fork.
 */
export interface ForkChange {
  property: string;
  base: AtomicValue | undefined;
  fork: AtomicValue | undefined;
  original: AtomicValue | undefined;
  conflict: boolean;
}

/**
 * The properties a fork changed relative to what it forked, three-way against
 * the live original. A property the fork never touched is not listed, so it
 * cannot revert a concurrent edit to the original. Powers both the merge and a
 * review/diff view.
 */
export function diffFork(fork: Resource, original: Resource): ForkChange[] {
  const base = readForkBase(fork);
  const theirs = contentPropsOf(fork);
  const ours = contentPropsOf(original);

  const changes: ForkChange[] = [];

  for (const prop of new Set([...Object.keys(base), ...Object.keys(theirs)])) {
    const baseVal = base[prop];
    const forkVal = theirs[prop];

    if (valuesEqual(baseVal, forkVal)) {
      continue; // the fork did not change this property
    }

    changes.push({
      property: prop,
      base: baseVal,
      fork: forkVal,
      original: ours[prop],
      conflict: !valuesEqual(baseVal, ours[prop]),
    });
  }

  return changes;
}

/** Whether this resource proposes a change to another one. */
export const isFork = (resource: Resource): boolean =>
  resource.getClasses().includes(forks.classes.fork);

/**
 * Fork a resource into a Fork: a new resource that carries the original's
 * content and classes, plus the `Fork` class and a link back to the original.
 *
 * The fork is an ordinary resource. It is private exactly when `parent` is —
 * putting it in a folder that carries no public read grant is what keeps an
 * unpublished fork unpublished.
 *
 * Use this both to stage your own edit to a resource you can write, and to
 * suggest an edit to one you cannot — in the latter case `parent` is a folder
 * on your own drive.
 */
export async function forkResource(
  store: Store,
  original: Resource,
  parent: string,
): Promise<Resource> {
  const fork = await store.newResource({
    parent,
    deferGenesis: original.hasLoroBody(),
    isA: [...original.getClasses(), forks.classes.fork],
    propVals: {
      ...contentPropsOf(original),
      [forks.properties.originalSubject]: original.subject,
      // Freeze the forked-from content so a later merge can tell what the fork
      // actually changed, rather than overwriting the original wholesale. Stored
      // as JSON: content propvals are JSON-serializable (identity/binary props
      // are excluded by `contentPropsOf`).
      [forks.properties.forkBase]: contentPropsOf(
        original,
      ) as unknown as JSONValue,
    },
  });

  // A document/canvas body lives in a Loro container, not in propvals, so
  // `newResource` above gave the fork an empty body. Seed it from the original
  // so the fork's body shares the original's causal history — that is what lets
  // the merge be a real CRDT merge rather than an overwrite.
  if (original.hasLoroBody()) {
    // Seeding overwrites the fork's propvals with the original's, so snapshot
    // the fork's own propvals first and re-assert them afterward.
    const identity = fork.getPropVals();
    const forkVersion = fork.seedLoroBodyFrom(original);

    for (const [prop, value] of Object.entries(identity)) {
      await fork.set(prop, value as AtomicValue, false);
    }

    if (forkVersion) {
      await fork.set(forks.properties.forkVersion, forkVersion, false);
    }
  }

  await fork.save();

  return fork;
}

/**
 * Copy a resource into a new, independent resource under `parent`, carrying its
 * content (propvals and classes) but not its identity, ACL, or history.
 *
 * Unlike {@link forkResource}, the copy is not a Fork: it has no link back to the
 * source and cannot be merged into it — it is simply a duplicate. Copying a fork
 * yields a plain resource (the fork marker and its bookkeeping are dropped, just
 * like the original's identity and grants). This backs the "copy / paste" and
 * "duplicate" actions.
 *
 * The copy's name gets a " (copy)" suffix when the source has one, so a duplicate
 * sitting next to its source is tellable apart.
 */
export async function copyResource(
  store: Store,
  source: Resource,
  parent: string,
): Promise<Resource> {
  const name = source.get(core.properties.name);

  const copy = await store.newResource({
    parent,
    deferGenesis: source.hasLoroBody(),
    isA: contentClassesOf(source),
    propVals: {
      ...contentPropsOf(source),
      ...(typeof name === 'string' && name.length > 0
        ? { [core.properties.name]: `${name} (copy)` }
        : {}),
    },
  });

  // A document/canvas body lives in a Loro container, not in propvals, so
  // `newResource` gave the copy an empty body. Seed it from the source. Seeding
  // overwrites the copy's propvals with the source's, so snapshot the copy's own
  // identity/propvals first and re-assert them afterward (mirrors forkResource).
  if (source.hasLoroBody()) {
    const identity = copy.getPropVals();
    copy.seedLoroBodyFrom(source);

    for (const [prop, value] of Object.entries(identity)) {
      await copy.set(prop, value as AtomicValue, false);
    }
  }

  await copy.save();

  return copy;
}

export interface MergeForkOptions {
  /**
   * What to do when a property was edited on both the fork and the original
   * since the fork. `'fork-wins'` (default) takes the fork's value.
   * `'throw'` aborts the merge and writes nothing, so a caller can review the
   * conflicts (see {@link diffFork}) and decide.
   */
  onConflict?: 'fork-wins' | 'throw';
}

/**
 * Merge a Fork onto the resource it forked, as a single commit signed by the
 * current agent — so merging needs no special authorization: it succeeds exactly
 * when the agent may write to the original.
 *
 * Propvals are a *three-way* squash: it writes only the properties the fork
 * changed relative to the version it forked (its `forkBase`), so a property the
 * fork never touched is left alone and a concurrent edit to the original
 * survives. Where both sides changed the same property, `onConflict` decides.
 * The fork's revision history stays behind on the fork rather than becoming
 * part of the original's (and, once published, public) doc.
 *
 * A Loro body (DocumentV2's `doc` container) is instead a true CRDT merge: the
 * fork's ops since `forkVersion` are exported and imported into the original,
 * so a body edit on each side both survive. See {@link Resource.mergeLoroBodyFrom}.
 *
 * Returns the updated original. The fork is left alone — discard it separately
 * if you want it gone.
 */
export async function mergeFork(
  store: Store,
  fork: Resource,
  options: MergeForkOptions = {},
): Promise<Resource> {
  const { onConflict = 'fork-wins' } = options;
  const originalSubject = fork.get(forks.properties.originalSubject);

  if (!originalSubject) {
    throw new Error(
      `Cannot merge ${fork.subject}: it has no ${forks.properties.originalSubject}, so it is not a fork of anything.`,
    );
  }

  const original = await store.getResource(originalSubject);
  // Three-way propval diff must be computed against the original's *current*
  // state, before any of the mutations below touch it.
  const changes = diffFork(fork, original);

  if (onConflict === 'throw') {
    const conflicts = changes.filter(c => c.conflict);

    if (conflicts.length > 0) {
      throw new Error(
        `Cannot merge ${fork.subject}: ${conflicts.length} propert${
          conflicts.length === 1 ? 'y was' : 'ies were'
        } changed on both the fork and the original since the fork (${conflicts
          .map(c => c.property)
          .join(', ')}). Resolve them first.`,
      );
    }
  }

  // For a document/canvas fork, CRDT-merge the body first. Importing the fork's
  // body delta also overwrites the original's propvals with the fork's, so
  // snapshot the original's propvals beforehand and restore them below — that
  // keeps the body merge (Loro) and the propval merge (three-way) independent.
  const forkVersion = fork.get(forks.properties.forkVersion);

  if (forkVersion) {
    const originalPropvals = original.getPropVals();

    original.mergeLoroBodyFrom(fork, forkVersion);

    // Restore all of the original's own propvals — this undoes the propval
    // clobber from the delta import, so a concurrent propval edit on the
    // original is preserved, not reverted.
    for (const [prop, value] of Object.entries(originalPropvals)) {
      await original.set(prop, value as AtomicValue, false);
    }

    // The import also dragged the fork's own bookkeeping onto the original.
    for (const prop of [
      forks.properties.originalSubject,
      forks.properties.forkBase,
      forks.properties.forkVersion,
    ]) {
      original.remove(prop);
    }
  }

  // Propvals: apply exactly what the fork changed relative to its fork base.
  for (const change of changes) {
    if (change.fork === undefined) {
      original.remove(change.property); // the fork dropped this property
    } else {
      await original.set(change.property, change.fork);
    }
  }

  // Classes: add any class the fork has that the original now lacks, and never
  // remove one, so a class added to the original since the fork survives. `Fork`
  // itself is the fork's marker (stripped by `contentClassesOf`) and must not
  // follow the content home. Fork-side class *removal* is intentionally not
  // propagated — it is rare and the safe default is to keep the original's.
  const originalClasses = contentClassesOf(original);
  const addedClasses = contentClassesOf(fork).filter(
    c => !originalClasses.includes(c),
  );

  if (addedClasses.length > 0) {
    await original.set(core.properties.isA, [
      ...originalClasses,
      ...addedClasses,
    ]);
  }

  await original.save();

  return original;
}
