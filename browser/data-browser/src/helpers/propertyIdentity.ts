import {
  Datatype,
  JSONValue,
  Resource,
  Store,
  Transform,
  core,
  dataBrowser,
  ensureLens,
  isPropertySubject,
} from '@tomic/react';

/**
 * A Property's `parent`, `shortname` and `datatype` are its identity: they
 * derive its `atomic:prop:{hash}` subject and can never change afterwards (see
 * `docs/src/schema/property-identity.md`). Legacy properties keep their old
 * subject and are still editable.
 */
export const isContentAddressed = (subject: string): boolean =>
  isPropertySubject(subject);

/** Fields of a Property that are never copied onto a new Property. */
const NOT_COPIED: string[] = [
  core.properties.parent,
  core.properties.isA,
  core.properties.localId,
  core.properties.read,
  core.properties.write,
];

/** System-managed keys materialised by the server onto saved resources. */
const SYSTEM_KEY_RE =
  /\/properties\/(drive|genesis|createdAt|createdBy|lastCommit|previousCommit|signer)$/;

/**
 * The classes and values to carry over when a Property is recreated, e.g. with
 * another datatype: name, description, classtype, allowsOnly, constraints.
 */
export function copyablePropertyFields(source: Resource): {
  isA: string[];
  propVals: Record<string, JSONValue>;
} {
  const propVals: Record<string, JSONValue> = {};

  for (const [key, value] of Object.entries(source.getPropVals())) {
    if (NOT_COPIED.includes(key) || SYSTEM_KEY_RE.test(key)) {
      continue;
    }

    propVals[key] = value as JSONValue;
  }

  // Some forms replace `isA` wholesale; a Property is always a Property.
  const isA = Array.from(
    new Set([core.classes.property, ...source.getClasses()]),
  );

  return { isA, propVals };
}

/** Fields and classes a copy of a Property leaves behind. */
export interface CopyOmit {
  fields?: string[];
  classes?: string[];
}

/**
 * An unsaved Property that only holds form state. It is never saved: the
 * real, content-addressed Property is created on confirm (see
 * {@link createContentAddressedFromDraft}).
 */
export async function createPropertyDraft(
  store: Store,
  parent: string,
  init: {
    /** Clone this Property's editable fields. */
    source?: Resource;
    isA?: string | string[];
    propVals?: Record<string, JSONValue>;
  } = {},
): Promise<Resource> {
  const fields = init.source ? copyablePropertyFields(init.source) : undefined;

  return store.newResource({
    parent,
    isA: init.isA ?? fields?.isA ?? [core.classes.property],
    propVals: { ...fields?.propVals, ...init.propVals },
  });
}

/**
 * Creates (and saves) the content-addressed Property for a draft. Returns the
 * existing Property when the same (parent, shortname, datatype) is already
 * known to the store.
 */
export async function createContentAddressedFromDraft(
  store: Store,
  parent: string,
  draft: Resource,
  omit: CopyOmit = {},
): Promise<Resource> {
  const copied = copyablePropertyFields(draft);
  const isA = copied.isA.filter(c => !omit.classes?.includes(c));
  const propVals = Object.fromEntries(
    Object.entries(copied.propVals).filter(
      ([key]) => !omit.fields?.includes(key),
    ),
  );
  const property = await store.newResource({
    parent,
    isA,
    propVals,
    contentAddressedProperty: true,
  });

  // Not `if (property.new)`: signing the genesis commit already clears `new`,
  // while the commit itself stays parked on the resource until `save()`. Gating
  // on `new` skipped the save, so the Property existed only in this session
  // and every other load found nothing. `save()` is a no-op for a Property
  // that is already known and clean.
  await property.save();

  return property;
}

const replaceIn = (list: string[], oldSubject: string, newSubject: string) =>
  Array.from(new Set(list.map(s => (s === oldSubject ? newSubject : s))));

/**
 * Swaps `oldSubject` for `newSubject` in the `requires` / `recommends` of every
 * loaded class that lists it (plus `knownClasses`) and in the `properties` of
 * the old Property's ontology.
 *
 * Values stored under the old property are not moved here; a lens does that
 * ({@link carryValuesOver}).
 */
export async function replacePropertyReferences(
  store: Store,
  oldSubject: string,
  newSubject: string,
  knownClasses: Resource[] = [],
): Promise<void> {
  const lists = [core.properties.requires, core.properties.recommends];
  const listed = (res: Resource, prop: string) =>
    ((res.get(prop) ?? []) as string[]).includes(oldSubject);

  const classes = new Map<string, Resource>();

  for (const cls of [
    ...knownClasses,
    ...store.clientSideQuery(
      res =>
        res.hasClasses(core.classes.class) &&
        lists.some(prop => listed(res, prop)),
    ),
  ]) {
    classes.set(cls.subject, cls);
  }

  for (const cls of classes.values()) {
    let changed = false;

    for (const prop of lists) {
      if (listed(cls, prop)) {
        await cls.set(
          prop,
          replaceIn((cls.get(prop) ?? []) as string[], oldSubject, newSubject),
        );
        changed = true;
      }
    }

    if (changed) {
      await cls.save();
    }
  }

  // A view that lists its columns explicitly would otherwise hide the new
  // property (the old one is no longer a column) and show nothing for it.
  for (const view of store.clientSideQuery(res =>
    listed(res, dataBrowser.properties.viewColumns),
  )) {
    await view.set(
      dataBrowser.properties.viewColumns,
      replaceIn(
        (view.get(dataBrowser.properties.viewColumns) ?? []) as string[],
        oldSubject,
        newSubject,
      ),
      false,
    );
    await view.save();
  }

  const old = await store.getResource(oldSubject);
  const parentSubject = old.get(core.properties.parent) as string | undefined;

  if (!parentSubject) {
    return;
  }

  const parent = await store.getResource(parentSubject);

  if (
    parent.hasClasses(core.classes.ontology) &&
    listed(parent, core.properties.properties)
  ) {
    await parent.set(
      core.properties.properties,
      replaceIn(
        (parent.get(core.properties.properties) ?? []) as string[],
        oldSubject,
        newSubject,
      ),
    );
    await parent.save();
  }
}

const NUMERIC_OR_BOOLEAN: string[] = [
  Datatype.INTEGER,
  Datatype.FLOAT,
  Datatype.BOOLEAN,
];

const TEXTUAL: string[] = [
  Datatype.STRING,
  Datatype.MARKDOWN,
  Datatype.SLUG,
  Datatype.DATE,
  Datatype.URI,
  Datatype.ATOMIC_URL,
];

/**
 * How a value stored under a property of datatype `from` becomes a value under
 * a property of datatype `to` (see `docs/src/schema/lenses.md`). `undefined`
 * when no lens can say: the old values then stay readable only through the old
 * property.
 */
export function lensTransformForDatatypes(
  from: string,
  to: string,
): Transform | undefined {
  if (from === to) {
    return { op: 'rename' };
  }

  if (from === Datatype.ATOMIC_URL && to === Datatype.RESOURCEARRAY) {
    return { op: 'wrap' };
  }

  if (from === Datatype.RESOURCEARRAY && to === Datatype.ATOMIC_URL) {
    return { op: 'head' };
  }

  const isText = (d: string) => TEXTUAL.includes(d);
  const isScalar = (d: string) => NUMERIC_OR_BOOLEAN.includes(d);

  if ((isText(from) && isScalar(to)) || (isScalar(from) && isText(to))) {
    return { op: 'convert', to, from };
  }

  if (isText(from) && isText(to)) {
    return { op: 'convert', to, from };
  }

  return undefined;
}

/**
 * Make `to` the new home of the values stored under `from`, by saving a lens
 * between them. Never throws: a property change must not fail because its
 * values could not be carried over; they just stay under the old property.
 */
export async function carryValuesOver(
  store: Store,
  from: Resource,
  to: Resource,
): Promise<void> {
  if (from.subject === to.subject) {
    return;
  }

  const transform = lensTransformForDatatypes(
    String(from.get(core.properties.datatype)),
    String(to.get(core.properties.datatype)),
  );

  if (!transform) {
    return;
  }

  try {
    await ensureLens(store, { from: from.subject, to: to.subject, transform });
  } catch (error) {
    console.error('Could not save a lens for the changed property', error);
  }
}

/**
 * Changing the datatype of an existing Property: creates a sibling Property
 * (same parent and shortname, new datatype, everything else copied), and
 * replaces the old one in the classes that list it. A lens from the old
 * property to the new one carries the stored values over, where the two
 * datatypes allow it.
 */
export async function recreatePropertyWithDatatype(
  store: Store,
  original: Resource,
  draft: Resource,
  knownClasses: Resource[] = [],
  omit: CopyOmit = {},
): Promise<Resource> {
  const parent = original.get(core.properties.parent) as string;
  const created = await createContentAddressedFromDraft(
    store,
    parent,
    draft,
    omit,
  );

  if (created.subject !== original.subject) {
    await carryValuesOver(store, original, created);
    await replacePropertyReferences(
      store,
      original.subject,
      created.subject,
      knownClasses,
    );
  }

  return created;
}

/** Copies every editable field of `draft` onto `target`, leaving identity alone. */
export async function applyDraftFields(
  target: Resource,
  draft: Resource,
  omit: CopyOmit = {},
): Promise<void> {
  const omitted = (key: string) => omit.fields?.includes(key) ?? false;
  const drafted = copyablePropertyFields(draft);
  const propVals = Object.fromEntries(
    Object.entries(drafted.propVals).filter(([key]) => !omitted(key)),
  );
  const identity: string[] = [
    core.properties.shortname,
    core.properties.datatype,
  ];
  const current = Object.fromEntries(
    Object.entries(copyablePropertyFields(target).propVals).filter(
      ([key]) => !omitted(key),
    ),
  );

  for (const [key, value] of Object.entries(propVals)) {
    if (identity.includes(key) && isContentAddressed(target.subject)) {
      continue;
    }

    if (JSON.stringify(current[key]) !== JSON.stringify(value)) {
      await target.set(key, value);
    }
  }

  const wanted = drafted.isA.filter(c => !omit.classes?.includes(c));
  const have = target.getClasses().filter(c => !omit.classes?.includes(c));

  await target.addClasses(...wanted.filter(c => !have.includes(c)));
  target.removeClasses(...have.filter(c => !wanted.includes(c)));

  for (const key of Object.keys(current)) {
    if (!(key in propVals) && !identity.includes(key)) {
      target.remove(key);
    }
  }
}
