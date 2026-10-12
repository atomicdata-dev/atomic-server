import {
  Datatype,
  JSONValue,
  Resource,
  Store,
  core,
  dataBrowser,
  perfSpan,
  isAtomicIdentifier,
  isOwnServerUrl,
  setClassConstraint,
  getEffectiveConstraint,
  type ConstraintPatch,
} from '@tomic/react';
import { sortSubjectList } from '@views/OntologyPage/sortSubjectList';
import { stringToSlug } from '@helpers/stringToSlug';
import { randomItem } from '@helpers/randomItem';
import { tagColours } from '@components/Tag/tagColours';

export interface TagSeed {
  name: string;
  color?: string;
  emoji?: string;
}

/** Where a column's options, limits and linked class are stored. */
export type ConstraintsOn = 'class' | 'property';

export interface CreatedSelectProperty {
  subject: string;
  /** Tag option name → created tag subject. */
  tags: Record<string, string>;
}

/**
 * How a new Property is labelled — one of two shapes, never both halves
 * missing:
 *
 * - `name` (with an optional explicit `shortname`): the ordinary case. The
 *   free-text label goes on the Property, and the shortname is slugified from
 *   it unless one is given.
 * - `shortname` alone: a Property whose label lives somewhere else. The form
 *   builder's fields are the case — the Label is on the FormField, and a
 *   second copy on the Property only went stale (see
 *   `planning/form-field-shortnames.md`).
 */
export type PropertyNaming =
  | { name: string; shortname?: string }
  | { name?: undefined; shortname: string };

/** The shortname a new Property asks for, before collision handling. */
function namingShortname(naming: PropertyNaming): string {
  if (naming.name === undefined) {
    return naming.shortname;
  }

  return naming.shortname ?? stringToSlug(naming.name);
}

function namingPropVals(naming: PropertyNaming): Record<string, JSONValue> {
  if (naming.name === undefined) {
    return { [core.properties.shortname]: naming.shortname };
  }

  return {
    [core.properties.shortname]: naming.shortname ?? stringToSlug(naming.name),
    [core.properties.name]: naming.name,
  };
}

/** Resolves the parent a new property of `tableClass` should be created under. */
async function resolvePropertyParent(
  store: Store,
  tableClass: Resource,
): Promise<{ subject: string; isOntology: boolean; resource: Resource }> {
  const classParentSubject = tableClass.get(core.properties.parent) as string;
  const classParent = await store.getResource(classParentSubject);
  const isOntology = classParent.hasClasses(core.classes.ontology);

  return {
    subject: isOntology ? classParent.subject : tableClass.subject,
    isOntology,
    resource: classParent,
  };
}

/**
 * Every property already registered on `ontology`, keyed by shortname. Used to
 * detect a shortname a new column would collide with before minting a
 * duplicate property that shares it — see `createPropertyOnClass` and
 * `createSelectPropertyOnClass`.
 */
async function loadOntologyPropertiesByShortname(
  store: Store,
  ontology: Resource,
): Promise<Map<string, Resource>> {
  const subjects = (ontology.get(core.properties.properties) ?? []) as string[];
  const resources = await Promise.all(
    subjects.map(subject => store.getResource(subject)),
  );
  const taken = new Map<string, Resource>();

  for (const resource of resources) {
    const shortname = resource.get(core.properties.shortname);

    if (typeof shortname === 'string' && shortname) {
      taken.set(shortname, resource);
    }
  }

  return taken;
}

/**
 * Shortnames a new property of `tableClass` must not collide with: the
 * ontology's properties plus the class's own columns. With content-addressed
 * IDs an identical (parent, shortname, datatype) *is* the same property, so a
 * collision would silently hand back an existing column instead of a new one.
 */
async function loadTakenShortnames(
  store: Store,
  parent: { isOntology: boolean; resource: Resource },
  tableClass: Resource,
): Promise<Map<string, Resource>> {
  const taken = parent.isOntology
    ? await loadOntologyPropertiesByShortname(store, parent.resource)
    : new Map<string, Resource>();
  const columnSubjects = [
    ...((tableClass.get(core.properties.requires) ?? []) as string[]),
    ...((tableClass.get(core.properties.recommends) ?? []) as string[]),
  ];

  for (const subject of columnSubjects) {
    const column = await store.getResource(subject);
    const shortname = column.get(core.properties.shortname);

    if (typeof shortname === 'string' && shortname && !taken.has(shortname)) {
      taken.set(shortname, column);
    }
  }

  return taken;
}

/** The next shortname after `base` not already in `taken` — `status-2`,
 *  `status-3`, etc. */
function disambiguateShortname(
  taken: Map<string, Resource>,
  base: string,
): string {
  let n = 2;

  while (taken.has(`${base}-${n}`)) {
    n += 1;
  }

  return `${base}-${n}`;
}

/** A plain (non-select) property can be reused for a new column with the same
 *  shortname only if it stores the same kind of value. */
function isCompatiblePlainProperty(
  existing: Resource,
  datatype: Datatype,
): boolean {
  return (
    existing.hasClasses(core.classes.property) &&
    !existing.hasClasses(dataBrowser.classes.selectProperty) &&
    existing.get(core.properties.datatype) === datatype
  );
}

/** A select property can be reused for a new column with the same shortname
 *  only if it's actually a select (tag-backed enum), not some other property
 *  that happens to share the slug. */
function isCompatibleSelectProperty(existing: Resource): boolean {
  return (
    existing.hasClasses(core.classes.property) &&
    existing.hasClasses(dataBrowser.classes.selectProperty) &&
    existing.get(core.properties.datatype) === Datatype.RESOURCEARRAY
  );
}

/**
 * Registers already-saved properties into the class's ontology (if any) and
 * adds them as columns of the table's row class. Shared by every property
 * created for a table so they behave like hand-made columns.
 *
 * Takes a list rather than one subject because the ontology and the row class
 * are the same two resources for every column of a table: attaching per column
 * costs two round-trip commits each, attaching a whole table's columns at once
 * costs two in total. `createTableFromSpec` builds its columns with
 * `deferAttach` and calls this once at the end.
 */
export async function attachPropertiesToClass(
  store: Store,
  tableClass: Resource,
  propertySubjects: string[],
): Promise<void> {
  if (propertySubjects.length === 0) {
    return;
  }

  const closeAttach = perfSpan('table.attachPropertyToClass', {
    n: propertySubjects.length,
  });
  const classParentSubject = tableClass.get(core.properties.parent) as string;
  const classParent = await store.getResource(classParentSubject);

  if (classParent.hasClasses(core.classes.ontology)) {
    const ontologyProps = (classParent.get(core.properties.properties) ??
      []) as string[];
    // A reused property (see `createPropertyOnClass` / `createSelectPropertyOnClass`'s
    // shortname dedupe, or an explicit `column.propertySubject`) may already be
    // registered here — don't duplicate its entry.
    const newProps = propertySubjects.filter(
      subject => !ontologyProps.includes(subject),
    );
    const closeSort = perfSpan('table.sortSubjectList', {
      n: ontologyProps.length + newProps.length,
    });
    const sorted = await sortSubjectList(store, [
      ...ontologyProps,
      ...newProps,
    ]);
    closeSort();
    await classParent.set(core.properties.properties, sorted);
    const closeOntologySave = perfSpan('table.ontologySave');
    await classParent.save();
    closeOntologySave();
  }

  // A reused property may already be a column of this class.
  const present = new Set([
    ...((tableClass.get(core.properties.requires) ?? []) as string[]),
    ...((tableClass.get(core.properties.recommends) ?? []) as string[]),
  ]);
  const toPush = propertySubjects.filter(subject => !present.has(subject));

  if (toPush.length > 0) {
    await tableClass.push(core.properties.recommends, toPush, true);
  }

  const closeClassSave = perfSpan('table.rowClassSave');
  await tableClass.save();
  closeClassSave();
  closeAttach();
}

/**
 * Creates a plain (non-enum) property with the given datatype and attaches it
 * to the table's row class. Returns the new property's subject.
 */
export async function createPropertyOnClass(
  store: Store,
  tableClass: Resource,
  opts: PropertyNaming & {
    datatype: Datatype;
    /**
     * The class a link points at. Stored in the table class's `constraints`
     * map (`class`), not on the Property, which is immutable.
     */
    classtype?: string;
    /**
     * Where `classtype` goes: the table class's constraints (default), or the
     * Property's legacy `classtype`. Only the form builder still wants the
     * latter, until forms move to the class map.
     */
    constraintsOn?: ConstraintsOn;
    /** Other class constraints for this column, e.g. `{ minimum: 0 }`. */
    constraint?: ConstraintPatch;
    description?: string;
    /**
     * Extra classes the property is an instance of — how a number becomes a
     * FormattedNumber, the same way the property form does it.
     */
    classes?: string[];
    /** Extra propVals, e.g. the constraints those classes recommend. */
    propVals?: Record<string, JSONValue>;
    /**
     * Skip registering the property on the ontology and the row class — the
     * caller is creating several columns at once and will call
     * {@link attachPropertiesToClass} for all of them together.
     */
    deferAttach?: boolean;
    /**
     * Attach an existing compatible property with the same shortname instead
     * of minting a disambiguated one (default true). The new-column dialog
     * turns this off: the user asked for a new column, not an existing one.
     */
    reuse?: boolean;
  },
): Promise<string> {
  const parent = await resolvePropertyParent(store, tableClass);
  let shortname = namingShortname(opts);
  const taken = await loadTakenShortnames(store, parent, tableClass);
  const existing = taken.get(shortname);

  if (existing) {
    if (
      (opts.reuse ?? true) &&
      parent.isOntology &&
      isCompatiblePlainProperty(existing, opts.datatype)
    ) {
      await writeColumnConstraint(tableClass, existing.subject, opts);

      if (!opts.deferAttach) {
        await attachPropertiesToClass(store, tableClass, [existing.subject]);
      }

      return existing.subject;
    }

    // A different, incompatible property already owns this shortname
    // (e.g. a "Status" text column elsewhere vs. this select column) —
    // mint under a disambiguated one instead of silently colliding.
    shortname = disambiguateShortname(taken, shortname);
  }

  const propVals: Record<string, JSONValue> = {
    ...namingPropVals(opts),
    // May differ from the requested one: see the collision handling above.
    [core.properties.shortname]: shortname,
    [core.properties.description]: opts.description ?? '',
    [core.properties.datatype]: opts.datatype,
    ...opts.propVals,
  };

  if (opts.classtype && opts.constraintsOn === 'property') {
    propVals[core.properties.classtype] = opts.classtype;
  }

  // Content-addressed: parent, shortname and datatype are final here, and an
  // identical triple resolves to the property that already exists.
  const property = await store.newResource({
    parent: parent.subject,
    isA: [core.classes.property, ...(opts.classes ?? [])],
    propVals,
    contentAddressedProperty: true,
  });
  await property.save();
  await writeColumnConstraint(tableClass, property.subject, opts);

  if (!opts.deferAttach) {
    await attachPropertiesToClass(store, tableClass, [property.subject]);
  }

  return property.subject;
}

/**
 * Puts a new column's linked class and other limits in the table class's
 * `constraints` map. Does not save: the class is saved when the column is
 * attached to it (see {@link attachPropertiesToClass}).
 */
async function writeColumnConstraint(
  tableClass: Resource,
  propertySubject: string,
  opts: {
    classtype?: string;
    constraint?: ConstraintPatch;
    constraintsOn?: ConstraintsOn;
  },
): Promise<void> {
  if (opts.constraintsOn === 'property') {
    return;
  }

  const patch: ConstraintPatch = {
    ...opts.constraint,
    ...(opts.classtype ? { class: opts.classtype } : {}),
  };

  if (Object.keys(patch).length > 0) {
    await setClassConstraint(tableClass, propertySubject, patch);
  }
}

/**
 * Attaches an already-existing select property to a new table instead of
 * minting a duplicate that would share its shortname.
 *
 * Only when it can answer for every option the caller asked for: silently
 * adding options to a property other tables/columns already use would
 * surprise them, and a "Status" of Want to read / Reading / Finished is not
 * the same property as a "Status" of Todo / Doing / Done. Returns undefined
 * for that case so the caller mints its own under a disambiguated shortname.
 */
async function reuseSelectProperty(
  store: Store,
  tableClass: Resource,
  existing: Resource,
  opts: { tags: TagSeed[]; deferAttach?: boolean },
): Promise<CreatedSelectProperty | undefined> {
  const optionSubjects = (existing.get(core.properties.allowsOnly) ??
    []) as string[];
  // Tags always carry a shortname (older ones carry nothing else), so match
  // the caller's option names against that, the same slug they were minted
  // with.
  const subjectByShortname: Record<string, string> = {};

  for (const subject of optionSubjects) {
    const tag = await store.getResource(subject);
    const shortname = tag.get(core.properties.shortname);

    if (typeof shortname === 'string') {
      subjectByShortname[shortname] = subject;
    }
  }

  const tagsByName: Record<string, string> = {};

  for (const seed of opts.tags) {
    const subject = subjectByShortname[stringToSlug(seed.name)];

    if (!subject) {
      return undefined;
    }

    tagsByName[seed.name] = subject;
  }

  if (!opts.deferAttach) {
    await attachPropertiesToClass(store, tableClass, [existing.subject]);
  }

  return { subject: existing.subject, tags: tagsByName };
}

const isColumnOf = (tableClass: Resource, propertySubject: string): boolean =>
  [
    ...((tableClass.get(core.properties.requires) ?? []) as string[]),
    ...((tableClass.get(core.properties.recommends) ?? []) as string[]),
  ].includes(propertySubject);

/** Option name (as created) to tag subject, for tags that already exist. */
async function tagSubjectsByName(
  store: Store,
  tagSubjects: string[],
): Promise<Record<string, string>> {
  const byName: Record<string, string> = {};

  for (const subject of tagSubjects) {
    const tag = await store.getResource(subject);
    const name =
      tag.get(core.properties.name) ?? tag.get(core.properties.shortname);

    if (typeof name === 'string') byName[name] = subject;
  }

  return byName;
}

/**
 * Creates the Tags for a select column's options, parented to the property.
 * Returns their subjects in order, and by option name.
 */
export async function createOptionTags(
  store: Store,
  propertySubject: string,
  seeds: TagSeed[],
  /**
   * Where the Tags go when the property is a hosted one (an ontology on
   * another server, such as the Tasks ontology): nobody here may add children
   * to it, so they sit under this resource instead (the table's row class).
   */
  fallbackParent?: string,
): Promise<{ subjects: string[]; byName: Record<string, string> }> {
  const subjects: string[] = [];
  const byName: Record<string, string> = {};

  for (const seed of seeds) {
    const closeTag = perfSpan('table.tag');
    const closeSubject = perfSpan('table.tagUniqueSubject');
    // Only a property of our own may have Tags under it. A reused one from a
    // hosted ontology (`https://atomicdata.dev/task/v1/status`) is not ours:
    // the server refuses subjects there and children of it.
    const ownProperty =
      isAtomicIdentifier(propertySubject) ||
      isOwnServerUrl(propertySubject, store.getServerUrl());
    const parent = ownProperty
      ? propertySubject
      : (fallbackParent ?? propertySubject);
    const subject =
      isAtomicIdentifier(parent) ||
      !isOwnServerUrl(parent, store.getServerUrl())
        ? undefined
        : await store.buildUniqueSubjectFromParts(['tag', seed.name], parent);
    closeSubject();

    const tag = await store.newResource({
      subject,
      parent,
      isA: dataBrowser.classes.tag,
      propVals: {
        // `shortname` is the slug the class requires; `name` carries the
        // label verbatim, since a seed like "Strongly agree — daily" does not
        // survive slugification. `useTitle` prefers `name`, so every tag
        // renderer shows the original text.
        [core.properties.shortname]: stringToSlug(seed.name),
        [core.properties.name]: seed.name,
        [dataBrowser.properties.color]: seed.color ?? randomItem(tagColours),
        ...(seed.emoji ? { [dataBrowser.properties.emoji]: seed.emoji } : {}),
      },
    });
    await tag.save();
    closeTag();
    subjects.push(tag.subject);
    byName[seed.name] = tag.subject;
  }

  return { subjects, byName };
}

/**
 * A select column's options and pick limit as a class constraint: `enum` lists
 * the Tags, `maxItems: 1` makes it a single pick. Does not save the class.
 */
export function selectConstraintPatch(
  tagSubjects: string[],
  max?: number,
): ConstraintPatch {
  return {
    enum: tagSubjects,
    ...(max !== undefined ? { maxItems: max } : {}),
  };
}

/**
 * Creates a SelectProperty (enum) with the given Tags and attaches it to a
 * table's row Class — mirroring `NewPropertyDialog`'s "select" genesis path so
 * the property is indistinguishable from one a user made by hand. Returns the
 * new property's subject.
 *
 * The options (`enum`) and a single pick (`maxItems: 1`) are written to the
 * ROW CLASS's `constraints` map, so each table owns its own option list and
 * editing it never touches the immutable Property. An existing select property
 * of the same shortname is reused, with fresh Tags for this class.
 *
 * This deliberately does NOT touch the canonical atomic-data ontology: the
 * property is parented under the table class's own ontology (or the class
 * itself), so a "status" enum is per-drive template data, not a shared schema
 * change.
 */
export async function createSelectPropertyOnClass(
  store: Store,
  tableClass: Resource,
  opts: PropertyNaming & {
    tags: TagSeed[];
    /**
     * How many tags may be picked at once. A SelectProperty is always a
     * `resourceArray`, so single-select is `maxItems: 1` rather than a
     * different datatype.
     */
    max?: number;
    /** See {@link createPropertyOnClass}'s `deferAttach`. */
    deferAttach?: boolean;
    /** See {@link createPropertyOnClass}'s `reuse`. */
    reuse?: boolean;
    /** See {@link createPropertyOnClass}'s `constraintsOn`. */
    constraintsOn?: ConstraintsOn;
  },
): Promise<CreatedSelectProperty> {
  const legacy = opts.constraintsOn === 'property';
  const parent = await resolvePropertyParent(store, tableClass);
  let shortname = namingShortname(opts);
  const taken = await loadTakenShortnames(store, parent, tableClass);
  const existing = taken.get(shortname);

  if (existing) {
    if (
      (opts.reuse ?? true) &&
      parent.isOntology &&
      isCompatibleSelectProperty(existing)
    ) {
      if (legacy) {
        const reused = await reuseSelectProperty(
          store,
          tableClass,
          existing,
          opts,
        );

        if (reused) return reused;
      } else {
        // Already a column of this class with its options: nothing to add.
        const own = getEffectiveConstraint(
          store,
          [tableClass.subject],
          existing.subject,
        );
        const ownTags = (own.enum ?? []).filter(
          (v): v is string => typeof v === 'string',
        );

        if (isColumnOf(tableClass, existing.subject) && ownTags.length > 0) {
          return {
            subject: existing.subject,
            tags: await tagSubjectsByName(store, ownTags),
          };
        }

        // Options belong to the class, so the property itself is shared and
        // this table gets Tags of its own.
        const { subjects, byName } = await createOptionTags(
          store,
          existing.subject,
          opts.tags,
          tableClass.subject,
        );
        await setClassConstraint(
          tableClass,
          existing.subject,
          selectConstraintPatch(subjects, opts.max),
        );

        if (!opts.deferAttach) {
          await attachPropertiesToClass(store, tableClass, [existing.subject]);
        }

        return { subject: existing.subject, tags: byName };
      }
    }

    // A different, incompatible property already owns this shortname —
    // mint under a disambiguated one instead of silently colliding.
    shortname = disambiguateShortname(taken, shortname);
  }

  // Content-addressed: the ID is known up front, so the tags below can be
  // parented to it before the property is saved.
  const property = await store.newResource({
    contentAddressedProperty: true,
    parent: parent.subject,
    isA: [core.classes.property, dataBrowser.classes.selectProperty],
    propVals: {
      ...namingPropVals(opts),
      [core.properties.shortname]: shortname,
      [core.properties.description]: '',
      [core.properties.datatype]: Datatype.RESOURCEARRAY,
      // The SelectProperty class requires `allowsOnly`, so it stays on the
      // Property as an empty marker. The options are in the class map.
      [core.properties.classtype]: dataBrowser.classes.tag,
      [core.properties.allowsOnly]: [],
      ...(legacy && opts.max !== undefined
        ? { [dataBrowser.properties.max]: opts.max }
        : {}),
    },
  });

  // Saved before its tags: a child saved under a parent the server has not
  // seen yet is refused, and the Tag then reads as an empty placeholder until
  // the parent lands, so a cell opened right after the column was created
  // lists options without titles.
  if (!legacy) {
    await property.save();
  }

  // Create the tags, parented to the property (same as SelectPropertyForm).
  const { subjects: tagSubjects, byName: tagsByName } = await createOptionTags(
    store,
    property.subject,
    opts.tags,
  );

  if (legacy) {
    await property.set(core.properties.allowsOnly, tagSubjects);
    await property.save();
  } else {
    await setClassConstraint(
      tableClass,
      property.subject,
      selectConstraintPatch(tagSubjects, opts.max),
    );
  }

  if (!opts.deferAttach) {
    await attachPropertiesToClass(store, tableClass, [property.subject]);
  }

  return { subject: property.subject, tags: tagsByName };
}

/** The default Todo / Doing / Done status seed for auto-created kanban columns. */
export const DEFAULT_STATUS_TAGS: TagSeed[] = [
  { name: 'Todo' },
  { name: 'Doing' },
  { name: 'Done' },
];
