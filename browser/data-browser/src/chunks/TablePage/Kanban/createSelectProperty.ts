import {
  Datatype,
  JSONValue,
  Resource,
  Store,
  core,
  dataBrowser,
  perfSpan,
} from '@tomic/react';
import { sortSubjectList } from '@views/OntologyPage/sortSubjectList';
import { stringToSlug } from '@helpers/stringToSlug';
import { randomItem } from '@helpers/randomItem';
import { tagColours } from '@components/Tag/tagColours';

export interface TagSeed {
  name: string;
  color?: string;
}

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
): Promise<{ subject: string; isOntology: boolean }> {
  const classParentSubject = tableClass.get(core.properties.parent) as string;
  const classParent = await store.getResource(classParentSubject);
  const isOntology = classParent.hasClasses(core.classes.ontology);

  return {
    subject: isOntology ? classParent.subject : tableClass.subject,
    isOntology,
  };
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
    const ontologyProps = classParent.get(core.properties.properties) ?? [];
    const closeSort = perfSpan('table.sortSubjectList', {
      n: (ontologyProps as string[]).length + propertySubjects.length,
    });
    const sorted = await sortSubjectList(store, [
      ...ontologyProps,
      ...propertySubjects,
    ]);
    closeSort();
    await classParent.set(core.properties.properties, sorted);
    const closeOntologySave = perfSpan('table.ontologySave');
    await classParent.save();
    closeOntologySave();
  }

  await tableClass.push(core.properties.recommends, propertySubjects, true);
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
    classtype?: string;
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
  },
): Promise<string> {
  const parent = await resolvePropertyParent(store, tableClass);

  const propVals: Record<string, JSONValue> = {
    ...namingPropVals(opts),
    [core.properties.description]: opts.description ?? '',
    [core.properties.datatype]: opts.datatype,
    ...opts.propVals,
  };

  if (opts.classtype) {
    propVals[core.properties.classtype] = opts.classtype;
  }

  const property = await store.newResource({
    parent: parent.subject,
    isA: [core.classes.property, ...(opts.classes ?? [])],
    propVals,
  });
  await property.save();

  if (!opts.deferAttach) {
    await attachPropertiesToClass(store, tableClass, [property.subject]);
  }

  return property.subject;
}

/**
 * Creates a SelectProperty (enum) with the given Tags and attaches it to a
 * table's row Class — mirroring `NewPropertyDialog`'s "select" genesis path so
 * the property is indistinguishable from one a user made by hand. Returns the
 * new property's subject.
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
     * `resourceArray`, so single-select is `max: 1` rather than a different
     * datatype — see `SelectProperty`'s `max` in `lib/defaults/table.json`.
     */
    max?: number;
    /** See {@link createPropertyOnClass}'s `deferAttach`. */
    deferAttach?: boolean;
  },
): Promise<CreatedSelectProperty> {
  const parent = await resolvePropertyParent(store, tableClass);

  const property = await store.newResource({
    parent: parent.subject,
    isA: [core.classes.property, dataBrowser.classes.selectProperty],
    propVals: {
      ...namingPropVals(opts),
      [core.properties.description]: '',
      [core.properties.datatype]: Datatype.RESOURCEARRAY,
      [core.properties.classtype]: dataBrowser.classes.tag,
      [core.properties.allowsOnly]: [],
      ...(opts.max !== undefined
        ? { [dataBrowser.properties.max]: opts.max }
        : {}),
    },
  });

  // Create the tags, parented to the property (same as SelectPropertyForm).
  const tagSubjects: string[] = [];
  const tagsByName: Record<string, string> = {};

  for (const seed of opts.tags) {
    const closeTag = perfSpan('table.tag');
    const closeSubject = perfSpan('table.tagUniqueSubject');
    const subject = property.subject.startsWith('did:')
      ? undefined
      : await store.buildUniqueSubjectFromParts(
          ['tag', seed.name],
          property.subject,
        );
    closeSubject();

    const tag = await store.newResource({
      subject,
      parent: property.subject,
      isA: dataBrowser.classes.tag,
      propVals: {
        // `shortname` is the slug the class requires; `name` carries the
        // label verbatim, since a seed like "Strongly agree — daily" does not
        // survive slugification. `useTitle` prefers `name`, so every tag
        // renderer shows the original text.
        [core.properties.shortname]: stringToSlug(seed.name),
        [core.properties.name]: seed.name,
        [dataBrowser.properties.color]: seed.color ?? randomItem(tagColours),
      },
    });
    await tag.save();
    closeTag();
    tagSubjects.push(tag.subject);
    tagsByName[seed.name] = tag.subject;
  }

  await property.set(core.properties.allowsOnly, tagSubjects);
  await property.save();

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
