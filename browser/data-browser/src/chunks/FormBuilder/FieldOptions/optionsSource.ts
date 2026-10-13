import {
  core,
  dataBrowser,
  getEffectiveConstraint,
  Resource,
  setClassConstraint,
  type JSONValue,
  type Store,
} from '@tomic/react';
import { optionSubjects } from '@helpers/withConstraint';
import type { OptionsSource } from '@tomic/form-renderer';
import { useCallback } from 'react';
import { useFieldOptions } from './useFieldOptions';

export type { OptionsSource };

/**
 * The two ways a choice question can borrow its options from a table.
 *
 * - `tags` — the options are the Tags of another column (a SelectProperty).
 *   A fixed list, the same shape the question would have on its own.
 * - `rows` — the options are the table's *rows*, so an answer is a reference
 *   to a row. The list is resolved on every read of the form definition, so
 *   it follows the table.
 */
export type OptionsSourceMode = 'tags' | 'rows';

export const OPTIONS_SOURCE_KEY = 'optionsSource';

export function optionsSourceMode(source: OptionsSource): OptionsSourceMode {
  return source.property ? 'tags' : 'rows';
}

/** The column the source points at, whichever mode it is in. */
export function sourceColumn(source: OptionsSource): string | undefined {
  return source.property ?? source.labelProperty;
}

function parseOptionsSource(
  raw: JSONValue | undefined,
): OptionsSource | undefined {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return undefined;
  }

  const source = raw as OptionsSource;

  // A bag written before this feature — or one left half-empty by a failed
  // link — reads as "not linked" rather than as a source resolving to nothing.
  return source.property || source.table ? source : undefined;
}

/**
 * Reads and writes a choice question's `optionsSource` — the pointer at the
 * table its options are borrowed from. Absent means the question owns its
 * options (the default).
 */
export function useOptionsSource(
  field: Resource,
): [OptionsSource | undefined, (next: OptionsSource | undefined) => void] {
  const [options, setOptions] = useFieldOptions(field);

  const setSource = useCallback(
    (next: OptionsSource | undefined) => {
      const { [OPTIONS_SOURCE_KEY]: _dropped, ...rest } = options;

      setOptions(
        next ? { ...rest, [OPTIONS_SOURCE_KEY]: next as JSONValue } : rest,
      );
    },
    [options, setOptions],
  );

  return [parseOptionsSource(options[OPTIONS_SOURCE_KEY]), setSource];
}

/**
 * Rewires the question's column to match `column`, and returns the
 * `optionsSource` to store on the field.
 *
 * The server resolves the published options from the source, but the column is
 * also a real column on the responses table, so the data class has to keep
 * describing what lands in it. That is the class's `constraints` entry for the
 * question's Property (which is immutable and so is never touched):
 *
 * - Borrowing another column's Tags mirrors that column's `enum`, so the
 *   response column still renders and edits as the enum it is. The mirror is a
 *   snapshot — the *published* list always comes from the source, so the two
 *   only diverge inside the table UI until the next {@link syncMirroredTags}.
 * - Borrowing rows makes it a plain relation column (`class` = the table's row
 *   class, no `enum`) — there is no fixed set to enumerate.
 *
 * Options the question created for itself are destroyed on the way: they are
 * parented under this Property and nothing else can reach them.
 */
export async function applyOptionsSource(
  store: Store,
  dataClass: Resource,
  fieldProperty: Resource,
  table: Resource,
  column: Resource,
): Promise<OptionsSource> {
  const previousTags = columnTags(store, dataClass.subject, fieldProperty);

  let source: OptionsSource;

  if (column.hasClasses(dataBrowser.classes.selectProperty)) {
    const sourceClass = await store.getResource(
      table.get(core.properties.classtype) as string,
    );
    await setClassConstraint(dataClass, fieldProperty.subject, {
      enum: columnTags(store, sourceClass.subject, column),
      class: dataBrowser.classes.tag,
    });
    source = { table: table.subject, property: column.subject };
  } else {
    // A row-sourced column has no fixed list to enumerate.
    await setClassConstraint(dataClass, fieldProperty.subject, {
      enum: undefined,
      class: table.get(core.properties.classtype) as string,
    });
    source = { table: table.subject, labelProperty: column.subject };
  }

  await dataClass.save();
  await destroyOwnTags(store, fieldProperty.subject, previousTags);

  return source;
}

/** The option Tags a class puts on a column: its `enum`, or the Property's
 * legacy `allowsOnly`. */
function columnTags(
  store: Store,
  classSubject: string,
  property: Resource,
): string[] {
  return optionSubjects(
    getEffectiveConstraint(store, [classSubject], property.subject),
  );
}

/**
 * Puts the question back in charge of its own options: an empty enum column,
 * as a freshly added choice question has.
 *
 * The mirrored Tags are dropped rather than kept — they belong to the other
 * table, and editing a label here would rename it over there.
 */
export async function clearOptionsSource(
  dataClass: Resource,
  fieldProperty: Resource,
): Promise<void> {
  await setClassConstraint(dataClass, fieldProperty.subject, {
    enum: [],
    class: dataBrowser.classes.tag,
  });
  await dataClass.save();
}

/**
 * Re-reads the source column's Tags into the question's own `enum`. Cheap
 * no-op when they already match — called when the settings panel opens so the
 * response column does not drift while the source gains or loses tags.
 * `sourceClass` is the row class of the table the source column belongs to.
 */
export async function syncMirroredTags(
  store: Store,
  dataClass: Resource,
  fieldProperty: Resource,
  sourceClass: string,
  sourceProperty: Resource,
): Promise<void> {
  const wanted = columnTags(store, sourceClass, sourceProperty);
  const current = columnTags(store, dataClass.subject, fieldProperty);

  if (
    wanted.length === current.length &&
    wanted.every((subject, i) => subject === current[i])
  ) {
    return;
  }

  await setClassConstraint(dataClass, fieldProperty.subject, { enum: wanted });
  await dataClass.save();
}

/** Destroys the option Tags parented under this Property — the ones the form
 * builder made for it. Tags borrowed from another column live under *that*
 * column and are left alone. */
async function destroyOwnTags(
  store: Store,
  propertySubject: string,
  tagSubjects: string[],
): Promise<void> {
  for (const subject of tagSubjects) {
    const tag = await store.getResource(subject);

    if (tag.get(core.properties.parent) === propertySubject) {
      await tag.destroy();
    }
  }
}
