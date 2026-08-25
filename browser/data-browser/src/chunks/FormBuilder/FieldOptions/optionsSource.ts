import {
  core,
  dataBrowser,
  Resource,
  type JSONValue,
  type Store,
} from '@tomic/react';
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
 * Rewires the question's own Property to match `column`, and returns the
 * `optionsSource` to store on the field.
 *
 * The server resolves the published options from the source, but the Property
 * is also a real column on the responses table, so it has to keep describing
 * what lands in it:
 *
 * - Borrowing another column's Tags keeps it a SelectProperty and mirrors that
 *   column's `allowsOnly`, so the response column still renders and edits as
 *   the enum it is. The mirror is a snapshot — the *published* list always
 *   comes from the source, so the two only diverge inside the table UI until
 *   the next {@link syncMirroredTags}.
 * - Borrowing rows makes it a plain relation column (`classtype` = the table's
 *   row class, no `allowsOnly`) — there is no fixed set to enumerate.
 *
 * Options the question created for itself are destroyed on the way: they are
 * parented under this Property and nothing else can reach them.
 */
export async function applyOptionsSource(
  store: Store,
  fieldProperty: Resource,
  table: Resource,
  column: Resource,
): Promise<OptionsSource> {
  const previousTags = fieldProperty.getSubjects(core.properties.allowsOnly);

  let source: OptionsSource;

  if (column.hasClasses(dataBrowser.classes.selectProperty)) {
    await fieldProperty.addClasses(dataBrowser.classes.selectProperty);
    await fieldProperty.set(core.properties.classtype, dataBrowser.classes.tag);
    await fieldProperty.set(
      core.properties.allowsOnly,
      column.getSubjects(core.properties.allowsOnly),
    );
    source = { table: table.subject, property: column.subject };
  } else {
    // `SelectProperty` requires `allowsOnly`, and a row-sourced column has no
    // fixed list — so it stops being one.
    fieldProperty.removeClasses(dataBrowser.classes.selectProperty);
    await fieldProperty.set(
      core.properties.classtype,
      table.get(core.properties.classtype) as string,
    );
    fieldProperty.remove(core.properties.allowsOnly);
    source = { table: table.subject, labelProperty: column.subject };
  }

  await fieldProperty.save();
  await destroyOwnTags(store, fieldProperty.subject, previousTags);

  return source;
}

/**
 * Puts the question back in charge of its own options: an empty enum column,
 * as a freshly added choice question has.
 *
 * The mirrored Tags are dropped rather than kept — they belong to the other
 * table, and editing a label here would rename it over there.
 */
export async function clearOptionsSource(
  fieldProperty: Resource,
): Promise<void> {
  await fieldProperty.addClasses(dataBrowser.classes.selectProperty);
  await fieldProperty.set(core.properties.classtype, dataBrowser.classes.tag);
  await fieldProperty.set(core.properties.allowsOnly, []);
  await fieldProperty.save();
}

/**
 * Re-reads the source column's Tags into the question's own `allowsOnly`.
 * Cheap no-op when they already match — called when the settings panel opens
 * so the response column does not drift while the source gains or loses tags.
 */
export async function syncMirroredTags(
  fieldProperty: Resource,
  sourceProperty: Resource,
): Promise<void> {
  const wanted = sourceProperty.getSubjects(core.properties.allowsOnly);
  const current = fieldProperty.getSubjects(core.properties.allowsOnly);

  if (
    wanted.length === current.length &&
    wanted.every((subject, i) => subject === current[i])
  ) {
    return;
  }

  await fieldProperty.set(core.properties.allowsOnly, wanted);
  await fieldProperty.save();
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
