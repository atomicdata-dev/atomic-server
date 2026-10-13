import {
  Datatype,
  core,
  dataBrowser,
  setClassConstraint,
  type Constraint,
  type ConstraintPatch,
  type Resource,
} from '@tomic/react';

/**
 * The column forms (number range, link target, select options) edit a draft
 * Property whose fields carry the legacy names: `min`, `max`, `classtype`,
 * `allowsOnly`. Properties are immutable, so these never reach the Property.
 * They are translated into the table class's `constraints` map on confirm.
 */

/** Property fields that now live in the class map. */
export const CONSTRAINT_FIELDS = [
  core.properties.allowsOnly,
  core.properties.classtype,
  dataBrowser.properties.min,
  dataBrowser.properties.max,
];

const NUMBER_TYPES: string[] = [Datatype.INTEGER, Datatype.FLOAT];
const TEXT_TYPES: string[] = [
  Datatype.STRING,
  Datatype.MARKDOWN,
  Datatype.SLUG,
  Datatype.URI,
];

/** The class constraint keywords a `min`/`max` pair maps to for a datatype. */
function rangeKeywords(datatype: string | undefined): {
  min: 'minimum' | 'minLength' | 'minItems';
  max: 'maximum' | 'maxLength' | 'maxItems';
} {
  if (datatype && NUMBER_TYPES.includes(datatype))
    return { min: 'minimum', max: 'maximum' };

  if (datatype && TEXT_TYPES.includes(datatype))
    return { min: 'minLength', max: 'maxLength' };

  return { min: 'minItems', max: 'maxItems' };
}

const count = (n: number | undefined) =>
  n === undefined ? undefined : Math.max(0, Math.trunc(n));

/**
 * What the draft's `min` and `max` (number and text columns) or `classtype`
 * (link columns) say, as a patch for the class entry. A value the draft does
 * not have is `undefined`, which removes that keyword. Other columns edit no
 * constraint here, so they patch nothing and leave the class entry alone.
 */
export function constraintPatchFromDraft(draft: Resource): ConstraintPatch {
  const datatype = draft.get(core.properties.datatype) as string | undefined;

  if (
    datatype &&
    (NUMBER_TYPES.includes(datatype) || TEXT_TYPES.includes(datatype))
  ) {
    const keywords = rangeKeywords(datatype);
    const min = draft.get(dataBrowser.properties.min) as number | undefined;
    const max = draft.get(dataBrowser.properties.max) as number | undefined;
    const isCount = keywords.min !== 'minimum';

    return {
      [keywords.min]: isCount ? count(min) : min,
      [keywords.max]: isCount ? count(max) : max,
    };
  }

  if (datatype === Datatype.ATOMIC_URL || datatype === Datatype.RESOURCEARRAY) {
    return {
      class: (draft.get(core.properties.classtype) as string) || undefined,
    };
  }

  return {};
}

/**
 * Fills the legacy-named draft fields from what applies to the column now, so
 * the form opens on the real values (class map first, legacy Property after).
 */
export function seedDraftFromConstraint(
  draft: Resource,
  constraint: Constraint,
): void {
  const datatype = draft.get(core.properties.datatype) as string | undefined;
  const keywords = rangeKeywords(datatype);

  const set = (prop: string, value: unknown) => {
    if (value === undefined) {
      draft.remove(prop);
    } else {
      void draft.set(prop, value as never, false);
    }
  };

  if (
    datatype &&
    (NUMBER_TYPES.includes(datatype) || TEXT_TYPES.includes(datatype))
  ) {
    set(dataBrowser.properties.min, constraint[keywords.min]);
    set(dataBrowser.properties.max, constraint[keywords.max]);
  } else if (
    datatype === Datatype.ATOMIC_URL ||
    datatype === Datatype.RESOURCEARRAY
  ) {
    set(core.properties.classtype, constraint.class);
  }
}

/** Writes the draft's constraint fields into the class entry. Does not save. */
export async function applyDraftConstraint(
  tableClass: Resource,
  propertySubject: string,
  draft: Resource,
): Promise<void> {
  const patch = constraintPatchFromDraft(draft);

  if (Object.keys(patch).length > 0) {
    await setClassConstraint(tableClass, propertySubject, patch);
  }
}
