import {
  type Constraint,
  type ConstraintKeyword,
  CONSTRAINT_KEYWORDS,
  parseConstraint,
  parseConstraints,
} from './class-constraints.js';
import { Datatype } from './datatypes.js';
import type { Resource } from './resource.js';
import type { Store } from './store.js';
import { canonicalizeScheme } from './subject.js';
import { core } from './ontologies/core.js';
import type { JSONObject, JSONValue } from './value.js';

/**
 * Read and write helpers for the `constraints` map on a Class. The map is the
 * source of truth; the legacy Property fields (`allowsOnly`, `classtype`,
 * `min`, `max`) are only a fallback for data that predates it.
 * See `planning/class-constraints-and-forms.md`.
 */

const LEGACY_MIN = 'https://atomicdata.dev/properties/min';
const LEGACY_MAX = 'https://atomicdata.dev/properties/max';

/** The slice of a Resource the readers need. */
interface Readable {
  isReady?(): boolean;
  get(prop: string): unknown;
}

const ARRAY_DATATYPES: string[] = [Datatype.RESOURCEARRAY];
const NUMBER_DATATYPES: string[] = [
  Datatype.INTEGER,
  Datatype.FLOAT,
  Datatype.TIMESTAMP,
];
const TEXT_DATATYPES: string[] = [
  Datatype.STRING,
  Datatype.MARKDOWN,
  Datatype.SLUG,
  Datatype.URI,
];

const isNumber = (v: unknown): v is number =>
  typeof v === 'number' && Number.isFinite(v);

/** Combines two constraints on the same property: a value must satisfy both. */
function tighten(a: Constraint, b: Constraint): Constraint {
  const out: Constraint = { ...a };
  const lower = [
    'minimum',
    'exclusiveMinimum',
    'minLength',
    'minItems',
  ] as const;
  const upper = [
    'maximum',
    'exclusiveMaximum',
    'maxLength',
    'maxItems',
  ] as const;

  for (const k of lower) {
    if (b[k] !== undefined) out[k] = Math.max(a[k] ?? -Infinity, b[k]);
  }

  for (const k of upper) {
    if (b[k] !== undefined) out[k] = Math.min(a[k] ?? Infinity, b[k]);
  }

  if (b.enum) {
    out.enum = a.enum
      ? a.enum.filter(x =>
          b.enum!.some(y => canonicalJson(x) === canonicalJson(y)),
        )
      : b.enum;
  }

  // A pattern or linked class cannot be combined: the first class wins.
  out.pattern ??= b.pattern;
  out.class ??= b.class;

  return out;
}

const canonicalJson = (v: unknown): string =>
  JSON.stringify(typeof v === 'string' ? canonicalizeScheme(v) : v);

/** What the legacy Property fields say, in class-constraint vocabulary. */
function legacyConstraint(property: Readable | undefined): Constraint {
  const out: Constraint = {};

  if (!property || (property.isReady && !property.isReady())) return out;

  const allowsOnly = property.get(core.properties.allowsOnly);

  if (Array.isArray(allowsOnly) && allowsOnly.length > 0) {
    out.enum = allowsOnly.map(item =>
      typeof item === 'object' && item !== null && '@id' in item
        ? ((item as { '@id': string })['@id'] as JSONValue)
        : (item as JSONValue),
    );
  }

  const classtype = property.get(core.properties.classtype);

  if (typeof classtype === 'string' && classtype) {
    out.class = canonicalizeScheme(classtype);
  }

  const datatype = String(property.get(core.properties.datatype) ?? '');
  const min = property.get(LEGACY_MIN);
  const max = property.get(LEGACY_MAX);

  if (ARRAY_DATATYPES.includes(datatype)) {
    if (isNumber(min) && min >= 0) out.minItems = Math.trunc(min);
    if (isNumber(max) && max >= 0) out.maxItems = Math.trunc(max);
  } else if (NUMBER_DATATYPES.includes(datatype)) {
    if (isNumber(min)) out.minimum = min;
    if (isNumber(max)) out.maximum = max;
  } else if (TEXT_DATATYPES.includes(datatype)) {
    if (isNumber(min) && min >= 0) out.minLength = Math.trunc(min);
    if (isNumber(max) && max >= 0) out.maxLength = Math.trunc(max);
  }

  return out;
}

/**
 * The constraint that applies to `propertySubject` for a resource (or table)
 * that is an instance of all of `classSubjects`.
 *
 * - The class maps of every given class are merged by tightening: a value has to
 *   satisfy each class, so `enum`s intersect, minimums take the larger value and
 *   maximums the smaller.
 * - Per keyword, the class maps win. Only a keyword no class sets falls back to
 *   the Property's legacy `allowsOnly` (`enum`), `classtype` (`class`) and
 *   `min`/`max` (`minItems`/`maxItems` for arrays, `minimum`/`maximum` for numbers,
 *   `minLength`/`maxLength` for text).
 *
 * Reads the local store and starts a background fetch for anything missing; call
 * again (or use `useEffectiveConstraint`) when the resources load. Classes whose
 * map does not parse are skipped.
 */
export function getEffectiveConstraint(
  store: Pick<Store, 'getResourceLoading'>,
  classSubjects: string[],
  propertySubject: string,
): Constraint {
  const key = canonicalizeScheme(propertySubject);
  let fromClasses: Constraint | undefined;

  for (const classSubject of classSubjects) {
    const klass = store.getResourceLoading(classSubject) as Readable;

    if (klass.isReady && !klass.isReady()) continue;

    const raw = klass.get(core.properties.constraints);

    if (raw === undefined) continue;

    let entry: Constraint | undefined;

    try {
      entry = parseConstraints(raw).get(key);
    } catch {
      continue;
    }

    if (entry) fromClasses = fromClasses ? tighten(fromClasses, entry) : entry;
  }

  const legacy = legacyConstraint(
    store.getResourceLoading(propertySubject) as Readable,
  );

  return { ...legacy, ...definedOnly(fromClasses) };
}

function definedOnly(c: Constraint | undefined): Constraint {
  const out: Constraint = {};

  for (const k of CONSTRAINT_KEYWORDS) {
    if (c?.[k] !== undefined) (out as Record<string, unknown>)[k] = c[k];
  }

  return out;
}

/** A partial constraint to merge into a class entry. `undefined` removes a keyword. */
export type ConstraintPatch = {
  [K in ConstraintKeyword]?: K extends 'pattern'
    ? string | RegExp | undefined
    : Constraint[K] | undefined;
};

const isObject = (v: unknown): v is JSONObject =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Edits one property's entry in the class's `constraints` map. Keywords in
 * `patch` are merged into the entry, a keyword set to `undefined` is removed, an
 * entry left without keywords is removed, and `patch === undefined` removes the
 * entry outright. An emptied map removes the `constraints` property. The
 * result is validated with {@link parseConstraint} first, so an invalid patch
 * throws and leaves the class untouched. Does not save.
 */
export async function setClassConstraint(
  classResource: Resource,
  propertySubject: string,
  patch: ConstraintPatch | undefined,
): Promise<void> {
  const key = canonicalizeScheme(propertySubject);
  const raw = classResource.get(core.properties.constraints);
  let map: JSONObject = {};

  if (raw !== undefined) {
    const parsed: unknown = typeof raw === 'string' ? JSON.parse(raw) : raw;

    if (isObject(parsed)) map = { ...(parsed as JSONObject) };
  }

  // Entries may be keyed by the legacy `did:ad:` spelling; fold them into one.
  let entry: JSONObject = {};

  for (const existingKey of Object.keys(map)) {
    if (canonicalizeScheme(existingKey) === key) {
      const value = map[existingKey];

      if (isObject(value)) entry = { ...entry, ...(value as JSONObject) };

      delete map[existingKey];
    }
  }

  if (patch !== undefined) {
    for (const [keyword, value] of Object.entries(patch)) {
      if (value === undefined) {
        delete entry[keyword];
      } else {
        entry[keyword] = (
          value instanceof RegExp ? value.source : value
        ) as JSONValue;
      }
    }

    // Throws on unknown keywords and wrong types.
    parseConstraint(entry);

    if (Object.keys(entry).length > 0) map[key] = entry;
  }

  if (Object.keys(map).length === 0) {
    if (raw !== undefined) classResource.remove(core.properties.constraints);

    return;
  }

  await classResource.set(
    core.properties.constraints,
    map,
    false,
    Datatype.JSON,
  );
}
