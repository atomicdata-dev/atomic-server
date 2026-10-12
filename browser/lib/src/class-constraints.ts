import { canonicalizeScheme, toLegacyScheme } from './subject.js';
import type { JSONObject, JSONValue } from './value.js';

/**
 * Value constraints that live on a Class, not on its Properties. The Rust twin
 * is `lib/src/class_constraints.rs`; both run
 * `lib/tests/fixtures/class-constraints.json`, so change them together.
 * See `docs/src/schema/classes.md`.
 */

/** Every keyword a constraint may use. Anything else is rejected. */
export const CONSTRAINT_KEYWORDS = [
  'enum',
  'minimum',
  'maximum',
  'exclusiveMinimum',
  'exclusiveMaximum',
  'minLength',
  'maxLength',
  'minItems',
  'maxItems',
  'pattern',
  'class',
] as const;

export type ConstraintKeyword = (typeof CONSTRAINT_KEYWORDS)[number];

export interface Constraint {
  enum?: JSONValue[];
  minimum?: number;
  maximum?: number;
  exclusiveMinimum?: number;
  exclusiveMaximum?: number;
  minLength?: number;
  maxLength?: number;
  minItems?: number;
  maxItems?: number;
  pattern?: RegExp;
  /** Subject of the class a link should point to. Never checked at write time. */
  class?: string;
}

/** A class's constraints, keyed by canonical property subject. */
export type Constraints = Map<string, Constraint>;

/** A value broke a constraint. */
export class ConstraintError extends Error {
  public constructor(
    public readonly keyword: ConstraintKeyword,
    public readonly detail: string,
  ) {
    super(`${keyword}: ${detail}`);
    this.name = 'ConstraintError';
  }
}

const isObject = (v: unknown): v is JSONObject =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

const isNumber = (v: unknown): v is number =>
  typeof v === 'number' && Number.isFinite(v);

const isCount = (v: unknown): v is number =>
  isNumber(v) && Number.isInteger(v) && v >= 0;

const NUMBER_KEYWORDS = [
  'minimum',
  'maximum',
  'exclusiveMinimum',
  'exclusiveMaximum',
] as const;
const COUNT_KEYWORDS = [
  'minLength',
  'maxLength',
  'minItems',
  'maxItems',
] as const;

/** Parses one constraint object, throwing on unknown keywords and wrong types. */
export function parseConstraint(json: unknown): Constraint {
  if (!isObject(json)) {
    throw new Error(
      `A constraint must be a JSON object, got ${JSON.stringify(json)}`,
    );
  }

  const out: Constraint = {};

  for (const [keyword, v] of Object.entries(json)) {
    if ((NUMBER_KEYWORDS as readonly string[]).includes(keyword)) {
      if (!isNumber(v)) {
        throw new Error(
          `Constraint \`${keyword}\` must be a number, got ${JSON.stringify(v)}`,
        );
      }

      out[keyword as (typeof NUMBER_KEYWORDS)[number]] = v;
    } else if ((COUNT_KEYWORDS as readonly string[]).includes(keyword)) {
      if (!isCount(v)) {
        throw new Error(
          `Constraint \`${keyword}\` must be a non-negative integer, got ${JSON.stringify(v)}`,
        );
      }

      out[keyword as (typeof COUNT_KEYWORDS)[number]] = v;
    } else if (keyword === 'enum') {
      if (!Array.isArray(v)) {
        throw new Error(
          `Constraint \`enum\` must be an array, got ${JSON.stringify(v)}`,
        );
      }

      out.enum = v;
    } else if (keyword === 'pattern') {
      if (typeof v !== 'string') {
        throw new Error(
          `Constraint \`pattern\` must be a string, got ${JSON.stringify(v)}`,
        );
      }

      try {
        out.pattern = new RegExp(v);
      } catch (e) {
        throw new Error(
          `Constraint \`pattern\` is not a valid regex: ${(e as Error).message}`,
        );
      }
    } else if (keyword === 'class') {
      if (typeof v !== 'string') {
        throw new Error(
          `Constraint \`class\` must be a string, got ${JSON.stringify(v)}`,
        );
      }

      out.class = canonicalizeScheme(v);
    } else {
      throw new Error(
        `Unknown constraint keyword \`${keyword}\`. Allowed: ${CONSTRAINT_KEYWORDS.join(', ')}`,
      );
    }
  }

  return out;
}

/**
 * Parses a whole `constraints` map (an object, or its JSON string). Property
 * keys are canonicalized (`did:ad:` becomes `atomic:`).
 */
export function parseConstraints(json: unknown): Constraints {
  const parsed =
    typeof json === 'string' ? (JSON.parse(json) as unknown) : json;

  if (!isObject(parsed)) {
    throw new Error(
      `\`constraints\` must be a JSON object, got ${JSON.stringify(parsed)}`,
    );
  }

  const out: Constraints = new Map();

  for (const [prop, constraint] of Object.entries(parsed)) {
    try {
      out.set(canonicalizeScheme(prop), parseConstraint(constraint));
    } catch (e) {
      throw new Error(
        `Invalid constraint for ${prop}: ${(e as Error).message}`,
      );
    }
  }

  return out;
}

const canonical = (v: unknown): unknown =>
  typeof v === 'string' ? canonicalizeScheme(v) : v;

const jsonEq = (a: unknown, b: unknown): boolean =>
  JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));

/** Unwraps `{ '@id': subject }` list items so arrays of links compare as subjects. */
const plain = (v: unknown): unknown =>
  isObject(v) && typeof v['@id'] === 'string' ? v['@id'] : v;

/**
 * Checks a value, throwing a {@link ConstraintError}. A keyword that does not
 * apply to the value's type is ignored, as in JSON Schema. For an array,
 * `enum` applies to every item.
 */
export function checkValue(c: Constraint, rawValue: unknown): void {
  const value = Array.isArray(rawValue) ? rawValue.map(plain) : plain(rawValue);

  if (c.enum) {
    const allowed = c.enum;
    const items = Array.isArray(value) ? value : [value];

    for (const item of items) {
      if (!allowed.some(a => jsonEq(a, item))) {
        throw new ConstraintError(
          'enum',
          `${JSON.stringify(item)} is not one of ${JSON.stringify(allowed)}`,
        );
      }
    }
  }

  if (isNumber(value)) {
    if (c.minimum !== undefined && value < c.minimum) {
      throw new ConstraintError('minimum', `${value} is below ${c.minimum}`);
    }

    if (c.maximum !== undefined && value > c.maximum) {
      throw new ConstraintError('maximum', `${value} is above ${c.maximum}`);
    }

    if (c.exclusiveMinimum !== undefined && value <= c.exclusiveMinimum) {
      throw new ConstraintError(
        'exclusiveMinimum',
        `${value} is not above ${c.exclusiveMinimum}`,
      );
    }

    if (c.exclusiveMaximum !== undefined && value >= c.exclusiveMaximum) {
      throw new ConstraintError(
        'exclusiveMaximum',
        `${value} is not below ${c.exclusiveMaximum}`,
      );
    }
  } else if (typeof value === 'string') {
    // Length in Unicode code points, like Rust's `chars().count()`.
    const length = [...value].length;

    if (c.minLength !== undefined && length < c.minLength) {
      throw new ConstraintError(
        'minLength',
        `length ${length} is below ${c.minLength}`,
      );
    }

    if (c.maxLength !== undefined && length > c.maxLength) {
      throw new ConstraintError(
        'maxLength',
        `length ${length} is above ${c.maxLength}`,
      );
    }

    if (c.pattern && !c.pattern.test(value)) {
      throw new ConstraintError(
        'pattern',
        `${JSON.stringify(value)} does not match ${c.pattern.source}`,
      );
    }
  } else if (Array.isArray(value)) {
    if (c.minItems !== undefined && value.length < c.minItems) {
      throw new ConstraintError(
        'minItems',
        `${value.length} items is below ${c.minItems}`,
      );
    }

    if (c.maxItems !== undefined && value.length > c.maxItems) {
      throw new ConstraintError(
        'maxItems',
        `${value.length} items is above ${c.maxItems}`,
      );
    }
  }
}

/** The subset of a Resource that {@link checkResourceConstraints} reads. */
interface ConstraintResource {
  subject: string;
  getClasses(): string[];
  get(prop: string): unknown;
}

/**
 * Checks every value of `resource` against the constraints of each of its
 * classes that is already in the local store. Classes that are not loaded are
 * skipped, never fetched; so is a class whose map does not parse (the server
 * rejects those when the class is written).
 *
 * Throws `Value for <shortname> breaks <keyword> on class <class>: <detail>`.
 */
export function checkResourceConstraints(
  resource: ConstraintResource,
  getLocal: (subject: string) => ConstraintResource | undefined,
): void {
  for (const classSubject of resource.getClasses()) {
    const klass = getLocal(classSubject);
    const raw = klass?.get('https://atomicdata.dev/properties/constraints');

    if (!klass || raw === undefined) continue;

    let constraints: Constraints;

    try {
      constraints = parseConstraints(raw);
    } catch {
      continue;
    }

    for (const [prop, constraint] of constraints) {
      const value = resource.get(prop) ?? resource.get(toLegacyScheme(prop));

      if (value === undefined) continue;

      try {
        checkValue(constraint, value);
      } catch (e) {
        if (!(e instanceof ConstraintError)) throw e;

        const shortname = shortnameOf(prop, getLocal);
        const className = String(
          klass.get('https://atomicdata.dev/properties/shortname') ??
            classSubject,
        );

        throw new Error(
          `Value for ${shortname} breaks ${e.keyword} on class ${className}: ${e.detail}`,
        );
      }
    }
  }
}

function shortnameOf(
  prop: string,
  getLocal: (subject: string) => ConstraintResource | undefined,
): string {
  const short = getLocal(prop)?.get(
    'https://atomicdata.dev/properties/shortname',
  );

  return typeof short === 'string' ? short : prop;
}
