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
  'const',
  'type',
  'properties',
  'required',
  'additionalProperties',
  'items',
  'anyOf',
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

/** How deep schemas may nest. A constraint nested deeper is rejected. */
export const MAX_DEPTH = 16;

/** The JSON Schema `type` names a constraint accepts. */
export const CONSTRAINT_TYPES = [
  'string',
  'number',
  'integer',
  'boolean',
  'null',
  'object',
  'array',
] as const;

export type ConstraintType = (typeof CONSTRAINT_TYPES)[number];

const TYPES: readonly string[] = CONSTRAINT_TYPES;

/**
 * A constraint. Below the top level the same shape describes a nested JSON
 * Schema (`properties`, `items`, `anyOf`).
 */
export interface Constraint {
  enum?: JSONValue[];
  const?: JSONValue;
  /** Allowed JSON types, any of them. `null` makes a value nullable. */
  type?: ConstraintType[];
  properties?: Record<string, Constraint>;
  required?: string[];
  /** `false` forbids unlisted keys, a schema checks them, `true` changes nothing. */
  additionalProperties?: boolean | Constraint;
  items?: Constraint;
  anyOf?: Constraint[];
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
    public readonly keyword: ConstraintKeyword | 'depth',
    public readonly detail: string,
    /** JSON pointer to the failing value: empty for the value itself, `/pad/tune` for a nested one. */
    public readonly path: string = '',
  ) {
    super(path ? `${keyword} at ${path}: ${detail}` : `${keyword}: ${detail}`);
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
  return parseAt(json, 0);
}

function parseNested(
  keyword: string,
  key: string,
  v: unknown,
  depth: number,
): Constraint {
  try {
    return parseAt(v, depth + 1);
  } catch (e) {
    throw new Error(`in \`${keyword}\`${key}: ${(e as Error).message}`);
  }
}

function parseAt(json: unknown, depth: number): Constraint {
  if (depth > MAX_DEPTH) {
    throw new Error(`Constraints nest deeper than ${MAX_DEPTH} levels`);
  }

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
    } else if (keyword === 'const') {
      out.const = v;
    } else if (keyword === 'type') {
      const names = Array.isArray(v) ? v : [v];
      const types: ConstraintType[] = [];

      for (const name of names) {
        if (!(TYPES as readonly unknown[]).includes(name)) {
          throw new Error(
            `Constraint \`type\` must be one of ${TYPES.join(', ')} or an array of them, got ${JSON.stringify(v)}`,
          );
        }

        if (!types.includes(name as ConstraintType)) {
          types.push(name as ConstraintType);
        }
      }

      if (types.length === 0) {
        throw new Error('Constraint `type` cannot be an empty array');
      }

      out.type = types;
    } else if (keyword === 'properties') {
      if (!isObject(v)) {
        throw new Error(
          `Constraint \`properties\` must be an object, got ${JSON.stringify(v)}`,
        );
      }

      const props: Record<string, Constraint> = {};

      for (const [name, schema] of Object.entries(v)) {
        props[name] = parseNested(
          'properties',
          ` for "${name}"`,
          schema,
          depth,
        );
      }

      out.properties = props;
    } else if (keyword === 'required') {
      if (!Array.isArray(v) || !v.every(n => typeof n === 'string')) {
        throw new Error(
          `Constraint \`required\` must be an array of strings, got ${JSON.stringify(v)}`,
        );
      }

      out.required = v as string[];
    } else if (keyword === 'additionalProperties') {
      if (typeof v === 'boolean') {
        out.additionalProperties = v;
      } else if (isObject(v)) {
        out.additionalProperties = parseNested(
          'additionalProperties',
          '',
          v,
          depth,
        );
      } else {
        throw new Error(
          `Constraint \`additionalProperties\` must be a boolean or a schema, got ${JSON.stringify(v)}`,
        );
      }
    } else if (keyword === 'items') {
      out.items = parseNested('items', '', v, depth);
    } else if (keyword === 'anyOf') {
      if (!Array.isArray(v) || v.length === 0) {
        throw new Error(
          `Constraint \`anyOf\` must be a non-empty array, got ${JSON.stringify(v)}`,
        );
      }

      out.anyOf = v.map(branch => parseNested('anyOf', '', branch, depth));
    } else if (keyword === 'class') {
      if (depth > 0) {
        throw new Error(
          'Constraint `class` only applies to a property, not inside a nested schema',
        );
      }

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

const jsonEq = (a: unknown, b: unknown): boolean => {
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => jsonEq(x, b[i]));
  }

  if (isObject(a) && isObject(b)) {
    const keys = Object.keys(a);

    return (
      keys.length === Object.keys(b).length &&
      keys.every(k => k in b && jsonEq(a[k], b[k]))
    );
  }

  return JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
};

const pointerOf = (path: string[]): string =>
  path.map(s => `/${s.replaceAll('~', '~0').replaceAll('/', '~1')}`).join('');

const typeMatches = (name: ConstraintType, v: unknown): boolean => {
  switch (name) {
    case 'string':
      return typeof v === 'string';
    case 'boolean':
      return typeof v === 'boolean';
    case 'null':
      return v === null;
    case 'object':
      return isObject(v);
    case 'array':
      return Array.isArray(v);
    case 'number':
      return isNumber(v);
    case 'integer':
      return isNumber(v) && Number.isInteger(v);
  }
};

const typeNameOf = (v: unknown): string =>
  v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v;

/**
 * Unwraps `{ '@id': subject }` list items so arrays of links compare as
 * subjects. Only a bare link is unwrapped: an object with more keys is data (a
 * nested resource, or JSON that happens to have an `@id` key) and is checked as
 * an object, as `atomic_lib` does.
 */
const plain = (v: unknown): unknown =>
  isObject(v) && typeof v['@id'] === 'string' && Object.keys(v).length === 1
    ? v['@id']
    : v;

/**
 * Checks a value, throwing a {@link ConstraintError}. A keyword that does not
 * apply to the value's type is ignored, as in JSON Schema. For a top-level
 * array, `enum` applies to every item; below the top level it applies to the
 * value as a whole, as in JSON Schema. Nested schemas (`properties`, `items`,
 * `anyOf`) are checked recursively and the error carries the JSON pointer of
 * the failing value.
 */
export function checkValue(c: Constraint, rawValue: unknown): void {
  const value = Array.isArray(rawValue) ? rawValue.map(plain) : plain(rawValue);

  checkAt(c, value, [], 0);
}

function checkAt(
  c: Constraint,
  value: unknown,
  path: string[],
  depth: number,
): void {
  const fail = (
    keyword: ConstraintError['keyword'],
    detail: string,
    at: string[] = path,
  ): never => {
    throw new ConstraintError(keyword, detail, pointerOf(at));
  };

  if (depth > MAX_DEPTH) {
    fail('depth', `constraints nest deeper than ${MAX_DEPTH} levels`);
  }

  if (c.enum) {
    const allowed = c.enum;
    const items = Array.isArray(value) && depth === 0 ? value : [value];

    for (const item of items) {
      if (!allowed.some(a => jsonEq(a, item))) {
        fail(
          'enum',
          `${JSON.stringify(item)} is not one of ${JSON.stringify(allowed)}`,
        );
      }
    }
  }

  if (c.const !== undefined && !jsonEq(c.const, value)) {
    fail('const', `${JSON.stringify(value)} is not ${JSON.stringify(c.const)}`);
  }

  if (c.type && !c.type.some(t => typeMatches(t, value))) {
    fail('type', `${typeNameOf(value)} is not of type ${c.type.join(' or ')}`);
  }

  if (isNumber(value)) {
    if (c.minimum !== undefined && value < c.minimum) {
      fail('minimum', `${value} is below ${c.minimum}`);
    }

    if (c.maximum !== undefined && value > c.maximum) {
      fail('maximum', `${value} is above ${c.maximum}`);
    }

    if (c.exclusiveMinimum !== undefined && value <= c.exclusiveMinimum) {
      fail('exclusiveMinimum', `${value} is not above ${c.exclusiveMinimum}`);
    }

    if (c.exclusiveMaximum !== undefined && value >= c.exclusiveMaximum) {
      fail('exclusiveMaximum', `${value} is not below ${c.exclusiveMaximum}`);
    }
  } else if (typeof value === 'string') {
    // Length in Unicode code points, like Rust's `chars().count()`.
    const length = [...value].length;

    if (c.minLength !== undefined && length < c.minLength) {
      fail('minLength', `length ${length} is below ${c.minLength}`);
    }

    if (c.maxLength !== undefined && length > c.maxLength) {
      fail('maxLength', `length ${length} is above ${c.maxLength}`);
    }

    if (c.pattern && !c.pattern.test(value)) {
      fail(
        'pattern',
        `${JSON.stringify(value)} does not match ${c.pattern.source}`,
      );
    }
  } else if (Array.isArray(value)) {
    if (c.minItems !== undefined && value.length < c.minItems) {
      fail('minItems', `${value.length} items is below ${c.minItems}`);
    }

    if (c.maxItems !== undefined && value.length > c.maxItems) {
      fail('maxItems', `${value.length} items is above ${c.maxItems}`);
    }

    if (c.items) {
      value.forEach((item, i) =>
        checkAt(c.items!, item, [...path, String(i)], depth + 1),
      );
    }
  } else if (isObject(value)) {
    for (const name of c.required ?? []) {
      if (!Object.hasOwn(value, name))
        fail('required', `missing property ${JSON.stringify(name)}`);
    }

    for (const key of Object.keys(value).sort()) {
      const listed =
        c.properties && Object.hasOwn(c.properties, key)
          ? c.properties[key]
          : undefined;
      const extra = c.additionalProperties;
      let schema: Constraint | undefined = listed;

      if (!listed && extra === false) {
        fail('additionalProperties', 'property is not allowed', [...path, key]);
      } else if (!listed && isObject(extra)) {
        schema = extra as Constraint;
      }

      if (schema) checkAt(schema, value[key], [...path, key], depth + 1);
    }
  }

  if (c.anyOf) {
    const reasons: string[] = [];

    for (const branch of c.anyOf) {
      try {
        checkAt(branch, value, path, depth + 1);

        return;
      } catch (e) {
        if (!(e instanceof ConstraintError)) throw e;

        reasons.push(e.message);
      }
    }

    fail(
      'anyOf',
      `matches none of ${c.anyOf.length} alternatives (${reasons.join('; ')})`,
    );
  }
}

/** The subset of a Resource that {@link checkResourceConstraints} reads. */
interface ConstraintResource {
  subject: string;
  getClasses(): string[];
  get(prop: string): unknown;
}

/** One value that breaks a constraint of one of its resource's classes. */
export interface ConstraintViolation {
  /** Subject of the class whose `constraints` map holds the broken rule. */
  classSubject: string;
  /** Shortname of that class, or its subject when it has none. */
  className: string;
  /** The constrained property, as written in the class's `constraints`. */
  property: string;
  /** Shortname of the property, or its subject when it has none. */
  propertyName: string;
  /** The keyword that failed. */
  keyword: ConstraintError['keyword'];
  /** JSON pointer inside the property's value; empty for the value itself. */
  path: string;
  detail: string;
  /** `Value for <shortname> breaks <keyword> on class <class>[ at <path>]: <detail>` */
  message: string;
}

/**
 * Collects every violation of the constraints of each class of `resource`,
 * across all classes and all constrained properties. Per property only the
 * first failure is reported (a nested value is not walked for further failing
 * leaves). Rust twin: `class_constraints::violations`.
 *
 * `getLocal` returns a resource from the local store, or `undefined`. A class
 * it does not return, or whose `constraints` map does not parse (the server
 * rejects those when the class is written), is skipped and yields no
 * violations; classes are never fetched.
 *
 * Sync never runs these checks, so use this to find resources that arrived
 * from peers and break their classes.
 */
export function constraintViolations(
  getLocal: (subject: string) => ConstraintResource | undefined,
  resource: ConstraintResource,
): ConstraintViolation[] {
  const found: ConstraintViolation[] = [];

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

        const propertyName = shortnameOf(prop, getLocal);
        const className = String(
          klass.get('https://atomicdata.dev/properties/shortname') ??
            classSubject,
        );
        const at = e.path ? ` at ${e.path}` : '';

        found.push({
          classSubject,
          className,
          property: prop,
          propertyName,
          keyword: e.keyword,
          path: e.path,
          detail: e.detail,
          message: `Value for ${propertyName} breaks ${e.keyword} on class ${className}${at}: ${e.detail}`,
        });
      }
    }
  }

  return found;
}

/**
 * Checks every value of `resource` against the constraints of each of its
 * classes that is already in the local store, throwing the first violation of
 * {@link constraintViolations}. Classes that are not loaded are skipped, never
 * fetched; so is a class whose map does not parse.
 *
 * Throws `Value for <shortname> breaks <keyword> on class <class>: <detail>`.
 */
export function checkResourceConstraints(
  resource: ConstraintResource,
  getLocal: (subject: string) => ConstraintResource | undefined,
): void {
  const [first] = constraintViolations(getLocal, resource);

  if (first) throw new Error(first.message);
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
