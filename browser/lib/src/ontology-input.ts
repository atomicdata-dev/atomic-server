import { Datatype } from './datatypes.js';
import { parseConstraint } from './class-constraints.js';
import type { JSONValue } from './value.js';

/**
 * The description of an Ontology that {@link ensureOntology} makes real, and
 * that `ontologyFromJsonSchema` produces. The Rust twin is `OntologyPlan` in
 * `lib/src/schema/json_schema.rs`. See `docs/src/schema/json-schema.md`.
 */

/** JSON Schema keywords for one property of one class, see `class-constraints.ts`. */
export type ConstraintInput = Record<string, JSONValue>;

export interface OntologyPropertyInput {
  /** Slug. With the ontology and the datatype it is the property's identity. */
  shortname: string;
  /** A Datatype subject. */
  datatype: Datatype | string;
  name?: string;
  description?: string;
  /** Legacy hint for pickers. Prefer a `class` constraint on the class. */
  classtype?: string;
}

export interface OntologyClassInput {
  shortname: string;
  name?: string;
  description?: string;
  /**
   * Properties this class uses, declared in place. Equal declarations (same
   * shortname and datatype) in several classes are one Property. Properties
   * listed here but in neither `requires` nor `recommends` are recommended.
   */
  properties?: OntologyPropertyInput[];
  /** Shortnames. JSON Schema `required`. */
  requires?: string[];
  /** Shortnames. */
  recommends?: string[];
  /**
   * Property shortname to constraint keywords. A `class` keyword that holds a
   * bare shortname (no `:`) names a class of this ontology.
   * `undefined` leaves the class's constraints alone, `{}` clears them.
   */
  constraints?: Record<string, ConstraintInput>;
}

export interface OntologyInput {
  shortname: string;
  name?: string;
  description?: string;
  /** Properties that no single class owns. Optional. */
  properties?: OntologyPropertyInput[];
  classes: OntologyClassInput[];
}

/** What {@link planOntology} makes of an {@link OntologyInput}. */
export interface OntologyPlan {
  properties: Array<{
    shortname: string;
    name: string;
    description: string;
    datatype: Datatype;
    classtype?: string;
  }>;
  classes: Array<{
    shortname: string;
    name: string;
    description: string;
    requires: string[];
    recommends: string[];
  }>;
  /** Class shortname to property shortname to keywords. Absent: not managed. */
  constraints: Record<string, Record<string, ConstraintInput> | undefined>;
}

export const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

const isAsciiAlnum = (c: string): boolean => /^[A-Za-z0-9]$/.test(c);
const isUpper = (c: string | undefined): boolean =>
  c !== undefined && /^[A-Z]$/.test(c);
const isLowerOrDigit = (c: string | undefined): boolean =>
  c !== undefined && /^[a-z0-9]$/.test(c);

/**
 * `LineItem`, `line_item` and `line item` all become `line-item`. Anything that
 * is not an ASCII letter or digit separates words. Undefined when nothing is
 * left. The Rust twin is `slugify` in `lib/src/schema/json_schema.rs`.
 */
export function slugify(raw: string): string | undefined {
  const chars = [...raw];
  let out = '';
  let prev: string | undefined;

  chars.forEach((c, i) => {
    if (isAsciiAlnum(c)) {
      const next = chars[i + 1];
      const boundary =
        isUpper(c) &&
        (isLowerOrDigit(prev) || (isUpper(prev) && /^[a-z]$/.test(next ?? '')));

      if (boundary && out !== '' && !out.endsWith('-')) out += '-';

      out += c.toLowerCase();
      prev = c;
    } else {
      if (out !== '' && !out.endsWith('-')) out += '-';

      prev = undefined;
    }
  });

  while (out.endsWith('-')) out = out.slice(0, -1);

  return out === '' ? undefined : out;
}

const validDatatypes = new Set<string>(
  Object.values(Datatype).filter(d => d !== Datatype.UNKNOWN),
);

export const isKnownDatatype = (datatype: string): boolean =>
  validDatatypes.has(datatype);

const unique = (names: string[]): string[] => [...new Set(names)];

/**
 * Checks an ontology description and normalises it: one entry per property
 * (identified by shortname), defaults for names and descriptions, and every
 * class's `requires` and `recommends` complete. Throws on anything that could
 * not be made real, before anything is written.
 */
export function planOntology(input: OntologyInput): OntologyPlan {
  const properties = new Map<string, OntologyPlan['properties'][number]>();

  const declare = (property: OntologyPropertyInput, where: string): void => {
    if (!SLUG_RE.test(property.shortname)) {
      throw new Error(
        `${where}: invalid property shortname '${property.shortname}'`,
      );
    }

    if (!isKnownDatatype(property.datatype)) {
      throw new Error(
        `${where}: unknown datatype '${property.datatype}' for property '${property.shortname}'`,
      );
    }

    const previous = properties.get(property.shortname);

    if (previous) {
      if (previous.datatype !== property.datatype) {
        throw new Error(
          `${where}: property '${property.shortname}' is declared as ${property.datatype} but elsewhere as ${previous.datatype}. A property is identified by its shortname and datatype, and an ontology cannot hold two properties with one shortname`,
        );
      }

      return;
    }

    const name = property.name ?? property.shortname;

    properties.set(property.shortname, {
      shortname: property.shortname,
      name,
      description: property.description ?? name,
      datatype: property.datatype as Datatype,
      ...(property.classtype ? { classtype: property.classtype } : {}),
    });
  };

  for (const property of input.properties ?? []) declare(property, 'ontology');

  const classNames = new Set<string>();

  for (const klass of input.classes) {
    if (!klass.shortname) throw new Error('every class needs a shortname');

    if (classNames.has(klass.shortname)) {
      throw new Error(`duplicate class shortname '${klass.shortname}'`);
    }

    classNames.add(klass.shortname);

    for (const property of klass.properties ?? []) {
      declare(property, `class '${klass.shortname}'`);
    }
  }

  const classes: OntologyPlan['classes'] = [];
  const constraints: OntologyPlan['constraints'] = {};

  for (const klass of input.classes) {
    const where = `class '${klass.shortname}'`;
    const requires = unique(klass.requires ?? []);
    const explicit = unique(klass.recommends ?? []);
    const declared = (klass.properties ?? []).map(p => p.shortname);

    for (const name of [...requires, ...explicit]) {
      if (!properties.has(name)) {
        throw new Error(`${where}: '${name}' is not a declared property`);
      }
    }

    for (const name of requires) {
      if (explicit.includes(name)) {
        throw new Error(`${where}: '${name}' is both required and recommended`);
      }
    }

    const recommends = unique([
      ...explicit,
      ...declared.filter(name => !requires.includes(name)),
    ]);

    const name = klass.name ?? klass.shortname;

    classes.push({
      shortname: klass.shortname,
      name,
      description: klass.description ?? name,
      requires,
      recommends,
    });

    if (klass.constraints === undefined) continue;

    const own: Record<string, ConstraintInput> = {};

    for (const [property, keywords] of Object.entries(klass.constraints)) {
      if (![...requires, ...recommends].includes(property)) {
        throw new Error(
          `${where}: constraint on '${property}', which the class neither requires nor recommends`,
        );
      }

      try {
        parseConstraint(keywords);
      } catch (e) {
        throw new Error(
          `${where}: constraint on '${property}': ${(e as Error).message}`,
        );
      }

      const target = keywords.class;

      if (
        typeof target === 'string' &&
        !target.includes(':') &&
        !classNames.has(target)
      ) {
        throw new Error(
          `${where}: constraint on '${property}' names class '${target}', which is not in this ontology`,
        );
      }

      own[property] = keywords;
    }

    constraints[klass.shortname] = own;
  }

  return { properties: [...properties.values()], classes, constraints };
}

/** JSON with sorted keys, to compare two JSON values for equality. */
export const sortedJson = (value: unknown): string =>
  JSON.stringify(value, (_key, v: unknown) =>
    v && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(
          Object.entries(v as Record<string, unknown>).sort(([a], [b]) =>
            a < b ? -1 : a > b ? 1 : 0,
          ),
        )
      : v,
  );

/** The `constraints` value of a class resource as plain JSON. It may be stored as a JSON string. */
export function readConstraintsValue(value: unknown): unknown {
  if (typeof value !== 'string') return value;

  try {
    return JSON.parse(value) as unknown;
  } catch {
    return value;
  }
}
