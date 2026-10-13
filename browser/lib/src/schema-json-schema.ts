import { Datatype } from './datatypes.js';
import {
  CONSTRAINT_TYPES,
  MAX_DEPTH,
  parseConstraint,
  parseConstraints,
} from './class-constraints.js';
import { core } from './ontologies/core.js';
import { canonicalizeScheme } from './subject.js';
import {
  isKnownDatatype,
  readConstraintsValue,
  slugify,
  type ConstraintInput,
  type OntologyClassInput,
  type OntologyInput,
  type OntologyPropertyInput,
} from './ontology-input.js';
import type { SchemaStore } from './plugin-schema.js';
import type { JSONObject, JSONValue } from './value.js';

/**
 * JSON Schema (draft 2020-12) in and out of an Atomic ontology. The Rust twin
 * is `lib/src/schema/json_schema.rs`; both run
 * `lib/tests/fixtures/json-schema-interop.json`, so change them together.
 * See `docs/src/schema/json-schema.md`.
 *
 * Import is strict: a construct Atomic cannot express is an error naming its
 * JSON pointer, never silently dropped.
 */

export const JSON_SCHEMA_DIALECT =
  'https://json-schema.org/draft/2020-12/schema';

export interface JsonSchemaImportOptions {
  /** The ontology's shortname. Defaults to `x-atomic-ontology`, then the slugified `title`. */
  shortname?: string;
}

type Obj = Record<string, unknown>;

/** Annotations that change no validation result. Read and dropped. */
const ANNOTATIONS = [
  '$comment',
  'examples',
  'default',
  'deprecated',
  'readOnly',
  'writeOnly',
];

/** Atomic identity, written on export for readers. Never trusted on import: identity is derived. */
const INFORMATIONAL = ['x-atomic-subject', 'x-atomic-property'];

const CONSTRAINT_PASSTHROUGH = [
  'minimum',
  'maximum',
  'exclusiveMinimum',
  'exclusiveMaximum',
  'minLength',
  'maxLength',
  'minItems',
  'maxItems',
  'pattern',
];

const ROOT_KEYS = new Set([
  '$schema',
  '$id',
  '$defs',
  'title',
  'description',
  'type',
  'properties',
  'required',
  'additionalProperties',
  'x-atomic-ontology',
  ...ANNOTATIONS,
  ...INFORMATIONAL,
]);

const CLASS_KEYS = new Set([
  'type',
  'title',
  'description',
  'properties',
  'required',
  'additionalProperties',
  ...ANNOTATIONS,
  ...INFORMATIONAL,
]);

const PROPERTY_KEYS = new Set([
  'type',
  'format',
  'enum',
  'const',
  'items',
  '$ref',
  'title',
  'description',
  'x-atomic-datatype',
  'x-atomic-class',
  'properties',
  'required',
  'additionalProperties',
  'anyOf',
  ...CONSTRAINT_PASSTHROUGH,
  ...ANNOTATIONS,
  ...INFORMATIONAL,
]);

/** Keywords of a schema nested inside a json value (below a property). */
const NESTED_SCHEMA_KEYS = new Set([
  'type',
  'title',
  'description',
  'enum',
  'const',
  'properties',
  'required',
  'additionalProperties',
  'items',
  'anyOf',
  ...CONSTRAINT_PASSTHROUGH,
  ...ANNOTATIONS,
  ...INFORMATIONAL,
]);

/** Keywords that make a schema a nested one, stored whole in the class constraints. */
const NESTED_KEYWORDS = [
  'properties',
  'required',
  'additionalProperties',
  'items',
  'anyOf',
];

const SCHEMA_TYPES: readonly string[] = CONSTRAINT_TYPES;

const REF_KEYS = new Set([
  '$ref',
  'title',
  'description',
  'enum',
  'const',
  ...ANNOTATIONS,
  ...INFORMATIONAL,
]);

const ITEM_KEYS = new Set([
  'type',
  'format',
  '$ref',
  'enum',
  'const',
  'x-atomic-class',
]);

const escapePointer = (key: string): string =>
  key.replaceAll('~', '~0').replaceAll('/', '~1');

const child = (pointer: string, ...keys: Array<string | number>): string =>
  pointer + keys.map(k => `/${escapePointer(String(k))}`).join('');

function fail(pointer: string, message: string): never {
  throw new Error(`JSON Schema at ${pointer || '/'}: ${message}`);
}

function asObject(value: unknown, pointer: string): Obj {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail(pointer, 'expected a schema object (boolean schemas are unsupported)');
  }

  return value as Obj;
}

function checkKeys(schema: Obj, pointer: string, allowed: Set<string>): void {
  for (const key of Object.keys(schema)) {
    if (allowed.has(key)) continue;

    const extension = key.startsWith('x-')
      ? 'unknown extension keyword'
      : 'unsupported keyword';

    fail(
      child(pointer, key),
      `${extension} '${key}'. Atomic classes cannot express it, so it is rejected instead of dropped`,
    );
  }
}

function optionalString(
  schema: Obj,
  key: string,
  pointer: string,
): string | undefined {
  const value = schema[key];

  if (value === undefined) return undefined;

  if (typeof value !== 'string') fail(child(pointer, key), 'expected a string');

  return value;
}

interface ImportContext {
  /** `$defs` key to the shortname of its class. */
  classes: Map<string, string>;
}

function resolveRef(ref: unknown, pointer: string, ctx: ImportContext): string {
  if (typeof ref !== 'string') fail(pointer, '$ref must be a string');

  const match = /^#\/\$defs\/([^/]+)$/.exec(ref);

  if (!match) {
    fail(
      pointer,
      `only local '#/$defs/Name' references are supported, got '${ref}'`,
    );
  }

  const key = match[1].replaceAll('~1', '/').replaceAll('~0', '~');
  const target = ctx.classes.get(key);

  if (target === undefined) {
    fail(pointer, `'${ref}' does not name an object schema in $defs`);
  }

  return target;
}

interface ReadProperty {
  datatype: string;
  name?: string;
  description?: string;
  constraint: ConstraintInput;
}

/** Datatype from a bare `enum` or `const`, the way a JSON Schema author means it. */
function datatypeOfValues(values: unknown[], pointer: string): string {
  if (values.every(v => typeof v === 'string')) return Datatype.STRING;

  if (values.every(v => typeof v === 'boolean')) return Datatype.BOOLEAN;

  if (values.every(v => Number.isInteger(v))) return Datatype.INTEGER;

  if (values.every(v => typeof v === 'number')) return Datatype.FLOAT;

  return fail(
    pointer,
    'enum values of mixed types need an explicit type or x-atomic-datatype',
  );
}

/** `enum` and `const` as one list, undefined when neither is set. */
function enumOf(schema: Obj, pointer: string): unknown[] | undefined {
  if (schema.enum !== undefined && schema.const !== undefined) {
    fail(pointer, "'enum' and 'const' cannot be combined");
  }

  if (schema.enum !== undefined) {
    if (!Array.isArray(schema.enum)) {
      fail(child(pointer, 'enum'), 'expected an array');
    }

    return schema.enum;
  }

  if ('const' in schema) return [schema.const];

  return undefined;
}

/**
 * Reads the nested keywords of `node` into `out`: `properties`, `required`,
 * `additionalProperties`, `items` and `anyOf`, each validated by pointer.
 * `depth` is the nesting level of `node` itself.
 */
function readNestedKeywords(
  node: Obj,
  pointer: string,
  depth: number,
  withItems: boolean,
  out: Record<string, JSONValue>,
): void {
  if (node.properties !== undefined) {
    const at = child(pointer, 'properties');

    if (!isPlainObject(node.properties)) {
      fail(at, 'expected an object of schemas');
    }

    const read: Record<string, JSONValue> = {};

    for (const [key, value] of Object.entries(node.properties)) {
      read[key] = readNested(value, child(at, key), depth + 1);
    }

    out.properties = read;
  }

  if (node.required !== undefined) {
    const at = child(pointer, 'required');

    if (!Array.isArray(node.required)) {
      fail(at, 'expected an array of property names');
    }

    node.required.forEach((name, index) => {
      if (typeof name !== 'string') {
        fail(child(at, index), 'expected a property name');
      }
    });

    out.required = node.required as JSONValue;
  }

  if (node.additionalProperties !== undefined) {
    out.additionalProperties =
      typeof node.additionalProperties === 'boolean'
        ? node.additionalProperties
        : readNested(
            node.additionalProperties,
            child(pointer, 'additionalProperties'),
            depth + 1,
          );
  }

  if (withItems && node.items !== undefined) {
    out.items = readNested(node.items, child(pointer, 'items'), depth + 1);
  }

  if (node.anyOf !== undefined) {
    const at = child(pointer, 'anyOf');

    if (!Array.isArray(node.anyOf)) fail(at, 'expected an array of schemas');

    if (node.anyOf.length === 0) fail(at, 'anyOf needs at least one schema');

    out.anyOf = node.anyOf.map((branch, index) =>
      readNested(branch, child(at, index), depth + 1),
    );
  }
}

const isPlainObject = (v: unknown): v is Obj =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Reads a schema nested inside a json value into the constraint vocabulary of
 * `class-constraints`. Annotations are dropped; everything Atomic cannot check
 * (`$ref`, `oneOf`, `format`, ...) is refused by JSON pointer.
 */
function readNested(
  schema: unknown,
  pointer: string,
  depth: number,
): Record<string, JSONValue> {
  if (depth > MAX_DEPTH) {
    fail(pointer, `schemas nest deeper than ${MAX_DEPTH} levels`);
  }

  const s = asObject(schema, pointer);

  checkKeys(s, pointer, NESTED_SCHEMA_KEYS);

  const out: Record<string, JSONValue> = {};

  if (s.type !== undefined) {
    const names = Array.isArray(s.type) ? s.type : [s.type];

    if (names.length === 0) {
      fail(
        child(pointer, 'type'),
        'expected a type name or a non-empty array of them',
      );
    }

    for (const name of names) {
      if (typeof name !== 'string' || !SCHEMA_TYPES.includes(name)) {
        fail(
          child(pointer, 'type'),
          `unsupported type ${JSON.stringify(name)}. Supported: ${SCHEMA_TYPES.join(', ')}`,
        );
      }
    }

    out.type = s.type as JSONValue;
  }

  if (s.enum !== undefined && s.const !== undefined) {
    fail(pointer, "'enum' and 'const' cannot be combined");
  }

  if (s.enum !== undefined) {
    if (!Array.isArray(s.enum))
      fail(child(pointer, 'enum'), 'expected an array');

    out.enum = s.enum as JSONValue;
  }

  if (s.const !== undefined) out.const = s.const as JSONValue;

  for (const key of CONSTRAINT_PASSTHROUGH) {
    if (s[key] !== undefined) out[key] = s[key] as JSONValue;
  }

  readNestedKeywords(s, pointer, depth, true, out);

  // The children were checked on their own, so an error is about this node.
  try {
    parseConstraint(out);
  } catch (e) {
    fail(pointer, (e as Error).message);
  }

  return out;
}

/** Whether the `items` schema of an array needs the nested reader. */
function itemsAreNested(items: Obj): boolean {
  return (
    Object.keys(items).some(
      k => NESTED_KEYWORDS.includes(k) || CONSTRAINT_PASSTHROUGH.includes(k),
    ) || Array.isArray(items.type)
  );
}

function readProperty(
  schema: unknown,
  pointer: string,
  ctx: ImportContext,
): ReadProperty {
  const s = asObject(schema, pointer);
  const hasRef = '$ref' in s;

  checkKeys(s, pointer, hasRef ? REF_KEYS : PROPERTY_KEYS);

  const name = optionalString(s, 'title', pointer);
  const description = optionalString(s, 'description', pointer);
  const constraint: Record<string, JSONValue> = {};
  // `type` is a name, or an array of names where "null" makes the value
  // nullable and several other names make it a union.
  const typeList: string[] = [];
  const typeIsArray = Array.isArray(s.type);

  if (Array.isArray(s.type)) {
    for (const typeName of s.type) {
      if (typeof typeName !== 'string' || !SCHEMA_TYPES.includes(typeName)) {
        fail(
          child(pointer, 'type'),
          `unsupported type ${JSON.stringify(typeName)}. Supported: ${SCHEMA_TYPES.join(', ')}`,
        );
      }

      if (!typeList.includes(typeName)) typeList.push(typeName);
    }

    if (typeList.length === 0) {
      fail(child(pointer, 'type'), 'expected at least one type');
    }
  } else if (s.type !== undefined) {
    if (typeof s.type !== 'string') {
      fail(child(pointer, 'type'), 'expected a string');
    }

    typeList.push(s.type);
  }

  const nonNull = typeList.filter(t => t !== 'null');
  const union = nonNull.length > 1;
  const nullable = typeList.length > nonNull.length && nonNull.length > 0;
  const type: string | undefined = union
    ? undefined
    : (nonNull[0] ?? typeList[0]);

  for (const key of ['properties', 'required', 'additionalProperties']) {
    if (key in s && type !== undefined && type !== 'object') {
      fail(child(pointer, key), `'${key}' only applies to objects`);
    }
  }

  let inferred: string | undefined;
  let values: unknown[] | undefined;
  let linkClass: unknown;

  const isArray =
    !union && (type === 'array' || (type === undefined && 'items' in s));
  const nested: Record<string, JSONValue> = {};

  if (hasRef) {
    inferred = Datatype.ATOMIC_URL;
    linkClass = resolveRef(s.$ref, child(pointer, '$ref'), ctx);
    values = enumOf(s, pointer);
  } else if (isArray) {
    if (type !== undefined && type !== 'array') {
      fail(child(pointer, 'type'), "'items' only applies to arrays");
    }

    for (const key of ['enum', 'const']) {
      if (key in s) {
        fail(
          child(pointer, key),
          `'${key}' on an array constrains the whole array. Put it on 'items' to constrain every item`,
        );
      }
    }

    if (s.format !== undefined) {
      fail(child(pointer, 'format'), 'format only applies to strings');
    }

    if ('x-atomic-class' in s) {
      fail(
        child(pointer, 'x-atomic-class'),
        "put 'x-atomic-class' on 'items' for an array",
      );
    }

    inferred = Datatype.JSON;

    if (s.items !== undefined) {
      const itemsPointer = child(pointer, 'items');
      const items = asObject(s.items, itemsPointer);

      if (itemsAreNested(items)) {
        nested.items = readNested(items, itemsPointer, 1);
      } else {
        checkKeys(items, itemsPointer, ITEM_KEYS);
      }

      if (nested.items !== undefined) {
        // Checked by the nested reader; nothing maps to a link here.
      } else if ('$ref' in items) {
        for (const key of Object.keys(items)) {
          if (!['$ref', 'enum', 'const'].includes(key)) {
            fail(child(itemsPointer, key), `not supported next to '$ref'`);
          }
        }

        inferred = Datatype.RESOURCEARRAY;
        linkClass = resolveRef(items.$ref, child(itemsPointer, '$ref'), ctx);
      } else if (items.type === 'string' && items.format === 'uri') {
        inferred = Datatype.RESOURCEARRAY;
        linkClass = items['x-atomic-class'];
      }

      if (nested.items === undefined) values = enumOf(items, itemsPointer);
    }
  } else {
    linkClass = s['x-atomic-class'];
    values = enumOf(s, pointer);

    switch (type) {
      case 'string': {
        const format = s.format;

        if (format === undefined) inferred = Datatype.STRING;
        else if (format === 'date-time') inferred = Datatype.TIMESTAMP;
        else if (format === 'date') inferred = Datatype.DATE;
        else if (format === 'uri') inferred = Datatype.ATOMIC_URL;
        else {
          fail(
            child(pointer, 'format'),
            `unsupported format ${JSON.stringify(format)}. Supported: date-time, date, uri`,
          );
        }

        break;
      }

      case 'integer':
        inferred = Datatype.INTEGER;
        break;
      case 'number':
        inferred = Datatype.FLOAT;
        break;
      case 'boolean':
        inferred = Datatype.BOOLEAN;
        break;
      case 'object':
        inferred = Datatype.JSON;
        break;
      case undefined:
        if (union || 'anyOf' in s) inferred = Datatype.JSON;
        else if (values) inferred = datatypeOfValues(values, pointer);

        break;
      default:
        fail(
          child(pointer, 'type'),
          `unsupported type '${String(type)}'. Supported: string, integer, number, boolean, array, object`,
        );
    }

    if (type !== 'string' && s.format !== undefined) {
      fail(child(pointer, 'format'), 'format only applies to strings');
    }
  }

  for (const key of CONSTRAINT_PASSTHROUGH) {
    if (s[key] !== undefined) constraint[key] = s[key] as JSONValue;
  }

  if (!hasRef) {
    readNestedKeywords(s, pointer, 0, false, nested);
  }

  if (Object.keys(nested).length > 0 || (typeIsArray && (union || nullable))) {
    // The nested schema checks the type too, so keep it next to it.
    if (s.type !== undefined) constraint.type = s.type as JSONValue;

    Object.assign(constraint, nested);
  }

  if (values) constraint.enum = values as JSONValue[];

  if (linkClass !== undefined) {
    if (typeof linkClass !== 'string') {
      fail(child(pointer, 'x-atomic-class'), 'expected a string');
    }

    constraint.class = linkClass;
  }

  try {
    parseConstraint(constraint);
  } catch (e) {
    fail(pointer, (e as Error).message);
  }

  const override = s['x-atomic-datatype'];

  if (override !== undefined) {
    if (typeof override !== 'string' || !isKnownDatatype(override)) {
      fail(
        child(pointer, 'x-atomic-datatype'),
        `unknown Atomic datatype ${JSON.stringify(override)}`,
      );
    }
  }

  const datatype = (override as string | undefined) ?? inferred;

  if (datatype === undefined) {
    fail(
      pointer,
      "cannot tell the datatype: add 'type', '$ref' or 'x-atomic-datatype'",
    );
  }

  return {
    datatype,
    ...(name !== undefined ? { name } : {}),
    ...(description !== undefined ? { description } : {}),
    constraint,
  };
}

interface ClassSource {
  pointer: string;
  schema: Obj;
  shortname: string;
  /** The name when there is no title. */
  key?: string;
}

function readClass(
  source: ClassSource,
  ctx: ImportContext,
  seen: Map<string, { datatype: string; pointer: string }>,
): OntologyClassInput {
  const { pointer, schema } = source;

  if (schema.type !== undefined && schema.type !== 'object') {
    fail(child(pointer, 'type'), 'a class must be an object schema');
  }

  const additional = schema.additionalProperties;

  if (additional !== undefined && typeof additional !== 'boolean') {
    fail(
      child(pointer, 'additionalProperties'),
      'only a boolean is supported. Atomic classes are open and never reject extra properties',
    );
  }

  const title = optionalString(schema, 'title', pointer);
  const description = optionalString(schema, 'description', pointer);
  const props = schema.properties;

  if (props !== undefined) asObject(props, child(pointer, 'properties'));

  const entries = Object.entries((props ?? {}) as Obj);
  const shortnames = new Map<string, string>();
  const properties: OntologyPropertyInput[] = [];
  const constraints: Record<string, ConstraintInput> = {};

  for (const [key, value] of entries) {
    const propPointer = child(pointer, 'properties', key);
    const shortname = slugify(key);

    if (shortname === undefined) {
      fail(propPointer, `cannot turn '${key}' into a shortname`);
    }

    const clash = shortnames.get(shortname);

    if (clash !== undefined) {
      fail(
        propPointer,
        `'${key}' and '${clash}' both become the shortname '${shortname}'`,
      );
    }

    shortnames.set(shortname, key);

    const read = readProperty(value, propPointer, ctx);
    const earlier = seen.get(shortname);

    if (earlier && earlier.datatype !== read.datatype) {
      fail(
        propPointer,
        `'${shortname}' is ${read.datatype} here but ${earlier.datatype} at ${earlier.pointer}. An ontology cannot hold two properties with one shortname, so rename one`,
      );
    }

    if (!earlier)
      seen.set(shortname, { datatype: read.datatype, pointer: propPointer });

    properties.push({
      shortname,
      datatype: read.datatype,
      ...(read.name !== undefined ? { name: read.name } : {}),
      ...(read.description !== undefined
        ? { description: read.description }
        : {}),
    });

    if (Object.keys(read.constraint).length > 0) {
      constraints[shortname] = read.constraint;
    }
  }

  const required = schema.required ?? [];

  if (!Array.isArray(required)) {
    fail(child(pointer, 'required'), 'expected an array of property names');
  }

  const requires: string[] = [];

  required.forEach((key, index) => {
    const at = child(pointer, 'required', index);

    if (typeof key !== 'string') fail(at, 'expected a property name');

    const shortname = slugify(key);

    if (!props || !(key in (props as Obj)) || shortname === undefined) {
      fail(at, `'${key}' is required but not in properties`);
    }

    if (requires.includes(shortname)) fail(at, `'${key}' is listed twice`);

    requires.push(shortname);
  });

  const name = title ?? source.key;

  return {
    shortname: source.shortname,
    ...(name !== undefined ? { name } : {}),
    ...(description !== undefined ? { description } : {}),
    properties,
    requires,
    recommends: properties
      .map(p => p.shortname)
      .filter(shortname => !requires.includes(shortname)),
    constraints,
  };
}

/**
 * Reads a JSON Schema (draft 2020-12) into the input of `ensureOntology`.
 * Every object schema in `$defs` (and the root, when it has `properties`)
 * becomes a class. See `docs/src/schema/json-schema.md` for the mapping.
 *
 * Throws, naming the JSON pointer, for anything that does not map.
 */
export function ontologyFromJsonSchema(
  input: unknown,
  options: JsonSchemaImportOptions = {},
): OntologyInput {
  const root = asObject(input, '');

  checkKeys(root, '', ROOT_KEYS);

  if (root.$schema !== undefined && root.$schema !== JSON_SCHEMA_DIALECT) {
    fail('/$schema', `only ${JSON_SCHEMA_DIALECT} is supported`);
  }

  const title = optionalString(root, 'title', '');
  const description = optionalString(root, 'description', '');
  const declared = optionalString(root, 'x-atomic-ontology', '');
  const shortname =
    options.shortname ?? declared ?? (title ? slugify(title) : undefined);

  if (!shortname) {
    fail(
      '',
      "cannot tell the ontology's shortname: set 'x-atomic-ontology' or 'title', or pass one",
    );
  }

  const defs = root.$defs === undefined ? {} : asObject(root.$defs, '/$defs');
  const sources: ClassSource[] = [];
  const ctx: ImportContext = { classes: new Map() };
  const taken = new Map<string, string>();

  const claim = (name: string, pointer: string): void => {
    const clash = taken.get(name);

    if (clash !== undefined) {
      fail(pointer, `becomes the class shortname '${name}', like ${clash}`);
    }

    taken.set(name, pointer || '/');
  };

  if (root.properties !== undefined) {
    const name = (title ? slugify(title) : undefined) ?? shortname;

    claim(name, '');
    sources.push({ pointer: '', schema: root, shortname: name });
  } else if (root.required !== undefined) {
    fail('/required', 'required names a property, but the root has none');
  }

  for (const [key, def] of Object.entries(defs)) {
    const pointer = child('/$defs', key);
    const schema = asObject(def, pointer);

    if (schema.type !== 'object' && schema.properties === undefined) {
      fail(
        pointer,
        'only object schemas can become classes. Inline other definitions where they are used',
      );
    }

    checkKeys(schema, pointer, CLASS_KEYS);

    const classShortname = slugify(key);

    if (classShortname === undefined) {
      fail(pointer, `cannot turn '${key}' into a class shortname`);
    }

    claim(classShortname, pointer);
    ctx.classes.set(key, classShortname);
    sources.push({ pointer, schema, shortname: classShortname, key });
  }

  const seen = new Map<string, { datatype: string; pointer: string }>();
  const classes = sources.map(source => readClass(source, ctx, seen));

  return {
    shortname,
    ...(title !== undefined ? { name: title } : {}),
    ...(description !== undefined ? { description } : {}),
    classes,
  };
}

/** The identifier-like name a class is given in `$defs`, else its shortname. */
function defKey(name: string | undefined, shortname: string): string {
  return name &&
    /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) &&
    slugify(name) === shortname
    ? name
    : shortname;
}

const asList = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((v): v is string => typeof v === 'string')
    : [];

const asString = (value: unknown): string | undefined =>
  typeof value === 'string' && value !== '' ? value : undefined;

interface LoadedProperty {
  subject: string;
  shortname: string;
  datatype: string;
  name?: string;
  description?: string;
  classtype?: string;
}

interface Linked {
  /** `$defs` key of the class in this ontology, if the target is one. */
  key?: string;
  /** Subject, when the target is not in this ontology. */
  external?: string;
}

function propertySchema(
  property: LoadedProperty,
  constraint: Record<string, JSONValue>,
  link: (target: string | undefined) => Linked,
): JSONObject {
  const keywords: Record<string, JSONValue> = { ...constraint };
  const target = asString(keywords.class) ?? property.classtype;

  delete keywords.class;

  const linked = link(target);
  const schema: JSONObject = {};
  const uri: JSONObject = { type: 'string', format: 'uri' };

  const linkSchema = (): JSONObject =>
    linked.key !== undefined
      ? { $ref: `#/$defs/${escapePointer(linked.key)}` }
      : {
          ...uri,
          ...(linked.external ? { 'x-atomic-class': linked.external } : {}),
        };

  switch (property.datatype) {
    case Datatype.STRING:
      schema.type = 'string';
      break;
    case Datatype.MARKDOWN:
    case Datatype.SLUG:
      schema.type = 'string';
      schema['x-atomic-datatype'] = property.datatype;
      break;
    case Datatype.INTEGER:
      schema.type = 'integer';
      break;
    case Datatype.FLOAT:
      schema.type = 'number';
      break;
    case Datatype.BOOLEAN:
      schema.type = 'boolean';
      break;
    case Datatype.TIMESTAMP:
      schema.type = 'string';
      schema.format = 'date-time';
      break;
    case Datatype.DATE:
      schema.type = 'string';
      schema.format = 'date';
      break;
    case Datatype.ATOMIC_URL:
      Object.assign(schema, linkSchema());
      break;
    case Datatype.URI:
      Object.assign(schema, uri, { 'x-atomic-datatype': property.datatype });
      break;

    case Datatype.RESOURCEARRAY: {
      const items = linkSchema();

      if (keywords.enum !== undefined) {
        items.enum = keywords.enum;
        delete keywords.enum;
      }

      schema.type = 'array';
      schema.items = items;
      break;
    }

    default:
      schema['x-atomic-datatype'] = property.datatype;
  }

  Object.assign(schema, keywords);

  return schema;
}

/**
 * Writes an ontology as a JSON Schema (draft 2020-12): one `$defs` entry per
 * class, its properties keyed by shortname, `required` from `requires`, class
 * constraints as keywords, and a link constraint as a `$ref` to the target's
 * entry. Atomic-only information is written as `x-atomic-*` keywords, and
 * `x-atomic-property` carries each property's subject.
 *
 * Reads through `store.getResource`, so it needs the ontology, its classes and
 * its properties to be loadable.
 */
export async function ontologyToJsonSchema(
  store: Pick<SchemaStore, 'getResource'>,
  ontologySubject: string,
): Promise<JSONObject> {
  const ontology = await store.getResource(ontologySubject);
  const shortname = asString(ontology.get(core.properties.shortname));

  if (!shortname) throw new Error(`${ontologySubject} has no shortname`);

  const name = asString(ontology.get(core.properties.name));
  const description = asString(ontology.get(core.properties.description));

  const classes = await Promise.all(
    asList(ontology.get(core.properties.classes)).map(async subject => {
      const resource = await store.getResource(subject);
      const classShortname = asString(resource.get(core.properties.shortname));

      if (!classShortname) throw new Error(`${subject} has no shortname`);

      const className = asString(resource.get(core.properties.name));
      const raw = readConstraintsValue(
        resource.get(core.properties.constraints),
      );
      const constraints: Record<string, Record<string, JSONValue>> = {};

      if (raw !== undefined) {
        // Validates the whole map; the raw JSON is what gets written out.
        parseConstraints(raw);

        for (const [key, value] of Object.entries(raw as JSONObject)) {
          constraints[canonicalizeScheme(key)] = value as Record<
            string,
            JSONValue
          >;
        }
      }

      return {
        subject: canonicalizeScheme(subject),
        shortname: classShortname,
        name: className,
        description: asString(resource.get(core.properties.description)),
        requires: asList(resource.get(core.properties.requires)),
        recommends: asList(resource.get(core.properties.recommends)),
        constraints,
        key: defKey(className, classShortname),
      };
    }),
  );

  const keys = new Set<string>();

  for (const klass of classes) {
    if (keys.has(klass.key)) {
      throw new Error(`two classes would both be $defs/${klass.key}`);
    }

    keys.add(klass.key);
  }

  const keyBySubject = new Map(classes.map(c => [c.subject, c.key]));
  const loaded = new Map<string, LoadedProperty>();

  const load = async (subject: string): Promise<LoadedProperty> => {
    const canonical = canonicalizeScheme(subject);
    const known = loaded.get(canonical);

    if (known) return known;

    const resource = await store.getResource(subject);
    const propShortname = asString(resource.get(core.properties.shortname));
    const datatype = asString(resource.get(core.properties.datatype));

    if (!propShortname || !datatype) {
      throw new Error(
        `${subject} is not a property with a shortname and datatype`,
      );
    }

    const property: LoadedProperty = {
      subject: canonical,
      shortname: propShortname,
      datatype,
      name: asString(resource.get(core.properties.name)),
      description: asString(resource.get(core.properties.description)),
      classtype: asString(resource.get(core.properties.classtype)),
    };

    loaded.set(canonical, property);

    return property;
  };

  const link = (target: string | undefined): Linked => {
    if (!target) return {};

    const canonical = canonicalizeScheme(target);
    const key = keyBySubject.get(canonical);

    return key !== undefined ? { key } : { external: canonical };
  };

  const defs: JSONObject = {};

  for (const klass of classes) {
    const members = [...klass.requires, ...klass.recommends];
    const properties: JSONObject = {};

    for (const subject of members) {
      const property = await load(subject);
      const schema = propertySchema(
        property,
        klass.constraints[canonicalizeScheme(subject)] ?? {},
        link,
      );

      if (property.name && property.name !== property.shortname) {
        schema.title = property.name;
      }

      if (
        property.description &&
        property.description !== property.name &&
        property.description !== property.shortname
      ) {
        schema.description = property.description;
      }

      schema['x-atomic-property'] = property.subject;
      properties[property.shortname] = schema;
    }

    const required = await Promise.all(
      klass.requires.map(async subject => (await load(subject)).shortname),
    );

    defs[klass.key] = {
      type: 'object',
      ...(klass.name && klass.name !== klass.key ? { title: klass.name } : {}),
      ...(klass.description &&
      klass.description !== klass.name &&
      klass.description !== klass.shortname
        ? { description: klass.description }
        : {}),
      'x-atomic-subject': klass.subject,
      properties,
      ...(required.length > 0 ? { required } : {}),
    };
  }

  return {
    $schema: JSON_SCHEMA_DIALECT,
    ...(name && name !== shortname ? { title: name } : {}),
    ...(description && description !== name && description !== shortname
      ? { description }
      : {}),
    'x-atomic-ontology': shortname,
    'x-atomic-subject': canonicalizeScheme(ontologySubject),
    $defs: defs,
  };
}

/**
 * The JSON Schema of one property as one class sees it: the datatype's schema
 * with the class's constraint written as keywords (`enum` on the items of an
 * array, `class` as the linked class). The same shape
 * {@link ontologyToJsonSchema} writes for a class member, for callers that
 * hold one resolved constraint instead of an ontology (a form's JSON Schema is
 * the class's, narrowed by the form's own options).
 */
export function propertyJsonSchema(
  property: {
    subject: string;
    shortname: string;
    datatype: string;
    name?: string;
    description?: string;
    classtype?: string;
  },
  constraint: Record<string, JSONValue>,
): JSONObject {
  const schema = propertySchema(
    { ...property, subject: canonicalizeScheme(property.subject) },
    constraint,
    target => (target ? { external: canonicalizeScheme(target) } : {}),
  );

  if (property.name && property.name !== property.shortname) {
    schema.title = property.name;
  }

  if (
    property.description &&
    property.description !== property.name &&
    property.description !== property.shortname
  ) {
    schema.description = property.description;
  }

  schema['x-atomic-property'] = canonicalizeScheme(property.subject);

  return schema;
}
