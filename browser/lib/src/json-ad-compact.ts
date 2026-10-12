/**
 * JSON-AD-Compact: the single wire dialect for LLM assistant tool I/O.
 * See planning/json-ad-compact.md for the format spec and rules.
 *
 * Flat like JSON-AD; `@`-prefixed keys are structural (`@id`, `@class`,
 * `@parent`), all other keys are property shortnames resolved against the
 * resource's class schema. Full URLs remain legal keys everywhere (escape
 * hatch). Values follow the property datatype: timestamps as ISO strings,
 * select values as tag shortnames, relations as subjects.
 *
 * Reads are forgiving (unresolvable → full URL key), writes are strict
 * (unknown/ambiguous keys throw, listing candidates). This module is the only
 * place the dialect is implemented — tools and context providers must not
 * hand-roll their own serialization. Compact is never stored.
 */
import { Client } from './client.js';
import { Datatype } from './datatypes.js';
import { core, type Core } from './ontologies/core.js';
import { dataBrowser } from './ontologies/dataBrowser.js';
import { commits } from './ontologies/commits.js';
import type { JSONValue } from './value.js';
import type { Resource } from './resource.js';
import type { Store } from './store.js';
import { getEffectiveConstraint } from './effective-constraint.js';
import { expandSubject, tryExpandRef } from './subject-refs.js';

export interface CompactPropertyInfo {
  subject: string;
  shortname: string;
  /** Display name (title), when it differs from the shortname. */
  name?: string;
  datatype: string;
  classtype?: string;
  /** For select properties: tag shortname → tag subject. */
  tags?: Record<string, string>;
  /** For select properties: tag subject → tag shortname. */
  tagNames?: Record<string, string>;
}

export interface ClassContext {
  /** class subject → class shortname */
  classNames: Map<string, string>;
  /** lookup key (lowercased shortname or display name) → matching properties */
  byName: Map<string, CompactPropertyInfo[]>;
  /** property subject → info */
  bySubject: Map<string, CompactPropertyInfo>;
}

export const createEmptyContext = (): ClassContext => ({
  classNames: new Map(),
  byName: new Map(),
  bySubject: new Map(),
});

export const addPropertyToContext = (
  ctx: ClassContext,
  info: CompactPropertyInfo,
): void => {
  if (ctx.bySubject.has(info.subject)) {
    return;
  }

  ctx.bySubject.set(info.subject, info);

  const keys = new Set(
    [info.shortname, info.name]
      .filter((k): k is string => !!k)
      .map(k => k.toLowerCase()),
  );

  for (const key of keys) {
    const existing = ctx.byName.get(key) ?? [];
    ctx.byName.set(key, [...existing, info]);
  }
};

/**
 * Resolves a compact key to a property. Full URLs pass through unresolved
 * (returned as a minimal info). Throws on unknown or ambiguous shortnames,
 * listing what IS available/matching — the model repairs from the message.
 */
export const resolveKey = (
  ctx: ClassContext,
  key: string,
): CompactPropertyInfo => {
  if (Client.isValidSubject(key)) {
    return (
      ctx.bySubject.get(key) ?? { subject: key, shortname: key, datatype: '' }
    );
  }

  const matches = ctx.byName.get(key.toLowerCase()) ?? [];

  if (matches.length === 1) {
    return matches[0];
  }

  if (matches.length > 1) {
    throw new Error(
      `Ambiguous property "${key}": matches ${matches
        .map(m => `${m.shortname} (${m.subject})`)
        .join(', ')}. Use the full property URL to disambiguate.`,
    );
  }

  throw new Error(
    `Unknown property "${key}". Available properties: ${
      Array.from(ctx.bySubject.values())
        .map(p => p.shortname)
        .join(', ') || 'none'
    }. Use a listed shortname or a full property URL.`,
  );
};

/** Short `#ref` strings (in any position, incl. array members) expand to
 *  their full subjects; everything else passes through. */
const expandValueRefs = (value: JSONValue): JSONValue => {
  if (typeof value === 'string') {
    return tryExpandRef(value) ?? value;
  }

  if (Array.isArray(value)) {
    return value.map(expandValueRefs);
  }

  return value;
};

/** Coerces a compact wire value into its stored JSON-AD form. */
export const coerceValueIn = (
  info: CompactPropertyInfo,
  rawValue: JSONValue,
): JSONValue => {
  const value = expandValueRefs(rawValue);

  if (info.tags) {
    const entries = Array.isArray(value) ? value : [value];

    return entries.map(entry => {
      const asString = String(entry);

      if (Client.isValidSubject(asString)) {
        return asString;
      }

      const subject =
        info.tags![asString] ?? info.tags![asString.toLowerCase()];

      if (!subject) {
        throw new Error(
          `Unknown tag "${asString}" for ${info.shortname}. Allowed tags: ${Object.keys(
            info.tags!,
          ).join(', ')}`,
        );
      }

      return subject;
    });
  }

  if (info.datatype === Datatype.TIMESTAMP && typeof value === 'string') {
    const ms = Date.parse(value);

    if (Number.isNaN(ms)) {
      throw new Error(
        `Invalid timestamp "${value}" for ${info.shortname}. Use an ISO date-time string or milliseconds since epoch.`,
      );
    }

    return ms;
  }

  if (
    (info.datatype === Datatype.INTEGER || info.datatype === Datatype.FLOAT) &&
    typeof value === 'string' &&
    value.trim() !== '' &&
    !Number.isNaN(Number(value))
  ) {
    return Number(value);
  }

  if (info.datatype === Datatype.RESOURCEARRAY && !Array.isArray(value)) {
    return [value];
  }

  return value;
};

/** Renders a stored JSON-AD value in its compact wire form. */
export const compactValueOut = (
  info: CompactPropertyInfo,
  value: JSONValue,
): JSONValue => {
  if (info.tagNames && Array.isArray(value)) {
    return value.map(v => info.tagNames![String(v)] ?? v);
  }

  if (info.datatype === Datatype.TIMESTAMP && typeof value === 'number') {
    return new Date(value).toISOString();
  }

  return value;
};

/**
 * One-line schema signature for a class within a context, e.g.
 * `deal: name, status(lead|qualified), value [integer], closes [timestamp]`.
 * Cheap enough to embed in read results so get_schema is rarely needed.
 */
export const describeClassCompact = (
  ctx: ClassContext,
  classSubject: string,
): string => {
  const className = ctx.classNames.get(classSubject) ?? classSubject;
  const props = Array.from(ctx.bySubject.values()).map(info => {
    if (info.tags) {
      return `${info.shortname}(${Object.keys(info.tags).join('|')})`;
    }

    const datatypeName = info.datatype.split('/').pop();

    return datatypeName && info.datatype !== Datatype.STRING
      ? `${info.shortname} [${datatypeName}]`
      : info.shortname;
  });

  return `${className}: ${props.join(', ')}`;
};

/** Common properties resolvable on every resource regardless of class. */
const UNIVERSAL_PROPERTIES = [
  core.properties.name,
  core.properties.description,
];

const loadPropertyInfo = async (
  store: Store,
  propertySubject: string,
  classSubjects: string[] = [],
): Promise<CompactPropertyInfo | undefined> => {
  const property = await store.getResource<Core.Property>(propertySubject);

  if (property.error) {
    return undefined;
  }

  const shortname = property.props.shortname;

  if (!shortname) {
    return undefined;
  }

  const info: CompactPropertyInfo = {
    subject: propertySubject,
    shortname,
    name: property.get(core.properties.name) as string | undefined,
    datatype: (property.props.datatype as string) ?? Datatype.STRING,
    classtype: property.props.classtype as string | undefined,
  };

  // The class's `constraints` first (options as `enum`, the linked class as
  // `class`), then the Property's legacy `allowsOnly` and `classtype`.
  const constraint = getEffectiveConstraint(
    store,
    classSubjects,
    propertySubject,
  );
  const allowsOnly = (constraint.enum ?? []).filter(
    (v): v is string => typeof v === 'string',
  );

  info.classtype = constraint.class ?? info.classtype;

  if (info.classtype === dataBrowser.classes.tag && allowsOnly.length) {
    info.tags = {};
    info.tagNames = {};

    for (const tagSubject of allowsOnly) {
      const tag = await store.getResource(tagSubject);
      const tagName =
        (tag.get(core.properties.shortname) as string) ?? tag.title;
      info.tags[tagName] = tagSubject;
      info.tagNames[tagSubject] = tagName;
    }
  }

  return info;
};

/** Builds the resolution context for a set of classes (the `@class` scope). */
export const buildClassContext = async (
  store: Store,
  classSubjects: string[],
): Promise<ClassContext> => {
  const ctx = createEmptyContext();

  for (const classSubject of classSubjects) {
    const classResource = await store.getResource<Core.Class>(classSubject);

    if (classResource.error) {
      continue;
    }

    ctx.classNames.set(
      classSubject,
      classResource.props.shortname ?? classResource.title,
    );

    const propertySubjects = [
      ...(classResource.props.requires ?? []),
      ...(classResource.props.recommends ?? []),
    ];

    for (const propertySubject of propertySubjects) {
      const info = await loadPropertyInfo(store, propertySubject, [
        classSubject,
      ]);

      if (info) {
        addPropertyToContext(ctx, info);
      }
    }
  }

  for (const propertySubject of UNIVERSAL_PROPERTIES) {
    if (!ctx.bySubject.has(propertySubject)) {
      const info = await loadPropertyInfo(store, propertySubject);

      if (info) {
        addPropertyToContext(ctx, info);
      }
    }
  }

  return ctx;
};

const STRUCTURAL_PROPERTIES = new Set<string>([
  core.properties.isA,
  core.properties.parent,
]);

export interface ToCompactOptions {
  includeCommitData?: boolean;
  /** Reuse a prebuilt context (e.g. when compacting many rows of one class). */
  context?: ClassContext;
}

/** Serializes a resource into its compact wire form. Always safe: keys that
 *  can't be resolved (or whose shortname collides) fall back to full URLs. */
export const toCompact = async (
  store: Store,
  resource: Resource,
  options: ToCompactOptions = {},
): Promise<Record<string, JSONValue>> => {
  const classes = resource.getClasses();
  const ctx = options.context ?? (await buildClassContext(store, classes));

  const out: Record<string, JSONValue> = { '@id': resource.subject };

  const classNames = classes.map(c => ctx.classNames.get(c) ?? c);

  if (classNames.length > 0) {
    out['@class'] = classNames.length === 1 ? classNames[0] : classNames;
  }

  const parent = resource.get(core.properties.parent);

  if (parent) {
    out['@parent'] = parent as string;
  }

  for (const [propertySubject, value] of resource.getEntries()) {
    if (STRUCTURAL_PROPERTIES.has(propertySubject)) {
      continue;
    }

    if (
      !options.includeCommitData &&
      propertySubject === commits.properties.lastCommit
    ) {
      continue;
    }

    const info = ctx.bySubject.get(propertySubject);

    if (!info) {
      out[propertySubject] = value as JSONValue;
      continue;
    }

    // A shortname shared by several in-scope properties is ambiguous to write
    // back, so emit the full URL instead (deterministic and lossless).
    const collisions = ctx.byName.get(info.shortname.toLowerCase()) ?? [];
    const key = collisions.length > 1 ? propertySubject : info.shortname;

    out[key] = compactValueOut(info, value as JSONValue);
  }

  return out;
};

export interface FromCompactResult {
  isA: string[];
  parent: string;
  propVals: Record<string, JSONValue>;
  /** Echo of every resolved compact key → property subject, for the reply. */
  resolved: Record<string, string>;
}

export interface FromCompactOptions {
  /** Resolves a `@class` shortname to a class subject (e.g. drive lookup). */
  resolveClass: (nameOrSubject: string) => Promise<string>;
}

/**
 * Parses one compact object into the pieces `store.newResource` needs.
 * Accepts raw JSON-AD too: full-URL keys (including isA/parent) bypass
 * resolution, so the old format keeps working unchanged. Strict on
 * shortnames: unknown or ambiguous keys throw with candidates.
 */
export const fromCompact = async (
  store: Store,
  data: Record<string, JSONValue>,
  options: FromCompactOptions,
): Promise<FromCompactResult> => {
  const {
    '@id': atId,
    '@class': atClass,
    '@parent': atParent,
    [core.properties.isA]: rawIsA,
    [core.properties.parent]: rawParent,
    ...restRaw
  } = data;

  if (atId) {
    throw new Error('Do not include an @id, the subject is auto generated');
  }

  const classRefs = atClass
    ? Array.isArray(atClass)
      ? atClass.map(String)
      : [String(atClass)]
    : Array.isArray(rawIsA)
      ? rawIsA.map(String)
      : [];

  if (classRefs.length === 0) {
    throw new Error('Missing @class (or a full isA property)');
  }

  const isA = await Promise.all(
    classRefs.map(ref =>
      Client.isValidSubject(ref)
        ? Promise.resolve(ref)
        : options.resolveClass(ref),
    ),
  );

  const rawParentValue = (atParent ?? rawParent) as string | undefined;

  if (!rawParentValue) {
    throw new Error('Missing @parent (or a full parent property)');
  }

  const parent = expandSubject(rawParentValue);

  const propVals: Record<string, JSONValue> = {};
  const resolved: Record<string, string> = {};

  // Keys may be short `#refs` (emitted for shortname collisions on read).
  const rest = Object.fromEntries(
    Object.entries(restRaw).map(([key, value]) => [
      tryExpandRef(key) ?? key,
      value,
    ]),
  );

  // Raw JSON-AD (all-URL keys) needs no schema fetches; only build the
  // resolution context when a shortname key is actually present.
  const needsContext = Object.keys(rest).some(
    key => !Client.isValidSubject(key),
  );
  const ctx = needsContext
    ? await buildClassContext(store, isA)
    : createEmptyContext();

  for (const [key, value] of Object.entries(rest)) {
    if (Client.isValidSubject(key)) {
      propVals[key] = expandValueRefs(value as JSONValue);
      continue;
    }

    const info = resolveKey(ctx, key);
    propVals[info.subject] = coerceValueIn(info, value as JSONValue);
    resolved[key] = info.subject;
  }

  return { isA, parent, propVals, resolved };
};
