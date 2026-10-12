/**
 * The data verbs an LLM uses to read and edit Atomic Data, without any UI.
 *
 * The in-app assistant (`useAtomicTools`) and the MCP server (`@tomic/mcp`)
 * both call these, so there is one implementation behind every tool surface
 * (see planning/mcp-endpoint.md). Everything speaks JSON-AD-Compact
 * (`json-ad-compact.ts`). Results carry FULL subjects: shortening to `#refs`
 * is the caller's choice, done at its own tool boundary. Failures throw; each
 * surface decides how to report them.
 */
import { Client } from './client.js';
import {
  getClassesOnDrive,
  getClassNames,
  resolveClass,
} from './class-schema.js';
import {
  buildClassContext,
  coerceValueIn,
  compactValueOut,
  describeClassCompact,
  fromCompact,
  resolveKey,
  toCompact,
} from './json-ad-compact.js';
import { commits } from './ontologies/commits.js';
import { core } from './ontologies/core.js';
import { dataBrowser } from './ontologies/dataBrowser.js';
import { server } from './ontologies/server.js';
import type { Store } from './store.js';
import { expandSubject } from './subject-refs.js';
import { GENESIS } from './urls.js';
import type { JSONValue } from './value.js';

/**
 * Reads one resource as compact JSON-AD, with a one-line `_schema` signature
 * per class so the model rarely needs `get_schema` before writing.
 */
export async function readResourceCompact(
  store: Store,
  subjectOrRef: string,
  { includeCommitData = false }: { includeCommitData?: boolean } = {},
): Promise<Record<string, unknown>> {
  const subject = expandSubject(subjectOrRef);
  const resource = await store.getResource(subject);

  if (resource.error) {
    throw new Error(resource.error.message);
  }

  const classes = resource.getClasses();
  const ctx = await buildClassContext(store, classes);
  const entry: Record<string, unknown> = await toCompact(store, resource, {
    includeCommitData,
    context: ctx,
  });
  // The genesis certificate is hundreds of base64 characters that only
  // prove where the subject came from; no model needs to read it.
  delete entry[GENESIS];
  entry._schema = classes.map(c => describeClassCompact(ctx, c));

  return entry;
}

export interface QueryResourcesOptions {
  /** Class to query instances of: a shortname or full URL. Scopes shortname
   * resolution for `where` and `select`, and adds an isA filter. */
  class?: string;
  /** Filters. Shortnames and tag names when `class` is set, full property
   * URLs otherwise. */
  where: { property: string; value: JSONValue }[];
  /** Properties to include. Defaults to name, shortname and filename. */
  select?: string[];
  limit?: number;
}

/** Finds resources by property values. Results are not sorted. */
export async function queryResources(
  store: Store,
  drive: string,
  {
    class: classRef,
    where,
    select = [
      core.properties.name,
      core.properties.shortname,
      server.properties.filename,
    ],
    limit = 30,
  }: QueryResourcesOptions,
): Promise<Record<string, unknown>[]> {
  const classSubject = classRef
    ? await resolveClass(store, drive, classRef)
    : undefined;
  const ctx = classSubject
    ? await buildClassContext(store, [classSubject])
    : undefined;

  const filters: Record<string, string | number | string[]> = {};
  const filterProps: string[] = [];

  for (const { property, value } of where) {
    if (!ctx && !Client.isValidSubject(property)) {
      throw new Error(
        `Invalid property subject in where clause: '${property}'. Pass \`class\` to use shortnames.`,
      );
    }

    const info = ctx
      ? resolveKey(ctx, property)
      : { subject: property, shortname: property, datatype: '' };
    const coerced = coerceValueIn(info, value);
    // The query index matches array membership on scalars.
    filters[info.subject] = (
      Array.isArray(coerced) && coerced.length === 1 ? coerced[0] : coerced
    ) as string | number | string[];
    filterProps.push(info.subject);
  }

  if (classSubject) {
    filters[core.properties.isA] = classSubject;
  }

  const results = await store.search('', {
    filters,
    limit,
    include: true,
  });

  const resources = await Promise.all(
    results.map(subject => store.getResource(subject)),
  );

  const selectProps = ctx
    ? select.map(s => resolveKey(ctx, s).subject)
    : select;
  const props = Array.from(new Set([...selectProps, ...filterProps]));

  return resources.map(res => {
    const obj: Record<string, unknown> = { '@id': res.subject };

    for (const prop of props) {
      const val = res.get(prop);

      if (val) {
        const info = ctx?.bySubject.get(prop);
        obj[info?.shortname ?? prop] = info
          ? compactValueOut(info, val as JSONValue)
          : val;
      }
    }

    return obj;
  });
}

export interface FoundResource {
  subject: string;
  title: string;
  classes: string;
  /** For semantic search: the first chunk of the resource that matched. */
  chunk?: string;
}

/** Full-text search, scoped to `parents` (usually a drive). */
export async function textSearch(
  store: Store,
  query: string,
  { parents, limit = 10 }: { parents?: string[]; limit?: number } = {},
): Promise<FoundResource[]> {
  const subjects = await store.search(query, {
    parents: parents?.map(expandSubject),
    limit,
  });

  return Promise.all(
    subjects.map(async subject => {
      const resource = await store.getResource(subject);

      return {
        subject,
        title: resource.title,
        classes: await getClassNames(resource, store),
      };
    }),
  );
}

/** Hybrid semantic / text search. Needs a server with embeddings enabled. */
export async function semanticSearch(
  store: Store,
  query: string,
  {
    parents,
    limit = 10,
    textQuery,
  }: { parents?: string[]; limit?: number; textQuery?: string } = {},
): Promise<FoundResource[]> {
  if (limit < 1 || limit > 50) {
    throw new Error('Limit must be between 1 and 50');
  }

  const results = await store.semanticSearch(query, {
    limit,
    parents: parents?.map(expandSubject),
    text_query: textQuery,
  });

  return Promise.all(
    results.map(async ({ subject, chunk }) => {
      const resource = await store.getResource(subject);

      return {
        subject,
        title: resource.title,
        classes: await getClassNames(resource, store),
        chunk,
      };
    }),
  );
}

/** The classes defined on a drive, as `{ shortname, subject }`. */
export async function listDriveClasses(
  store: Store,
  drive: string,
): Promise<{ shortname: string; subject: string }[]> {
  const classSubjects = await getClassesOnDrive(drive, store);

  return Promise.all(
    classSubjects.map(async subject => {
      const resource = await store.getResource(subject);

      return { shortname: resource.title, subject };
    }),
  );
}

/**
 * Sets one property on a resource and, unless `save` is false, saves it. The
 * property may be a shortname from the resource's classes or a full URL; tag
 * values may be tag names. Returns the stored value and the property it
 * resolved to. The in-app assistant passes `save: false` because the person
 * reviews its edits before they are saved.
 */
export async function setResourceProperty(
  store: Store,
  subjectOrRef: string,
  property: string,
  value: JSONValue,
  { save = true }: { save?: boolean } = {},
): Promise<{ subject: string; property: string; value: JSONValue }> {
  const subject = expandSubject(subjectOrRef);
  const resource = await store.getResource(subject);

  if (resource.error) {
    throw new Error(resource.error.message);
  }

  const ctx = await buildClassContext(store, resource.getClasses());
  const info = resolveKey(ctx, property);
  const coerced = coerceValueIn(info, value);

  await resource.set(info.subject, coerced);

  if (save) {
    await resource.save();
  }

  return { subject, property: info.subject, value: coerced };
}

/**
 * Creates and saves one resource from a compact JSON-AD object with `@class`
 * and `@parent`. `resolved` echoes every shortname → property subject, so a
 * silent misresolution is visible to the model.
 */
export async function createResourceFromCompact(
  store: Store,
  drive: string,
  data: Record<string, JSONValue>,
): Promise<{ subject: string; resolved: Record<string, string> }> {
  const { isA, parent, propVals, resolved } = await fromCompact(store, data, {
    resolveClass: name => resolveClass(store, drive, name),
  });

  const parentResource = await store.getResource(parent);
  const isTableRow = parentResource.hasClasses(dataBrowser.classes.table);

  if (isTableRow) {
    propVals[commits.properties.createdAt] ??= Date.now();
  }

  const resource = await store.newResource({ parent, isA, propVals });
  await resource.save();

  // Rows and ontology members do not belong in the sidebar.
  if (!isTableRow && !parentResource.hasClasses(core.classes.ontology)) {
    await store.notifyResourceManuallyCreated(resource);
  }

  return { subject: resource.subject, resolved };
}
