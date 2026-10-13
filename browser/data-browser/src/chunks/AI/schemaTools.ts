// @wc-ignore-file
import {
  canonicalizeScheme,
  core,
  ensureOntology,
  ontologyFromJsonSchema,
  ontologyToJsonSchema,
  server,
  type Store,
} from '@tomic/lib';

type Json = Record<string, unknown>;

const DEFAULT_LIMIT = 10;

const asString = (value: unknown): string =>
  typeof value === 'string' ? value : '';

export interface SchemaMatch {
  class: string;
  shortname: string;
  ontology?: { subject: string; shortname: string };
  /** The class as a JSON Schema object schema (an entry of the ontology's `$defs`). */
  jsonSchema?: unknown;
  /** Set when the class could not be exported. */
  error?: string;
}

/**
 * Finds classes among `classSubjects` by words in their shortname, name,
 * description or ontology, and returns each with its JSON Schema so the model
 * can reuse it. Words are OR-ed; classes that match more words come first.
 * An empty query lists everything (up to `limit`).
 */
export async function findSchemas(
  store: Store,
  classSubjects: string[],
  query: string,
  limit = DEFAULT_LIMIT,
): Promise<{ matches: SchemaMatch[]; total: number }> {
  const words = query
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean);

  const candidates = await Promise.all(
    classSubjects.map(async subject => {
      const resource = await store.getResource(subject);
      const ontologySubject = asString(resource.get(core.properties.parent));
      const ontology = ontologySubject
        ? await store.getResource(ontologySubject)
        : undefined;
      const isOntology =
        ontology?.get(core.properties.isA) !== undefined &&
        (ontology.get(core.properties.isA) as string[]).includes(
          core.classes.ontology,
        );
      const shortname = asString(resource.get(core.properties.shortname));
      const haystack = [
        shortname,
        asString(resource.get(core.properties.name)),
        asString(resource.get(core.properties.description)),
        isOntology ? asString(ontology?.get(core.properties.shortname)) : '',
        isOntology ? asString(ontology?.get(core.properties.name)) : '',
      ]
        .join(' ')
        .toLowerCase();
      const score = words.filter(word => haystack.includes(word)).length;

      return {
        subject,
        shortname,
        score,
        ontology: isOntology && ontology ? ontologySubject : undefined,
        ontologyShortname: isOntology
          ? asString(ontology?.get(core.properties.shortname))
          : '',
      };
    }),
  );

  const hits = candidates
    .filter(c => words.length === 0 || c.score > 0)
    .sort(
      (a, b) => b.score - a.score || a.shortname.localeCompare(b.shortname),
    );

  const exports = new Map<string, Promise<Json>>();

  const exportOntology = (subject: string) => {
    if (!exports.has(subject)) {
      exports.set(
        subject,
        ontologyToJsonSchema(store, subject) as Promise<Json>,
      );
    }

    return exports.get(subject)!;
  };

  const matches = await Promise.all(
    hits.slice(0, limit).map(async (hit): Promise<SchemaMatch> => {
      const base: SchemaMatch = {
        class: hit.subject,
        shortname: hit.shortname,
        ...(hit.ontology
          ? {
              ontology: {
                subject: hit.ontology,
                shortname: hit.ontologyShortname,
              },
            }
          : {}),
      };

      if (!hit.ontology) {
        return { ...base, error: 'This class is not part of an ontology.' };
      }

      try {
        const schema = await exportOntology(hit.ontology);
        const wanted = canonicalizeScheme(hit.subject);
        const entry = Object.values((schema.$defs ?? {}) as Json).find(
          def => (def as Json)['x-atomic-subject'] === wanted,
        );

        return entry
          ? { ...base, jsonSchema: entry }
          : { ...base, error: 'The class is missing from its ontology.' };
      } catch (error) {
        return {
          ...base,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    }),
  );

  return { matches, total: hits.length };
}

export interface EnsureOntologyToolInput {
  /** JSON Schema (draft 2020-12) with object schemas in `$defs`. */
  schema: unknown;
  /** Ontology shortname. Defaults to the schema's `x-atomic-ontology` / `title`, then the drive's default ontology. */
  shortname?: string;
}

/**
 * Makes a JSON Schema real as an ontology under the drive. Idempotent. Errors
 * from the import name a JSON pointer and are returned verbatim so the model
 * can fix its schema.
 */
export async function ensureOntologyFromJsonSchema(
  store: Store,
  drive: string,
  { schema, shortname }: EnsureOntologyToolInput,
): Promise<
  | {
      ontology: string;
      shortname: string;
      classes: Record<string, string>;
      properties: Record<string, string>;
    }
  | { error: string }
> {
  const parsed = typeof schema === 'string' ? safeParse(schema) : schema;

  if (parsed === undefined) {
    return { error: 'schema is not valid JSON.' };
  }

  let fallback: string | undefined = shortname;

  if (!fallback) {
    const root = (parsed ?? {}) as Json;

    if (!root['x-atomic-ontology'] && !root.title) {
      const driveResource = await store.getResource(drive);
      const defaultOntology = driveResource.get(
        server.properties.defaultOntology,
      );

      if (typeof defaultOntology === 'string' && defaultOntology) {
        const ontology = await store.getResource(defaultOntology);
        fallback =
          asString(ontology.get(core.properties.shortname)) || undefined;
      }
    }
  }

  let input;

  try {
    input = ontologyFromJsonSchema(parsed, { shortname: fallback });
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }

  try {
    const ensured = await ensureOntology(
      store as unknown as Parameters<typeof ensureOntology>[0],
      drive,
      input,
    );

    return {
      ontology: ensured.ontology,
      shortname: input.shortname,
      classes: ensured.classes,
      properties: ensured.properties,
    };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

function safeParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}
