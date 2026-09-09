import type { JSONValue } from './value.js';

/**
 * What a plugin declares it needs.
 *
 * Written in the plugin's own source, beside the code that uses it:
 *
 * ```js
 * export const manifest = {
 *   secrets: [{ name: 'google', origin: 'https://www.googleapis.com',
 *               description: 'Google Calendar API token' }],
 * };
 * ```
 *
 * Two things follow from putting it there rather than in resource properties.
 * The declaration cannot drift from the code that spends it — the same file
 * says `secret:google` and asks for `google`. And an author, human or model,
 * writes one artifact rather than remembering to fill in a form elsewhere.
 */
export interface DeclaredSecret {
  /** Referred to in the source as `secret:<name>`. */
  name: string;
  /** The exact origin it may be sent to. */
  origin: string;
  /** Shown to whoever has to find the credential. */
  description?: string;
}

export interface DeclaredOperation {
  id: string;
  method: 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** Endpoint without query/fragment. Typed {number}/{uuid} segments permit positive decimal IDs/hyphenated UUIDs only. */
  url: string;
  effect: 'read' | 'write';
}

export interface PluginManifest {
  actions?: DeclaredAction[];
  schemaVersion?: 1;
  operations?: DeclaredOperation[];
  secrets: DeclaredSecret[];
}

export interface DeclaredAction {
  name: string;
  title: string;
  description: string;
  operation: string;
  inputSchema: {
    type: 'object';
    properties: Record<
      string,
      { type: 'string' | 'integer' | 'boolean'; description: string }
    >;
    required?: string[];
    additionalProperties: false;
  };
}

/**
 * Normalizes whatever a plugin exported as `manifest`.
 *
 * Same posture as `parseVerdict`: the export is authored by an LLM as often as
 * a person, so anything malformed is dropped rather than trusted, and a plugin
 * that declares nothing usable declares nothing.
 */
export function parseManifest(raw: unknown): PluginManifest {
  if (raw && typeof raw === 'object' && 'schemaVersion' in raw) {
    return validateManifest(raw);
  }

  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { secrets: [] };
  }

  const secrets = (raw as { secrets?: unknown }).secrets;

  if (!Array.isArray(secrets)) return { secrets: [] };

  const seen = new Set<string>();

  return {
    secrets: secrets.flatMap(entry => {
      if (!entry || typeof entry !== 'object') return [];

      const { name, origin, description } = entry as Record<string, JSONValue>;

      if (typeof name !== 'string' || name.length === 0) return [];

      if (typeof origin !== 'string' || origin.length === 0) return [];

      // A name declared twice would render two slots writing to one secret.
      if (seen.has(name)) return [];

      seen.add(name);

      return [
        {
          name,
          origin,
          ...(typeof description === 'string' ? { description } : {}),
        },
      ];
    }),
  };
}

/**
 * Secret names a plugin's source actually spends, whether or not it declared
 * them.
 *
 * A plugin that writes `secret:google_calendar_token` needs that credential
 * even if it forgot to say so — and an author who forgot is exactly the one who
 * cannot work out where to enter it. Scanning the source means the page can
 * offer a slot anyway, asking for the origin the declaration would have named.
 */
export function secretsMentionedIn(source: string): string[] {
  const found = new Set<string>();

  for (const match of source.matchAll(/secret:([A-Za-z0-9_-]+)/g)) {
    found.add(match[1]);
  }

  return [...found].sort();
}

/**
 * Origins a plugin's source actually requests.
 *
 * Where a credential may be sent is a fact about the plugin, not a second part
 * of the credential — and the source already says it. Reading it here lets an
 * undeclared secret be stored with one field, instead of asking someone to copy
 * an origin out of code they were not looking at.
 *
 * Only literal URLs are found, which is the point: a host assembled at runtime
 * is exactly the one nobody should pre-authorise by guess.
 */
export function originsMentionedIn(source: string): string[] {
  const found = new Set<string>();

  for (const match of source.matchAll(/https?:\/\/[a-zA-Z0-9.-]+(?::\d+)?/g)) {
    found.add(match[0]);
  }

  return [...found].sort();
}

/** Strict validation for released code. Draft source scans never grant access. */
export function validateManifest(raw: unknown): PluginManifest {
  const object = (value: unknown): Record<string, unknown> => {
    if (!value || typeof value !== 'object' || Array.isArray(value))
      throw new Error('manifest entry must be an object');

    return value as Record<string, unknown>;
  };

  const known = (entry: Record<string, unknown>, keys: string[]) => {
    if (Object.keys(entry).some(key => !keys.includes(key)))
      throw new Error('unknown manifest field');
  };

  const endpoint = (value: unknown) => {
    if (typeof value !== 'string') throw new Error('endpoint must be a URL');
    const url = new URL(value);
    if (
      !['http:', 'https:'].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    )
      throw new Error('invalid endpoint');

    return url;
  };

  const entry = object(raw);
  known(entry, ['schemaVersion', 'secrets', 'operations', 'actions']);
  if (entry.schemaVersion !== 1)
    throw new Error('unsupported manifest schemaVersion');

  const list = (value: unknown): unknown[] => {
    if (value === undefined) return [];
    if (!Array.isArray(value))
      throw new Error('manifest field must be an array');

    return value;
  };

  const names = new Set<string>();
  const secrets = list(entry.secrets).map(value => {
    const secret = object(value);
    known(secret, ['name', 'origin', 'description']);
    if (
      typeof secret.name !== 'string' ||
      !secret.name ||
      names.has(secret.name)
    )
      throw new Error('secret names must be unique');
    names.add(secret.name);
    const url = endpoint(secret.origin);
    if (url.origin !== secret.origin)
      throw new Error('secret origin must be exact');
    if (
      secret.description !== undefined &&
      typeof secret.description !== 'string'
    )
      throw new Error('description must be text');

    return secret as unknown as DeclaredSecret;
  });
  names.clear();
  const operations = list(entry.operations).map(value => {
    const operation = object(value);
    known(operation, ['id', 'method', 'url', 'effect']);
    if (
      typeof operation.id !== 'string' ||
      !operation.id ||
      names.has(operation.id)
    )
      throw new Error('operation IDs must be unique');
    names.add(operation.id);
    endpoint(operation.url);
    if (
      typeof operation.method !== 'string' ||
      !['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(
        operation.method,
      )
    )
      throw new Error('unsupported method');
    if (
      typeof operation.effect !== 'string' ||
      !['read', 'write'].includes(operation.effect)
    )
      throw new Error('unsupported effect');

    return operation as unknown as DeclaredOperation;
  });
  names.clear();
  const actions = list(entry.actions).map(value => {
    const action = object(value);
    known(action, ['name', 'title', 'description', 'operation', 'inputSchema']);
    if (
      typeof action.name !== 'string' ||
      !/^[A-Za-z0-9_.-]{1,128}$/.test(action.name) ||
      names.has(action.name) ||
      typeof action.title !== 'string' ||
      !action.title ||
      typeof action.description !== 'string' ||
      action.description.length > 8192 ||
      !operations.some(o => o.id === action.operation)
    )
      throw new Error('invalid action declaration');
    names.add(action.name);
    const schema = object(action.inputSchema);
    known(schema, ['type', 'properties', 'required', 'additionalProperties']);
    const properties = object(schema.properties);
    if (
      schema.type !== 'object' ||
      schema.additionalProperties !== false ||
      Object.keys(properties).length > 32 ||
      list(schema.required).some(
        key => typeof key !== 'string' || !(key in properties),
      )
    )
      throw new Error('unsupported action input schema');

    for (const rawField of Object.values(properties)) {
      const field = object(rawField);
      known(field, ['type', 'description']);
      if (
        !['string', 'integer', 'boolean'].includes(String(field.type)) ||
        typeof field.description !== 'string'
      )
        throw new Error('unsupported action field');
    }

    return action as unknown as DeclaredAction;
  });
  if (actions.length > 64) throw new Error('at most 64 actions per release');

  return {
    schemaVersion: 1,
    secrets,
    operations,
    ...(actions.length ? { actions } : {}),
  };
}
