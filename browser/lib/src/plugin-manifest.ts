import type { JSONValue } from './value.js';
import { validateHttp, type DeclaredHttp } from './plugin-manifest-http.js';

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
 *
 * Version two of the schema is the single manifest for both runtimes; the
 * server's `server/src/plugins/manifest.rs` is the reference and both sides
 * are checked against the fixtures in `testdata/plugin-manifest/`.
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

/**
 * One field of the user-editable config a plugin reads from `input.config`.
 *
 * Declared beside the code that destructures it, for the same reason secrets
 * are: an import whose config never made it into the resource then fails as a
 * readable problem naming the field, instead of as a `TypeError` thrown out of
 * `run()` that only the plugin's author can decode.
 */
export interface DeclaredConfigField {
  type: 'string' | 'object';
  description?: string;
}

export interface DeclaredConfig {
  /**
   * Key this plugin's config sits under in the installation's stored config.
   * Omitted when the config is stored flat, which is what a plugin written
   * against one destination does.
   */
  key?: string;
  properties: Record<string, DeclaredConfigField>;
  /** Fields `run()` cannot work without. Checked before the plugin is called. */
  required?: string[];
}

/** How an accepted file reaches the plugin; see {@link DeclaredAccept}. */
export type AcceptEncoding = 'text' | 'base64';

/** What the host accepts when no `maxBytes` is declared: 5 MiB. */
export const DEFAULT_ACCEPT_MAX_BYTES = 5 * 1024 * 1024;
/**
 * The largest `maxBytes` a plugin may declare: 20 MiB. The file is held
 * several times over during a run (request body, host string, sandbox string,
 * parse output), so this stays well under the sandbox's 256 MiB default.
 */
export const ACCEPT_MAX_BYTES_CEILING = 20 * 1024 * 1024;

/**
 * A file a plugin can be handed by the host, instead of fetching data itself.
 *
 * The host draws the picker, enforces `maxBytes` on the file's raw size and
 * passes it as `input.upload` (`ctx.upload` in `run`), in the declared
 * encoding, under a field named after it:
 *
 * - `as: 'text'` (the default when `as` is left out):
 *   `{ name, mediaType, size, text }`, decoded as UTF-8 and falling back to
 *   Windows-1252 when the file is not valid UTF-8.
 * - `as: 'base64'`: `{ name, mediaType, size, base64 }`, the file's exact bytes
 *   base64-encoded (standard alphabet, padded), with no charset detection.
 *
 * `size` is always the byte size of the file. `extensions` and `mediaTypes`
 * only filter the picker; the plugin must still validate the content it is
 * given. See `PluginUpload` in `plugin-upload.ts`.
 */
export interface DeclaredAccept {
  /** Lower-case, with the leading dot: `.xml`. */
  extensions?: string[];
  mediaTypes?: string[];
  /**
   * How the host hands over the file. Left out, it is `text`, and it stays
   * left out when serialized, so a release's id does not change.
   */
  as?: AcceptEncoding;
  /** Bytes, at most {@link ACCEPT_MAX_BYTES_CEILING}. */
  maxBytes?: number;
}

/**
 * One table a destination declares: created beneath the plugin, with a default
 * table view of `columns`.
 */
export interface DeclaredDestinationTable {
  name: string;
  /** Shortname of a class in the destination's `schema`. */
  rowClass: string;
  /** Property shortnames shown by the default view, in order. */
  columns: string[];
}

/**
 * Where an importer writes, declared so the host can create it before the
 * first run instead of a plugin-specific setup screen.
 *
 * The host ensures `schema` in the drive's ontology and creates every declared
 * table (each with a default table view of its `columns`) beneath the plugin.
 * It then stores the plugin's config (under `config.key` when the manifest
 * declares one):
 *
 * - `table` → `{ table, rowClass }`: the table subject and the subject of its
 *   row class, flat, as before `tables` existed;
 * - `tables` → `{ tables: { [key]: { table, rowClass } } }`, one entry per key,
 *   for a plugin that writes more than one kind of record;
 * - always `properties`: every property's subject by shortname.
 *
 * Declare `table`, `tables` or both; each table needs its own row class.
 * Repeating setup resumes the same resources, so adding a table to `tables` in
 * a later release only creates the new one.
 *
 * A property or class may name an existing term to reuse as `subject` (an
 * `https` URL, such as a shared ontology's), which `ensureSchema` binds to
 * without editing or copying it, after checking it is a Property of the
 * declared datatype or a Class.
 */
export interface DeclaredDestination {
  schema: {
    properties: {
      subject?: string;
      shortname: string;
      name: string;
      description: string;
      datatype: string;
    }[];
    classes: {
      subject?: string;
      shortname: string;
      name: string;
      description: string;
      requires?: string[];
      recommends?: string[];
    }[];
  };
  /** The single table, stored flat as `{ table, rowClass }`. */
  table?: DeclaredDestinationTable;
  /**
   * More tables, each under a key the plugin chooses (`statements`,
   * `closingBalances`) and reads back as `config.tables.<key>`.
   */
  tables?: Record<string, DeclaredDestinationTable>;
}

export type ManifestRuntime = 'atomic-js/1' | 'wasip2/1';

/** The trust boundary, independent of the language. */
export type ManifestWorld = 'extension' | 'server-extension';

export type CapabilityName =
  | 'storage'
  | 'full-drive-access'
  | 'extended-fuel'
  | 'extended-memory'
  | 'custom-view';

/** Either the bare name or the name with the reason shown at review. */
export type DeclaredCapability =
  | CapabilityName
  | { name: CapabilityName; reason?: string };

export interface DeclaredEntrypoints {
  /** Exports `run`. Defaults to true only when `entrypoints` is absent. */
  run?: boolean;
  /** Package-relative path of the custom view module. Needs `custom-view`. */
  view?: string;
  /** Class URLs whose hooks this package exports. Only in `server-extension`. */
  classExtender?: string[];
  /**
   * Exports `afterCommit(ctx)`: told when rows change in tables where it is
   * added as a view (#1851). Only in `extension`. Grants nothing by itself.
   */
  afterCommit?: boolean;
}

/**
 * Coarse egress allowance for packages that call the host `fetch` without an
 * operation id. Exact origins, no wildcards. Never widens `operations`.
 */
export interface DeclaredNetwork {
  origins?: string[];
  reason?: string;
}

export interface PluginManifestV2 {
  schemaVersion: 2;
  /** Defaults to `atomic-js/1`. */
  runtime?: ManifestRuntime;
  /** Defaults to `extension`. */
  world?: ManifestWorld;
  entrypoints?: DeclaredEntrypoints;
  capabilities?: DeclaredCapability[];
  secrets: DeclaredSecret[];
  operations?: DeclaredOperation[];
  actions?: DeclaredAction[];
  network?: DeclaredNetwork;
  /**
   * Integration-proxy platforms the plugin calls with
   * `atomic-proxy:/<platform>/...` URLs, which the server host resolves to the
   * installation's delegated connection and signs. Operations name those URLs.
   */
  proxy?: string[];
  config?: DeclaredConfig;
  configSchema?: Record<string, JSONValue>;
  defaultConfig?: Record<string, JSONValue>;
  accepts?: DeclaredAccept[];
  destination?: DeclaredDestination;
  name?: string;
  namespace?: string;
  version?: string;
  description?: string;
  author?: string;
}

/**
 * Version three adds the optional `http` block: public endpoints, which need
 * the node's plugin-routes gates. Without it, a v3 manifest is a v2 one.
 */
export interface PluginManifestV3 extends Omit<
  PluginManifestV2,
  'schemaVersion'
> {
  schemaVersion: 3;
  http?: DeclaredHttp;
}

export interface PluginManifest extends Omit<
  PluginManifestV2,
  'schemaVersion'
> {
  schemaVersion?: 1 | 2 | 3;
  http?: DeclaredHttp;
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

const RUNTIMES: ManifestRuntime[] = ['atomic-js/1', 'wasip2/1'];
const WORLDS: ManifestWorld[] = ['extension', 'server-extension'];
const CAPABILITIES: CapabilityName[] = [
  'storage',
  'full-drive-access',
  'extended-fuel',
  'extended-memory',
  'custom-view',
];
const IDENTIFIER = /^[A-Za-z0-9_-]{1,128}$/;

/**
 * Strict validation for released code. Draft source scans never grant access.
 *
 * Returns the manifest in its canonical serialized form: the one the server
 * stores in a release and addresses it by. A version-one manifest stays
 * version one; version-two fields at their default are left out.
 */
export function validateManifest(raw: unknown): PluginManifest {
  const object = (value: unknown, what = 'manifest entry') => {
    if (!value || typeof value !== 'object' || Array.isArray(value))
      throw new Error(`${what}: invalid type, expected a map`);

    return value as Record<string, unknown>;
  };

  const known = (entry: Record<string, unknown>, keys: string[]) => {
    for (const key of Object.keys(entry))
      if (!keys.includes(key)) throw new Error(`unknown field \`${key}\``);
  };

  const text = (value: unknown, what: string): string => {
    if (typeof value !== 'string')
      throw new Error(`${what}: invalid type, expected a string`);

    return value;
  };

  const endpoint = (value: unknown) => {
    if (typeof value !== 'string')
      throw new Error(
        'operation URLs must be HTTP endpoints without credentials, query or fragment',
      );
    const url = new URL(value);
    if (
      !['http:', 'https:'].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    )
      throw new Error(
        'operation URLs must be HTTP endpoints without credentials, query or fragment',
      );

    return url;
  };

  const exactOrigin = (value: unknown, what: string) => {
    if (endpoint(value).origin !== value)
      throw new Error(`${what} must be an exact HTTP origin`);

    return value as string;
  };

  const list = (value: unknown, what = 'manifest field'): unknown[] => {
    if (value === undefined) return [];
    if (!Array.isArray(value))
      throw new Error(`${what}: invalid type, expected a sequence`);

    return value;
  };

  const entry = object(raw, 'manifest');
  const version = entry.schemaVersion;
  if (version !== 1 && version !== 2 && version !== 3)
    throw new Error('unsupported manifest schemaVersion');
  known(
    entry,
    version === 1
      ? ['schemaVersion', 'secrets', 'operations', 'actions', 'proxy', 'config']
      : [
          'schemaVersion',
          'runtime',
          'world',
          'entrypoints',
          'capabilities',
          'secrets',
          'operations',
          'actions',
          'network',
          'proxy',
          'config',
          'configSchema',
          'defaultConfig',
          'accepts',
          'destination',
          'name',
          'namespace',
          'version',
          'description',
          'author',
          'http',
        ],
  );

  const proxy = list(entry.proxy, 'proxy').map(value => {
    if (typeof value !== 'string' || !PROXY_PLATFORM.test(value))
      throw new Error(PROXY_PLATFORMS_RULE);

    return value;
  });
  if (new Set(proxy).size !== proxy.length)
    throw new Error(PROXY_PLATFORMS_RULE);

  const names = new Set<string>();
  const secrets = list(entry.secrets, 'secrets').map(value => {
    const secret = object(value);
    known(secret, ['name', 'origin', 'description']);
    if (
      typeof secret.name !== 'string' ||
      !secret.name ||
      names.has(secret.name)
    )
      throw new Error('secret names must be nonempty and unique');
    names.add(secret.name);
    if (
      secret.description !== undefined &&
      typeof secret.description !== 'string'
    )
      throw new Error('secret description must be text');
    exactOrigin(secret.origin, 'secret origin');

    return secret as unknown as DeclaredSecret;
  });
  names.clear();
  // Declared in `http.sidecars`, which is validated last (as in Rust); only
  // the names are needed here, to check `atomic-sidecar:` operations.
  const httpEntry = entry.http as { sidecars?: unknown } | undefined;
  const declaredSidecars = Array.isArray(httpEntry?.sidecars)
    ? httpEntry.sidecars.map(s => (s as { name?: unknown } | null)?.name)
    : [];
  const operations = list(entry.operations, 'operations').map(value => {
    const operation = object(value);
    known(operation, ['id', 'method', 'url', 'effect']);
    if (
      typeof operation.id !== 'string' ||
      !operation.id ||
      names.has(operation.id)
    )
      throw new Error('operation IDs must be nonempty and unique');
    names.add(operation.id);
    const sidecar =
      typeof operation.url === 'string'
        ? parseSidecarRelative(operation.url)
        : undefined;
    const relative =
      typeof operation.url === 'string' && !sidecar
        ? parseProxyRelative(operation.url)
        : undefined;

    if (sidecar) {
      if (sidecar.query !== undefined) throw new Error(SIDECAR_URL_RULE);
      if (!declaredSidecars.includes(sidecar.name))
        throw new Error(
          `operation ${operation.id} does not declare sidecar '${sidecar.name}' in \`http.sidecars\``,
        );
    } else if (relative) {
      if (relative.query !== undefined) throw new Error(PROXY_URL_RULE);
      if (!proxy.includes(relative.platform))
        throw new Error(
          `operation ${operation.id} does not declare proxy platform '${relative.platform}' in \`proxy\``,
        );
    } else {
      endpoint(operation.url);
    }

    if (
      typeof operation.method !== 'string' ||
      !['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(
        operation.method,
      )
    )
      throw new Error('operation has an unsupported HTTP method');
    if (
      typeof operation.effect !== 'string' ||
      !['read', 'write'].includes(operation.effect)
    )
      throw new Error('operation effect must be read or write');

    return operation as unknown as DeclaredOperation;
  });
  names.clear();
  const actions = list(entry.actions, 'actions').map(value => {
    const action = object(value);
    known(action, ['name', 'title', 'description', 'operation', 'inputSchema']);
    if (
      typeof action.name !== 'string' ||
      !/^[A-Za-z0-9_.-]{1,128}$/.test(action.name) ||
      names.has(action.name) ||
      typeof action.title !== 'string' ||
      !action.title ||
      typeof action.description !== 'string' ||
      action.description.length > 8192
    )
      throw new Error('invalid or duplicate action name/description');
    if (!operations.some(o => o.id === action.operation))
      throw new Error('action references an undeclared operation');
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
        throw new Error('unsupported action input schema');
    }

    return action as unknown as DeclaredAction;
  });
  if (actions.length > 64) throw new Error('at most 64 actions per release');
  const declaredConfig =
    entry.config === undefined ? undefined : object(entry.config);

  if (declaredConfig) {
    known(declaredConfig, ['key', 'properties', 'required']);
    if (
      declaredConfig.key !== undefined &&
      (typeof declaredConfig.key !== 'string' ||
        !/^[A-Za-z0-9_.-]{1,128}$/.test(declaredConfig.key))
    )
      throw new Error('invalid config key');

    const fields = object(declaredConfig.properties);
    if (Object.keys(fields).length > 64)
      throw new Error('unsupported config schema');

    for (const rawField of Object.values(fields)) {
      const field = object(rawField);
      known(field, ['type', 'description']);
      if (
        !['string', 'object'].includes(String(field.type)) ||
        (field.description !== undefined &&
          typeof field.description !== 'string')
      )
        throw new Error('unsupported config field');
    }

    // Required fields the declaration does not describe could not be reported
    // in the plugin's own words, which is the whole point of declaring them.
    if (
      list(declaredConfig.required).some(
        key => typeof key !== 'string' || !(key in fields),
      )
    )
      throw new Error('unsupported config schema');
  }

  if (version === 1) {
    return {
      schemaVersion: 1,
      secrets,
      operations,
      ...(actions.length ? { actions } : {}),
      ...(proxy.length ? { proxy } : {}),
      ...(declaredConfig
        ? { config: declaredConfig as unknown as DeclaredConfig }
        : {}),
    };
  }

  const variant = <T extends string>(
    value: unknown,
    allowed: T[],
    fallback: T,
  ): T => {
    if (value === undefined) return fallback;
    if (typeof value !== 'string' || !allowed.includes(value as T))
      throw new Error(`unknown variant \`${String(value)}\``);

    return value as T;
  };

  const runtime = variant(entry.runtime, RUNTIMES, 'atomic-js/1');
  const world = variant(entry.world, WORLDS, 'extension');

  const network = { origins: [] as string[], reason: undefined as unknown };

  if (entry.network !== undefined) {
    const declared = object(entry.network, 'network');
    known(declared, ['origins', 'reason']);
    network.origins = list(declared.origins, 'network.origins').map(origin =>
      exactOrigin(origin, 'network origin'),
    );
    if (new Set(network.origins).size !== network.origins.length)
      throw new Error('network origins must be unique');
    if (declared.reason !== undefined)
      network.reason = text(declared.reason, 'network.reason');
  }

  const seenCapabilities = new Set<string>();
  const capabilities = list(entry.capabilities, 'capabilities').map(value => {
    let name: unknown;
    let reason: unknown;

    if (typeof value === 'string') name = value;
    else if (value && typeof value === 'object' && !Array.isArray(value)) {
      const declared = value as Record<string, unknown>;
      if (Object.keys(declared).some(key => !['name', 'reason'].includes(key)))
        throw new Error('capability must be a known name or {name, reason}');
      name = declared.name;
      reason = declared.reason;
    }

    if (
      typeof name !== 'string' ||
      !CAPABILITIES.includes(name as CapabilityName) ||
      (reason !== undefined && typeof reason !== 'string')
    )
      throw new Error('capability must be a known name or {name, reason}');
    if (seenCapabilities.has(name))
      throw new Error('capabilities must be unique');
    seenCapabilities.add(name);

    return reason === undefined
      ? (name as CapabilityName)
      : { name: name as CapabilityName, reason: reason as string };
  });

  const entrypoints: Required<DeclaredEntrypoints> = {
    run: entry.entrypoints === undefined,
    view: undefined as unknown as string,
    classExtender: undefined as unknown as string[],
    afterCommit: false,
  };

  if (entry.entrypoints !== undefined) {
    const declared = object(entry.entrypoints, 'entrypoints');
    known(declared, ['run', 'view', 'classExtender', 'afterCommit']);

    if (declared.run !== undefined) {
      if (typeof declared.run !== 'boolean')
        throw new Error('entrypoints.run: invalid type, expected a boolean');
      entrypoints.run = declared.run;
    }

    if (declared.afterCommit !== undefined) {
      if (typeof declared.afterCommit !== 'boolean')
        throw new Error(
          'entrypoints.afterCommit: invalid type, expected a boolean',
        );
      entrypoints.afterCommit = declared.afterCommit;
    }

    if (declared.view !== undefined)
      entrypoints.view = text(declared.view, 'entrypoints.view');
    if (declared.classExtender !== undefined)
      entrypoints.classExtender = list(
        declared.classExtender,
        'entrypoints.classExtender',
      ).map(url => text(url, 'entrypoints.classExtender'));
  }

  const classUrls = entrypoints.classExtender ?? [];
  if (entrypoints.classExtender !== undefined && classUrls.length === 0)
    throw new Error('classExtender must list at least one class URL');
  names.clear();

  for (const cls of classUrls) {
    const url = new URL(cls);
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname)
      throw new Error('classExtender entries must be class URLs');
    if (names.has(cls)) throw new Error('classExtender entries must be unique');
    names.add(cls);
  }

  if (world === 'extension' && classUrls.length > 0)
    throw new Error('world extension may not declare classExtender');
  if (world === 'server-extension' && entrypoints.afterCommit)
    throw new Error(
      'entrypoints.afterCommit is for world extension; a server extension hooks commits with classExtender',
    );
  if (
    world === 'server-extension' &&
    runtime !== 'wasip2/1' &&
    classUrls.length === 0
  )
    throw new Error(
      'world server-extension requires runtime wasip2/1 or entrypoints.classExtender',
    );

  if (entrypoints.view !== undefined) {
    const view = entrypoints.view;
    if (
      !view ||
      view.startsWith('/') ||
      view.includes('\\') ||
      view.split('/').some(segment => !segment || segment === '..')
    )
      throw new Error('view entrypoint must be a package-relative path');
    if (!seenCapabilities.has('custom-view'))
      throw new Error('view entrypoint requires the custom-view capability');
  }

  const accepts = list(entry.accepts, 'accepts').map(value => {
    const accept = object(value, 'accepts entry');
    known(accept, ['extensions', 'mediaTypes', 'as', 'maxBytes']);
    if (
      accept.as !== undefined &&
      accept.as !== 'text' &&
      accept.as !== 'base64'
    )
      throw new Error('accepts entries must be read `as` text or base64');
    const extensions = list(accept.extensions, 'accepts.extensions').map(
      extension => {
        if (
          typeof extension !== 'string' ||
          !/^\.[a-z0-9][a-z0-9._-]{0,31}$/.test(extension)
        )
          throw new Error(
            'accepts extensions must be lower-case and start with a dot',
          );

        return extension;
      },
    );
    const mediaTypes = list(accept.mediaTypes, 'accepts.mediaTypes').map(
      mediaType => {
        if (
          typeof mediaType !== 'string' ||
          !/^[a-z0-9][a-z0-9.+-]*\/[a-z0-9][a-z0-9.+-]*$/.test(mediaType)
        )
          throw new Error('accepts mediaTypes must be type/subtype');

        return mediaType;
      },
    );
    if (
      accept.maxBytes !== undefined &&
      (typeof accept.maxBytes !== 'number' ||
        !Number.isInteger(accept.maxBytes) ||
        accept.maxBytes < 1 ||
        accept.maxBytes > ACCEPT_MAX_BYTES_CEILING)
    )
      throw new Error(
        `accepts maxBytes must be a whole number from 1 to ${ACCEPT_MAX_BYTES_CEILING}`,
      );

    return {
      ...(extensions.length ? { extensions } : {}),
      ...(mediaTypes.length ? { mediaTypes } : {}),
      // Kept exactly as declared: an absent `as` stays absent.
      ...(accept.as !== undefined ? { as: accept.as as AcceptEncoding } : {}),
      ...(accept.maxBytes !== undefined
        ? { maxBytes: accept.maxBytes as number }
        : {}),
    };
  });
  if (entry.accepts !== undefined && accepts.length === 0)
    throw new Error('accepts must list at least one entry');
  if (accepts.length > 8) throw new Error('at most 8 accepts entries');

  const destination =
    entry.destination === undefined
      ? undefined
      : validateDestination(object(entry.destination, 'destination'));

  const metadata: Partial<
    Pick<
      PluginManifestV2,
      'name' | 'namespace' | 'version' | 'description' | 'author'
    >
  > = {};

  for (const key of [
    'name',
    'namespace',
    'version',
    'description',
    'author',
  ] as const) {
    if (entry[key] !== undefined) metadata[key] = text(entry[key], key);
  }

  for (const key of ['namespace', 'name'] as const) {
    const value = metadata[key];
    if (value !== undefined && !IDENTIFIER.test(value))
      throw new Error(
        `plugin ${key} '${value}' is invalid: only ASCII letters, digits, '-' and '_' are allowed`,
      );
  }

  // Last, as in Rust: the http block is validated after everything else.
  if (entry.http !== undefined && version !== 3)
    throw new Error('the http block needs schemaVersion 3');
  const http =
    entry.http === undefined
      ? undefined
      : validateHttp(entry.http, {
          serverExtension: world === 'server-extension',
          operations: operations.map(o => ({
            id: o.id,
            method: o.method,
            effect: o.effect,
            url: o.url,
          })),
        });

  const entrypointsDefault =
    entrypoints.run === true &&
    entrypoints.view === undefined &&
    entrypoints.classExtender === undefined &&
    !entrypoints.afterCommit;

  return {
    schemaVersion: version,
    ...(http ? { http } : {}),
    ...(runtime !== 'atomic-js/1' ? { runtime } : {}),
    ...(world !== 'extension' ? { world } : {}),
    ...(entrypointsDefault
      ? {}
      : {
          entrypoints: {
            ...(entrypoints.run ? { run: true } : {}),
            ...(entrypoints.view !== undefined
              ? { view: entrypoints.view }
              : {}),
            ...(entrypoints.classExtender !== undefined
              ? { classExtender: entrypoints.classExtender }
              : {}),
            ...(entrypoints.afterCommit ? { afterCommit: true } : {}),
          },
        }),
    ...(capabilities.length ? { capabilities } : {}),
    secrets,
    operations,
    ...(actions.length ? { actions } : {}),
    ...(declaredConfig
      ? { config: declaredConfig as unknown as DeclaredConfig }
      : {}),
    ...(network.origins.length || network.reason !== undefined
      ? {
          network: {
            ...(network.origins.length ? { origins: network.origins } : {}),
            ...(network.reason !== undefined
              ? { reason: network.reason as string }
              : {}),
          },
        }
      : {}),
    ...(proxy.length ? { proxy } : {}),
    ...(entry.configSchema !== undefined
      ? {
          configSchema: object(entry.configSchema, 'configSchema') as Record<
            string,
            JSONValue
          >,
        }
      : {}),
    ...(entry.defaultConfig !== undefined
      ? {
          defaultConfig: object(entry.defaultConfig, 'defaultConfig') as Record<
            string,
            JSONValue
          >,
        }
      : {}),
    ...(accepts.length ? { accepts } : {}),
    ...(destination ? { destination } : {}),
    ...metadata,
  };
}

const SHORTNAME = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
/** A `destination.tables` key: what the plugin reads as `config.tables.<key>`. */
const TABLE_KEY = /^[a-z][A-Za-z0-9]{0,63}$/;
/** Keys that would shadow `Object.prototype` members when read as `config.tables[key]`. */
const RESERVED_KEYS = [
  'constructor',
  'hasOwnProperty',
  'isPrototypeOf',
  'propertyIsEnumerable',
  'toLocaleString',
  'toString',
  'valueOf',
];

/** Checks a destination declaration; see {@link DeclaredDestination}. */
function validateDestination(
  entry: Record<string, unknown>,
): DeclaredDestination {
  const fail = (message: string): never => {
    throw new Error(`destination: ${message}`);
  };

  const object = (value: unknown, keys: string[]) => {
    if (!value || typeof value !== 'object' || Array.isArray(value))
      fail('expected a map');
    const result = value as Record<string, unknown>;
    for (const key of Object.keys(result))
      if (!keys.includes(key)) fail(`unknown field \`${key}\``);

    return result;
  };

  const text = (value: unknown, what: string) => {
    if (typeof value !== 'string' || !value.trim() || value.length > 1024)
      fail(`${what} must be nonempty text`);

    return value as string;
  };

  // A term to reuse instead of minting one: absolute https, no credentials.
  const subject = (value: unknown, what: string) => {
    if (value === undefined) return {};
    const url = text(value, `${what} subject`);
    let parsed: URL | undefined;

    try {
      parsed = new URL(url);
    } catch {
      parsed = undefined;
    }

    if (
      parsed?.protocol !== 'https:' ||
      parsed.username ||
      parsed.password ||
      parsed.href !== url
    )
      fail(`${what} subject must be an https URL`);

    return { subject: url };
  };

  const shortnames = (value: unknown, what: string) => {
    if (value === undefined) return [];
    if (!Array.isArray(value)) fail(`${what} must be a list`);

    return (value as unknown[]).map(item => {
      if (typeof item !== 'string' || !SHORTNAME.test(item))
        fail(`${what} must list shortnames`);

      return item as string;
    });
  };

  object(entry, ['schema', 'table', 'tables']);
  const schema = object(entry.schema, ['properties', 'classes']);
  if (!Array.isArray(schema.properties) || !Array.isArray(schema.classes))
    fail('schema needs properties and classes lists');
  const properties = (schema.properties as unknown[]).map(raw => {
    const property = object(raw, [
      'subject',
      'shortname',
      'name',
      'description',
      'datatype',
    ]);
    const shortname = text(property.shortname, 'property shortname');
    if (!SHORTNAME.test(shortname)) fail(`invalid shortname ${shortname}`);
    const datatype = text(property.datatype, 'property datatype');
    if (!/^https:\/\/atomicdata\.dev\/datatypes\/[a-zA-Z]+$/.test(datatype))
      fail(`unsupported datatype ${datatype}`);

    return {
      ...subject(property.subject, 'property'),
      shortname,
      name: text(property.name, 'property name'),
      description: text(property.description, 'property description'),
      datatype,
    };
  });
  const known = new Set(properties.map(p => p.shortname));
  if (known.size !== properties.length || known.size > 64)
    fail('property shortnames must be unique, at most 64');
  const classes = (schema.classes as unknown[]).map(raw => {
    const klass = object(raw, [
      'subject',
      'shortname',
      'name',
      'description',
      'requires',
      'recommends',
    ]);
    const shortname = text(klass.shortname, 'class shortname');
    if (!SHORTNAME.test(shortname)) fail(`invalid shortname ${shortname}`);
    const requires = shortnames(klass.requires, 'requires');
    const recommends = shortnames(klass.recommends, 'recommends');
    if ([...requires, ...recommends].some(name => !known.has(name)))
      fail(`class ${shortname} names an undeclared property`);

    return {
      ...subject(klass.subject, 'class'),
      shortname,
      name: text(klass.name, 'class name'),
      description: text(klass.description, 'class description'),
      ...(klass.requires !== undefined ? { requires } : {}),
      ...(klass.recommends !== undefined ? { recommends } : {}),
    };
  });
  if (
    classes.length === 0 ||
    classes.length > 8 ||
    new Set(classes.map(c => c.shortname)).size !== classes.length
  )
    fail('declare one to eight uniquely named classes');

  const table = (raw: unknown): DeclaredDestinationTable => {
    const declared = object(raw, ['name', 'rowClass', 'columns']);
    const rowClass = text(declared.rowClass, 'table rowClass');
    if (!classes.some(c => c.shortname === rowClass))
      fail('table rowClass must name a class in schema');
    const columns = shortnames(declared.columns, 'table columns');
    if (columns.some(name => !known.has(name)))
      fail('table columns must name properties in schema');

    return { name: text(declared.name, 'table name'), rowClass, columns };
  };

  if (entry.table === undefined && entry.tables === undefined)
    fail('declare `table` or `tables`');
  const primary = entry.table === undefined ? undefined : table(entry.table);
  let keyed: Record<string, DeclaredDestinationTable> | undefined;

  if (entry.tables !== undefined) {
    const declared = object(entry.tables, Object.keys(entry.tables ?? {}));
    const keys = Object.keys(declared);
    if (keys.length === 0) fail('tables must not be empty');
    keyed = {};

    for (const key of keys) {
      if (!TABLE_KEY.test(key) || RESERVED_KEYS.includes(key))
        fail(
          'table keys must be identifiers of letters and digits starting with a lower-case letter, at most 64',
        );
      keyed[key] = table(declared[key]);
    }
  }

  const rowClasses = [
    ...(primary ? [primary.rowClass] : []),
    ...Object.values(keyed ?? {}).map(t => t.rowClass),
  ];
  if (new Set(rowClasses).size !== rowClasses.length)
    fail('each table needs its own rowClass');

  return {
    schema: { properties, classes },
    ...(primary ? { table: primary } : {}),
    ...(keyed ? { tables: keyed } : {}),
  };
}

const PROXY_PLATFORM = /^[A-Za-z0-9_-]{1,64}$/;
const PROXY_PLATFORMS_RULE =
  'proxy platforms must be unique identifiers of letters, digits, `-` and `_`';
const PROXY_URL_RULE =
  'atomic-proxy: URLs are `atomic-proxy:/<platform>/<path>`, with no dot segments, backslashes, fragment or (in an operation) query';

const SIDECAR_URL_RULE =
  'atomic-sidecar: URLs are `atomic-sidecar:/<name>/<path>`, with no dot segments, backslashes, fragment or (in an operation) query';
const SIDECAR_NAME = /^[a-z0-9-]{1,64}$/;

/** An `atomic-sidecar:/<name>/<path>?<query>` URL, split. */
export interface SidecarRelativeUrl {
  name: string;
  /** Starts with `/`. */
  path: string;
  query?: string;
}

/**
 * Splits an `atomic-sidecar:` URL the way the server does
 * (`SidecarRelative::parse` in `server/src/plugins/manifest.rs`): the path
 * rules of `atomic-proxy:`, and a name as `http.sidecars` names one. Returns
 * `undefined` for any other URL and throws for a malformed one.
 */
export function parseSidecarRelative(
  raw: string,
): SidecarRelativeUrl | undefined {
  if (!raw.startsWith('atomic-sidecar:')) return undefined;
  let split: ProxyRelativeUrl | undefined;

  try {
    split = parseProxyRelative(
      `atomic-proxy:${raw.slice('atomic-sidecar:'.length)}`,
    );
  } catch {
    throw new Error(SIDECAR_URL_RULE);
  }

  if (!split || !SIDECAR_NAME.test(split.platform))
    throw new Error(SIDECAR_URL_RULE);

  return {
    name: split.platform,
    path: split.path,
    ...(split.query !== undefined ? { query: split.query } : {}),
  };
}

/** An `atomic-proxy:/<platform>/<path>?<query>` URL, split. */
export interface ProxyRelativeUrl {
  platform: string;
  /** Starts with `/`. */
  path: string;
  query?: string;
}

/**
 * Splits an `atomic-proxy:` URL the way the server does
 * (`ProxyRelative::parse` in `server/src/plugins/manifest.rs`). Returns
 * `undefined` for any other URL and throws for a malformed one.
 */
export function parseProxyRelative(raw: string): ProxyRelativeUrl | undefined {
  if (!raw.startsWith('atomic-proxy:')) return undefined;
  const rest = raw.slice('atomic-proxy:'.length);
  if (rest.includes('#') || rest.includes('\\'))
    throw new Error(PROXY_URL_RULE);
  const q = rest.indexOf('?');
  const pathPart = q === -1 ? rest : rest.slice(0, q);
  const query = q === -1 ? undefined : rest.slice(q + 1);
  if (!pathPart.startsWith('/')) throw new Error(PROXY_URL_RULE);
  const slash = pathPart.indexOf('/', 1);
  if (slash === -1) throw new Error(PROXY_URL_RULE);
  const platform = pathPart.slice(1, slash);
  const path = pathPart.slice(slash + 1);
  if (!PROXY_PLATFORM.test(platform) || !path) throw new Error(PROXY_URL_RULE);

  const dot = (segment: string) => {
    const decoded = segment.toLowerCase().replaceAll('%2e', '.');

    return decoded === '.' || decoded === '..';
  };

  if (path.split('/').some(dot) || path.toLowerCase().includes('%2f'))
    throw new Error(PROXY_URL_RULE);

  return {
    platform,
    path: `/${path}`,
    ...(query !== undefined ? { query } : {}),
  };
}
