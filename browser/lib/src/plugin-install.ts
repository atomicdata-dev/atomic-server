/**
 * One install path for both plugin runtimes.
 *
 * A Release is an immutable, content-addressed package (JS source or a wasip2
 * zip). Installing it into a drive means committing an `Installation`
 * resource with `installationStatus: active`; the server resolves the pinned
 * release, verifies its id, checks the grants and materializes by runtime.
 * Pausing, revoking or destroying that resource undoes it. See
 * `planning/plugin-runtime-convergence.md`, "One install path and a
 * marketplace".
 */
import { signRequest } from './authentication.js';
import { Datatype } from './datatypes.js';
import { core } from './ontologies/core.js';
import { server, type Server } from './ontologies/server.js';
import type { Store } from './store.js';
import type { JSONValue } from './value.js';

export const RUNTIME_JS = 'atomic-js/1';
const WORLD_EXTENSION = 'extension';

export type InstallationStatus = 'draft' | 'active' | 'paused' | 'revoked';

/** The release record the server publishes and serves (`lib/src/db/plugin_release.rs`). */
export interface PublishedRelease {
  runtime: string;
  /** Defaults to `extension` when absent. */
  world?: string;
  manifest: JSONValue;
  source?: string;
  /** Blake3 hex of the zip bytes for `wasip2/1`. */
  package?: string;
  schemas?: Record<string, string>;
  version?: string;
  previousRelease?: string;
}

/**
 * Where an Installation finds its Release and what it pins.
 *
 * `url` is the `Release` resource the server recorded when the release was
 * published, which is what `release` is declared to hold. `id` is the content
 * hash the installer reviewed; the server refuses to install when `url`
 * resolves to anything else.
 *
 * The server still resolves a bare `blake3:` id, for Installations written
 * before every publish recorded a Release resource. Nothing writes one now.
 */
export interface ReleaseReference {
  url: string;
  id: string;
}

type CapabilityKind =
  | 'permission'
  | 'secret'
  | 'operation'
  | 'capability'
  | 'network';

/** One line of the install review: what the plugin asks for and why. */
export interface ReviewCapability {
  kind: CapabilityKind;
  title: string;
  reason?: string;
  /**
   * The grant name written to `Installation.grants` when the installer
   * approves; `check_grants` on the server requires exactly the declared
   * set. Absent for secrets, operations and network, which are declared,
   * not granted.
   */
  grant?: string;
}

export interface InstallationReview {
  name?: string;
  namespace?: string;
  description?: string;
  author?: string;
  version?: string;
  runtime: string;
  world: string;
  releaseId?: string;
  capabilities: ReviewCapability[];
  configSchema?: JSONValue;
  defaultConfig?: JSONValue;
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/**
 * Turns a release's manifest into what the review screen shows before the
 * installer approves. Drops anything malformed instead of trusting it.
 */
export function readInstallationReview(
  release: Pick<PublishedRelease, 'manifest'> &
    Partial<PublishedRelease> & { id?: string },
): InstallationReview {
  const manifest = asObject(release.manifest) ?? {};
  const capabilities: ReviewCapability[] = [];

  // A release published before plugin.json was translated at the boundary
  // still stores `permissions: [{ permission, reason }]`; the server's
  // `declared_capabilities` reads those the same way.
  for (const entry of asArray(manifest.permissions)) {
    const name = asString(entry) ?? asString(asObject(entry)?.permission);
    if (!name) continue;
    capabilities.push({
      kind: 'permission',
      title: name,
      reason: asString(asObject(entry)?.reason),
      grant: name,
    });
  }

  // Secrets and operations (`plugin-manifest.ts`).
  for (const entry of asArray(manifest.secrets)) {
    const secret = asObject(entry);
    const name = asString(secret?.name);
    if (!name) continue;
    const origin = asString(secret?.origin);
    const description = asString(secret?.description);
    capabilities.push({
      kind: 'secret',
      title: `Secret "${name}"`,
      reason: [description, origin && `Sent only to ${origin}`]
        .filter(Boolean)
        .join('. '),
    });
  }

  for (const entry of asArray(manifest.operations)) {
    const operation = asObject(entry);
    const id = asString(operation?.id);
    if (!id) continue;
    const method = asString(operation?.method) ?? 'GET';
    const url = asString(operation?.url) ?? '';
    const effect = asString(operation?.effect);
    capabilities.push({
      kind: 'operation',
      title: `${method} ${url}`.trim(),
      reason: effect ? `${id}: ${effect}s external data` : id,
    });
  }

  // `DeclaredCapability`: a bare name or `{ name, reason }`. These are what
  // `Installation.grants` records.
  for (const entry of asArray(manifest.capabilities)) {
    const object = asObject(entry);
    const name = asString(entry) ?? asString(object?.name);
    if (!name) continue;
    capabilities.push({
      kind: 'capability',
      title: name,
      reason: asString(object?.reason),
      grant: name,
    });
  }

  // `network`: coarse egress for host `fetch` without an operation id.
  const network = asObject(manifest.network);
  const origins = asArray(network?.origins).flatMap(o => asString(o) ?? []);

  if (origins.length > 0) {
    capabilities.push({
      kind: 'network',
      title: `Network access to ${origins.join(', ')}`,
      reason: asString(network?.reason),
    });
  }

  return {
    name: asString(manifest.name),
    namespace: asString(manifest.namespace),
    description: asString(manifest.description),
    author: asString(manifest.author),
    version: release.version ?? asString(manifest.version),
    runtime: release.runtime ?? RUNTIME_JS,
    world: release.world ?? WORLD_EXTENSION,
    releaseId: release.id,
    capabilities,
    configSchema: manifest.configSchema as JSONValue | undefined,
    defaultConfig: manifest.defaultConfig as JSONValue | undefined,
  };
}

/** The grant names an installer approves when accepting the whole review. */
export function grantsFor(review: InstallationReview): string[] {
  return review.capabilities.flatMap(c => (c.grant ? [c.grant] : []));
}

/** Namespace for releases whose manifest declares none (catalog JS releases). */
export const DEFAULT_INSTALLATION_NAMESPACE = 'community';

/**
 * A plugin identifier the server accepts (`validate_plugin_identifier`):
 * ASCII letters, digits, `-` and `_`, at most 128 characters.
 */
export function installationIdentifier(name: string): string {
  const cleaned = name
    .trim()
    .replace(/[^A-Za-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 128);

  return cleaned || 'plugin';
}

export interface InstallReleaseOptions {
  drive: string;
  release: ReleaseReference;
  /** Plugin identifier on the drive; for wasip2 it must equal the manifest's name. */
  name: string;
  /** For wasip2 it must equal the manifest's namespace. */
  namespace?: string;
  description?: string;
  version?: string;
  config?: JSONValue;
  /** Capability names the installer approved. */
  grants: string[];
  /** Committing `active` (the default) is what installs. */
  status?: InstallationStatus;
}

/**
 * Creates and saves an `Installation` under the drive. The server's commit
 * hook does the actual install; the returned subject is the resource to
 * open, pause, revoke or destroy.
 */
export async function installRelease(
  store: Store,
  options: InstallReleaseOptions,
): Promise<string> {
  const {
    drive,
    release,
    name,
    namespace,
    description,
    version,
    config,
    grants,
    status = 'active',
  } = options;
  const propVals: Record<string, JSONValue> = {
    [core.properties.name]: name,
    // `release` belongs in the genesis commit, not in a `set` after it.
    // `store.newResource` signs the genesis from these propvals alone, and
    // `save()` sends it first; a property the class requires that is only set
    // afterwards is missing from the commit the server validates, which
    // refuses it and drops the whole installation.
    [server.properties.release]: release.url,
    [server.properties.releaseId]: release.id,
    [server.properties.installationStatus]: status,
    [server.properties.grants]: grants,
  };
  if (namespace) propVals[server.properties.namespace] = namespace;
  if (description) propVals[core.properties.description] = description;
  if (version) propVals[server.properties.version] = version;
  if (config !== undefined) propVals[server.properties.config] = config;

  const installation = await store.newResource<Server.Installation>({
    isA: server.classes.installation,
    parent: drive,
    propVals,
    // These built-in Installation fields are validated locally and by the
    // server. Their Property URLs need not resolve on the public ontology
    // site. JSON tags preserve grants/config as JSON in the Loro genesis.
    propDatatypes: {
      [core.properties.name]: Datatype.STRING,
      [core.properties.description]: Datatype.MARKDOWN,
      [server.properties.release]: Datatype.ATOMIC_URL,
      [server.properties.releaseId]: Datatype.STRING,
      [server.properties.installationStatus]: Datatype.STRING,
      [server.properties.grants]: Datatype.JSON,
      [server.properties.namespace]: Datatype.STRING,
      [server.properties.version]: Datatype.STRING,
      [server.properties.config]: Datatype.JSON,
    },
  });
  await installation.save();

  return installation.subject;
}

export interface UpdateReleaseOptions {
  release: ReleaseReference;
  /** Capability names the installer approved for the new release. */
  grants: string[];
  config?: JSONValue;
  version?: string;
}

/**
 * Repoints an existing `Installation` at another release, in place.
 *
 * This is how a plugin is updated: the resource keeps its subject, its config
 * and the agent it signs as, so everything it already owns stays its own. The
 * server re-runs the activation, which verifies the new id, checks the grants
 * and puts the new code on disk.
 *
 * All of it is one commit on purpose. `check_grants` requires the grants to
 * equal what the new release declares, so a release that asks for a capability
 * the old grants do not cover would be refused if the release landed first.
 */
export async function updateInstallationRelease(
  store: Store,
  installation: string,
  options: UpdateReleaseOptions,
): Promise<void> {
  const { release, grants, config, version } = options;
  const resource = await store.getResource<Server.Installation>(installation);

  await resource.set(
    server.properties.releaseId,
    release.id,
    false,
    Datatype.STRING,
  );
  await resource.set(
    server.properties.release,
    release.url,
    false,
    Datatype.ATOMIC_URL,
  );
  await resource.set(server.properties.grants, grants, false, Datatype.JSON);

  if (version !== undefined) {
    await resource.set(
      server.properties.version,
      version,
      false,
      Datatype.STRING,
    );
  }

  if (config !== undefined) {
    await resource.set(server.properties.config, config, false, Datatype.JSON);
  }

  await resource.save();
}

type InstallStore = Pick<Store, 'getAgent' | 'getServerUrl'>;

/**
 * Publishes a wasip2 zip as a private release on the store's server and
 * returns its id, the `Release` resource the server recorded for it, and the
 * record itself, so the caller can review and install it without a second
 * request.
 *
 * `subject` is what an Installation's `release` points at. Take it from here
 * rather than passing the id: the id is not a URL, and the property is.
 */
export async function publishZipRelease(
  store: InstallStore,
  drive: string,
  file: Blob,
  options: { world?: string; public?: boolean } = {},
  transport: typeof fetch = fetch,
): Promise<{ id: string; subject: string; release: PublishedRelease }> {
  const agent = store.getAgent();
  if (!agent) throw new Error('sign in before publishing a plugin release');
  const url = new URL('/plugin-release-package', store.getServerUrl());
  url.searchParams.set('drive', drive);
  if (options.world) url.searchParams.set('world', options.world);
  if (options.public) url.searchParams.set('public', 'true');
  const bytes = await file.arrayBuffer();
  const response = await transport(url.toString(), {
    method: 'POST',
    headers: {
      ...(await signRequest(
        url.toString(),
        agent,
        {},
        {
          method: 'POST',
          body: bytes,
        },
      )),
      'Content-Type': 'application/zip',
    },
    body: bytes,
  });
  if (!response.ok) throw new Error(await response.text());

  return response.json() as Promise<{
    id: string;
    subject: string;
    release: PublishedRelease;
  }>;
}
