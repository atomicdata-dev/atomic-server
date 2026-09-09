import { core } from './ontologies/core.js';
import { findSchema } from './plugin-schema.js';
import { pluginSchema } from './plugin-log.js';
import { readConnectionSubjects } from './plugin-connection.js';
import type { Store } from './store.js';

function object(value: unknown): Record<string, unknown> {
  const decoded = typeof value === 'string' ? JSON.parse(value) : value;

  return decoded && typeof decoded === 'object' && !Array.isArray(decoded)
    ? (decoded as Record<string, unknown>)
    : {};
}

/** Workspace association is navigation, never authority or containment. */
export function pluginWorkspace(
  resource: { get(property: string): unknown },
  properties: Record<string, string>,
): string | undefined {
  const read = (name: string) =>
    properties[name] ? resource.get(properties[name]) : undefined;
  const explicit = read('plugin-workspace');

  if (explicit !== undefined) {
    if (typeof explicit !== 'string' || !explicit.trim())
      throw new Error('Invalid workspace relationship');

    return explicit;
  }

  // Read-only compatibility for installed releases. Never change their parent,
  // source, approval or private sync state just because someone opens a view.
  const connection = object(read('plugin-connection'));
  const schemas = object(read('plugin-schemas'));
  const table =
    object(connection.config).table ??
    schemas.table ??
    object(schemas.mt940).table;
  if (table === undefined) return undefined;
  if (typeof table !== 'string' || !table.trim())
    throw new Error('Invalid connection destination');

  return table;
}

export interface WorkspaceConnection {
  subject: string;
  name: string;
  workspace: string;
}

/** Existing drives need the class query until their old JSON bindings migrate.
 * readConnectionSubjects is authorized, paginated and fails on incomplete data.
 * This runs on opening workspace controls, not on each table or row render.
 */
export async function workspaceConnections(
  store: Store,
  drive: string,
  workspace: string,
): Promise<WorkspaceConnection[]> {
  const schema = await findSchema(store, drive, pluginSchema());
  const klass = schema.classes?.['plugin-script'];
  if (!klass) return [];
  const subjects = await readConnectionSubjects(
    store,
    drive,
    core.properties.isA,
    klass,
  );
  const result: WorkspaceConnection[] = [];

  for (const subject of subjects) {
    const resource = await store.getResource(subject);
    if (resource.error) throw resource.error;
    const usage = schema.properties?.['automation-integrations'];
    if (usage && resource.get(usage)) continue;

    // Only resolve configuration for a complete installed resource.
    if (pluginWorkspace(resource, schema.properties ?? {}) === workspace) {
      result.push({ subject, name: resource.title || subject, workspace });
    }
  }

  return result.sort((a, b) => a.name.localeCompare(b.name));
}
