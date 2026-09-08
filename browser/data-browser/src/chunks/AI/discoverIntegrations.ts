// @wc-ignore-file
import {
  core,
  findSchema,
  pluginSchema,
  readConnectionSubjects,
  listIntegrationActions,
  type Store,
} from '@tomic/lib';

/** Read local connection metadata and host action declarations, never provider records. */
export async function discoverIntegrations(
  store: Store,
  drive: string,
  query = '',
) {
  const schema = await findSchema(store, drive, pluginSchema());
  const klass = schema.classes?.['plugin-script'];
  const connection = schema.properties?.['plugin-connection'];
  if (!klass || !connection) return { connections: [], errors: [] };
  const subjects = await readConnectionSubjects(
    store,
    drive,
    core.properties.isA,
    klass,
  );
  const connections = [];
  const errors = [];
  const terms = query.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);

  // Sequential host lookups avoid a burst of requests on large drives.
  for (const subject of subjects) {
    try {
      const resource = await store.getResource(subject);
      if (!resource.get(connection)) continue;
      const catalog = await listIntegrationActions(store, {
        drive,
        plugin: subject,
      });
      const name = String(resource.get(core.properties.name) ?? subject);
      const searchable = [
        name,
        ...catalog.tools.flatMap(t => [t.name, t.title, t.description]),
      ]
        .join(' ')
        .toLocaleLowerCase();

      if (terms.every(term => searchable.includes(term))) {
        connections.push({
          integration: subject,
          name,
          release: catalog.release,
          actions: catalog.tools,
        });
      }
    } catch (error) {
      errors.push({ integration: subject, error: String(error) });
    }
  }

  return { connections, errors };
}
