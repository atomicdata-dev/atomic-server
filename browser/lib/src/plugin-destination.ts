import { core } from './ontologies/core.js';
import { dataBrowser } from './ontologies/dataBrowser.js';
import { pluginSchema } from './plugin-log.js';
import type {
  DeclaredDestination,
  DeclaredDestinationTable,
} from './plugin-manifest.js';
import {
  ensureSchema,
  findSchema,
  type SchemaResource,
  type SchemaSpec,
  type SchemaStore,
} from './plugin-schema.js';
import type { JSONObject, JSONValue } from './value.js';

/** One table Set up created: its subject and the subject of its row class. */
export interface DestinationTable {
  table: string;
  rowClass: string;
}

/**
 * The config Set up stores for a `destination`. `table`/`rowClass` are there
 * when the manifest declares `table`, `tables` when it declares `tables`.
 */
export interface DestinationConfig {
  table?: string;
  rowClass?: string;
  tables?: Record<string, DestinationTable>;
  /** Every property of the destination schema, by shortname. */
  properties: Record<string, string>;
}

/** The localId of the table `destination.table` creates, kept from before `tables`. */
const PRIMARY_TABLE = 'atomic:destination:table';
const tableLocalId = (key: string) => `atomic:destination:tables:${key}`;
const DEFAULT_VIEW = 'atomic:destination:default-view';

async function ensureChild(
  store: SchemaStore,
  drive: string,
  parent: string,
  localId: string,
  isA: string,
  propVals: Record<string, JSONValue>,
): Promise<SchemaResource> {
  const existing = await store.findByLocalId(drive, parent, localId);

  if (!existing) {
    // Created whole: a Table's genesis commit must already carry its
    // required classtype.
    const created = await store.newResource({
      parent,
      isA: [isA],
      propVals: { ...propVals, [core.properties.localId]: localId },
    });
    await created.save();

    return created;
  }

  for (const [property, value] of Object.entries(propVals))
    await existing.set(property, value);
  await existing.save();

  return existing;
}

/** One declared table beneath the plugin, with a default table view of its columns. */
async function ensureTable(
  store: SchemaStore,
  drive: string,
  plugin: string,
  localId: string,
  declared: DeclaredDestinationTable,
  terms: {
    classes: Record<string, string>;
    properties: Record<string, string>;
  },
): Promise<DestinationTable> {
  const rowClass = terms.classes[declared.rowClass];
  const table = await ensureChild(
    store,
    drive,
    plugin,
    localId,
    dataBrowser.classes.table,
    {
      [core.properties.name]: declared.name,
      [core.properties.classtype]: rowClass,
    },
  );
  const view = await ensureChild(
    store,
    drive,
    table.subject,
    DEFAULT_VIEW,
    dataBrowser.classes.view,
    {
      [core.properties.name]: declared.name,
      [dataBrowser.properties.viewKind]: 'table',
      [dataBrowser.properties.viewColumns]: declared.columns.map(
        column => terms.properties[column],
      ),
    },
  );
  await table.set(dataBrowser.properties.tableViews, [view.subject]);
  await table.set(dataBrowser.properties.tableDefaultView, view.subject);
  await table.save();

  return { table: table.subject, rowClass };
}

/**
 * Creates what a `destination` declares and stores it as the plugin's config:
 * the schema in the drive's ontology, each declared table beneath the plugin
 * with a default table view, and the {@link DestinationConfig} under the
 * manifest's config key. Resumes the same resources when repeated, so a lost
 * response, a second click or a release that adds a table to `tables` does not
 * create a second copy of any table.
 *
 * A manifest that declares only `table` gets exactly the config it always did:
 * `{ table, rowClass, properties }`.
 */
export async function provisionDestination(
  store: SchemaStore,
  drive: string,
  plugin: string,
  destination: DeclaredDestination,
  key: string | undefined,
): Promise<DestinationConfig> {
  const terms = await ensureSchema(
    store,
    drive,
    destination.schema as SchemaSpec,
  );
  const primary = destination.table
    ? await ensureTable(
        store,
        drive,
        plugin,
        PRIMARY_TABLE,
        destination.table,
        terms,
      )
    : undefined;
  let tables: Record<string, DestinationTable> | undefined;

  if (destination.tables) {
    tables = {};

    for (const [name, declared] of Object.entries(destination.tables))
      tables[name] = await ensureTable(
        store,
        drive,
        plugin,
        tableLocalId(name),
        declared,
        terms,
      );
  }

  const config: DestinationConfig = {
    ...(primary ?? {}),
    ...(tables ? { tables } : {}),
    properties: terms.properties,
  };
  const pluginTerms = await ensureSchema(store, drive, pluginSchema());
  const resource = await store.getResource(plugin);
  const stored = resource.get(pluginTerms.properties['plugin-schemas']);
  const current =
    stored && typeof stored === 'object' && !Array.isArray(stored)
      ? (stored as JSONObject)
      : {};
  const value = config as unknown as JSONObject;
  await resource.set(
    pluginTerms.properties['plugin-schemas'],
    key ? { ...current, [key]: value } : { ...current, ...value },
  );
  // Where the plugin's page links to: the first table it writes.
  const workspace = primary ?? Object.values(tables ?? {})[0];
  if (workspace)
    await resource.set(
      pluginTerms.properties['plugin-workspace'],
      workspace.table,
    );
  await resource.save();

  return config;
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  const decoded =
    typeof value === 'string'
      ? (() => {
          try {
            return JSON.parse(value) as unknown;
          } catch {
            return undefined;
          }
        })()
      : value;

  return decoded && typeof decoded === 'object' && !Array.isArray(decoded)
    ? (decoded as Record<string, unknown>)
    : undefined;
}

function readTables(
  value: unknown,
): Record<string, DestinationTable> | undefined {
  const tables = asObject(value);
  if (!tables) return undefined;
  const result: Record<string, DestinationTable> = {};

  for (const [key, entry] of Object.entries(tables)) {
    const table = asObject(entry);
    if (typeof table?.table === 'string' && typeof table.rowClass === 'string')
      result[key] = { table: table.table, rowClass: table.rowClass };
  }

  return Object.keys(result).length ? result : undefined;
}

/**
 * The keyed tables of the destination `table` belongs to, if Set up created it
 * together with others. How a drive app shown as a view of one of those tables
 * finds its siblings (`store.getData().tables`).
 *
 * Read-only, and only reads what the app could already read: the table's
 * parent plugin and the config Set up stored on it.
 */
export async function destinationTablesFor(
  store: SchemaStore,
  drive: string,
  table: string,
): Promise<Record<string, DestinationTable> | undefined> {
  const tableResource = await store.getResource(table);
  const parent = tableResource.get(core.properties.parent);
  if (typeof parent !== 'string' || !parent) return undefined;

  const schema = await findSchema(store, drive, pluginSchema());
  const property = schema.properties?.['plugin-schemas'];
  if (!property) return undefined;

  const plugin = await store.getResource(parent);
  const stored = asObject(plugin.get(property));
  if (!stored) return undefined;

  // Flat, or under the manifest's config key.
  for (const candidate of [stored, ...Object.values(stored).map(asObject)]) {
    const tables = readTables(candidate?.tables);
    if (!tables) continue;
    if (
      candidate?.table === table ||
      Object.values(tables).some(entry => entry.table === table)
    )
      return tables;
  }

  return undefined;
}
