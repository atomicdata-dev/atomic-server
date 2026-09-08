// @wc-ignore-file
/** Shared installer for browser/CLI. Only the host contacts Notion. */
import {
  Store,
  core,
  dataBrowser,
  Datatype,
  ensureSchema,
  pluginSchema,
  signRequest,
  type JSONValue,
} from '../../browser/lib/src/index.js';
import {
  pinPluginRelease,
  readExternalOperation,
} from '../../browser/lib/src/plugin-connection.js';
import {
  manifest,
  uuid,
  request,
  parse,
  types,
  projectView,
  P,
  type Config,
  type FieldType,
} from './model.js';
export interface Connection extends Config {
  drive: string;
  plugin: string;
  release: string;
}
export async function install(
  store: Store,
  drive: string,
  dataSource: string,
  source: string,
  token: string | { connection: string },
): Promise<Connection> {
  const id = uuid(dataSource);
  if (typeof token === 'string' && !token.trim())
    throw new Error('A Notion connection token is required');
  if (typeof source !== 'string' || !source.trim())
    throw new Error('Notion provider bundle did not load');
  const schema = await ensureSchema(store, drive, pluginSchema());
  const plugin = await store.newResource({
    parent: drive,
    isA: [schema.classes['plugin-script']],
    propVals: {
      [core.properties.name]: 'Notion data source',
      [dataBrowser.properties.emoji]: '📓',
      [schema.properties['plugin-source']]:
        `${source}\nexport const manifest=${JSON.stringify(manifest(id))};`,
    },
  });
  await plugin.save();
  const secretUrl = `${store.getServerUrl()}/${typeof token === 'string' ? 'plugin-secret' : 'integration-oauth/notion/bind'}`;
  const response = await fetch(secretUrl, {
    method: 'POST',
    headers: {
      ...(await signRequest(secretUrl, store.getAgent()!, {})),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(
      typeof token === 'string'
        ? {
            drive,
            plugin: plugin.subject,
            name: 'notion',
            value: `Bearer ${token}`,
            origins: ['https://api.notion.com'],
          }
        : { drive, plugin: plugin.subject, connection: token.connection },
    ),
  });
  if (!response.ok) throw new Error('Could not store Notion credential');
  const pinned = await pinPluginRelease(store, {
    drive,
    plugin: plugin.subject,
  });
  const read = async (operation: string, path: string) =>
    parse(
      await readExternalOperation(store, {
        drive,
        plugin: plugin.subject,
        release: pinned.id,
        run: 'setup',
        intent: request(operation, 'GET', path),
      }),
    );
  const sourceSchema = await read('schema', `/data_sources/${id}`);
  if (uuid(sourceSchema.id) !== id) throw new Error('Unexpected data source');
  const warnings: string[] = [];
  const create = async (
    parent: string,
    isA: string[],
    values: Record<string, JSONValue>,
  ) => {
    const r = await store.newResource({
      parent,
      isA,
      propVals: {
        [core.properties.description]: 'Notion connection mapping',
        ...values,
      },
    });
    if ((await r.save()) === 'offline')
      throw new Error('AtomicServer disconnected during installation');
    return r;
  };
  const prop = async (
    label: string,
    shortname: string,
    datatype: Datatype,
    select = false,
  ) =>
    create(
      plugin.subject,
      [
        core.classes.property,
        ...(select ? [dataBrowser.classes.selectProperty] : []),
      ],
      {
        [core.properties.name]: label,
        [core.properties.shortname]: shortname,
        [core.properties.datatype]: datatype,
        ...(select
          ? {
              [core.properties.classtype]: dataBrowser.classes.tag,
              [core.properties.allowsOnly]: [],
            }
          : {}),
      },
    );
  const identity = await prop(
    'Notion page ID',
    'notion-page-id',
    Datatype.STRING,
  );
  const arrival = await prop(
    'Notion discovery',
    'notion-discovery',
    Datatype.STRING,
  );
  const fields: Config['fields'] = [];
  for (const p of Object.values(sourceSchema.properties) as any[]) {
    if (!types.includes(p.type)) {
      warnings.push(`${p.name}: ${p.type} is preserved in Notion, not synced`);
      continue;
    }
    const select = ['select', 'multi_select', 'status'].includes(p.type);
    const property = await prop(
      p.name,
      `notion-field-${fields.length}`,
      select
        ? Datatype.RESOURCEARRAY
        : p.type === 'number'
          ? Datatype.FLOAT
          : p.type === 'checkbox'
            ? Datatype.BOOLEAN
            : Datatype.STRING,
      select,
    );
    const field: Config['fields'][number] = {
      id: p.id,
      property: property.subject,
      type: p.type as FieldType,
    };
    if (select) {
      field.options = {};
      field.optionNames = {};
      for (const o of p[p.type].options) {
        const tag = await create(property.subject, [dataBrowser.classes.tag], {
          [core.properties.name]: o.name,
          [core.properties.shortname]:
            `option-${Object.keys(field.options).length}`,
        });
        field.options[o.id] = tag.subject;
        field.optionNames[o.id] = o.name;
      }
      await property.set(
        core.properties.allowsOnly,
        Object.values(field.options),
      );
      await property.save();
    }
    fields.push(field);
  }
  if (fields.filter(f => f.type === 'title').length !== 1)
    throw new Error('Data source needs exactly one title property');
  const rowClass = await create(plugin.subject, [core.classes.class], {
    [core.properties.name]: 'Notion row',
    [core.properties.shortname]: 'notion-row',
    [core.properties.requires]: [],
    [core.properties.recommends]: fields.map(f => f.property),
  });
  const table = await create(plugin.subject, [dataBrowser.classes.table], {
    [core.properties.name]: 'Notion rows',
    [core.properties.classtype]: rowClass.subject,
  });
  const c: Connection = {
    dataSource: id,
    drive,
    plugin: plugin.subject,
    release: pinned.id,
    table: table.subject,
    rowClass: rowClass.subject,
    identity: identity.subject,
    arrival: arrival.subject,
    fields,
    views: [],
  };
  let cursor: string | undefined;
  const seen = new Set<string>();
  for (let i = 0; ; i++) {
    if (i >= 100) throw new Error('View listing exceeds pilot limit');
    const list = await read(
      'views',
      `/views?data_source_id=${id}${cursor ? `&start_cursor=${encodeURIComponent(cursor)}` : ''}`,
    );
    if (!Array.isArray(list.results) || typeof list.has_more !== 'boolean')
      throw new Error('Invalid view listing');
    for (const ref of list.results) {
      const view = await read('view', `/views/${uuid(ref.id)}`);
      let projection;
      try {
        projection = projectView(view, c);
      } catch (e) {
        warnings.push(`${view.name ?? ref.id}: ${String(e)}`);
        continue;
      }
      const v = await create(table.subject, [dataBrowser.classes.view], {
        [P.name]: String(projection.name),
        [P.kind]: view.type === 'board' ? 'kanban' : 'table',
        [P.columns]: (projection.columns as string[]).map(
          id => fields.find(f => f.id === id)!.property,
        ),
        ...(projection.group
          ? { [P.group]: fields.find(f => f.id === projection.group)!.property }
          : {}),
      });
      c.views.push({ id: uuid(view.id), subject: v.subject, kind: view.type });
      if (view.configuration)
        warnings.push(
          `${view.name}: widths, covers and other presentation details remain Notion-only; only name, visible columns and supported grouping sync`,
        );
    }
    if (!list.has_more) break;
    if (
      typeof list.next_cursor !== 'string' ||
      !list.next_cursor ||
      seen.has(list.next_cursor)
    )
      throw new Error('Incomplete view pagination');
    cursor = list.next_cursor;
    seen.add(cursor!);
  }
  const views = c.views.map(v => v.subject);
  if (!views.length) {
    const v = await create(table.subject, [dataBrowser.classes.view], {
      [P.name]: 'Atomic table',
      [P.kind]: 'table',
      [P.columns]: fields.map(f => f.property),
    });
    views.push(v.subject);
    warnings.push('No compatible Notion view; the Atomic table is local-only');
  }
  await table.set(dataBrowser.properties.tableViews, views);
  await table.set(dataBrowser.properties.tableDefaultView, views[0]);
  await table.save();
  await plugin.set(schema.properties['plugin-connection'], {
    release: pinned.id,
    config: c as unknown as JSONValue,
    warnings,
    labels: Object.fromEntries(
      (Object.values(sourceSchema.properties) as any[]).map(p => [
        p.id,
        p.name,
      ]),
    ),
    events: [
      {
        id: 'page-discovered',
        name: 'New Notion row discovered',
        description:
          'New remote rows after initial backfill; excludes Atomic-created rows',
        filters: [
          { property: P.parent, value: c.table },
          { property: c.arrival, value: 'remote' },
        ],
      },
    ],
  });
  await plugin.save();
  return c;
}
