/** Installs schema, kanban, sandbox source and a private connection. */
import {
  Store,
  core,
  dataBrowser,
  Datatype,
  ensureSchema,
  findSchema,
  pluginSchema,
  signRequest,
  taskSchema,
  readConnectionSubjects,
} from '../../browser/lib/src/index.js';
import { pinPluginRelease } from '../../browser/lib/src/plugin-connection.js';
import { manifest, type Status } from './adapter.js';

export interface Connection {
  repository: string;
  drive: string;
  plugin: string;
  release: string;
  table: string;
  rowClass: string;
  status: string;
  number: string;
  body: string;
  arrival: string;
  tags: Record<Status, string>;
}
export async function install(
  store: Store,
  drive: string,
  repository: string,
  source: string,
  token?: string,
  targetTable?: string,
): Promise<Connection> {
  const declaration = manifest(repository);
  const target = targetTable
    ? (await compatibleTables(store, drive)).find(
        t => t.subject === targetTable,
      )
    : undefined;
  if (targetTable && !target)
    throw new Error('Choose a compatible task table on this drive');
  const schema = await ensureSchema(store, drive, pluginSchema());
  const plugin = await store.newResource({
    parent: drive,
    isA: [schema.classes['plugin-script']],
    propVals: {
      [core.properties.name]: `GitHub issues: ${repository}`,
      [dataBrowser.properties.emoji]: '🐙',
      [schema.properties['plugin-source']]:
        `${source}\nexport const manifest = ${JSON.stringify(declaration)};`,
    },
  });
  await plugin.save();
  const create = async (
    parent: string,
    isA: string[],
    propVals: Record<string, string | string[]>,
  ) => {
    const r = await store.newResource({
      parent,
      isA,
      propVals: {
        [core.properties.description]: 'GitHub issues pilot',
        ...propVals,
      },
    });
    if ((await r.save()) === 'offline')
      throw new Error('AtomicServer disconnected during installation');
    await store.fetchResourceFromServer(r.subject, { noWebSocket: true });
    return r;
  };
  const status = await store.getResource(taskSchema.properties.status);
  const tags: Record<Status, string> = {
    Todo: taskSchema.tags.Todo,
    Doing: taskSchema.tags.Doing,
    Done: taskSchema.tags.Done,
  };
  const number = await create(plugin.subject, [core.classes.property], {
    [core.properties.name]: 'GitHub issue number',
    [core.properties.shortname]: 'github-issue-number',
    [core.properties.datatype]: Datatype.INTEGER,
  });
  const body = await store.getResource(taskSchema.properties.body);
  const arrival = await create(plugin.subject, [core.classes.property], {
    [core.properties.name]: 'Issue discovery',
    [core.properties.shortname]: 'github-issue-discovery',
    [core.properties.datatype]: Datatype.STRING,
  });
  const rowClass = target
    ? await store.getResource(target.rowClass)
    : await create(plugin.subject, [core.classes.class], {
        [core.properties.name]: 'GitHub issue',
        [core.properties.shortname]: 'github-issue',
        [core.properties.requires]: [core.properties.name],
        [core.properties.recommends]: [
          core.properties.name,
          body.subject,
          status.subject,
          number.subject,
        ],
      });
  const table = target
    ? await store.getResource(target.subject)
    : await create(plugin.subject, [dataBrowser.classes.table], {
        [core.properties.name]: `${repository} issues`,
        [core.properties.classtype]: rowClass.subject,
      });
  if (!target) {
    const view = await create(table.subject, [dataBrowser.classes.view], {
      [core.properties.name]: 'Kanban',
      [dataBrowser.properties.viewKind]: 'kanban',
      [dataBrowser.properties.viewGroupBy]: status.subject,
      [dataBrowser.properties.viewColumns]: [
        core.properties.name,
        body.subject,
        status.subject,
        number.subject,
      ],
    });
    await table.set(dataBrowser.properties.tableViews, [view.subject]);
    await table.set(dataBrowser.properties.tableDefaultView, view.subject);
    await table.save();
  }
  if (token) {
    const url = `${store.getServerUrl()}/plugin-secret`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        ...(await signRequest(url, store.getAgent()!, {})),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        drive,
        plugin: plugin.subject,
        name: 'github',
        value: `Bearer ${token}`,
        origins: ['https://api.github.com'],
      }),
    });
    if (!response.ok)
      throw new Error('Could not store GitHub credential on AtomicServer');
  }
  await plugin.set(schema.properties['plugin-schemas'], {
    row: rowClass.subject,
    status: status.subject,
    number: number.subject,
    body: body.subject,
  });
  await plugin.save();
  const pinned = await pinPluginRelease(store, {
    drive,
    plugin: plugin.subject,
  });
  const connection = {
    repository,
    drive,
    plugin: plugin.subject,
    release: pinned.id,
    table: table.subject,
    rowClass: rowClass.subject,
    status: status.subject,
    number: number.subject,
    body: body.subject,
    arrival: arrival.subject,
    tags,
  };
  await plugin.set(schema.properties['plugin-connection'], {
    release: pinned.id,
    config: connection,
    events: [
      {
        id: 'issue-discovered',
        name: 'New issue discovered',
        description:
          'Fires for issues first discovered after the initial sync. Excludes initial imports and issues created from Atomic cards.',
        filters: [
          { property: core.properties.parent, value: table.subject },
          { property: core.properties.isA, value: rowClass.subject },
          { property: number.subject },
          { property: arrival.subject, value: 'remote' },
        ],
      },
    ],
  });
  await plugin.save();
  return connection;
}

/** Identity-based compatibility. A matching display label is not a schema mapping. */
export async function compatibleTables(store: Store, drive: string) {
  const subjects = await readConnectionSubjects(
    store,
    drive,
    core.properties.isA,
    dataBrowser.classes.table,
  );
  const result: Array<{ subject: string; name: string; rowClass: string }> = [];
  const pluginTerms = await findSchema(store, drive, pluginSchema());
  const pluginClass = pluginTerms.classes?.['plugin-script'];
  const connectionProperty = pluginTerms.properties?.['plugin-connection'];
  const occupied = new Set<string>();
  if (pluginClass && connectionProperty) {
    for (const subject of await readConnectionSubjects(
      store,
      drive,
      core.properties.isA,
      pluginClass,
    )) {
      const resource = await store.getResource(subject);
      const raw = resource.get(connectionProperty);
      const connection = typeof raw === 'string' ? JSON.parse(raw) : raw;
      if (
        connection &&
        typeof connection === 'object' &&
        !Array.isArray(connection)
      ) {
        const config = connection.config;
        if (
          config &&
          typeof config === 'object' &&
          !Array.isArray(config) &&
          typeof config.table === 'string'
        )
          occupied.add(config.table);
      }
    }
  }
  for (const subject of subjects) {
    if (occupied.has(subject)) continue;
    const table = await store.getResource(subject);
    const klass = table.get(core.properties.classtype);
    if (typeof klass !== 'string') continue;
    const row = await store.getResource(klass);
    const properties = [
      ...((row.get(core.properties.requires) as string[]) ?? []),
      ...((row.get(core.properties.recommends) as string[]) ?? []),
    ];
    if (
      [taskSchema.properties.status, taskSchema.properties.body].every(p =>
        properties.includes(p),
      )
    ) {
      result.push({
        subject,
        rowClass: klass,
        name: String(table.get(core.properties.name) ?? subject),
      });
    }
  }
  return result;
}
