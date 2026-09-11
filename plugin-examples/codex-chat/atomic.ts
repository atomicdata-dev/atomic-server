import {
  Agent,
  Store,
  CollectionBuilder,
  signRequest,
} from '../../browser/lib/src/index.js';
import { enableLoro } from '../../browser/lib/src/loro-loader.js';
import { createApp, updateApp } from '../../browser/lib/src/plugin-app.js';
import { ensureSchema } from '../../browser/lib/src/plugin-schema.js';
import { fields, core } from './model.mjs';
import { writeFile } from 'node:fs/promises';

export async function connect(serverUrl, secret, drive, subscribeDrive = true) {
  await enableLoro();
  const store = new Store({ serverUrl, agent: Agent.fromSecret(secret, 'js') });
  if (drive && subscribeDrive) store.setDrive(drive);
  if (!(await store.waitForServerConnected(10000)))
    throw new Error('AtomicServer did not connect');
  return store;
}
export async function children(store, drive, parent) {
  const query = new CollectionBuilder(store)
    .setDrive(drive)
    .setProperty(core + 'parent')
    .setValue(parent)
    .build();
  const result = await query.getAllMembers();
  return Promise.all(result.map(subject => store.getResource(subject)));
}
export async function install(serverUrl, drive, file, source, workspace) {
  if (!process.env.ATOMIC_AGENT_SECRET)
    throw new Error('Set ATOMIC_AGENT_SECRET to install');
  // Reserve first: never overwrite an existing app binding or worker credential.
  await writeFile(file, '{}\n', { flag: 'wx', mode: 0o600 });
  const store = await connect(
    serverUrl,
    process.env.ATOMIC_AGENT_SECRET,
    drive,
  );
  const app = await createApp(store, {
    drive,
    name: 'Codex',
    emoji: '✳️',
    source,
    description: 'Conversations with your local Codex worker.',
    rowName: { singular: 'Conversation', plural: 'Conversations' },
  });
  const schema = await ensureSchema(store, app.app, {
    properties: Object.entries(fields).map(([key, datatype]) => ({
      shortname: `codex-${key}`,
      name: key,
      description: `Codex chat ${key}.`,
      datatype: `https://atomicdata.dev/datatypes/${datatype}` as any,
    })),
    classes: [
      {
        shortname: 'codex-turn',
        name: 'Turn',
        description: 'One requested Codex turn.',
      },
      {
        shortname: 'codex-approval',
        name: 'Approval',
        description: 'A pending Codex approval.',
      },
    ],
  });
  const properties = Object.fromEntries(
    Object.keys(fields).map(key => [key, schema.properties[`codex-${key}`]]),
  );
  const config = {
    version: 1,
    serverUrl,
    drive,
    app: app.app,
    data: app.data,
    entrypoint: app.entrypoint,
    rowClass: app.rowClass,
    turnClass: schema.classes['codex-turn'],
    approvalClass: schema.classes['codex-approval'],
    properties,
    workspace,
  };
  // Embed public vocabulary bindings in source; no network addresses or secrets in the view.
  await updateApp(store, drive, {
    app: app.app,
    source: `const CONFIG = ${JSON.stringify(config)};\n${source}`,
  });
  const url = `${serverUrl}/app-agent`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      ...(await signRequest(url, store.getAgent()!, {})),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ drive, app: app.app, secret: app.secret }),
  });
  if (!response.ok)
    throw new Error(`App identity registration failed (${response.status})`);
  await writeFile(file + '.secret', app.secret, { flag: 'wx', mode: 0o600 });
  await writeFile(file, JSON.stringify(config, null, 2) + '\n', {
    mode: 0o600,
  });
  console.log(`Created Codex app: ${app.app}`);
  return config;
}
