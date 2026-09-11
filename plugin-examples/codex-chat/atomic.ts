import { installApp } from './install.js';
import {
  Agent,
  Store,
  CollectionBuilder,
} from '../../browser/lib/src/index.js';
import { enableLoro } from '../../browser/lib/src/loro-loader.js';
import { core } from './model.mjs';
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
  const installed = await installApp(store, drive, source);
  const config = { ...installed.config, workspace };
  await writeFile(file + '.secret', installed.secret, {
    flag: 'wx',
    mode: 0o600,
  });
  await writeFile(file, JSON.stringify(config, null, 2) + '\n', {
    mode: 0o600,
  });
  console.log(`Created Codex app: ${config.app}`);
  return config;
}
