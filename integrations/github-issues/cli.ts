import { enableLoro } from '../../browser/lib/src/loro-loader.js';
import { readFile, writeFile } from 'node:fs/promises';
import { Agent, Store } from '../../browser/lib/src/index.js';
import { install, type Connection } from './atomic.js';
import {
  previewPluginSync,
  applyPluginSync,
  getPluginSync,
  type PluginSyncSession,
} from '../../browser/lib/src/plugin-connection.js';

// Credentials are deliberately absent from arguments, output and connection files.
const [command, connectionFile, argument] = process.argv.slice(2);
if (
  !connectionFile ||
  !['install', 'preview', 'apply', 'resume'].includes(command)
)
  throw new Error(
    'Usage: github-issues <install|preview|apply|resume> connection.json [owner/repo|preview.json]',
  );
const secret = process.env.ATOMIC_AGENT_SECRET;
const serverUrl = process.env.ATOMIC_SERVER_URL;
if (!secret || !serverUrl)
  throw new Error('Set ATOMIC_AGENT_SECRET and ATOMIC_SERVER_URL');
await enableLoro();
const agent = Agent.fromSecret(secret, 'js');
const store = new Store({ serverUrl, agent });
try {
  if (!(await store.waitForServerConnected(10000)))
    throw new Error('AtomicServer did not connect');
  if (command === 'install') {
    if (!argument || !process.env.ATOMIC_DRIVE)
      throw new Error('Install requires owner/repo and ATOMIC_DRIVE');
    // Reserve the file first so an existing installation can never be overwritten.
    await writeFile(connectionFile, '{}\n', { flag: 'wx', mode: 0o600 });
    const connection = await install(
      store,
      process.env.ATOMIC_DRIVE,
      argument,
      await readFile('integrations/github-issues/plugin.js', 'utf8'),
      process.env.GITHUB_TOKEN,
    );
    await writeFile(connectionFile, JSON.stringify(connection, null, 2), {
      mode: 0o600,
    });
    console.log(`Created kanban table: ${connection.table}`);
  } else {
    const connection = JSON.parse(
      await readFile(connectionFile, 'utf8'),
    ) as Connection;
    const target = { drive: connection.drive, plugin: connection.plugin };
    if (command === 'preview') {
      const result = await previewPluginSync(store, {
        ...target,
        release: connection.release,
        config: connection,
      });
      if (argument)
        await writeFile(argument, JSON.stringify(result, null, 2), {
          flag: 'wx',
          mode: 0o600,
        });
      else console.log(JSON.stringify(result, null, 2));
    } else {
      if (command === 'apply' && !argument)
        throw new Error('Apply requires a reviewed preview.json');
      const reviewed =
        command === 'resume'
          ? await getPluginSync(store, target)
          : (JSON.parse(await readFile(argument, 'utf8')) as PluginSyncSession);
      if (!reviewed?.run) throw new Error('No saved preview to approve');
      let result: PluginSyncSession;
      do {
        result = await applyPluginSync(store, { ...target, run: reviewed.run });
      } while (result.status === 'running');
      if (result.status !== 'complete')
        throw new Error(result.error ?? 'Sync stopped');
      console.log('GitHub issues and kanban are synchronized.');
    }
  }
  process.exit(0);
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Sync failed');
  process.exit(1);
}
