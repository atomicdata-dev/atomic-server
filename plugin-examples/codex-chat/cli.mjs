import { readFile, realpath } from 'node:fs/promises';
import { resolve } from 'node:path';
import { connect, install } from './atomic.ts';
import { work } from './worker.mjs';
const [command, inputFile, workspace] = process.argv.slice(2);
try {
  if (!inputFile || !['install', 'work'].includes(command))
    throw new Error(
      'Usage: node cli.js install connection.json /absolute/workspace | work connection.json',
    );
  const file = resolve(inputFile);
  if (command === 'install') {
    const url = process.env.ATOMIC_SERVER_URL;
    const drive = process.env.ATOMIC_DRIVE;
    if (!url || !drive || !workspace)
      throw new Error(
        'Set ATOMIC_SERVER_URL, ATOMIC_DRIVE and specify a workspace',
      );
    await install(
      url,
      drive,
      file,
      await readFile(new URL('./view.js', import.meta.url), 'utf8'),
      await realpath(workspace),
    );
  } else {
    const config = JSON.parse(await readFile(file, 'utf8'));
    if (config.version !== 1)
      throw new Error('Unsupported or incomplete connection file');
    config.workspace = await realpath(config.workspace);
    const store = await connect(
      config.serverUrl,
      await readFile(file + '.secret', 'utf8'),
      config.drive,
      false,
    );
    await work(store, config, file);
  }
  process.exit(0);
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
