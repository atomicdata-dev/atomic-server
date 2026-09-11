import { readFile, realpath, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { connect, install } from './atomic.ts';
import { work } from './worker.mjs';
const [command, inputFile, workspace, connectWorkspace] = process.argv.slice(2);
const shellQuote = value => "'" + value.replaceAll("'", "'\"'\"'") + "'";
try {
  if (!inputFile || !['install', 'connect', 'work'].includes(command))
    throw new Error(
      'Usage: node cli.js install connection.json /absolute/workspace | connect setup.json connection.json /absolute/workspace | work connection.json',
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
  } else if (command === 'connect') {
    if (!workspace || !connectWorkspace)
      throw new Error(
        'Usage: connect setup.json connection.json /absolute/workspace',
      );
    const setup = JSON.parse(await readFile(file, 'utf8'));
    if (
      setup.config?.version !== 1 ||
      !setup.config.app ||
      !setup.config.properties ||
      typeof setup.secret !== 'string'
    )
      throw new Error('Invalid Codex worker setup');
    const config = {
      ...setup.config,
      workspace: await realpath(connectWorkspace),
    };
    const target = resolve(workspace);
    await writeFile(target, JSON.stringify(config, null, 2) + '\n', {
      flag: 'wx',
      mode: 0o600,
    });
    await writeFile(target + '.secret', setup.secret, {
      flag: 'wx',
      mode: 0o600,
    });
    console.log(
      `Worker configured for project folder: ${config.workspace}\n\nStart the worker with:\nnode ${shellQuote(resolve(process.argv[1]))} work ${shellQuote(target)}\n\nKeep that terminal running. When it says \"Codex worker ready\", open Codex in Atomic and send a message.\nPress Ctrl+C to stop. Run the same work command to restart; configuration is only needed once.\nKeep the downloaded setup and connection credential private.`,
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
