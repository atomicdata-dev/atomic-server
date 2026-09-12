#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import {
  mkdirSync,
  openSync,
  closeSync,
  writeFileSync,
  mkdtempSync,
  copyFileSync,
  constants,
} from 'node:fs';
import { createServer } from 'node:net';
import { dirname, join, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { workerBudget } from './concurrency.mjs';
import { acquireRunLock } from './run-lock.mjs';
import { OwnedProcess } from './owned-process.mjs';

const root = resolvePath(dirname(fileURLToPath(import.meta.url)), '../../..');
const browser = join(root, 'browser');
const cliArgs = process.argv.slice(2).filter(arg => arg !== '--');
const sameOrigin = !cliArgs.includes('--preview');
const skipBuild = cliArgs.includes('--skip-build');
const playwrightArgs = cliArgs.filter(
  arg => !['--preview', '--same-origin', '--skip-build'].includes(arg),
);

if (cliArgs.some(arg => /^--(?:matrix|repeat)(?:=|$)/.test(arg))) {
  throw new Error(
    'Use Playwright --workers and --repeat-each, or a shell loop for separate runs. Use Dagger for isolated shards.',
  );
}

if (cliArgs.includes('--help')) {
  console.info(`Usage: pnpm test-e2e:local [--preview] [--skip-build] [Playwright arguments]
Builds and starts a fresh isolated server, runs Chromium, then stops owned processes.
--preview serves the app through Vite instead of the embedded server.
--skip-build explicitly reuses existing artifacts; rebuild after product changes.
Playwright owns --workers, --repeat-each, --shard, filters and reporting.
Reports and phase timings are retained under .e2e-runs/.`);
  process.exit(0);
}

if (!sameOrigin && skipBuild) {
  throw new Error(
    '--preview requires a rebuild for its fresh API port; omit --skip-build',
  );
}

mkdirSync(join(root, '.e2e-runs'), { recursive: true });
const output = mkdtempSync(
  join(root, '.e2e-runs', `${new Date().toISOString().replaceAll(':', '-')}-`),
);
const budget = workerBudget();
const active = new Set();
const phases = [];
const startedAt = Date.now();
const source = execFileSync('git', ['rev-parse', 'HEAD'], {
  cwd: root,
  encoding: 'utf8',
}).trim();
let releaseLock = () => {};

async function freePort() {
  const socket = createServer();
  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.listen(0, '127.0.0.1', resolve);
  });
  const { port } = socket.address();
  await new Promise(resolve => socket.close(resolve));

  return port;
}

function start(command, args, name, cwd, env) {
  const log = join(output, `${name}.log`);
  const fd = openSync(log, 'w');
  let task;

  try {
    task = new OwnedProcess(command, args, { cwd, env }, fd);
  } finally {
    closeSync(fd);
  }

  active.add(task);
  console.info(`${name}: ${command} ${args.join(' ')} (log: ${log})`);

  return task;
}

async function run(command, args, name, cwd, env) {
  const began = Date.now();
  const task = start(command, args, name, cwd, env);
  const code = await task.done;
  await task.stop();
  active.delete(task);
  phases.push({ name, durationMs: Date.now() - began, exitCode: code });
  if (code !== 0)
    throw new Error(
      `${name} exited ${code}; see ${join(output, `${name}.log`)}`,
    );
}

async function healthy(url, task) {
  for (let attempt = 0; attempt < 120; attempt++) {
    if (task.exited)
      throw new Error(
        `Service exited before readiness at ${url}; see ${output}`,
      );

    try {
      if ((await fetch(url, { signal: AbortSignal.timeout(1000) })).ok) return;
    } catch {
      /* Service may still be starting. */
    }

    await delay(500);
  }

  throw new Error(`Service did not become healthy at ${url}; see ${output}`);
}

async function cleanup() {
  await Promise.all([...active].map(task => task.stop()));
  active.clear();
}

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    void cleanup().finally(() => {
      releaseLock();
      process.exit(130);
    });
  });
}

try {
  releaseLock = acquireRunLock(join(root, '.e2e-runs'));
  const serverPort = await freePort();
  const serverURL = `http://${sameOrigin ? 'atomic.localhost' : 'localhost'}:${serverPort}`;
  const profile = process.env.ATOMIC_E2E_CARGO_PROFILE ?? 'e2e';
  if (!['dev', 'e2e', 'release'].includes(profile))
    throw new Error('ATOMIC_E2E_CARGO_PROFILE must be dev, e2e or release');
  const env = {
    ...process.env,
    VITE_E2E: 'true',
    CARGO_BUILD_JOBS:
      process.env.CARGO_BUILD_JOBS ??
      String(Math.max(1, Math.floor(budget.cpus / 2))),
    BINARYEN_CORES:
      process.env.BINARYEN_CORES ??
      String(Math.max(1, Math.floor(budget.cpus / 2))),
    ATOMIC_VAULT_PORTAL_URL: process.env.ATOMIC_VAULT_PORTAL_URL ?? '',
    PLAYWRIGHT_WORKERS: String(budget.workers),
    PLAYWRIGHT_RETRIES: '0',
    PLAYWRIGHT_HTML_OPEN: 'never',
    PLAYWRIGHT_HTML_OUTPUT_DIR: join(output, 'report'),
    PLAYWRIGHT_JSON_OUTPUT_FILE: join(output, 'report.json'),
    ATOMICSERVER_SKIP_JS_BUILD: 'true',
    SERVER_URL: serverURL,
    FRONTEND_URL: serverURL,
    ATOMIC_SERVICE_URL: `http://127.0.0.1:${serverPort}`,
    ATOMIC_TEST_HOST_MAP: sameOrigin ? 'MAP atomic.localhost 127.0.0.1' : '',
    ATOMIC_DATA_DIR: join(output, 'data'),
    ATOMIC_CONFIG_DIR: join(output, 'config'),
    ATOMIC_CACHE_DIR: join(output, 'cache'),
    ATOMIC_PORT: String(serverPort),
    ATOMIC_DOMAIN: sameOrigin ? 'atomic.localhost' : 'localhost',
    ATOMIC_INITIALIZE: 'true',
  };
  delete env.SKIP_WASM_BUILD;
  delete env.VITE_ATOMIC_SERVER_URL;
  if (!sameOrigin) env.VITE_ATOMIC_SERVER_URL = serverURL;
  console.info(
    `E2E artifacts: ${output}; default workers=${budget.workers}; profile=${profile}; skip-build=${skipBuild}`,
  );

  if (!skipBuild) {
    await run(
      'pnpm',
      ['install', '--frozen-lockfile'],
      'install',
      browser,
      env,
    );
    await run('pnpm', ['run', 'build'], 'build-browser', browser, env);
    await run(
      'cargo',
      ['build', '--locked', '--profile', profile, '-p', 'atomic-server'],
      'build-server',
      root,
      env,
    );
  }

  // A private copy cannot be replaced by another checkout's build or matched
  // by unrelated CI cleanup targeting target/debug/atomic-server.
  const target = resolvePath(root, env.CARGO_TARGET_DIR ?? 'target');
  const binary = join(output, 'bin', 'atomic-server');
  mkdirSync(dirname(binary), { recursive: true });
  copyFileSync(
    join(target, profile === 'dev' ? 'debug' : profile, 'atomic-server'),
    binary,
    constants.COPYFILE_FICLONE,
  );
  await run(
    'pnpm',
    ['exec', 'playwright', 'install', 'chromium', '--no-remove'],
    'install-chromium',
    join(browser, 'e2e'),
    env,
  );
  const startup = Date.now();
  const server = start(binary, [], 'server', root, env);
  await healthy(env.ATOMIC_SERVICE_URL, server);

  if (!sameOrigin) {
    const port = await freePort();
    env.FRONTEND_URL = `http://127.0.0.1:${port}`;
    const preview = start(
      'pnpm',
      [
        'exec',
        'vite',
        'preview',
        '--host',
        '127.0.0.1',
        '--port',
        String(port),
        '--strictPort',
      ],
      'preview',
      join(browser, 'data-browser'),
      env,
    );
    await healthy(`${env.FRONTEND_URL}/server`, preview);
  }

  phases.push({ name: 'startup', durationMs: Date.now() - startup });
  await run(
    'pnpm',
    [
      'exec',
      'playwright',
      'test',
      '--project=chromium',
      '--trace=retain-on-failure',
      `--output=${join(output, 'results')}`,
      '--reporter=line,html,json',
      ...playwrightArgs,
    ],
    'e2e',
    join(browser, 'e2e'),
    env,
  );
} catch (error) {
  console.error(error);
  process.exitCode = 1;
} finally {
  await cleanup();
  releaseLock();
  writeFileSync(
    join(output, 'run.json'),
    JSON.stringify(
      { source, skipBuild, startedAt, totalMs: Date.now() - startedAt, phases },
      null,
      2,
    ),
  );
}
