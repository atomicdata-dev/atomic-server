#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { mkdirSync, openSync, closeSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { dirname, join, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const root = resolvePath(dirname(fileURLToPath(import.meta.url)), '../../..');
const playwrightArgs = process.argv.slice(2).filter(arg => arg !== '--');

if (playwrightArgs.includes('--help')) {
  console.info(
    'Build and run isolated production Chromium E2E: pnpm test-e2e:local [Playwright arguments]\nRequires Cargo, cargo-run-bin/wasm-pack and the wasm32-unknown-unknown target.\nReports, build logs and fresh data are saved under .e2e-runs/. No existing services are stopped.',
  );
  process.exit(0);
}

const output = join(
  root,
  '.e2e-runs',
  new Date().toISOString().replaceAll(':', '-'),
);
mkdirSync(output, { recursive: true });
const active = new Set();

async function freePort(port = 0, host = '127.0.0.1') {
  const probe = createServer();
  await new Promise((resolve, reject) => {
    probe.once('error', reject);
    probe.listen(port, host, resolve);
  });
  const result = probe.address().port;
  await new Promise(resolve => probe.close(resolve));

  return result;
}

function start(command, args, name, cwd, env) {
  const log = join(output, `${name}.log`);
  const fd = openSync(log, 'w');
  const child = spawn(command, args, {
    cwd,
    env,
    detached: true,
    stdio: ['ignore', fd, fd],
  });
  closeSync(fd);
  const task = { child, log, done: undefined, exited: false };
  task.done = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', code => {
      task.exited = true;
      resolve(code ?? 1);
    });
  });
  // Background services may fail while another command is running.
  task.done.catch(() => {});
  active.add(task);

  return task;
}

async function run(command, args, name, cwd, env) {
  console.info(
    `${name}: ${command} ${args.join(' ')} (log: ${join(output, `${name}.log`)})`,
  );
  const task = start(command, args, name, cwd, env);
  const code = await task.done;
  if (code !== 0) throw new Error(`${name} exited ${code}; see ${task.log}`);
  active.delete(task);
}

async function healthy(url, task) {
  for (let attempt = 0; attempt < 120; attempt++) {
    if (task.exited) throw new Error(`Service exited; see ${task.log}`);

    try {
      if ((await fetch(url, { signal: AbortSignal.timeout(1000) })).ok) return;
    } catch {
      /* Service may still be starting. */
    }

    await delay(500);
  }

  throw new Error(`Service did not become healthy at ${url}; see ${task.log}`);
}

function signal(task, name) {
  if (!task.child.pid) return;

  try {
    process.kill(-task.child.pid, name);
  } catch (error) {
    if (error.code !== 'ESRCH') throw error;
  }
}

async function cleanup() {
  const tasks = [...active];
  if (tasks.length === 0) return;
  tasks.forEach(task => signal(task, 'SIGTERM'));
  await Promise.race([
    Promise.allSettled(tasks.map(task => task.done)),
    delay(2000),
  ]);
  tasks.forEach(task => signal(task, 'SIGKILL'));
}

for (const event of ['SIGINT', 'SIGTERM']) {
  process.once(event, () => {
    void cleanup().finally(() => process.exit(130));
  });
}

try {
  // Generated template tests use these fixed ports and invoke kill-port.
  // Refuse a conflicting setup before they can touch somebody else's server.
  await freePort(3000);
  await freePort(4174);

  for (const port of [3000, 4174]) {
    try {
      await freePort(port, '::1');
    } catch (error) {
      if (!['EAFNOSUPPORT', 'EADDRNOTAVAIL'].includes(error.code)) throw error;
    }
  }

  const serverPort = await freePort();
  let frontendPort = await freePort();
  while (frontendPort === serverPort) frontendPort = await freePort();
  const serverURL = `http://localhost:${serverPort}`;
  const frontendURL = `http://127.0.0.1:${frontendPort}`;
  const env = {
    ...process.env,
    SERVER_URL: serverURL,
    FRONTEND_URL: frontendURL,
    VITE_ATOMIC_SERVER_URL: serverURL,
    VITE_E2E: 'true',
    // External services are opt-in: an unrelated portal may occupy :3030.
    ATOMIC_VAULT_PORTAL_URL: process.env.ATOMIC_VAULT_PORTAL_URL ?? '',
    PLAYWRIGHT_WORKERS: process.env.PLAYWRIGHT_WORKERS ?? '1',
    PLAYWRIGHT_RETRIES: '0',
    PLAYWRIGHT_HTML_OUTPUT_DIR: join(output, 'report'),
    ATOMIC_DATA_DIR: join(output, 'data'),
    ATOMIC_CONFIG_DIR: join(output, 'config'),
    ATOMIC_CACHE_DIR: join(output, 'cache'),
    ATOMIC_PORT: String(serverPort),
    ATOMIC_DOMAIN: 'localhost',
    ATOMIC_INITIALIZE: 'true',
    ATOMICSERVER_SKIP_JS_BUILD: 'true',
  };
  // Never inherit a stale-artifact opt-out from the invoking shell.
  delete env.SKIP_WASM_BUILD;
  console.info(`E2E artifacts: ${output}`);
  const browser = join(root, 'browser');
  await run('pnpm', ['install', '--frozen-lockfile'], 'install', browser, env);
  await run('pnpm', ['run', 'build'], 'build-browser', browser, env);
  await run(
    'cargo',
    ['build', '--locked', '-p', 'atomic-server'],
    'build-server',
    root,
    env,
  );
  await run(
    'pnpm',
    ['exec', 'playwright', 'install', 'chromium'],
    'install-chromium',
    join(browser, 'e2e'),
    env,
  );
  const target = resolvePath(root, env.CARGO_TARGET_DIR ?? 'target');
  const server = start(
    join(target, 'debug/atomic-server'),
    [],
    'server',
    root,
    env,
  );
  await healthy(serverURL, server);
  const preview = start(
    'pnpm',
    [
      'exec',
      'vite',
      'preview',
      '--host',
      '127.0.0.1',
      '--port',
      String(frontendPort),
      '--strictPort',
    ],
    'preview',
    join(browser, 'data-browser'),
    env,
  );
  await healthy(frontendURL, preview);
  await healthy(`${frontendURL}/server`, preview);
  writeFileSync(
    join(output, 'environment.json'),
    JSON.stringify(
      {
        serverURL,
        frontendURL,
        vaultPortal: env.ATOMIC_VAULT_PORTAL_URL || null,
        retries: 0,
      },
      null,
      2,
    ),
  );
  await run(
    'pnpm',
    [
      'exec',
      'playwright',
      'test',
      '--project=chromium',
      '--trace=retain-on-failure',
      `--output=${join(output, 'results')}`,
      '--reporter=line,html',
      ...playwrightArgs,
    ],
    'e2e',
    join(browser, 'e2e'),
    env,
  );
  console.info(`E2E passed. Report: ${join(output, 'report/index.html')}`);
} catch (error) {
  console.error(error);
  process.exitCode = 1;
} finally {
  await cleanup();
}
