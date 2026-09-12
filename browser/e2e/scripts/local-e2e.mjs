#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import {
  mkdirSync,
  openSync,
  closeSync,
  writeFileSync,
  mkdtempSync,
  readFileSync,
  copyFileSync,
  constants,
} from 'node:fs';
import { createServer } from 'node:net';
import { dirname, join, relative, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';
import { workerBudget, positiveInteger } from './concurrency.mjs';
import {
  buildKey,
  artifactDigest,
  wasmArtifactDigest,
} from './build-cache.mjs';
import { acquireRunLock } from './run-lock.mjs';
import { OwnedProcess } from './owned-process.mjs';
import { setTimeout as delay } from 'node:timers/promises';

const root = resolvePath(dirname(fileURLToPath(import.meta.url)), '../../..');
const sameOrigin = !process.argv.includes('--preview');
const matrixArg = process.argv.find(arg => arg.startsWith('--matrix='));
const repeatsArg = process.argv.find(arg => arg.startsWith('--repeat='));
const repeats = repeatsArg
  ? positiveInteger(repeatsArg.split('=')[1], 'repeat')
  : 1;
const budget = workerBudget();
const matrix = matrixArg
  ? matrixArg
      .split('=')[1]
      .split(',')
      .map(item => {
        const parts = item.split('x');
        if (parts.length > 2)
          throw new Error('Matrix entries are workers or workers x shards');

        return {
          workers: positiveInteger(parts[0], 'workers'),
          shards: positiveInteger(parts[1] ?? '1', 'shards'),
        };
      })
  : [{ workers: budget.workers, shards: 1 }];
const playwrightArgs = process.argv
  .slice(2)
  .filter(
    arg =>
      !['--', '--same-origin', '--preview', matrixArg, repeatsArg].includes(
        arg,
      ),
  );

if (
  new Set(matrix.map(entry => `${entry.workers}x${entry.shards}`)).size !==
  matrix.length
) {
  throw new Error(
    'Matrix settings must be unique so artifacts and databases cannot be overwritten',
  );
}

if (
  playwrightArgs.some(arg =>
    /^--(?:workers|retries|shard|repeat-each)(?:=|$)/.test(arg),
  )
) {
  throw new Error(
    'Use PLAYWRIGHT_WORKERS, --matrix and --repeat to set concurrency and repetitions; this runner always disables retries',
  );
}

if (matrixArg && playwrightArgs.length && !playwrightArgs.includes('--help')) {
  throw new Error(
    'Matrix runs must use the complete Chromium suite without Playwright filters or overrides',
  );
}

if (playwrightArgs.includes('--help')) {
  console.info(
    'Build and run isolated embedded-server Chromium E2E: pnpm test-e2e:local [Playwright arguments]\nUse --preview for separate-origin Vite preview. Default matches CI at atomic.localhost.\nRequires Cargo, cargo-run-bin/wasm-pack and the wasm32-unknown-unknown target.\nUse --matrix=1,2,4,8,12,2x4 --repeat=5 to compare workers and isolated shards on one build.\nReports, build logs and fresh data are saved under .e2e-runs/. No existing services are stopped.',
  );
  process.exit(0);
}

mkdirSync(join(root, '.e2e-runs'), { recursive: true });
const output = mkdtempSync(
  join(root, '.e2e-runs', `${new Date().toISOString().replaceAll(':', '-')}-`),
);
const readSource = () => ({
  commit: execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd: root,
    encoding: 'utf8',
  }).trim(),
  dirty: execFileSync('git', ['status', '--porcelain'], {
    cwd: root,
    encoding: 'utf8',
  }).trim(),
});
const source = readSource();
const phases = [];
const runs = [];
const startedAt = Date.now();
let phaseOutput = output;
const active = new Set();
let releaseLock = () => {};

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
  const log = join(phaseOutput, `${name}.log`);
  const fd = openSync(log, 'w');
  let owned;

  try {
    owned = new OwnedProcess(command, args, { cwd, env }, fd);
  } finally {
    closeSync(fd);
  }

  const task = { owned, log, done: owned.done };
  active.add(task);

  return task;
}

async function run(command, args, name, cwd, env) {
  console.info(
    `${name}: ${command} ${args.join(' ')} (log: ${join(phaseOutput, `${name}.log`)})`,
  );
  const began = Date.now();
  const task = start(command, args, name, cwd, env);
  const code = await task.done;
  phases.push({
    name,
    directory: phaseOutput,
    durationMs: Date.now() - began,
    exitCode: code,
  });
  writeSummary();
  if (code !== 0) throw new Error(`${name} exited ${code}; see ${task.log}`);
  await task.owned.stop();
  active.delete(task);
}

async function healthy(url, task) {
  for (let attempt = 0; attempt < 120; attempt++) {
    if (task.owned.exited) throw new Error(`Service exited; see ${task.log}`);

    try {
      if ((await fetch(url, { signal: AbortSignal.timeout(1000) })).ok) return;
    } catch {
      /* Service may still be starting. */
    }

    await delay(500);
  }

  throw new Error(`Service did not become healthy at ${url}; see ${task.log}`);
}

async function cleanup() {
  await Promise.all([...active].map(task => task.owned.stop()));
  active.clear();
}

for (const event of ['SIGINT', 'SIGTERM']) {
  process.once(event, () => {
    void cleanup().finally(() => {
      releaseLock();
      process.exit(130);
    });
  });
}

function writeSummary() {
  writeFileSync(
    join(output, 'run.json'),
    JSON.stringify(
      {
        startedAt,
        source,
        sourceAtEnd: readSource(),
        totalMs: Date.now() - startedAt,
        budget,
        matrix,
        repeats,
        phases,
        runs,
      },
      null,
      2,
    ),
  );
}

try {
  releaseLock = acquireRunLock(join(root, '.e2e-runs'));
  console.info(`E2E artifacts: ${output}`);
  console.info(
    `Host budget: ${JSON.stringify(budget)}; matrix=${JSON.stringify(matrix)} repeat=${repeats}; retries=0`,
  );
  if (!sameOrigin && matrix.some(entry => entry.shards > 1))
    throw new Error(
      'Separate-origin preview supports one server per run; use same-origin mode to compare shards',
    );
  const previewServerPort = sameOrigin ? undefined : await freePort();
  const env = {
    ...process.env,
    VITE_E2E: 'true',
    CARGO_BUILD_JOBS:
      process.env.CARGO_BUILD_JOBS ??
      String(Math.max(1, Math.floor(budget.cpus / 2))),
    BINARYEN_CORES:
      process.env.BINARYEN_CORES ??
      String(Math.max(1, Math.floor(budget.cpus / 2))),
    // External services are opt-in: an unrelated portal may occupy :3030.
    ATOMIC_VAULT_PORTAL_URL: process.env.ATOMIC_VAULT_PORTAL_URL ?? '',
    PLAYWRIGHT_WORKERS: String(budget.workers),
    PLAYWRIGHT_RETRIES: '0',
    ATOMICSERVER_SKIP_JS_BUILD: 'true',
  };
  // Never inherit a stale-artifact opt-out from the invoking shell.
  delete env.SKIP_WASM_BUILD;
  // Same-origin app builds resolve the server from location.origin, allowing
  // the same immutable bundle to run on every fresh shard's port.
  delete env.VITE_ATOMIC_SERVER_URL;
  if (!sameOrigin)
    env.VITE_ATOMIC_SERVER_URL = `http://localhost:${previewServerPort}`;
  const browser = join(root, 'browser');
  await run('pnpm', ['install', '--frozen-lockfile'], 'install', browser, env);
  const target = resolvePath(root, env.CARGO_TARGET_DIR ?? 'target');
  const binary = join(target, 'debug/atomic-server');
  const cacheCheckStarted = Date.now();
  const key = buildKey(root, env);
  const manifestPath = join(root, '.e2e-runs', 'build-cache.json');
  let cached = false;

  try {
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    cached =
      manifest.key === key &&
      manifest.artifacts === artifactDigest(root, binary);
  } catch {
    /* Missing or changed artifacts require a build. */
  }

  phases.push({
    name: 'validate-build-cache',
    durationMs: Date.now() - cacheCheckStarted,
    cacheHit: cached,
  });
  const wasmKey = buildKey(root, env, undefined, 'wasm');
  const wasmManifestPath = join(root, '.e2e-runs', 'wasm-cache.json');

  const recordWasmBuild = () => {
    if (buildKey(root, env, undefined, 'wasm') !== wasmKey)
      throw new Error('WASM inputs changed during the build');
    writeFileSync(
      wasmManifestPath,
      JSON.stringify({ key: wasmKey, artifacts: wasmArtifactDigest(root) }),
    );
  };

  if (cached) {
    // The complete artifact check also attests the narrower WASM cache.
    recordWasmBuild();
    console.info(
      'Reusing verified build: product sources, tool versions, build environment and artifact checksums match',
    );
    phases.push({ name: 'verified-build-cache-hit', durationMs: 0 });
  } else {
    let wasmCached = false;

    try {
      const manifest = JSON.parse(readFileSync(wasmManifestPath, 'utf8'));
      wasmCached =
        manifest.key === wasmKey &&
        manifest.artifacts === wasmArtifactDigest(root);
    } catch {
      /* First run or changed WASM inputs/output. */
    }

    if (wasmCached) {
      console.info(
        'Reusing verified WASM build; rebuilding the changed frontend separately',
      );
      phases.push({ name: 'verified-wasm-cache-hit', durationMs: 0 });
    } else {
      await run(
        'pnpm',
        ['--filter', '@tomic/data-browser', 'build:wasm'],
        'build-wasm',
        browser,
        env,
      );
      recordWasmBuild();
    }

    await run('pnpm', ['run', 'build'], 'build-browser', browser, {
      ...env,
      SKIP_WASM_BUILD: '1',
    });
    await run(
      'cargo',
      ['build', '--locked', '-p', 'atomic-server'],
      'build-server',
      root,
      env,
    );
    if (buildKey(root, env) !== key)
      throw new Error(
        'Product inputs changed during the build; rerun before caching or testing',
      );
    writeFileSync(
      manifestPath,
      JSON.stringify({
        key,
        artifacts: artifactDigest(root, binary),
        source,
        output,
      }),
    );
  }

  // Run an immutable private copy. Other checkouts may rebuild the source
  // binary; CI cleanup must not match this run by a shared target/debug path.
  const runBinary = join(output, 'bin', 'atomic-server');
  mkdirSync(dirname(runBinary), { recursive: true });
  const copyStarted = Date.now();
  copyFileSync(binary, runBinary, constants.COPYFILE_FICLONE);
  phases.push({
    name: 'isolate-server-binary',
    durationMs: Date.now() - copyStarted,
  });

  await run(
    'pnpm',
    ['exec', 'playwright', 'install', 'chromium', '--no-remove'],
    'install-chromium',
    join(browser, 'e2e'),
    env,
  );

  for (let repetition = 1; repetition <= repeats; repetition++) {
    for (const { workers, shards } of matrix) {
      const runStarted = Date.now();
      const services = [];
      const shardRuns = [];

      try {
        for (let shard = 1; shard <= shards; shard++) {
          phaseOutput = join(
            output,
            `workers-${workers}-shards-${shards}-repeat-${repetition}`,
            `shard-${shard}`,
          );
          mkdirSync(phaseOutput, { recursive: true });
          const directory = phaseOutput;
          const serverPort = previewServerPort ?? (await freePort());
          let frontendPort = await freePort();
          while (frontendPort === serverPort) frontendPort = await freePort();
          const serverURL = `http://${sameOrigin ? 'atomic.localhost' : 'localhost'}:${serverPort}`;
          const frontendURL = sameOrigin
            ? serverURL
            : `http://127.0.0.1:${frontendPort}`;
          const runEnv = {
            ...env,
            SERVER_URL: serverURL,
            ATOMIC_SERVICE_URL: `http://127.0.0.1:${serverPort}`,
            FRONTEND_URL: frontendURL,
            ATOMIC_TEST_HOST_MAP: sameOrigin
              ? 'MAP atomic.localhost 127.0.0.1'
              : '',
            PLAYWRIGHT_WORKERS: String(workers),
            PLAYWRIGHT_HTML_OUTPUT_DIR: join(directory, 'report'),
            PLAYWRIGHT_JSON_OUTPUT_FILE: join(directory, 'report.json'),
            ATOMIC_E2E_METRICS_DIR: join(directory, 'metrics'),
            ATOMIC_DATA_DIR: join(directory, 'data'),
            ATOMIC_CONFIG_DIR: join(directory, 'config'),
            ATOMIC_CACHE_DIR: join(directory, 'cache'),
            ATOMIC_PORT: String(serverPort),
            ATOMIC_DOMAIN: sameOrigin ? 'atomic.localhost' : 'localhost',
            ATOMIC_INITIALIZE: 'true',
          };
          const serviceStarted = Date.now();
          const server = start(runBinary, [], 'server', root, runEnv);
          services.push(server);
          await healthy(`http://127.0.0.1:${serverPort}`, server);

          if (!sameOrigin) {
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
              runEnv,
            );
            services.push(preview);
            await healthy(frontendURL, preview);
            await healthy(`${frontendURL}/server`, preview);
          }

          phases.push({
            name: 'startup',
            directory,
            durationMs: Date.now() - serviceStarted,
          });
          writeFileSync(
            join(directory, 'environment.json'),
            JSON.stringify(
              {
                serverURL,
                frontendURL,
                vaultPortal: env.ATOMIC_VAULT_PORTAL_URL || null,
                deployment: sameOrigin ? 'embedded' : 'preview',
                cpuThrottle: env.ATOMIC_TEST_CPU_THROTTLE ?? null,
                clonedSessions: env.ATOMIC_E2E_CLONE_SESSION === '1',
                browserPlatformOverride:
                  env.PLAYWRIGHT_HOST_PLATFORM_OVERRIDE ?? null,
                workers,
                shards,
                shard,
                repetition,
                retries: 0,
              },
              null,
              2,
            ),
          );
          shardRuns.push({ directory, runEnv, shard });
          writeSummary();
        }

        // Start the test clocks together after all servers are ready.
        const testStarted = Date.now();
        const outcomes = await Promise.all(
          shardRuns.map(async ({ directory, runEnv, shard }) => {
            phaseOutput = directory;
            const task = start(
              'pnpm',
              [
                'exec',
                'playwright',
                'test',
                '--project=chromium',
                '--trace=retain-on-failure',
                `--output=${join(directory, 'results')}`,
                '--reporter=line,html,json,./scripts/load-reporter.ts',
                ...(shards > 1 ? [`--shard=${shard}/${shards}`] : []),
                ...playwrightArgs,
              ],
              'e2e',
              join(browser, 'e2e'),
              runEnv,
            );
            console.info(
              `Testing workers=${workers} shard=${shard}/${shards} repetition=${repetition}; ${task.log}`,
            );
            const code = await task.done;
            await task.owned.stop();
            active.delete(task);

            return {
              shard,
              exitCode: code,
              directory: relative(output, directory),
            };
          }),
        );
        runs.push({
          workers,
          shards,
          repetition,
          sourceAtEnd: readSource(),
          testTimeMs: Date.now() - testStarted,
          totalMs: Date.now() - runStarted,
          outcomes,
        });
        writeSummary();
        if (outcomes.some(result => result.exitCode !== 0))
          process.exitCode = 1;
      } finally {
        // End each fresh database's services before the next matrix entry.
        await Promise.all(services.map(task => task.owned.stop()));
        for (const task of services) active.delete(task);
      }
    }
  }

  console.info(
    `E2E completed. Matrix and timings: ${join(output, 'run.json')}`,
  );
} catch (error) {
  console.error(error);
  process.exitCode = 1;
} finally {
  await cleanup();
  releaseLock();
  writeSummary();
}
