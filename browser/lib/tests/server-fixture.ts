/**
 * Spawns a real `atomic-server` in a temp data dir on a free port for use in
 * Node integration tests. Reads the bootstrap agent secret out of the
 * server-written `config.toml` so tests can authenticate as the root agent.
 */

import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

export interface ServerHandle {
  serverUrl: string;
  agentSecret: string;
  initialDrive?: string;
  stop: () => Promise<void>;
}

const REPO_ROOT = path.resolve(
  path.dirname(new URL(import.meta.url).pathname),
  '../../../',
);

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, () => {
      const addr = srv.address();

      if (addr && typeof addr === 'object') {
        const port = addr.port;
        srv.close(() => resolve(port));
      } else {
        srv.close(() => reject(new Error('no port')));
      }
    });
  });
}

async function waitForReady(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown;

  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { method: 'GET' });
      if (res.ok || res.status === 401 || res.status === 404) return;
    } catch (e) {
      lastErr = e;
    }

    await delay(200);
  }

  throw new Error(
    `Server at ${url} did not become ready in ${timeoutMs}ms: ${String(lastErr)}`,
  );
}

interface MinimalConfigToml {
  shared?: {
    agent_secret?: string;
    initialDrive?: string;
  };
}

function parseConfigToml(text: string): MinimalConfigToml {
  // Tiny TOML reader — we only need `shared.agent_secret` and
  // `shared.initialDrive`. Avoids pulling a full TOML dep.
  const out: MinimalConfigToml = { shared: {} };
  let section = '';

  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const sec = line.match(/^\[([^\]]+)\]$/);

    if (sec) {
      section = sec[1];
      continue;
    }

    const kv = line.match(/^([A-Za-z_][\w]*)\s*=\s*"([^"]*)"\s*$/);
    if (!kv || section !== 'shared') continue;
    if (kv[1] === 'agent_secret') out.shared!.agent_secret = kv[2];
    if (kv[1] === 'initialDrive') out.shared!.initialDrive = kv[2];
  }

  return out;
}

export async function startServer(): Promise<ServerHandle> {
  // Respect Cargo's configured target directory, just like e2e-server.sh.
  // CI may provide only a prebuilt binary, without Cargo installed.
  let targetDir =
    process.env.CARGO_TARGET_DIR || path.join(REPO_ROOT, 'target');

  try {
    const metadata = JSON.parse(
      execFileSync(
        'cargo',
        ['metadata', '--no-deps', '--format-version', '1'],
        {
          cwd: REPO_ROOT,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      ),
    );
    targetDir = metadata.target_directory;
  } catch {
    // Use the supplied target directory or CI's conventional binary location.
  }

  const binPath = path.resolve(REPO_ROOT, targetDir, 'debug/atomic-server');

  if (!existsSync(binPath)) {
    throw new Error(
      `atomic-server binary not found at ${binPath}. Build it first: ` +
        `\`cargo build -p atomic-server\``,
    );
  }

  const port = await freePort();
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'atomic-it-'));
  const dataDir = path.join(tmpDir, 'data');
  const configDir = path.join(tmpDir, 'config');

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ATOMIC_PORT: String(port),
    ATOMIC_DATA_DIR: dataDir,
    ATOMIC_CONFIG_DIR: configDir,
    // Cache dir must be unique per server process so parallel tests do not collide.
    // server instance so parallel test files don't collide.
    ATOMIC_CACHE_DIR: path.join(tmpDir, 'cache'),
    ATOMIC_DOMAIN: 'localhost',
    ATOMIC_INITIALIZE: 'true',
    RUST_LOG: process.env.RUST_LOG ?? 'warn',
  };

  const child: ChildProcess = spawn(binPath, [], {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const stderrChunks: string[] = [];
  child.stderr?.on('data', d => stderrChunks.push(String(d)));
  child.stdout?.on('data', () => {});

  child.on('exit', code => {
    if (code !== 0 && code !== null) {
      // eslint-disable-next-line no-console
      console.error(
        `atomic-server exited with code ${code}\n${stderrChunks.join('')}`,
      );
    }
  });

  const serverUrl = `http://localhost:${port}`;

  // 90s: under dagger Main the host also runs nextest (8 threads) + 4 e2e
  // servers + clippy. Cold `ATOMIC_INITIALIZE` boot of the slim binary has
  // been observed near the old 30s ceiling (server-fixture.it took 28.6s
  // in the same run that timed upload-roundtrip out with empty stderr).
  try {
    await waitForReady(serverUrl, 90_000);
  } catch (e) {
    const exit =
      child.exitCode !== null
        ? ` (exited ${child.exitCode})`
        : ' (still running)';
    child.kill('SIGTERM');
    throw new Error(
      `${(e as Error).message}${exit}\nServer stderr:\n${stderrChunks.join('')}`,
    );
  }

  const configFile = path.join(configDir, 'config.toml');
  const configText = await readFile(configFile, 'utf8');
  const cfg = parseConfigToml(configText);

  if (!cfg.shared?.agent_secret) {
    child.kill('SIGTERM');
    throw new Error(`agent_secret not found in ${configFile}`);
  }

  return {
    serverUrl,
    agentSecret: cfg.shared.agent_secret,
    initialDrive: cfg.shared.initialDrive,
    stop: async () => {
      child.kill('SIGTERM');
      await new Promise<void>(resolve => {
        if (child.exitCode !== null) return resolve();
        child.once('exit', () => resolve());
        setTimeout(() => {
          child.kill('SIGKILL');
          resolve();
        }, 3000);
      });
      await rm(tmpDir, { recursive: true, force: true });
    },
  };
}
