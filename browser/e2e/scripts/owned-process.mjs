import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';

// Keep the group leader alive until the fixture releases it. IPC disconnect
// also fires when a Playwright worker is killed, so detached grandchildren do
// not outlive their owner even when fixture teardown cannot run.
const supervisor = `
const { spawn } = require('node:child_process');
let stopping = false;
function stop() {
  if (stopping) return;
  stopping = true;
  process.kill(-process.pid, 'SIGTERM');
  setTimeout(() => process.kill(-process.pid, 'SIGKILL'), 1500);
}
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
process.on('disconnect', stop);
const child = spawn(process.argv[1], process.argv.slice(2), { stdio: ['ignore', 'inherit', 'inherit'] });
child.on('error', error => { if (process.connected) process.send({ error: error.message }); });
child.on('exit', code => { if (process.connected) process.send({ code: code ?? 1 }); });
`;

/** Own the entire POSIX process group, including pnpm's grandchildren. */
export class OwnedProcess {
  exited = false;
  output = '';
  stopping;

  constructor(command, args, options = {}, outputFd) {
    if (process.platform === 'win32') {
      throw new Error(
        'E2E process fixtures require POSIX process groups (use WSL on Windows)',
      );
    }

    this.child = spawn(process.execPath, ['-e', supervisor, command, ...args], {
      ...options,
      detached: true,
      stdio: ['ignore', outputFd ?? 'pipe', outputFd ?? 'pipe', 'ipc'],
    });

    for (const stream of [this.child.stdout, this.child.stderr]) {
      stream?.on('data', data => {
        this.output = (this.output + data.toString()).slice(-100_000);
      });
    }

    this.closed = new Promise(resolve => {
      this.child.once('exit', () => resolve());
      this.child.once('error', () => resolve());
    });
    this.done = new Promise((resolve, reject) => {
      this.child.once('error', error => {
        this.exited = true;
        reject(error);
      });
      this.child.once('message', message => {
        this.exited = true;
        if (message.error) reject(new Error(message.error));
        else resolve(message.code ?? 1);
      });
      this.child.once('exit', code => {
        this.exited = true;
        resolve(code ?? 1);
      });
    });
    this.done.catch(() => {});
  }

  stop() {
    // Only the live supervisor signals its own group. Looking up an old PGID
    // after it exited can hit a reused process ID; repeated teardown is a no-op.
    this.stopping ??= (async () => {
      if (this.child.connected) this.child.disconnect();
      await this.closed;
    })();

    return this.stopping;
  }

  async readyURL(timeout = 120_000) {
    const deadline = Date.now() + timeout;

    while (Date.now() < deadline) {
      if (this.exited)
        throw new Error(`Server exited before readiness:\n${this.output}`);
      const url = this.output.match(
        /http:\/\/(?:localhost|127\.0\.0\.1):([1-9]\d*)/,
      )?.[0];

      if (url) {
        try {
          if ((await fetch(url, { signal: AbortSignal.timeout(1000) })).ok)
            return url;
        } catch {
          /* Not listening yet. */
        }
      }

      await delay(100);
    }

    throw new Error(`Server did not become HTTP-ready:\n${this.output}`);
  }
}
