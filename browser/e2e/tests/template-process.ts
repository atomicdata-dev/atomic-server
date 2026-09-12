import { spawn, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';

export async function freeTemplatePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No TCP port');
  const port = address.port;
  await new Promise<void>((resolve, reject) =>
    server.close(error => (error ? reject(error) : resolve())),
  );

  return port;
}

export function startTemplateProcess(
  command: string,
  cwd: string,
): ChildProcess {
  return spawn(command, {
    cwd,
    shell: true,
    detached: process.platform !== 'win32',
  });
}

export async function stopTemplateProcess(child: ChildProcess): Promise<void> {
  if (!child.pid) return;
  const exited =
    child.exitCode !== null || child.signalCode !== null
      ? Promise.resolve()
      : new Promise<void>(resolve => child.once('exit', () => resolve()));

  const signal = (value: NodeJS.Signals) => {
    try {
      if (process.platform === 'win32') child.kill(value);
      else process.kill(-child.pid!, value);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error;
    }
  };

  signal('SIGTERM');
  let timer: ReturnType<typeof setTimeout> | undefined;
  await Promise.race([
    exited,
    new Promise<void>(resolve => {
      timer = setTimeout(resolve, 2000);
    }),
  ]);
  clearTimeout(timer);
  // The shell may exit before its pnpm/node descendants. Reap our group too.
  signal('SIGKILL');
  await exited;
}
