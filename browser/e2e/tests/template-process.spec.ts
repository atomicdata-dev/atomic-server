import { test, expect } from '@playwright/test';
import { createServer } from 'node:net';
import {
  freeTemplatePort,
  startTemplateProcess,
  stopTemplateProcess,
} from './template-process';

test('template cleanup frees the port held by its shell child', async () => {
  test.skip(process.platform === 'win32', 'POSIX process groups');
  const port = await freeTemplatePort();
  const child = startTemplateProcess(
    `node -e 'require("node:net").createServer().listen(${port}, "127.0.0.1", () => console.log("ready"))'`,
    process.cwd(),
  );

  try {
    await new Promise<void>((resolve, reject) => {
      child.stdout!.once('data', () => resolve());
      child.once('error', reject);
      child.once('exit', code =>
        reject(new Error(`Exited before ready: ${code}`)),
      );
    });
  } finally {
    await stopTemplateProcess(child);
  }

  const probe = createServer();
  await new Promise<void>((resolve, reject) => {
    probe.once('error', reject);
    probe.listen(port, '127.0.0.1', resolve);
  });
  expect(probe.listening).toBe(true);
  await new Promise<void>(resolve => probe.close(() => resolve()));
});
