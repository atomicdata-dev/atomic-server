import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  openSync,
  closeSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { OwnedProcess } from './owned-process.mjs';

const server = `const http = require('node:http'); const s = http.createServer((q,r) => r.end('ok')); s.listen(0,'127.0.0.1',()=>console.log('http://127.0.0.1:'+s.address().port));`;

test('parallel fixtures bind different ephemeral ports and stop only their own descendants', async () => {
  const unrelated = new OwnedProcess(process.execPath, ['-e', server]);
  const owned = [0, 1].map(
    () =>
      new OwnedProcess(process.execPath, [
        '-e',
        `require('node:child_process').spawn(process.execPath, ['-e', ${JSON.stringify(server)}], {stdio:'inherit'}); setInterval(()=>{}, 1000);`,
      ]),
  );

  try {
    const urls = await Promise.all(
      [unrelated, ...owned].map(p => p.readyURL(5000)),
    );
    assert.equal(new Set(urls).size, 3);
    await Promise.all(owned.map(p => p.stop()));
    for (const url of urls.slice(1)) await assert.rejects(fetch(url));
    assert.equal((await fetch(urls[0])).status, 200);
  } finally {
    await Promise.all([unrelated, ...owned].map(p => p.stop()));
  }
});

test('readiness fails promptly when the process exits without listening', async () => {
  const child = new OwnedProcess(process.execPath, ['-e', 'process.exit(0)']);

  try {
    await assert.rejects(child.readyURL(5000), /exited before readiness/);
  } finally {
    await child.stop();
  }
});

test('worker loss closes its detached server through IPC disconnect', async () => {
  const owner = new OwnedProcess(process.execPath, ['-e', server]);
  const url = await owner.readyURL(5000);
  owner.child.disconnect();

  try {
    await new Promise(resolve => setTimeout(resolve, 2000));
    await assert.rejects(fetch(url));
  } finally {
    await owner.stop();
  }
});

test('failed spawn still permits idempotent cleanup', async () => {
  const child = new OwnedProcess(process.execPath, ['-e', 'process.exit(0)'], {
    cwd: '/nonexistent-atomic-e2e-directory',
  });
  await assert.rejects(child.done);
  await child.stop();
  await child.stop();
});

test('runner log files retain complete output and command exit status', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'owned-process-log-'));
  const log = join(directory, 'command.log');
  const fd = openSync(log, 'w');
  const child = new OwnedProcess(
    process.execPath,
    [
      '-e',
      "console.log('x'.repeat(120000)); console.error('stderr sentinel'); process.exitCode = 7;",
    ],
    {},
    fd,
  );
  closeSync(fd);

  try {
    assert.equal(await child.done, 7);
    await child.stop();
    const output = readFileSync(log, 'utf8');
    assert.equal(output.includes('x'.repeat(120000)), true);
    assert.equal(output.includes('stderr sentinel'), true);
  } finally {
    await child.stop();
    rmSync(directory, { recursive: true, force: true });
  }
});
