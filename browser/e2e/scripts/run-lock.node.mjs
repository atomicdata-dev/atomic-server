import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { acquireRunLock } from './run-lock.mjs';

test('a checkout cannot rebuild outputs underneath another run, and stale locks recover', () => {
  const root = mkdtempSync(join(tmpdir(), 'e2e-run-lock-'));

  try {
    const release = acquireRunLock(root);
    assert.throws(() => acquireRunLock(root), /owns this checkout/);
    release();
    release();
    const dead = spawnSync(process.execPath, ['-e', 'process.exit(0)']);
    writeFileSync(
      join(root, 'runner.lock'),
      JSON.stringify({ pid: dead.pid, token: 'stale' }),
    );
    acquireRunLock(root)();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
