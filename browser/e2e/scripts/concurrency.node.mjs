import { test } from 'node:test';
import assert from 'node:assert/strict';
import { positiveInteger, workerBudget } from './concurrency.mjs';

test('budget respects constrained machines and explicit overrides', () => {
  const host = {
    cpus: 24,
    freeBytes: 24 * 1024 ** 3,
    totalBytes: 32 * 1024 ** 3,
  };
  assert.equal(workerBudget({}, host).workers, 2);
  assert.equal(workerBudget({ CI: 'true' }, host).workers, 1);
  assert.equal(workerBudget({ PLAYWRIGHT_WORKERS: '8' }, host).workers, 8);
  assert.equal(workerBudget({}, { ...host, cpus: 1 }).workers, 1);
  assert.equal(workerBudget({}, { ...host, freeBytes: 1e9 }).workers, 1);
  for (const bad of ['0', '-1', 'NaN', '1.5', '50%', ''])
    assert.throws(() => positiveInteger(bad, 'workers'));
});
