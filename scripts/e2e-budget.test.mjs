import { test } from 'node:test';
import assert from 'node:assert/strict';
import { overrideE2eBudget } from '../.dagger/src/e2e-budget.ts';

test('CI overrides preserve coverage, defaults and simultaneous-job knobs', () => {
  const defaults = Object.freeze({
    shardCount: 4,
    workers: '2',
    retries: '2',
    grep: '',
  });
  assert.deepEqual(overrideE2eBudget(defaults), defaults);
  assert.deepEqual(overrideE2eBudget(defaults, 8, 1, 0), {
    shardCount: 1,
    workers: '8',
    retries: '0',
    grep: '',
  });
  assert.equal(
    overrideE2eBudget({ ...defaults, grep: '@smoke' }, 4).grep,
    '@smoke',
  );
  for (const args of [
    [-1, 1, 0],
    [1, -1, 0],
    [1, 1, -2],
    [1.5, 1, 0],
    [1, NaN, 0],
  ])
    assert.throws(() => overrideE2eBudget(defaults, ...args));
});
