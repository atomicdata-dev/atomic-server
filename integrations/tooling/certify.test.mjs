import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  discover,
  evaluateJs,
  evaluateRust,
  formatFailureSummary,
  summarizeFailure,
} from './certify.mjs';
test('zero executed tests cannot certify an integration', () => {
  assert.equal(
    evaluateJs({ success: true, numPassedTests: 0, numFailedTests: 0 }),
    false,
  );
  assert.equal(
    evaluateJs({ success: true, numPassedTests: 2, numFailedTests: 0 }),
    true,
  );
  assert.equal(
    evaluateJs({ success: false, numPassedTests: 2, numFailedTests: 1 }),
    false,
  );
  assert.equal(
    evaluateRust('test result: ok. 0 passed; 0 failed; 0 ignored;'),
    false,
  );
  assert.equal(
    evaluateRust('test result: ok. 1 passed; 0 failed; 0 ignored;'),
    true,
  );
  assert.equal(
    evaluateRust('test result: ok. 0 passed; 0 failed; 1 ignored;'),
    false,
  );
});
test('new packages cannot silently escape certification', () => {
  const base = mkdtempSync(join(tmpdir(), 'atomic-certification-'));
  try {
    mkdirSync(join(base, 'integrations/new-provider'), { recursive: true });
    writeFileSync(join(base, 'integrations/new-provider/package.json'), '{}');
    assert.throws(() => discover(base), /missing certification metadata/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
test('failed certification checks surface a concise useful diagnostic', () => {
  assert.equal(
    summarizeFailure({
      error: 'spawnSync /browser/node_modules/.bin/esbuild ENOENT',
      stderr: 'ignored stderr',
      stdout: 'ignored stdout',
    }),
    'spawnSync /browser/node_modules/.bin/esbuild ENOENT',
  );
  assert.equal(
    formatFailureSummary([
      { name: 'typecheck', status: 'passed' },
      {
        name: 'reproducible-bundle',
        status: 'failed',
        detail: 'generated bundle differs from committed plugin.js',
      },
      { name: 'fixtures', status: 'failed' },
    ]),
    'reproducible-bundle: generated bundle differs from committed plugin.js; fixtures',
  );
});
test('both current providers are discovered with exact sandbox tests', () => {
  const ids = discover().map(p => p.id);
  assert.ok(ids.includes('github-issues'));
  assert.ok(ids.includes('notion'));
  assert.equal(new Set(ids).size, ids.length);
});

test('store evidence rejects partial, failed and changed bundles; labels old evidence', async () => {
  const { assessEvidence } = await import('./evidence.mjs');
  const now = Date.now();
  const report = {
    schemaVersion: 1,
    layer: 'all',
    status: 'passed',
    generatedAt: new Date(now).toISOString(),
    integrations: [
      {
        id: 'test',
        owner: 'Fixture',
        version: '1.0.0',
        status: 'passed',
        bundleSha256: 'expected',
        checks: [
          'reproducible-bundle',
          'typecheck',
          'fixtures',
          'plugins::fixture::test',
        ].map(name => ({ name, status: 'passed' })),
      },
    ],
  };
  assert.ok(assessEvidence(report, 'test', 'expected', now));
  assert.equal(assessEvidence(report, 'test', 'changed', now), null);
  assert.equal(
    assessEvidence({ ...report, integrations: {} }, 'test', 'expected', now),
    null,
  );
  assert.equal(
    assessEvidence(
      {
        ...report,
        integrations: [{ ...report.integrations[0], checks: [null] }],
      },
      'test',
      'expected',
      now,
    ),
    null,
  );
  assert.equal(
    assessEvidence({ ...report, layer: 'js' }, 'test', 'expected', now),
    null,
  );
  assert.equal(
    assessEvidence({ ...report, status: 'failed' }, 'test', 'expected', now),
    null,
  );
  assert.equal(
    assessEvidence(
      { ...report, generatedAt: 'invalid' },
      'test',
      'expected',
      now,
    ),
    null,
  );
  assert.equal(
    assessEvidence(report, 'test', 'expected', now + 31 * 86400000).stale,
    true,
  );
  assert.equal(
    assessEvidence(report, 'test', 'expected', now - 86400000),
    null,
  );
});
