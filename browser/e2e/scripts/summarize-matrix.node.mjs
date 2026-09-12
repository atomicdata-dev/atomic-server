import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

test('acceptance requires five complete zero-retry runs and a clean source commit', () => {
  const root = mkdtempSync(join(tmpdir(), 'matrix-accounting-'));
  const write = (path, value) => writeFileSync(path, JSON.stringify(value));

  const summarize = () => {
    execFileSync(process.execPath, [
      fileURLToPath(new URL('./summarize-matrix.mjs', import.meta.url)),
      root,
    ]);

    return JSON.parse(readFileSync(join(root, 'matrix-summary.json'), 'utf8'));
  };

  const expected = [
    { id: 'pass', title: ['pass'] },
    { id: 'opt-in', title: ['opt-in'] },
  ];
  const results = [
    {
      id: 'pass',
      status: 'passed',
      expectedStatus: 'passed',
      retry: 0,
      durationMs: 200,
    },
    {
      id: 'opt-in',
      status: 'skipped',
      expectedStatus: 'skipped',
      retry: 0,
      durationMs: 0,
      annotations: [{ type: 'skip', description: 'requires a portal' }],
    },
  ];
  const matrix = {
    source: { commit: 'abc', dirty: '' },
    sourceAtEnd: { commit: 'abc', dirty: '' },
    matrix: [{ workers: 8, shards: 1 }],
    phases: [],
    runs: [],
  };

  try {
    for (let repetition = 1; repetition <= 5; repetition++) {
      const directory = join(root, String(repetition));
      mkdirSync(join(directory, 'metrics'), { recursive: true });
      write(join(directory, 'metrics/summary.json'), { expected, results });
      writeFileSync(join(directory, 'metrics/host-samples.jsonl'), '');
      matrix.runs.push({
        sourceAtEnd: { commit: 'abc', dirty: '' },
        workers: 8,
        shards: 1,
        repetition,
        testTimeMs: 250,
        outcomes: [{ directory, exitCode: 0 }],
      });
    }

    write(join(root, 'run.json'), matrix);
    assert.equal(summarize().settings[0].fivePassAcceptance, true);
    write(join(root, '5/metrics/summary.json'), {
      expected,
      results: results.slice(1),
    });
    assert.equal(summarize().settings[0].fivePassAcceptance, false);
    write(join(root, '5/metrics/summary.json'), {
      expected,
      results: [{ ...results[0], retry: 1 }, results[1]],
    });
    assert.equal(summarize().settings[0].fivePassAcceptance, false);
    write(join(root, '5/metrics/summary.json'), {
      expected,
      results: [{ ...results[0], status: 'failed' }, results[1]],
    });
    assert.equal(summarize().settings[0].fivePassAcceptance, false);
    write(join(root, '5/metrics/summary.json'), { expected, results });
    matrix.runs[4].sourceAtEnd.commit = 'changed-during-run';
    write(join(root, 'run.json'), matrix);
    assert.equal(summarize().settings[0].fivePassAcceptance, false);
    matrix.runs[4].sourceAtEnd.commit = 'abc';
    matrix.source.dirty = ' M source.ts';
    write(join(root, 'run.json'), matrix);
    assert.equal(summarize().settings[0].fivePassAcceptance, false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
