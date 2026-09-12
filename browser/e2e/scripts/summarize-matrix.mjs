#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const root = resolve(process.argv[2] ?? '.');
const matrix = JSON.parse(readFileSync(join(root, 'run.json'), 'utf8'));

const quantile = (values, q) => {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);

  return sorted[Math.ceil((sorted.length - 1) * q)];
};

const distribution = values => ({
  min: quantile(values, 0),
  median: quantile(values, 0.5),
  p95: quantile(values, 0.95),
  max: quantile(values, 1),
});
let expectedIds;
const runs = matrix.runs.map(run => {
  const reports = run.outcomes.map(outcome => {
    const directory = resolve(root, outcome.directory);

    try {
      return {
        summary: JSON.parse(
          readFileSync(join(directory, 'metrics/summary.json'), 'utf8'),
        ),
        samples: readFileSync(
          join(directory, 'metrics/host-samples.jsonl'),
          'utf8',
        )
          .trim()
          .split('\n')
          .filter(Boolean)
          .map(line => JSON.parse(line)),
      };
    } catch (error) {
      return { error: String(error), samples: [] };
    }
  });
  const expected = reports.flatMap(report => report.summary?.expected ?? []);
  const results = reports.flatMap(report => report.summary?.results ?? []);
  const samples = reports.flatMap(report => report.samples);
  const ids = expected.map(test => test.id).sort();
  expectedIds ??= ids;
  const accounted =
    ids.length > 0 &&
    JSON.stringify(ids) === JSON.stringify(expectedIds) &&
    JSON.stringify(results.map(test => test.id).sort()) === JSON.stringify(ids);
  const failures = results.filter(
    test => test.status !== test.expectedStatus && test.status !== 'skipped',
  );
  const skips = results
    .filter(test => test.status === 'skipped')
    .map(test => ({ title: test.title, annotations: test.annotations }));

  return {
    ...run,
    accounted,
    expected: ids.length,
    executed: results.filter(test => test.status !== 'skipped').length,
    skips,
    failures,
    completePass:
      accounted &&
      !reports.some(report => report.error) &&
      !run.outcomes.some(outcome => outcome.exitCode !== 0) &&
      failures.length === 0 &&
      results.every(test => test.retry === 0),
    cpuBusyPercent: distribution(
      samples
        .map(sample => sample.cpuBusyPercent)
        .filter(value => value !== null),
    ),
    availableBytes: distribution(samples.map(sample => sample.availableBytes)),
    serverLatencyMs: distribution(
      samples
        .filter(sample => sample.server.status === 200)
        .map(sample => sample.server.ms),
    ),
    serverProbeErrors: samples.filter(sample => sample.server.status !== 200)
      .length,
    setupTimeMs: distribution(
      results
        .map(test => test.setupMs)
        .filter(value => typeof value === 'number'),
    ),
    totalSetupMs: results.reduce((sum, test) => sum + (test.setupMs ?? 0), 0),
    slowest: [...results]
      .sort((a, b) => b.durationMs - a.durationMs)
      .slice(0, 15),
  };
});
const baseline = quantile(
  runs
    .filter(run => run.workers === 1 && run.shards === 1)
    .map(run => run.testTimeMs),
  0.5,
);
const settings = matrix.matrix.map(({ workers, shards }) => {
  const matching = runs.filter(
    run => run.workers === workers && run.shards === shards,
  );
  const timing = distribution(matching.map(run => run.testTimeMs));

  return {
    workers,
    shards,
    totalWorkers: workers * shards,
    runs: matching.length,
    completePasses: matching.filter(run => run.completePass).length,
    testTimeMs: timing,
    speedupVsOne: baseline && timing.median ? baseline / timing.median : null,
    fivePassAcceptance:
      matrix.source?.dirty === '' &&
      JSON.stringify(matrix.sourceAtEnd) === JSON.stringify(matrix.source) &&
      matching.every(
        run =>
          JSON.stringify(run.sourceAtEnd) === JSON.stringify(matrix.source),
      ) &&
      matching.length >= 5 &&
      matching.every(run => run.completePass),
  };
});
const summary = {
  source: matrix.source,
  buildPhases: matrix.phases.filter(phase => phase.name !== 'startup'),
  startup: distribution(
    matrix.phases
      .filter(phase => phase.name === 'startup')
      .map(phase => phase.durationMs),
  ),
  settings,
  runs,
};
writeFileSync(
  join(root, 'matrix-summary.json'),
  JSON.stringify(summary, null, 2),
);
// eslint-disable-next-line no-console -- Tabular CLI summary.
console.table(
  settings.map(setting => ({
    workers: setting.workers,
    shards: setting.shards,
    passes: `${setting.completePasses}/${setting.runs}`,
    medianSeconds: setting.testTimeMs.median / 1000,
    speedup: setting.speedupVsOne,
    acceptance: setting.fivePassAcceptance,
  })),
);
console.info(
  `Full accounting and skip reasons: ${join(root, 'matrix-summary.json')}`,
);
