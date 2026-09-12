import type {
  FullConfig,
  FullResult,
  Reporter,
  Suite,
  TestCase,
  TestResult,
  TestStep,
} from '@playwright/test/reporter';
import { cpus, freemem, loadavg, totalmem } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  appendFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { monitorEventLoopDelay } from 'node:perf_hooks';

const exec = promisify(execFile);

/** One bounded host sampler per shard, plus complete test accounting. No app data. */
export default class LoadReporter implements Reporter {
  private samples: unknown[] = [];
  private results: unknown[] = [];
  private setupMs = new Map<string, number>();
  private templateSteps = new Map<
    string,
    Array<{ name: string; durationMs: number }>
  >();
  private timer?: ReturnType<typeof setInterval>;
  private pending: Promise<void> = Promise.resolve();
  private lag = monitorEventLoopDelay({ resolution: 20 });
  private start = Date.now();
  private previousCPU = cpus();
  private suite?: Suite;
  private directory = process.env.ATOMIC_E2E_METRICS_DIR ?? 'test-results/load';
  private workers = 0;

  onBegin(config: FullConfig, suite: Suite) {
    this.suite = suite;
    this.workers = config.workers;
    mkdirSync(this.directory, { recursive: true });
    writeFileSync(join(this.directory, 'host-samples.jsonl'), '');
    writeFileSync(join(this.directory, 'test-results.jsonl'), '');
    this.lag.enable();
    this.pending = this.sample();
    this.timer = setInterval(() => {
      this.pending = this.pending.then(() => this.sample());
    }, 5000);
  }

  private async sample() {
    const current = cpus();
    let total = 0,
      idle = 0;
    current.forEach((cpu, i) => {
      const previous = this.previousCPU[i]?.times ?? cpu.times;
      idle += cpu.times.idle - previous.idle;
      total += Object.entries(cpu.times).reduce(
        (sum, [key, value]) =>
          sum + value - previous[key as keyof typeof previous],
        0,
      );
    });
    this.previousCPU = current;
    const started = performance.now();
    let server: unknown;

    try {
      const response = await fetch(
        `${process.env.ATOMIC_SERVICE_URL ?? process.env.SERVER_URL ?? 'http://localhost:9883'}/server`,
        {
          signal: AbortSignal.timeout(2000),
          headers: { Accept: 'application/ad+json' },
        },
      );
      server = { ms: performance.now() - started, status: response.status };
    } catch (error) {
      server = { ms: performance.now() - started, error: String(error) };
    }

    let processes = '',
      pressure: Record<string, string> = {};

    try {
      // Include other jobs so saturation cannot be attributed to browsers alone.
      processes = (
        await exec('ps', ['-eo', 'pid,ppid,pcpu,rss,comm'], {
          timeout: 2000,
          maxBuffer: 1024 * 1024,
        })
      ).stdout;
    } catch {
      /* unavailable on this host */
    }

    if (process.platform === 'linux') {
      for (const kind of ['cpu', 'memory', 'io']) {
        try {
          pressure[kind] = readFileSync(`/proc/pressure/${kind}`, 'utf8');
        } catch {
          /* optional kernel feature */
        }
      }
    }

    let availableBytes = freemem();

    try {
      const available = readFileSync('/proc/meminfo', 'utf8').match(
        /^MemAvailable:\s+(\d+)/m,
      );
      if (available) availableBytes = Number(available[1]) * 1024;
    } catch {
      /* Linux reports reclaimable cache separately from free memory. */
    }

    const sample = {
      at: Date.now(),
      elapsedMs: Date.now() - this.start,
      cpuBusyPercent: total ? 100 * (1 - idle / total) : null,
      freeBytes: freemem(),
      availableBytes,
      totalBytes: totalmem(),
      load: loadavg(),
      reporterEventLoopMaxMs: this.lag.max / 1e6,
      server,
      pressure,
      processes,
    };
    this.samples.push(sample);
    this.samples = this.samples.slice(-12);
    this.lag.reset();
    // Persist during the run, including when Playwright is interrupted.
    appendFileSync(
      join(this.directory, 'host-samples.jsonl'),
      JSON.stringify(sample) + '\n',
    );
  }

  onStepEnd(test: TestCase, _result: TestResult, step: TestStep) {
    if (step.title.startsWith('Template ')) {
      const steps = this.templateSteps.get(test.id) ?? [];
      steps.push({ name: step.title, durationMs: step.duration });
      this.templateSteps.set(test.id, steps);
    }

    if (step.title === 'Initialize fresh agent and drive')
      this.setupMs.set(test.id, step.duration);
  }

  onTestEnd(test: TestCase, result: TestResult) {
    const record = {
      id: test.id,
      title: test.titlePath(),
      status: result.status,
      expectedStatus: test.expectedStatus,
      durationMs: result.duration,
      setupMs: this.setupMs.get(test.id) ?? null,
      templateSteps: this.templateSteps.get(test.id) ?? [],
      retry: result.retry,
      worker: result.workerIndex,
      parallelIndex: result.parallelIndex,
      annotations: test.annotations,
    };
    this.results.push(record);
    appendFileSync(
      join(this.directory, 'test-results.jsonl'),
      JSON.stringify(record) + '\n',
    );
    if (result.status !== test.expectedStatus)
      result.attachments.push({
        name: 'host-load',
        contentType: 'application/json',
        body: Buffer.from(JSON.stringify(this.samples.slice(-12))),
      });
  }

  async onEnd(result: FullResult) {
    clearInterval(this.timer);
    await this.pending;
    this.lag.disable();
    writeFileSync(
      join(this.directory, 'summary.json'),
      JSON.stringify(
        {
          status: result.status,
          testTimeMs: result.duration,
          workers: this.workers,
          expected: this.suite?.allTests().map(test => ({
            id: test.id,
            title: test.titlePath(),
            annotations: test.annotations,
          })),
          results: this.results,
        },
        null,
        2,
      ),
    );
  }
}
