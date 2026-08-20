import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  runPlugin,
  type PluginRunRequest,
  type PluginRunResponse,
  type PluginWorkerLike,
} from './plugin-runner.js';
import type { RunInput } from './plugin-sandbox.js';

const input: RunInput = { trigger: { kind: 'manual', at: 1_700_000_000_000 } };

class FakeWorker implements PluginWorkerLike {
  public onmessage: ((e: { data: PluginRunResponse }) => void) | null = null;
  public onerror: ((e: { message?: string }) => void) | null = null;
  public onmessageerror: ((e: unknown) => void) | null = null;
  public terminated = 0;
  public received: PluginRunRequest[] = [];

  public constructor(
    private readonly behaviour: (worker: FakeWorker) => void = () => {},
  ) {}

  public postMessage(message: PluginRunRequest): void {
    this.received.push(message);
    this.behaviour(this);
  }

  public terminate(): void {
    this.terminated++;
  }

  public respond(response: PluginRunResponse): void {
    this.onmessage?.({ data: response });
  }
}

const verdictJson = (over: Record<string, unknown> = {}) =>
  JSON.stringify({ intents: [], problems: [], ...over });

afterEach(() => {
  vi.useRealTimers();
});

describe('runPlugin', () => {
  it('parses the verdict the sandbox returned', async () => {
    const worker = new FakeWorker(w =>
      w.respond({
        ok: true,
        json: verdictJson({
          intents: [{ op: 'destroy', subject: 'https://x/a' }],
          cursor: 'p2',
        }),
      }),
    );

    const { verdict, timedOut } = await runPlugin('', input, {
      createWorker: () => worker,
    });

    expect(timedOut).toBe(false);
    expect(verdict.intents).toHaveLength(1);
    expect(verdict.cursor).toBe('p2');
  });

  it('forwards the source, input and output cap to the sandbox', async () => {
    const worker = new FakeWorker(w =>
      w.respond({ ok: true, json: verdictJson() }),
    );

    await runPlugin('export function run() {}', input, {
      createWorker: () => worker,
      maxOutputBytes: 1234,
    });

    expect(worker.received[0]).toEqual({
      source: 'export function run() {}',
      input,
      maxOutputBytes: 1234,
    });
  });

  it('applies the intent limit while parsing', async () => {
    const intents = Array.from({ length: 4 }, (_, i) => ({
      op: 'destroy',
      subject: `https://x/${i}`,
    }));
    const worker = new FakeWorker(w =>
      w.respond({ ok: true, json: verdictJson({ intents }) }),
    );

    const { verdict } = await runPlugin('', input, {
      createWorker: () => worker,
      maxIntents: 2,
    });

    expect(verdict.intents).toEqual([]);
    expect(verdict.problems[0].message).toContain('limit of 2');
  });

  it('tears the sandbox down after a normal run', async () => {
    const worker = new FakeWorker(w =>
      w.respond({ ok: true, json: verdictJson() }),
    );

    await runPlugin('', input, { createWorker: () => worker });

    expect(worker.terminated).toBe(1);
  });
});

describe('failures', () => {
  const blocked = async (worker: FakeWorker) => {
    const { verdict } = await runPlugin('', input, {
      createWorker: () => worker,
    });

    return verdict.problems.filter(p => p.severity === 'error');
  };

  it('reports a problem the sandbox raised', async () => {
    const problems = await blocked(
      new FakeWorker(w =>
        w.respond({
          ok: false,
          problem: { severity: 'error', message: 'run() threw: Error: boom' },
        }),
      ),
    );

    expect(problems[0].message).toContain('boom');
  });

  it('reports a sandbox that failed to start', async () => {
    const { verdict } = await runPlugin('', input, {
      createWorker: () => {
        throw new Error('no worker support');
      },
    });

    expect(verdict.problems[0].message).toContain('could not start');
  });

  it('reports a sandbox error event', async () => {
    const problems = await blocked(
      new FakeWorker(w => w.onerror?.({ message: 'SyntaxError' })),
    );

    expect(problems[0].message).toContain('SyntaxError');
  });

  it('reports an unreadable verdict instead of throwing', async () => {
    const problems = await blocked(
      new FakeWorker(w => w.respond({ ok: true, json: 'not json' })),
    );

    expect(problems[0].message).toContain('could not read the verdict');
  });

  it('reports a sandbox that answered with nothing', async () => {
    const problems = await blocked(
      new FakeWorker(w => w.respond(undefined as unknown as PluginRunResponse)),
    );

    expect(problems[0].message).toContain('no result');
  });

  it('ignores a late reply after the first outcome', async () => {
    const worker = new FakeWorker(w => w.onerror?.({ message: 'first' }));

    const { verdict } = await runPlugin('', input, {
      createWorker: () => worker,
    });

    worker.respond({ ok: true, json: verdictJson({ cursor: 'late' }) });

    expect(verdict.cursor).toBeUndefined();
    expect(worker.terminated).toBe(1);
  });
});

describe('time budget', () => {
  it('stops a run that overruns and says so', async () => {
    vi.useFakeTimers();
    const worker = new FakeWorker();

    const pending = runPlugin('', input, {
      createWorker: () => worker,
      timeoutMs: 5000,
    });

    await vi.advanceTimersByTimeAsync(5000);
    const { verdict, timedOut } = await pending;

    expect(timedOut).toBe(true);
    expect(worker.terminated).toBe(1);
    expect(verdict.intents).toEqual([]);
    expect(verdict.problems[0].message).toContain('5000ms');
    expect(verdict.problems[0].message).toContain('Nothing was planned');
  });

  it('does not fire the budget for a run that finished', async () => {
    vi.useFakeTimers();
    const worker = new FakeWorker(w =>
      w.respond({ ok: true, json: verdictJson() }),
    );

    const { verdict } = await runPlugin('', input, {
      createWorker: () => worker,
      timeoutMs: 5000,
    });

    await vi.advanceTimersByTimeAsync(10_000);

    expect(verdict.problems).toEqual([]);
    expect(worker.terminated).toBe(1);
  });
});
