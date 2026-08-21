import { parseVerdict, type Problem, type Verdict } from './plugin-run.js';
import { parseManifest, type PluginManifest } from './plugin-manifest.js';
import type { RunInput } from './plugin-sandbox.js';

/**
 * Host half of the `run` runner: spawns a sandbox, gives it a time budget, and
 * turns whatever comes back into a {@link Verdict}.
 *
 * A run gets a fresh sandbox and the sandbox is always torn down, so nothing a
 * plugin leaves behind — a timer, a huge array, a monkey-patched prototype —
 * outlives the run that created it.
 */

export interface PluginRunRequest {
  /** ES module source exporting `run`. */
  source: string;
  input: RunInput;
  maxOutputBytes?: number;
  /**
   * `manifest` evaluates the module and returns its declaration without
   * calling `run`. Reading a declaration must not run the plugin.
   */
  want?: 'run' | 'manifest';
}

export type PluginRunResponse = {
  /**
   * Ambient globals the sandbox could not shadow. Reported rather than
   * swallowed so a weaker-than-intended sandbox shows up in the preview.
   */
  undeniable?: string[];
} & ({ ok: true; json: string } | { ok: false; problem: Problem });

/** The slice of `Worker` the runner uses, so hosts and tests can substitute. */
export interface PluginWorkerLike {
  postMessage(message: PluginRunRequest): void;
  terminate(): void;
  onmessage: ((event: { data: PluginRunResponse }) => void) | null;
  onerror: ((event: { message?: string }) => void) | null;
  onmessageerror?: ((event: unknown) => void) | null;
}

export type PluginWorkerFactory = () => PluginWorkerLike;

export interface RunPluginOptions {
  createWorker: PluginWorkerFactory;
  /**
   * Wall-clock budget. A plugin that overruns is terminated, not waited on: an
   * infinite loop in generated code is a normal Tuesday, and the run has to end
   * in something a user can read.
   */
  timeoutMs?: number;
  maxOutputBytes?: number;
  maxIntents?: number;
}

export interface PluginRunOutcome {
  verdict: Verdict;
  /** True when the budget was hit; the verdict then carries the explanation. */
  timedOut: boolean;
}

const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * Runs a plugin's `run` export and returns a verdict that is always safe to
 * show. Every failure — a crash, a hang, a sandbox that would not start — comes
 * back as a blocking problem rather than a rejected promise, so a caller can
 * render one result screen instead of two.
 */
export async function runPlugin(
  source: string,
  input: RunInput,
  options: RunPluginOptions,
): Promise<PluginRunOutcome> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  let worker: PluginWorkerLike;

  try {
    worker = options.createWorker();
  } catch (e) {
    return failed(`could not start the plugin sandbox: ${describeError(e)}`);
  }

  let settle: (outcome: PluginRunOutcome) => void;
  const outcome = new Promise<PluginRunOutcome>(resolve => {
    settle = resolve;
  });

  let done = false;

  const finish = (result: PluginRunOutcome) => {
    if (done) return;

    done = true;
    clearTimeout(timer);
    worker.onmessage = null;
    worker.onerror = null;
    worker.terminate();
    settle(result);
  };

  const timer = setTimeout(() => {
    finish({
      ...failed(
        `run() did not finish within ${timeoutMs}ms and was stopped. Nothing was planned.`,
      ),
      timedOut: true,
    });
  }, timeoutMs);

  worker.onmessage = event => {
    finish(toOutcome(event.data, options.maxIntents));
  };

  worker.onerror = event => {
    finish(
      failed(
        `the plugin sandbox failed to run: ${event.message ?? 'unknown error'}`,
      ),
    );
  };

  if (worker.onmessageerror !== undefined) {
    worker.onmessageerror = () => {
      finish(
        failed('the plugin sandbox returned a message that could not be read'),
      );
    };
  }

  try {
    worker.postMessage({
      source,
      input,
      maxOutputBytes: options.maxOutputBytes,
    });
  } catch (e) {
    finish(
      failed(`could not send the run to the sandbox: ${describeError(e)}`),
    );
  }

  return outcome;
}

function toOutcome(
  response: PluginRunResponse,
  maxIntents?: number,
): PluginRunOutcome {
  const sandboxProblems: Problem[] = response?.undeniable?.length
    ? [
        {
          severity: 'warning',
          message: `the sandbox could not deny ${response.undeniable.join(', ')}; this run was less contained than intended`,
        },
      ]
    : [];

  if (!response?.ok) {
    const problem = response?.problem ?? {
      severity: 'error' as const,
      message: 'the plugin sandbox returned no result',
    };

    return {
      verdict: { intents: [], problems: [...sandboxProblems, problem] },
      timedOut: false,
    };
  }

  let raw: unknown;

  try {
    raw = JSON.parse(response.json);
  } catch (e) {
    return failed(`could not read the verdict: ${describeError(e)}`);
  }

  const verdict = parseVerdict(raw, { maxIntents });

  return {
    verdict: {
      ...verdict,
      problems: [...sandboxProblems, ...verdict.problems],
    },
    timedOut: false,
  };
}

function failed(message: string): PluginRunOutcome {
  return {
    verdict: { intents: [], problems: [{ severity: 'error', message }] },
    timedOut: false,
  };
}

function describeError(e: unknown): string {
  if (e instanceof Error) return `${e.name}: ${e.message}`;

  return String(e);
}

/**
 * Reads a plugin's `manifest` export without running it.
 *
 * A declaration is meant to be read before anyone trusts the plugin, so it is
 * evaluated in the same sandbox rather than on the page: a module body still
 * runs, and that is code nobody has approved.
 */
export async function describePlugin(
  source: string,
  options: RunPluginOptions,
): Promise<PluginManifest> {
  let worker: PluginWorkerLike;

  try {
    worker = options.createWorker();
  } catch {
    return { secrets: [] };
  }

  return new Promise<PluginManifest>(resolve => {
    let done = false;

    const finish = (manifest: PluginManifest) => {
      if (done) return;

      done = true;
      clearTimeout(timer);
      worker.onmessage = null;
      worker.onerror = null;
      worker.terminate();
      resolve(manifest);
    };

    const timer = setTimeout(
      () => finish({ secrets: [] }),
      options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    );

    // A plugin that cannot be read declares nothing: the page still renders,
    // and the reason surfaces when the plugin is actually run.
    worker.onmessage = event => {
      const data = event.data;

      finish(data?.ok ? parseManifest(safeParse(data.json)) : { secrets: [] });
    };

    worker.onerror = () => finish({ secrets: [] });

    try {
      worker.postMessage({
        source,
        input: { trigger: { kind: 'manual', at: 0 } },
        want: 'manifest',
      });
    } catch {
      finish({ secrets: [] });
    }
  });
}

function safeParse(json: string): unknown {
  try {
    return JSON.parse(json);
  } catch {
    return undefined;
  }
}
