import type { JSONObject, JSONValue } from './value.js';
import type { Problem } from './plugin-run.js';

/**
 * The execution half of the plugin `run` contract.
 *
 * Kept free of any Worker or DOM API so it can be exercised directly in tests;
 * `plugin-run.worker` is a thin shell that applies these to its own global
 * scope and calls {@link invokeRun}.
 */

export type TriggerKind =
  | 'manual'
  | 'cron'
  | 'timer'
  | 'webhook'
  | 'query:entered'
  | 'query:left'
  | 'query:changed'
  | 'commit:before'
  | 'commit:after';

export interface RunTrigger {
  kind: TriggerKind;
  /**
   * When the host started this run. The only clock a plugin gets: the sandbox
   * freezes `Date` to it so two runs over the same input agree, which is what
   * makes fixtures worth anything.
   */
  at: number;
  /** The resource that triggered, for commit, query and timer triggers. */
  subject?: string;
  /** Webhook body or cron payload, unparsed. */
  payload?: JSONValue;
}

export interface RunInput {
  trigger: RunTrigger;
  /** Already-parsed records. The host owns acquisition and parsing. */
  records?: JSONValue[];
  /** User-editable plugin config. */
  config?: JSONObject;
  /** Cursor the previous run returned, for incremental sync. */
  cursor?: string;
  /** Seeds the sandbox PRNG. Defaults to a hash of the rest of the input. */
  seed?: number;
}

export interface InvokeOptions {
  /**
   * Cap on the serialized verdict. Exceeding it is an error, never a truncation
   * — a clipped verdict is a wrong verdict, not a smaller one.
   */
  maxOutputBytes?: number;
}

export interface InvokeResult {
  /** JSON text of what `run` returned. Absent when it could not run. */
  json?: string;
  /** Why there is no output. */
  problem?: Problem;
}

const DEFAULT_MAX_OUTPUT_BYTES = 32 * 1024 * 1024;

/** Shape a plugin module is expected to have. */
export interface PluginModule {
  run?: unknown;
}

/**
 * Calls a plugin's `run` and serializes the result.
 *
 * Never throws: a plugin that blows up, hangs on a rejected promise, returns a
 * cycle, or floods the output all come back as a {@link Problem} the preview
 * can show, because "the import silently did nothing" is the failure mode worth
 * designing against.
 */
export async function invokeRun(
  module: PluginModule,
  input: RunInput,
  options: InvokeOptions = {},
): Promise<InvokeResult> {
  if (typeof module.run !== 'function') {
    return {
      problem: {
        severity: 'error',
        message: 'plugin does not export a run() function',
      },
    };
  }

  let result: unknown;

  try {
    result = await (module.run as (input: RunInput) => unknown)(input);
  } catch (e) {
    return {
      problem: {
        severity: 'error',
        message: `run() threw: ${describeError(e)}`,
      },
    };
  }

  return serializeResult(
    result,
    options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES,
  );
}

function serializeResult(
  result: unknown,
  maxOutputBytes: number,
): InvokeResult {
  let json: string;

  try {
    json = JSON.stringify(result) ?? 'null';
  } catch (e) {
    return {
      problem: {
        severity: 'error',
        message: `run() returned something that cannot be serialized: ${describeError(e)}`,
      },
    };
  }

  if (json.length > maxOutputBytes) {
    return {
      problem: {
        severity: 'error',
        message: `run() returned ${json.length} bytes, over the limit of ${maxOutputBytes}. Nothing was planned.`,
      },
    };
  }

  return { json };
}

/**
 * Replaces the ambient clock and PRNG with deterministic ones.
 *
 * Plugins are re-run: on a fixture before a release is trusted, on a sample
 * before the full input, and on the server after being authored in a browser.
 * A `Date.now()` that moves between those runs turns every one of those checks
 * into a coin flip, so the sandbox pins it to `trigger.at` rather than
 * forbidding it and breaking incidental library calls.
 */
export function applyDeterministicGlobals(
  scope: Record<string, unknown>,
  input: RunInput,
): () => void {
  const frozen = input.trigger.at;
  const NativeDate = scope.Date as DateConstructor;
  const nativeMath = scope.Math as Math;
  const nativePerformance = scope.performance as { now?: () => number };

  class FrozenDate extends NativeDate {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    constructor(...args: any[]) {
      if (args.length === 0) {
        super(frozen);
      } else {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        super(...(args as [any]));
      }
    }

    public static now(): number {
      return frozen;
    }
  }

  // `Date` is swapped on the scope, but `Math` and `performance` are singletons
  // with no per-scope binding, so those are patched in place and put back by
  // the returned restore. In the worker both are `globalThis`.
  const random = mulberry32(input.seed ?? seedFrom(input));
  const originalRandom = nativeMath.random;
  const originalPerformanceNow = nativePerformance?.now;

  scope.Date = FrozenDate;
  nativeMath.random = random;

  if (nativePerformance) {
    let ticks = 0;
    nativePerformance.now = () => ticks++;
  }

  return () => {
    scope.Date = NativeDate;
    nativeMath.random = originalRandom;

    if (nativePerformance && originalPerformanceNow) {
      nativePerformance.now = originalPerformanceNow;
    }
  };
}

/** Ambient globals a `run` sandbox must not have. */
export const DENIED_GLOBALS = [
  'fetch',
  'XMLHttpRequest',
  'WebSocket',
  'EventSource',
  'importScripts',
  'indexedDB',
  'caches',
  'Worker',
  'SharedWorker',
  'BroadcastChannel',
  'navigator',
  'localStorage',
  'sessionStorage',
] as const;

export interface DenyResult {
  /** Globals that now throw when touched. */
  denied: string[];
  /**
   * Globals that are present but could not be shadowed. Surfaced rather than
   * swallowed: a denial that quietly did not apply is worse than none, because
   * it reads as containment that is not there.
   */
  undeniable: string[];
  restore: () => void;
}

/**
 * Makes ambient I/O throw a message that says what to do instead.
 *
 * `run` holds no authority by design, so reaching for the network is an
 * authoring mistake, not an attack — and `fetch is not a function` is a bad way
 * to learn that the host is supposed to do the fetching.
 *
 * Worker globals like `fetch` and `indexedDB` live on `WorkerGlobalScope.prototype`
 * rather than on `globalThis` itself, so this shadows by defining an own
 * property, and looks up the original along the prototype chain to restore.
 */
export function denyAmbientGlobals(scope: Record<string, unknown>): DenyResult {
  const denied: string[] = [];
  const undeniable: string[] = [];
  const restores: Array<() => void> = [];

  for (const name of DENIED_GLOBALS) {
    if (!(name in scope)) continue;

    const own = Object.getOwnPropertyDescriptor(scope, name);

    try {
      Object.defineProperty(scope, name, {
        configurable: true,
        get() {
          throw new Error(
            `run() cannot use ${name}: it has no I/O of its own. Return intents and let the host write, or declare a network capability so the host fetches for you.`,
          );
        },
      });
    } catch {
      undeniable.push(name);
      continue;
    }

    denied.push(name);
    restores.push(() => {
      if (own) {
        Object.defineProperty(scope, name, own);
      } else {
        // Was inherited; dropping the shadow exposes the original again.
        delete scope[name];
      }
    });
  }

  return {
    denied,
    undeniable,
    restore: () => restores.forEach(restore => restore()),
  };
}

function describeError(e: unknown): string {
  if (e instanceof Error) return `${e.name}: ${e.message}`;

  return String(e);
}

/** Deterministic 32-bit PRNG. Small, seedable, good enough for sampling. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;

  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;

    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function seedFrom(input: RunInput): number {
  const text = `${input.trigger.kind}:${input.trigger.at}:${input.cursor ?? ''}`;
  let hash = 2166136261;

  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }

  return hash >>> 0;
}
