/**
 * DedicatedWorker that executes a plugin's `run` export.
 *
 * Bundled as its own entry so hosts can load it with
 * `new Worker(new URL('@tomic/lib/plugin-run.worker.js', import.meta.url))`.
 *
 * This worker is meant to be nested inside a null-origin iframe whose CSP sets
 * `connect-src 'none'` — that iframe, not this file, is what actually denies
 * the network. What happens here is defence in depth and, mostly, a better
 * error message.
 */

import {
  applyDeterministicGlobals,
  denyAmbientGlobals,
  invokeRun,
  type PluginModule,
} from './plugin-sandbox.js';
import type { PluginRunRequest, PluginRunResponse } from './plugin-runner.js';

const scope = globalThis as unknown as Record<string, unknown>;

// Captured before the globals are denied, so the reply still works.
const reply = (response: PluginRunResponse) =>
  (
    globalThis as unknown as {
      postMessage: (m: PluginRunResponse) => void;
    }
  ).postMessage(response);

globalThis.onmessage = async (event: MessageEvent<PluginRunRequest>) => {
  const { source, input, maxOutputBytes } = event.data;

  const denial = denyAmbientGlobals(scope);
  applyDeterministicGlobals(scope, input);

  let module: PluginModule;

  try {
    module = await importModule(source);
  } catch (e) {
    reply({
      ok: false,
      problem: {
        severity: 'error',
        message: `plugin source could not be loaded: ${
          e instanceof Error ? `${e.name}: ${e.message}` : String(e)
        }`,
      },
      undeniable: denial.undeniable,
    });

    return;
  }

  const result = await invokeRun(module, input, { maxOutputBytes });

  reply(
    result.json !== undefined
      ? { ok: true, json: result.json, undeniable: denial.undeniable }
      : {
          ok: false,
          problem: result.problem ?? {
            severity: 'error',
            message: 'run() produced no result',
          },
          undeniable: denial.undeniable,
        },
  );
};

/**
 * Evaluates the plugin as a real ES module.
 *
 * A blob URL keeps `import` and top-level `await` working, which matters
 * because generated code looks like ordinary TypeScript output and failing on
 * a stray `export` would be a confusing first experience.
 */
async function importModule(source: string): Promise<PluginModule> {
  const url = URL.createObjectURL(
    new Blob([source], { type: 'text/javascript' }),
  );

  try {
    return (await import(/* @vite-ignore */ url)) as PluginModule;
  } finally {
    URL.revokeObjectURL(url);
  }
}
