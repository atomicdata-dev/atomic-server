import type { Plugin } from 'vite';
import { transform } from 'oxc-transform-react';

// Same skip-filter @vitejs/plugin-react uses for the Babel compiler preset:
// files with neither a capitalized name nor a `use*` identifier are not
// worth running the compiler on. JSX/TS stripping still runs for every
// matched file so Fast Refresh instrumentation stays in this pass.
const looksLikeReactCode = /\b[A-Z]|\buse/;

const includeRE = /\.[cm]?[jt]sx?(?:$|\?)/;
// Worker entrypoints are excluded along with node_modules: Fast Refresh
// instrumentation calls `$RefreshReg$`, which only exists on `window`, so a
// worker module that picks it up dies on load. `@tomic/lib`'s
// `client-db.worker.js` is the one that bites — pnpm links it from
// `browser/lib/dist`, outside any `node_modules/` path, and it is in
// `optimizeDeps.exclude`, so it reaches this transform like first-party code.
const excludeRE = /\/node_modules\/|\.worker\.[cm]?[jt]sx?(?:$|\?)/;

/**
 * Matches the old `babel-plugin-styled-components` options: `displayName` so
 * DOM classes read `Foo-sc-XXX`, `fileName: false` so they aren't prefixed
 * with the source path. Vite's oxc pass (Rolldown) applies this; the React
 * Compiler package does not expose the plugin.
 *
 * @see https://oxc.rs/docs/guide/usage/transformer/plugins.html#styled-components
 */
export const styledComponentsOxcOptions = {
  displayName: true,
  fileName: false,
} as const;

/**
 * Native React Compiler via `oxc-transform-react`, mirroring the unreleased
 * `@vitejs/plugin-react` `compiler: true` integration
 * (vitejs/vite-plugin-react#1419, shipping in 6.1.0).
 *
 * oxc-transform-react owns compiler + TS + JSX + Fast Refresh in one pass.
 * Rolldown's built-in JSX refresh must stay off or it double-instruments.
 * styled-components displayName/SSR ids run in Vite's oxc pass (the compiler
 * package has no `plugins` option).
 *
 * Once plugin-react 6.1.0 is on npm the compiler plugin can be deleted in
 * favour of `react({ compiler: true })`; keep the oxc styled-components
 * options either way.
 */
export function oxcReactCompiler({
  compile = true,
}: { compile?: boolean } = {}): Plugin[] {
  let sourcemap = true;
  let jsxDevelopment = false;
  let fastRefresh = false;
  let appSourceDir = '';

  const compilerPlugin: Plugin = {
    name: 'atomic:oxc-react-compiler',
    enforce: 'pre',
    config() {
      return {
        optimizeDeps: {
          include: ['react/compiler-runtime'],
        },
      };
    },
    configResolved(config) {
      sourcemap = config.command !== 'build' || !!config.build.sourcemap;
      jsxDevelopment = !config.isProduction;
      fastRefresh =
        !config.isProduction &&
        config.command === 'serve' &&
        config.server.hmr !== false;
      appSourceDir = `${config.root}/src/`;
    },
    transform: {
      filter: {
        id: {
          include: includeRE,
          exclude: excludeRE,
        },
      },
      async handler(code, id) {
        const isClient = this.environment?.config.consumer !== 'server';
        const shouldCompile = isClient && looksLikeReactCode.test(code);
        const filename = id.split('?')[0]!;

        // Only this app's own source gets Fast Refresh instrumentation.
        //
        // `includeRE` matches every `.ts` in the workspace, and the refresh
        // transform registers anything capitalized — which in `@tomic/lib`
        // means classes like `Store` and `Resource`, not components. Those
        // modules also load inside the ClientDb worker, where the
        // `$RefreshReg$` definition never runs: plugin-react's footer that
        // declares it is guarded by `!inWebWorker`, while the call this pass
        // emits is not. The worker then dies on
        // `ReferenceError: $RefreshReg$ is not defined`, the app reports it as
        // an error toast on every page, and that toast has a "Copy" button
        // that collides with e2e selectors elsewhere on the page.
        //
        // Nothing is lost: the workspace packages hold no components, and
        // editing them needs a rebuild before vite sees the change anyway.
        const isAppSource = filename.startsWith(appSourceDir);

        const result = await transform(filename, code, {
          jsx: {
            runtime: 'automatic',
            development: jsxDevelopment,
            refresh: isClient && fastRefresh && isAppSource,
          },
          reactCompiler: shouldCompile ? { target: '19' } : false,
          sourcemap,
        });

        const diagnostics = result.errors.map(
          error =>
            `${error.message}${error.codeframe ? `\n${error.codeframe}` : ''}`,
        );

        if (result.fatal) {
          this.error(
            diagnostics.join('\n\n') || 'React Compiler transform failed.',
          );
        }

        for (const diagnostic of diagnostics) {
          this.warn(diagnostic);
        }

        return { code: result.code, map: result.map };
      },
    },
  };

  // plugin-react 6.0.x always turns Rolldown JSX refresh on in serve mode.
  // A post-enforce config hook wins that merge so only oxc-transform-react
  // emits `$RefreshReg$` / `$RefreshSig$`. styled-components lives here too
  // because `vite:oxc` already re-transforms `.tsx` after the compiler pass.
  const oxcViteOptions: Plugin = {
    name: 'atomic:oxc-vite-options',
    enforce: 'post',
    config() {
      return {
        oxc: {
          jsx: {
            refresh: false,
          },
          plugins: {
            styledComponents: styledComponentsOxcOptions,
          },
        },
      };
    },
  };

  return [...(compile ? [compilerPlugin] : []), oxcViteOptions];
}
