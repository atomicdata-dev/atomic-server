import { defineConfig, searchForWorkspaceRoot } from 'vite';
import react from '@vitejs/plugin-react';
import { VitePWA } from 'vite-plugin-pwa';
import { oxcReactCompiler } from './oxcReactCompilerPlugin';
import webfontDownload from 'vite-plugin-webfont-dl';
import prismjs from 'vite-plugin-prismjs';
import wasm from 'vite-plugin-wasm';
import { wuchale } from 'wuchale/vite';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { execSync } from 'node:child_process';

// TAURI=1 produces a Tauri-compatible bundle: no CSP nonces (Tauri serves
// HTML verbatim, so the server's runtime ATOMICSERVER_NONCE substitution
// doesn't happen), no PWA service worker (tauri:// isn't HTTP), separate
// outDir so the server build keeps its own nonce'd dist.
const isTauri = process.env.TAURI === '1';
const isVitest = process.env.VITEST === 'true';

// Where the optional NextGraph mirror lives, when it is linked from a sibling
// checkout rather than installed.
//
// It ships TypeScript sources and runs its wasm engine in a module worker.
// Vite serves that worker entry over `/@fs/…` as a separate request, and
// refuses any path outside the workspace root — so without this the worker
// 403s, the mirror falls back to running the engine on the main thread, and
// nothing says why. Installed from a registry it sits in `node_modules` and
// none of this applies.
function ngBridgeRoots(): string[] {
  try {
    // `<bridge>/packages/ui` → `<bridge>`, so the engine package beside it is
    // covered too.
    const linked = fs.realpathSync(
      path.resolve(__dirname, 'node_modules/@tomic/ng-bridge-react'),
    );

    return [path.resolve(linked, '../..')];
  } catch {
    // Not installed, or not linked. Then there is no worker to serve.
    return [];
  }
}

// Source maps are 28MB of the 48MB dist -- and that dist is compiled into the
// atomic-server binary by build.rs, so every user downloads ~60% debugging
// artifacts they will never open. `vite dev` serves maps regardless of this
// setting, so day-to-day debugging is unaffected; set SOURCEMAP=1 to put them
// back into a production build when you need to read a minified stack trace.
const wantSourcemaps = process.env.SOURCEMAP === '1';

const repoLibDefaults = path.resolve(__dirname, '../../lib/defaults');
const ciLibDefaults = path.resolve(__dirname, '../lib-defaults');
const libDefaultsDir = fs.existsSync(
  path.join(repoLibDefaults, 'default_base_models.json'),
)
  ? repoLibDefaults
  : ciLibDefaults;

// Build/version info surfaced on the About page. Computed at build time and
// injected via `define`. Falls back gracefully outside a git checkout.
const appVersion = (
  JSON.parse(
    fs.readFileSync(path.resolve(__dirname, 'package.json'), 'utf-8'),
  ) as { version: string }
).version;

let gitCommit = 'unknown';

try {
  gitCommit = execSync('git rev-parse --short HEAD', { cwd: __dirname })
    .toString()
    .trim();
} catch {
  // Not a git checkout (e.g. published tarball) — leave as 'unknown'.
}

const buildTime = new Date().toISOString();

// A content hash of the atomic-wasm pair, appended to their URLs as `?v=`.
//
// These two files are the only ones the app loads from a STABLE url: they're
// copied into `public/wasm/` by `build:wasm` instead of going through Rollup,
// so unlike every hashed chunk their url stays identical across builds. That is
// what let a page span a service-worker update in 2026-08 and run the NEW app
// chunks against the PREVIOUS generation's precached glue, whose namespace has
// no `argon2idDeriveKey` — recovery-code generation died on a stale module the
// server had already replaced. Hashing the content into the url means the two
// generations no longer collide, so a mixed-generation page misses and refetches
// instead of silently resolving to the old body.
function wasmVersion(): string {
  const dir = path.resolve(__dirname, 'public/wasm');
  const hash = crypto.createHash('sha256');
  let hashedAny = false;

  for (const file of ['atomic_wasm.js', 'atomic_wasm_bg.wasm']) {
    const full = path.join(dir, file);

    if (!fs.existsSync(full)) continue;

    hash.update(fs.readFileSync(full));
    hashedAny = true;
  }

  // Absent under SKIP_WASM_BUILD=1 (and before the first `build:wasm`). A
  // constant beats a hash of nothing, which would read as a real version.
  return hashedAny ? hash.digest('hex').slice(0, 12) : 'dev';
}

// Computed once: hashing the pair reads ~6MB off disk.
const wasmVersionHash = wasmVersion();

export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify(appVersion),
    __GIT_COMMIT__: JSON.stringify(gitCommit),
    __BUILD_TIME__: JSON.stringify(buildTime),
    __WASM_VERSION__: JSON.stringify(wasmVersionHash),
  },
  resolve: {
    // `loro-prosemirror` is excluded from dep-optimization (see
    // optimizeDeps.exclude — it pulls in the WASM `loro-crdt`), so its
    // `import "prosemirror-view"` is served raw from node_modules. Meanwhile
    // tiptap's ProseMirror is prebundled into an optimized chunk. Without
    // deduping, that yields TWO copies of the `prosemirror-view` module at
    // runtime: a `DecorationSet` produced by loro's cursor plugin then fails
    // `instanceof DecorationSet` inside tiptap's `DecorationGroup.from`, which
    // reads `.members` off the foreign set (undefined) and pushes it as a null
    // group member — crashing `DecorationGroup.locals` ("Cannot read
    // properties of undefined (reading 'localsInner')") on the next view
    // update (e.g. opening the slash menu next to a collaborator cursor).
    // Deduping forces a single shared instance so the `instanceof` holds.
    dedupe: ['prosemirror-view', 'prosemirror-state', 'prosemirror-model'],
    alias: [
      // Force EVERY `loro-crdt` import (our `enableLoro`, plus
      // `loro-prosemirror` used by the editor) onto the `web` build.
      // The default entry resolves via the `module` field to the
      // `bundler` build, whose WASM↔JS circular import + top-level
      // -await glue hangs under `vite-plugin-wasm` (loro-crdt ≥ 1.12).
      // Aliasing to one build also guarantees a SINGLE Loro module
      // instance — otherwise a web-build `LoroDoc` handed to a
      // bundler-build `loro-prosemirror` fails `instanceof` checks and
      // the two WASM memories diverge. Exact-match regex so the
      // `loro-crdt/web` subpath import in `LoroLoader` is left alone.
      { find: /^loro-crdt$/, replacement: 'loro-crdt/web' },
      {
        find: '@components',
        replacement: path.resolve(__dirname, 'src/components'),
      },
      { find: '@views', replacement: path.resolve(__dirname, 'src/views') },
      { find: '@hooks', replacement: path.resolve(__dirname, 'src/hooks') },
      { find: '@helpers', replacement: path.resolve(__dirname, 'src/helpers') },
      { find: '@chunks', replacement: path.resolve(__dirname, 'src/chunks') },
      { find: '@repo-lib-defaults', replacement: libDefaultsDir },
    ],
  },
  plugins: [
    wasm(),
    {
      // index.html preloads the wasm pair to warm the worker's fetch, so those
      // hrefs have to carry the same `?v=` the app requests — a preload for a
      // url nobody asks for is a wasted download plus a console warning.
      name: 'atomic-wasm-version-html',
      transformIndexHtml: (html: string) =>
        html.replaceAll('__WASM_VERSION__', wasmVersionHash),
    },
    !isVitest && webfontDownload(),
    !isVitest && wuchale(),
    // Native React Compiler (oxc-transform-react). Must run before JSX
    // transforms; this plugin does compiler + TS + JSX + Fast Refresh in one
    // pass. Replace with `react({ compiler: true })` once plugin-react 6.1.0
    // is released (vitejs/vite-plugin-react#1419). The compiler transform is
    // skipped under Vitest — unit tests call `transformSync` directly — but
    // the oxc styled-components options still apply so displayName works.
    ...oxcReactCompiler({ compile: !isVitest }),
    react(),
    !isVitest &&
      !isTauri &&
      VitePWA({
        registerType: 'autoUpdate',
        injectRegister: 'auto',
        manifest: {
          name: 'Atomic Data Browser',
          short_name: 'Atomic',
          description:
            'The easiest way to create, share and model Linked Atomic Data.',
          theme_color: '#ffffff',
          icons: [
            {
              src: 'app_data/images/android-chrome-192x192.png',
              sizes: '192x192',
              type: 'image/png',
              purpose: 'any',
            },
            {
              src: 'app_data/images/android-chrome-512x512.png',
              sizes: '512x512',
              type: 'image/png',
              purpose: 'any',
            },
            {
              src: 'app_data/images/maskable_icon.png',
              sizes: '1024x1024',
              type: 'image/png',
              purpose: 'maskable',
            },
            {
              src: 'app_data/images/maskable_icon_x512.png',
              sizes: '512x512',
              type: 'image/png',
              purpose: 'maskable',
            },
            {
              src: 'app_data/images/maskable_icon_x384.png',
              sizes: '384x384',
              type: 'image/png',
              purpose: 'maskable',
            },
            {
              src: 'app_data/images/maskable_icon_x192.png',
              sizes: '192x192',
              type: 'image/png',
              purpose: 'maskable',
            },
            {
              src: 'app_data/images/maskable_icon_x128.png',
              sizes: '128x128',
              type: 'image/png',
              purpose: 'maskable',
            },
          ],
        },
        workbox: {
          // See https://github.com/atomicdata-dev/atomic-data-browser/issues/294
          // index.html is excluded from precaching because atomic-server injects
          // CSP nonces dynamically. Instead we use runtime caching with NetworkFirst
          // so the SW caches whatever HTML the server serves (with nonce), and falls
          // back to it offline.
          // `/wasm/` is excluded because the app now requests those files with
          // a `?v=<hash>` query (see `wasmVersion` above), which no precache
          // entry keyed on the bare path can serve — precaching them would
          // just park ~6MB per generation that nothing ever reads. The
          // runtimeCaching rule below still caches them (keyed by the full
          // versioned url), so offline use is unaffected after first load.
          globIgnores: ['**/index.html', '**/wasm/**'],
          // Purge precache entries from prior builds on SW activation, so a
          // stale worker/wasm can never linger after the hashed names change.
          cleanupOutdatedCaches: true,
          // Increased for WASM binaries (loro-crdt + atomic-wasm)
          maximumFileSizeToCacheInBytes: 10 * 1024 * 1024,
          // index.html is NOT precached because atomic-server injects CSP nonces.
          // Disable the default navigateFallback (which requires precached index.html).
          // Instead we cache navigation responses at runtime with NetworkFirst.
          navigateFallback: null,
          runtimeCaching: [
            {
              // Cache ALL navigation requests (SPA — same HTML shell for all routes).
              // NetworkFirst: use server when online, fall back to cache offline.
              urlPattern: ({ request }) => request.mode === 'navigate',
              handler: 'NetworkFirst',
              options: {
                cacheName: 'html-cache',
                expiration: {
                  maxEntries: 10,
                  maxAgeSeconds: 60 * 60 * 24 * 7, // 7 days
                },
                cacheableResponse: {
                  statuses: [200],
                },
              },
            },
            {
              // Cache WASM and worker files
              urlPattern: /\/wasm\/.*/i,
              handler: 'CacheFirst',
              options: {
                cacheName: 'wasm-cache',
                expiration: {
                  maxEntries: 10,
                  maxAgeSeconds: 60 * 60 * 24 * 30, // 30 days
                },
                cacheableResponse: {
                  statuses: [0, 200],
                },
              },
            },
            {
              urlPattern: /^https:\/\/fonts\.googleapis\.com\/.*/i,
              handler: 'CacheFirst',
              options: {
                cacheName: 'google-fonts-cache',
                expiration: {
                  maxEntries: 10,
                  maxAgeSeconds: 60 * 60 * 24 * 365, // <== 365 days
                },
                cacheableResponse: {
                  statuses: [0, 200],
                },
              },
            },
            {
              urlPattern:
                /^https?:\/\/.*\.(?:png|jpg|jpeg|gif|bmp|svg|webp|ico)/i,
              handler: 'CacheFirst',
              options: {
                cacheName: 'images-cache',
                expiration: {
                  maxEntries: 100,
                  maxAgeSeconds: 60 * 60 * 24 * 30, // <== 30 days
                },
                cacheableResponse: {
                  statuses: [0, 200],
                },
              },
            },
            {
              urlPattern: /^https:\/\/fonts\.gstatic\.com\/.*/i,
              handler: 'CacheFirst',
              options: {
                cacheName: 'gstatic-fonts-cache',
                expiration: {
                  maxEntries: 10,
                  maxAgeSeconds: 60 * 60 * 24 * 365, // <== 365 days
                },
                cacheableResponse: {
                  statuses: [0, 200],
                },
              },
            },
          ],
        },
      }),
    !isVitest &&
      prismjs({
        languages: ['typescript', 'json', 'diff'],
        plugins: ['diff-highlight'],
        css: true,
        theme: 'default',
      }),
  ],
  // The optional NextGraph mirror runs its wasm engine in a module worker, so
  // `vite-plugin-wasm` has to apply to worker builds too — `plugins` here is
  // deliberately separate from the array above and does not inherit it.
  // Without this the worker fails to build and the mirror silently falls back
  // to running the engine on the main thread, where a long SPARQL call
  // competes with rendering.
  //
  // Costs nothing when the mirror is not enabled: no worker is spawned, so no
  // worker bundle is produced.
  worker: {
    format: 'es',
    plugins: () => [wasm()],
  },
  optimizeDeps: {
    // React Compiler emits `import { c as _c } from "react/compiler-runtime"`
    // in every memoised component. Without this hint, Vite only discovers
    // the dep the first time a compiled module loads — it prebundles
    // mid-session and serves a half-written file to the next request,
    // surfacing as `NS_ERROR_CORRUPTED_CONTENT` + empty MIME type on the
    // browser. Listing it up front makes the optimization happen at boot.
    //
    // The AI SDK graph (`ai`, `@ai-sdk/react`, the provider packages and the
    // MCP SDK) is only reachable behind the `React.lazy` AI sidebar chunk, so
    // Vite's boot-time scan (which follows static imports from index.html)
    // never sees it. The first time the sidebar opens, Vite discovers the
    // whole graph, re-optimizes, and HARD-RELOADS the page — surfacing as a
    // ~20s "Loading AI" stall (the lazy chunk's Suspense fallback). Listing
    // them here prebundles them at boot so first-open is warm. Dev-only:
    // production builds prebundle everything at build time. Keep in sync with
    // the AI-only deps in `src/chunks/AI/`.
    include: [
      'react/compiler-runtime',
      'ai',
      '@ai-sdk/react',
      'zod',
      'ollama-ai-provider-v2',
      '@openrouter/ai-sdk-provider',
      '@modelcontextprotocol/sdk/client/index.js',
      '@modelcontextprotocol/sdk/client/sse.js',
      '@modelcontextprotocol/sdk/client/streamableHttp.js',
      'fast-json-patch',
      // Prebundle the collaborative editor's CRDT-ProseMirror bridge into the
      // same optimize graph as tiptap so they share ONE `prosemirror-view`
      // instance (see the exclude note below re: the DecorationGroup crash).
      // `loro-crdt` stays external, so the WASM is unaffected.
      'loro-prosemirror',
      // Lazy-loaded only when a leftover Yjs-era DocumentV2 is opened. Listed
      // so the first `import('yjs')` does not trigger a mid-session re-optimize
      // that 504s the dynamic import.
      'yjs',
    ],
    // `loro-crdt` ships a WASM module that `vite-plugin-wasm` (see the
    // `wasm()` plugin above) handles. esbuild's dep-optimizer CANNOT —
    // if Vite prebundles loro-crdt, the WASM init in the optimized
    // chunk hangs forever: `import('loro-crdt')` in `enableLoro()`
    // never resolves OR rejects, so `LoroLoader.isLoaded()` stays
    // false, every `getLoroDoc()` returns undefined, and documents are
    // stuck (now surfaced as the "editor failed to load" error in
    // `DocumentV2FullPage`). Excluding it from optimization lets
    // `vite-plugin-wasm` serve the module untouched. This is the
    // documented requirement for WASM deps under vite-plugin-wasm.
    //
    // It also explains the *intermittent* original failure: with
    // loro-crdt neither included nor excluded, Vite auto-discovered it
    // on the first lazy import and tried to optimize it mid-session —
    // sometimes racing cleanly, sometimes hanging. Excluding makes it
    // deterministic.
    // Both must skip esbuild prebundling: the `web` build loads its
    // `.wasm` via `fetch(new URL('loro_wasm_bg.wasm', import.meta.url))`.
    // If esbuild inlines either into an optimized chunk, `import.meta.url`
    // points at `.vite/deps/…` where the `.wasm` doesn't exist → 404.
    // Excluding keeps it served from `node_modules` so the relative
    // `.wasm` URL resolves.
    //
    // NOTE: `loro-prosemirror` is deliberately NOT excluded (it's `include`d
    // above). It only imports `loro-crdt` as a peer, which stays external
    // here, so optimizing it doesn't drag the WASM into a chunk. Crucially,
    // optimizing it puts its `prosemirror-view`/`-state`/`-model` imports in
    // the SAME prebundled graph as tiptap's. If loro were excluded (served
    // raw) while tiptap's ProseMirror was prebundled, there would be TWO
    // runtime copies of `prosemirror-view`: a `DecorationSet` from loro's
    // cursor plugin then fails `instanceof DecorationSet` inside tiptap's
    // `DecorationGroup.from`, which reads `.members` off the foreign set
    // (undefined) and stores it as a null group member — crashing
    // `DecorationGroup.locals` ("Cannot read properties of undefined (reading
    // 'localsInner')") on the next view update (e.g. opening the slash menu
    // next to a collaborator's caret). One optimize graph + `resolve.dedupe`
    // above keeps it a single instance. (Prod is unaffected: rollup bundles
    // once.)
    // `@tomic/lib` / `@tomic/react` are workspace packages built in watch mode
    // (tsup) alongside this dev server. If Vite PRE-BUNDLES them into
    // `.vite/deps`, that cache is keyed on the lockfile/config hash — NOT on the
    // packages' `dist` content — so a rebuilt `dist` is invisible until a
    // `--force` re-optimize. Excluding them makes Vite serve their `dist`
    // directly, so every watch rebuild shows up on a plain reload (the documented
    // workspace-link workaround). They don't drag in WASM/ProseMirror, so there's
    // no single-instance concern like `loro-crdt` below.
    exclude: [
      'loro-crdt',
      '@tomic/lib',
      '@tomic/react',
      // Same rule as `loro-crdt` above, for the same reason: a WASM dep that
      // esbuild prebundles has its init hang forever rather than fail. Only
      // reached when the NextGraph mirror is enabled.
      '@ng-org/lib-wasm',
    ],
    //
    // Vite's boot-time dep scan only follows static imports from index.html, so
    // it never sees the deps behind `React.lazy` chunks (RTE/tiptap, AI SDK,
    // code/table/PDF editors). The first time such a chunk loads, Vite
    // discovers its deps mid-session, re-optimizes, and 504s the in-flight
    // dynamic import ("Outdated Optimize Dep" → "Failed to fetch dynamically
    // imported module: CollaborativeEditor.tsx"). Crawling the chunk roots at
    // boot pre-optimizes everything, so first-open is warm and e2e is stable.
    entries: ['./index.html', './src/chunks/**/*.{ts,tsx}'],
  },
  build: {
    target: 'baseline-widely-available',
    outDir: isTauri ? 'dist-tauri' : 'dist',
    sourcemap: wantSourcemaps,
    // Don't inline worker scripts as `data:` URLs — the production CSP is
    // `worker-src 'self'` and would block them, killing the ClientDb. Below
    // the default 4096-byte limit, Vite would otherwise inline our 1.7KB
    // ClientDb worker and break in prod (works in dev because dev has no CSP).
    assetsInlineLimit: (filePath: string) =>
      filePath.endsWith('.worker.js') ? 0 : undefined,
    rollupOptions: {
      output: {
        entryFileNames: `assets/[name]-[hash].js`,
        chunkFileNames: `assets/chunk_[name]-[hash].js`,
        // Content-hash ALL assets — including the `?url`-imported ClientDb
        // worker and the loro-crdt `.wasm`. With stable names these were
        // precached by Workbox with `revision: null` (it assumes an unhashed
        // name is immutable), so a content change kept the same URL+revision
        // and the SW served the OLD worker/wasm to NEW hashed chunks forever:
        // a soft (cmd+r) reload hit a stale worker (missing newer message
        // handlers → empty resources) and the stale loro bundler glue
        // (`./loro_wasm_bg.js` import error). Hashing makes every change a new
        // URL Workbox correctly re-fetches. atomic-wasm is unaffected: it's
        // served from the stable `/wasm/` public path, not via this pipeline.
        assetFileNames: `assets/[name]-[hash].[ext]`,
      },
    },
  },
  html: {
    cspNonce: isTauri ? undefined : 'ATOMICSERVER_NONCE',
  },
  server: {
    // Fixed, uncommon port so the atomicbrowser dev server never collides with
    // vite's default 5173 (used by other local apps).
    // strictPort makes a collision fail loudly instead of silently shifting.
    port: 6747,
    strictPort: true,
    host: true,
    allowedHosts: ['.tunn.dev', 't-1sk9qbdw.tunn.dev'],
    fs: {
      // Setting this replaces Vite's default rather than extending it, so the
      // workspace root has to be listed explicitly alongside the addition.
      allow: [searchForWorkspaceRoot(process.cwd()), ...ngBridgeRoots()],
    },
    // Pre-transform the lazy AI chunk's source graph in the background at
    // boot, so the first time the sidebar opens its modules are already
    // through the React Compiler pass instead of being transformed on-demand
    // while the user waits behind "Loading AI". Complements the
    // `optimizeDeps.include` AI entries above (those cover the npm deps;
    // this covers our own source modules).
    warmup: {
      clientFiles: [
        './src/chunks/AI/AISidebar.tsx',
        './src/chunks/RTE/AIChatInput/AsyncAIChatInput.tsx',
      ],
    },
    // Kept in step with VITE_ATOMIC_SERVER_URL in .env.development — these
    // proxy to the same server the app talks to.
    proxy: {
      '/server': 'http://localhost:9885',
      '/iroh-sync': 'http://localhost:9885',
    },
  },
});
