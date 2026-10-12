import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

const root = path.dirname(fileURLToPath(import.meta.url));
const formRendererSrc = path.resolve(root, '../form-renderer/src');

// The API routes `App.tsx` calls when the HTML shell carries no injected
// `window.__FORM_DEFINITION__` — i.e. exactly the dev-server case. Everything
// else under `/form/` is the page itself, which Vite's SPA fallback serves.
const FORM_API_ROUTES = '^/form/[^/]+/(definition|submit|challenge|image)';

// TAURI is not relevant here — form-app is only ever server-embedded HTML,
// never bundled into the desktop shell. `cspNonce` mirrors data-browser's
// vite.config.ts: Vite stamps every script/link tag it emits with
// `nonce="ATOMICSERVER_NONCE"`, and the server substitutes the real
// per-request nonce at serve time (see server/src/handlers/form.rs).
//
// Resolve `@tomic/form-renderer` from source, not `dist/`. The published
// `/form/:id` runtime is this package's production bundle (embedded by
// server/build.rs); the builder preview imports the same renderer via
// Vite HMR. Bundling from source keeps the two in lockstep when
// form-renderer changes — otherwise a stale form-app/dist (common with
// ATOMICSERVER_SKIP_JS_BUILD) ships an old renderer that ignores new
// definition fields such as `conditions`.
export default defineConfig(({ command, mode }) => {
  // Reuse data-browser's `VITE_ATOMIC_SERVER_URL` — its `.env.development`
  // (plus your own `.env.development.local`) is the one place this repo
  // records which atomic-server a vite dev server should talk to, and both
  // dev servers want the same answer. A `.env*` file in this package wins if
  // you ever need them to differ.
  const serverUrl =
    loadEnv(mode, root, '').VITE_ATOMIC_SERVER_URL ??
    loadEnv(mode, path.resolve(root, '../data-browser'), '')
      .VITE_ATOMIC_SERVER_URL ??
    'http://localhost:9883';

  return {
    // Only the production bundle lives under `/form-assets/` — that is where
    // atomic-server mounts the embedded dist. In dev the app is served from
    // the root instead, so a `/form/:id` URL reaches Vite's SPA fallback and
    // the app can read the id out of the path like it does in production.
    base: command === 'build' ? '/form-assets/' : '/',
    plugins: [react()],
    resolve: {
      alias: [
        {
          find: '@tomic/form-renderer/style.css',
          replacement: path.join(formRendererSrc, 'style.css'),
        },
        {
          find: '@tomic/form-renderer',
          replacement: path.join(formRendererSrc, 'index.ts'),
        },
      ],
    },
    build: {
      outDir: 'dist',
    },
    html: {
      cspNonce: 'ATOMICSERVER_NONCE',
    },
    server: {
      port: 6748,
      // Dev-only: the page HTML comes from Vite (with HMR), while the
      // definition / submit / challenge / image calls go to the real
      // atomic-server. Without this the app renders "Could not load this
      // form." because it fetched its own dev server.
      proxy: {
        [FORM_API_ROUTES]: serverUrl,
      },
    },
  };
});
