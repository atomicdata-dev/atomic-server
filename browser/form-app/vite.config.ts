import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const root = path.dirname(fileURLToPath(import.meta.url));
const formRendererSrc = path.resolve(root, '../form-renderer/src');

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
export default defineConfig({
  base: '/form-assets/',
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
  },
});
