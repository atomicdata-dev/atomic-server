import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// TAURI is not relevant here — form-app is only ever server-embedded HTML,
// never bundled into the desktop shell. `cspNonce` mirrors data-browser's
// vite.config.ts: Vite stamps every script/link tag it emits with
// `nonce="ATOMICSERVER_NONCE"`, and the server substitutes the real
// per-request nonce at serve time (see server/src/handlers/form.rs).
export default defineConfig({
  base: '/form-assets/',
  plugins: [react()],
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
