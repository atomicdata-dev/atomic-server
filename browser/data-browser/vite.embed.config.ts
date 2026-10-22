import { defineConfig, mergeConfig, type UserConfig } from 'vite';
import * as path from 'node:path';
import base from './vite.config';

/**
 * The Flutter app's embedded renderer (`embed.html`): the same app code and
 * plugins as the web build, one entry, relative asset URLs so it loads from the
 * app's own files, written to `dist-embed`. Build with `TAURI=1` so the base
 * config leaves out the service worker and the server's CSP nonces, which only
 * make sense on a web origin:
 *
 *   TAURI=1 pnpm exec vite build -c vite.embed.config.ts
 */
export default defineConfig(env =>
  mergeConfig(base(env) as UserConfig, {
    base: './',
    build: {
      outDir: 'dist-embed',
      emptyOutDir: true,
      rollupOptions: {
        input: path.resolve(__dirname, 'embed.html'),
      },
    },
  } satisfies UserConfig),
);
