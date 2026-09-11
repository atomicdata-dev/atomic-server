import { build } from 'esbuild';
import { mkdir, copyFile } from 'node:fs/promises';
const out = new URL('./dist/', import.meta.url);
await mkdir(out, { recursive: true });
await build({
  entryPoints: [new URL('./cli.mjs', import.meta.url).pathname],
  outfile: new URL('cli.js', out).pathname,
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  external: ['loro-crdt', 'loro-crdt/web'],
  banner: {
    js: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);",
  },
});
await build({
  entryPoints: [new URL('./live.ts', import.meta.url).pathname],
  outfile: new URL('live.js', out).pathname,
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  external: ['loro-crdt', 'loro-crdt/web'],
  banner: {
    js: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);",
  },
});
await copyFile(new URL('./view.js', import.meta.url), new URL('view.js', out));
console.log('Built dist/cli.js and dist/view.js');
