import { build } from 'esbuild';
import { spawnSync } from 'node:child_process';
await build({
  entryPoints: [new URL('./worker.test.mjs', import.meta.url).pathname],
  outfile: new URL('./dist/worker.test.mjs', import.meta.url).pathname,
  bundle: true,
  platform: 'node',
  format: 'esm',
  external: ['loro-crdt', 'loro-crdt/web'],
  banner: {
    js: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);",
  },
});
const result = spawnSync(
  process.execPath,
  [
    '--test',
    ...['model.test.mjs', 'protocol.test.mjs', 'dist/worker.test.mjs'].map(
      x => new URL(x, import.meta.url).pathname,
    ),
  ],
  { stdio: 'inherit' },
);
process.exit(result.status ?? 1);
