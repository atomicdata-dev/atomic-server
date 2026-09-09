/// <reference types="node" />
import { defineConfig } from 'tsup';
import * as fs from 'node:fs/promises';
import { exec } from 'node:child_process';

export default defineConfig(options => ({
  minify: !options.watch,
  entry: {
    index: 'src/index.ts',
    // The DedicatedWorker that hosts the WASM ClientDb. Bundled as its own
    // entry so consumers can load it via `new Worker(new URL(...,
    // import.meta.url))`. Without this, the previous setup relied on a
    // hand-written `public/wasm/client-db-worker.js` that drifted out of
    // sync with the TS source whenever message types changed.
    'client-db.worker': 'src/client-db.worker.ts',
    // The DedicatedWorker that executes a plugin's `run` export. Same
    // reasoning as above: its own entry so hosts can point a `new Worker(...)`
    // at it without hand-maintaining a parallel copy.
    'plugin-run.worker': 'src/plugin-run.worker.ts',
    'ontologies/core': 'src/ontologies/core.ts',
    'ontologies/server': 'src/ontologies/server.ts',
    'ontologies/dataBrowser': 'src/ontologies/dataBrowser.ts',
    'ontologies/ai': 'src/ontologies/ai.ts',
    'ontologies/collections': 'src/ontologies/collections.ts',
    'ontologies/commits': 'src/ontologies/commits.ts',
  },
  sourcemap: true,
  clean: !options.watch,
  format: ['esm', 'cjs'],
  target: 'es2023',
  external: ['loro-crdt'],
  // We need to generate the type definition files ourselves because the build in rollup dts plugin does not work with the way we use module augmentation.
  // Tsup will switch to microsoft-api-extractor in the future but they don't even support rolling up module augments at all. https://github.com/microsoft/rushstack/issues/1709
  onSuccess: async () => {
    console.log('Generating type definition files...');

    // Run the typescript compiler but only emit declaration files.
    await new Promise<void>((resolve, reject) => {
      exec('tsc --emitDeclarationOnly --declaration', (err, stdout, stderr) => {
        if (err || stderr) {
          console.error(err ?? stderr);
        }

        // We need a copy of index.d.ts for cjs builds but the actual content can be the same so we can just copy it.
        console.log('Creating index.d.cts...');
        fs.copyFile('dist/src/index.d.ts', 'dist/src/index.d.cts')
          .then(() => {
            console.log('Build Finished!');
            resolve();
          })
          .catch(e => {
            console.error(e);
            reject(e);
          });
      });
    });
  },
}));
