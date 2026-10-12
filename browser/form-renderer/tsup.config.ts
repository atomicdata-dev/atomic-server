/// <reference types="node" />
import { defineConfig } from 'tsup';
import * as fs from 'node:fs/promises';
import { exec } from 'node:child_process';

export default defineConfig(options => ({
  minify: !options.watch,
  entry: ['src/index.ts'],
  sourcemap: true,
  clean: !options.watch,
  format: ['esm', 'cjs'],
  target: 'es2023',
  onSuccess: async () => {
    console.warn('Copying stylesheet...');
    await fs.copyFile('src/style.css', 'dist/style.css');

    console.warn('Generating type definition files...');

    await new Promise<void>((resolve, reject) => {
      exec('tsc --emitDeclarationOnly --declaration', (err, stdout, stderr) => {
        if (err || stderr) {
          console.error(err ?? stderr);
        }

        fs.copyFile('dist/src/index.d.ts', 'dist/src/index.d.cts')
          .then(() => {
            console.warn('Build Finished!');
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
