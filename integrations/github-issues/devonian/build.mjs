/** Development-time bundle; the demo itself runs entirely in the browser. */
import { createRequire } from 'node:module';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const require = createRequire(import.meta.url);
const { build } = require(
  require.resolve('esbuild', {
    paths: [
      resolve(root, 'browser'),
      resolve(root, 'browser/node_modules/.pnpm'),
    ],
  }),
);
if (!process.env.DEVONIAN_PATH)
  throw new Error('Set DEVONIAN_PATH to Devonian main');
await build({
  stdin: {
    contents: ['Resource', 'Store', 'IdentityMap', 'Lens']
      .map(name => `export * from './src/atomic/${name}.js';`)
      .join('\n'),
    resolveDir: resolve(process.env.DEVONIAN_PATH),
    loader: 'ts',
  },
  bundle: true,
  platform: 'browser',
  format: 'esm',
  external: ['@tomic/lib'],
  banner: {
    js: '// Devonian native resource API, e11104f78ebd151a361171ca0b21489b25e1e2c8. Apache-2.0; see DEVONIAN-LICENSE.',
  },
  outfile: resolve(
    root,
    'browser/data-browser/src/chunks/DevonianDemo/devonian.js',
  ),
});
