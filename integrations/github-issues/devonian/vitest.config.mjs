import { resolve } from 'node:path';

export default {
  resolve: {
    alias: {
      devonian: process.env.DEVONIAN_PATH
        ? resolve(process.env.DEVONIAN_PATH, 'build/src/main.js')
        : resolve('browser/data-browser/src/chunks/DevonianDemo/devonian.js'),
      '@tomic/lib': resolve('browser/lib/src/index.ts'),
      vitest: resolve('browser/node_modules/vitest/dist/index.js'),
    },
  },
  test: { include: ['integrations/github-issues/devonian/*.test.*'] },
};
