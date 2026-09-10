import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const external = path.join(
  root,
  'browser/data-browser/node_modules/devonian/platform-lenses',
);
const host = (file: string) => path.join(root, file);

export default {
  resolve: {
    alias: {
      devonian: path.join(root, 'browser/data-browser/node_modules/devonian'),
      '@tomic/lib': host('browser/lib/src/index.ts'),
      '@integration-host/import-records': host('browser/lib/src/import-records.ts'),
      '@integration-host/plugin-connection': host('browser/lib/src/plugin-connection.ts'),
      '@integration-host/plugin-reconcile': host('browser/lib/src/plugin-reconcile.ts'),
      '@integration-host/plugin-manifest': host('browser/lib/src/plugin-manifest.ts'),
      '@integration-host/integration-automation': host('browser/data-browser/src/chunks/PluginRuns/integrationAutomation.ts'),
      '@integration-host/ontologies/core': host('browser/lib/src/ontologies/core.ts'),
      '@integration-host/ontologies/dataBrowser': host('browser/lib/src/ontologies/dataBrowser.ts'),
      '@integration-host/time-tracking-schema': host('browser/lib/src/time-tracking-schema.ts'),
    },
  },
  test: {
    include: [
      `${external}/atomic-integrations/clockify/{atomic,plugin}.test.ts`,
      `${external}/atomic-integrations/notion/{model,plugin,package}.test.ts`,
      `${external}/github-issues/{adapter,automation}.test.ts`,
    ],
    exclude: [],
  },
};
