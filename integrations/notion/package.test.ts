import { it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { manifest } from './model.js';
import { validateManifest } from '../../browser/lib/src/plugin-manifest.js';
import { install } from './atomic.js';
import type { Store } from '../../browser/lib/src/index.js';
it('rejects a missing provider before touching the store or credentials', async () => {
  await expect(
    install(
      {} as Store,
      'drive',
      '11111111-1111-1111-1111-111111111111',
      undefined as unknown as string,
      'fixture-token',
    ),
  ).rejects.toThrow('provider bundle did not load');
});
it('ships the reproducible bundle that runtime tests execute', () => {
  const built = execFileSync(
    './browser/node_modules/.bin/esbuild',
    [
      'integrations/notion/plugin.ts',
      '--bundle',
      '--format=esm',
      '--platform=neutral',
      '--target=es2022',
    ],
    { encoding: 'utf8' },
  );
  expect(readFileSync('integrations/notion/plugin.js', 'utf8')).toBe(built);
});
it('declares POST queries as reads and row updates as journaled writes', () => {
  const m = validateManifest(manifest('11111111-1111-1111-1111-111111111111'));
  expect(
    JSON.parse(
      readFileSync('integrations/notion/manifest.fixture.json', 'utf8'),
    ),
  ).toEqual(m);
  expect(m.operations.find(o => o.id === 'query')?.effect).toBe('read');
  expect(m.operations.find(o => o.id === 'update')?.effect).toBe('write');
});
