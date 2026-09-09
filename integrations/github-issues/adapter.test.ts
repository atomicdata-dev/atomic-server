import { describe, it, expect } from 'vitest';
import { preview, project, manifest, type Issue } from './adapter.js';
import { validateManifest } from '../../browser/lib/src/plugin-manifest.js';
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
const issue = (number: number): Issue => ({
  number,
  title: `Issue ${number}`,
  body: null,
  state: 'open',
  labels: ['bug'],
});
describe('GitHub package', () => {
  it('uses a strict repository-scoped manifest', () => {
    expect(validateManifest(manifest('owner/repo')).operations).toHaveLength(6);
    expect(() => manifest('../escape')).toThrow();
    expect(() => manifest('owner/repo?token=x')).toThrow();
  });
  it('ships exactly the artifact tested by the sandbox', async () => {
    const built = execFileSync(
      existsSync('./browser/node_modules/.bin/esbuild')
        ? './browser/node_modules/.bin/esbuild'
        : './browser/node_modules/.pnpm/node_modules/.bin/esbuild',
      [
        'integrations/github-issues/plugin.ts',
        '--bundle',
        '--format=esm',
        '--platform=neutral',
        '--target=es2022',
      ],
      { encoding: 'utf8' },
    );
    expect(await readFile('integrations/github-issues/plugin.js', 'utf8')).toBe(
      built,
    );
  });
  it('reads every page and excludes pull requests', async () => {
    const issues = Array.from({ length: 101 }, (_, i) => issue(i + 1));
    issues[49].pull_request = {};
    const result = await preview(
      {
        read: async intent => {
          const page = Number(new URL(intent.url).searchParams.get('page'));
          return {
            status: 200,
            body: JSON.stringify(issues.slice((page - 1) * 100, page * 100)),
          };
        },
        cards: async () => [],
        state: async () => ({ revision: 0, records: {}, cursor: null }),
      },
      'owner/repo',
    );
    expect(result.changes).toHaveLength(100);
  });
  it('refuses failed reads instead of treating them as deletions', async () => {
    await expect(
      preview(
        {
          read: async () => ({ status: 429, body: '{}' }),
          cards: async () => [],
          state: async () => ({ revision: 0, records: {}, cursor: null }),
        },
        'owner/repo',
      ),
    ).rejects.toThrow('429');
  });
  it('normalizes closed issues with a remaining doing label', () => {
    expect(
      project({ ...issue(1), state: 'closed', labels: ['atomic:doing'] })
        .status,
    ).toBe('Done');
  });
});

it('keeps the sandbox action manifest fixture current', async () => {
  expect(
    JSON.parse(
      await readFile(
        'integrations/github-issues/manifest.fixture.json',
        'utf8',
      ),
    ),
  ).toEqual(manifest('atomic-fixtures/issues'));
});
