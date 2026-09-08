import { describe, expect, it, vi } from 'vitest';
import { pluginWorkspace, workspaceConnections } from './plugin-workspace.js';

const properties = {
  'plugin-workspace': 'workspace',
  'plugin-connection': 'connection',
  'plugin-schemas': 'schemas',
};
const resource = (values: Record<string, unknown>) => ({
  get: (property: string) => values[property],
});

describe('workspace identity across extension models', () => {
  it('uses the explicit relationship without mistaking containment for ownership', () => {
    expect(
      pluginWorkspace(
        resource({
          workspace: 'did:ad:workspace',
          connection: { config: { table: 'did:ad:table' } },
        }),
        properties,
      ),
    ).toBe('did:ad:workspace');
    expect(
      pluginWorkspace(resource({ parent: 'did:ad:drive' }), properties),
    ).toBeUndefined();
  });
  it('reads existing sync, importer and file-import destinations without writing a migration', () => {
    for (const values of [
      { connection: { config: { table: 'did:ad:table' } } },
      { connection: JSON.stringify({ config: { table: 'did:ad:table' } }) },
      { schemas: { table: 'did:ad:table' } },
      { schemas: { mt940: { table: 'did:ad:table' } } },
    ])
      expect(pluginWorkspace(resource(values), properties)).toBe(
        'did:ad:table',
      );
  });
  it('rejects malformed configuration rather than silently reporting no connection', () => {
    expect(() =>
      pluginWorkspace(resource({ connection: '{broken' }), properties),
    ).toThrow();
    expect(() =>
      pluginWorkspace(resource({ workspace: ['did:ad:table'] }), properties),
    ).toThrow();
  });
});

vi.mock('./plugin-schema.js', () => ({ findSchema: vi.fn() }));
vi.mock('./plugin-connection.js', () => ({ readConnectionSubjects: vi.fn() }));

it('discovers old and new connections while excluding automations and other workspaces', async () => {
  const { findSchema } = await import('./plugin-schema.js');
  const { readConnectionSubjects } = await import('./plugin-connection.js');
  vi.mocked(findSchema).mockResolvedValue({
    properties: { ...properties, 'automation-integrations': 'uses' },
    classes: { 'plugin-script': 'script' },
  });
  vi.mocked(readConnectionSubjects).mockResolvedValue([
    'old',
    'new',
    'automation',
    'other',
  ]);
  const records = {
    old: resource({ schemas: { table: 'workspace-a' } }),
    new: resource({ workspace: 'workspace-a' }),
    automation: resource({ workspace: 'workspace-a', uses: [] }),
    other: resource({ workspace: 'workspace-b' }),
  };
  const store = {
    getResource: vi.fn(
      async (id: string) => records[id as keyof typeof records],
    ),
  };
  const found = await workspaceConnections(
    store as never,
    'drive-a',
    'workspace-a',
  );
  expect(found.map(connection => connection.subject)).toEqual(['new', 'old']);
  expect(readConnectionSubjects).toHaveBeenLastCalledWith(
    store,
    'drive-a',
    'https://atomicdata.dev/properties/isA',
    'script',
  );
  vi.mocked(readConnectionSubjects).mockRejectedValueOnce(
    new Error('Unauthorized'),
  );
  await expect(
    workspaceConnections(store as never, 'drive-a', 'workspace-a'),
  ).rejects.toThrow('Unauthorized');
});
