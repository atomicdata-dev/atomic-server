import { describe, expect, it, vi } from 'vitest';
import type { Store } from '@tomic/lib';
const mocks = vi.hoisted(() => ({
  schema: vi.fn(),
  subjects: vi.fn(),
  actions: vi.fn(),
}));
vi.mock('@tomic/lib', () => ({
  core: { properties: { isA: 'class', name: 'name' } },
  pluginSchema: () => ({}),
  findSchema: mocks.schema,
  readConnectionSubjects: mocks.subjects,
  listIntegrationActions: mocks.actions,
}));
import { discoverIntegrations } from './discoverIntegrations';
describe('integration discovery', () => {
  it('finds capabilities, skips drafts and reports a broken connection without losing results', async () => {
    mocks.schema.mockResolvedValue({
      classes: { 'plugin-script': 'plugin' },
      properties: { 'plugin-connection': 'connection' },
    });
    mocks.subjects.mockResolvedValue(['draft', 'github', 'broken']);
    mocks.actions.mockImplementation(async (_store, target) => {
      if (target.plugin === 'broken') throw new Error('Unavailable');

      return {
        release: 'v1',
        tools: [
          {
            name: 'create_issue',
            title: 'Create issue',
            description: 'Create a repository issue',
          },
        ],
      };
    });
    const store = {
      getResource: async (id: string) => ({
        get: (property: string) =>
          property === 'name' ? 'GitHub' : id !== 'draft',
      }),
    } as unknown as Store;
    const result = await discoverIntegrations(
      store,
      'drive',
      'repository issue',
    );
    expect(result.connections.map(c => c.integration)).toEqual(['github']);
    expect(result.errors).toEqual([
      { integration: 'broken', error: 'Error: Unavailable' },
    ]);
    expect(mocks.actions.mock.calls.map(c => c[1].plugin)).toEqual([
      'github',
      'broken',
    ]);
    expect(
      (await discoverIntegrations(store, 'drive', 'calendar')).connections,
    ).toEqual([]);
  });
  it('does not create a schema on an empty drive', async () => {
    mocks.schema.mockResolvedValue({});
    expect(await discoverIntegrations({} as Store, 'empty')).toEqual({
      connections: [],
      errors: [],
    });
  });
});
