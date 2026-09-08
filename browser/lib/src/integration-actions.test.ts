import { afterEach, expect, it, vi } from 'vitest';
import {
  integrationMcpAdapter,
  integrationActionHistoryPage,
  compactIntegrationActionHistory,
  abandonIntegrationConsumer,
  confirmActionRecovery,
  setIntegrationActionGrant,
  cancelIntegrationAction,
  type ActionStore,
} from './integration-actions.js';
vi.mock('./authentication.js', () => ({
  signRequest: async () => ({ 'x-test-signature': 'signed' }),
}));
afterEach(() => vi.unstubAllGlobals());
it('MCP discovery and calls use the signed host API and never approve writes', async () => {
  const seen: { url: string; body: Record<string, unknown> }[] = [];
  const tools = [
    {
      name: 'create_issue',
      title: 'Create issue',
      description: 'Prepare',
      inputSchema: {
        type: 'object',
        properties: { title: { type: 'string', description: 'Title' } },
        required: ['title'],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: false, openWorldHint: true },
    },
  ];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url, init) => {
      seen.push({ url: String(url), body: JSON.parse(init.body) });
      expect(init.headers['x-test-signature']).toBe('signed');

      return new Response(
        JSON.stringify(
          String(url).endsWith('/integration-actions')
            ? { release: 'pinned', tools }
            : { status: 'needs_review', proposal: { id: 'stable' } },
        ),
      );
    }),
  );
  const adapter = integrationMcpAdapter(
    {
      getAgent: () => ({}),
      getServerUrl: () => 'http://localhost:9898',
    } as ActionStore,
    { drive: 'drive', plugin: 'connection' },
  );
  expect(await adapter.listTools()).toEqual({ tools });
  const result = await adapter.callTool({
    name: 'create_issue',
    arguments: { title: 'Test' },
    _meta: { 'atomic/callId': 'stable' },
  });
  expect(result.isError).toBe(false);
  expect(JSON.parse(result.content[0].text).status).toBe('needs_review');
  expect(seen[1].body).toEqual({
    drive: 'drive',
    plugin: 'connection',
    call: {
      action: 'create_issue',
      arguments: { title: 'Test' },
      id: 'stable',
    },
  });
  expect(seen.every(r => !r.url.includes('approve'))).toBe(true);
  expect(Object.keys(adapter).sort()).toEqual(['callTool', 'listTools']);
});
it('MCP action failures are explicit tool errors', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response('Not authorized', { status: 403 })),
  );
  const adapter = integrationMcpAdapter(
    {
      getAgent: () => ({}),
      getServerUrl: () => 'http://localhost:9898',
    } as ActionStore,
    { drive: 'drive', plugin: 'connection' },
  );
  expect(
    (await adapter.callTool({ name: 'get_issue', arguments: { number: 1 } }))
      .isError,
  ).toBe(true);
});

it('recovery confirms a saved lookup and grant changes are explicit separate requests', async () => {
  const seen: { url: string; body: Record<string, unknown> }[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url, init) => {
      seen.push({ url: String(url), body: JSON.parse(init.body) });

      return new Response('true');
    }),
  );
  const store = {
    getAgent: () => ({}),
    getServerUrl: () => 'http://localhost:9898',
  } as ActionStore;
  const target = { drive: 'd', plugin: 'p' };
  await confirmActionRecovery(store, target, 'saved');
  expect(seen[0].body).toEqual({ ...target, id: 'saved' });
  expect(seen[0].body).not.toHaveProperty('receipt');
  await setIntegrationActionGrant(
    store,
    target,
    'caller',
    'create_issue',
    'revoke',
  );
  expect(seen[1].body).toEqual({
    ...target,
    caller: 'caller',
    action: 'create_issue',
    mode: 'revoke',
  });
  await cancelIntegrationAction(store, target, 'saved');
  expect(seen[2].body.id).toBe('saved');
});

it('history sends a bounded page and preserves the continuation cursor', async () => {
  const fetch = vi.fn(async (_url, init) => {
    expect(JSON.parse(init.body)).toEqual({
      drive: 'drive',
      plugin: 'connection',
      limit: 50,
      cursor: 'cursor',
    });
    expect(init.headers['x-test-signature']).toBe('signed');

    return new Response(JSON.stringify({ entries: [], nextCursor: null }));
  });
  vi.stubGlobal('fetch', fetch);
  const store = {
    getAgent: () => ({}),
    getServerUrl: () => 'http://localhost:9898',
  } as ActionStore;
  expect(
    await integrationActionHistoryPage(
      store,
      { drive: 'drive', plugin: 'connection' },
      'cursor',
    ),
  ).toEqual({ entries: [], nextCursor: null });
});

it('cleanup defaults to preview and only applies when explicitly requested', async () => {
  const bodies: Record<string, unknown>[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (_url, init) => {
      bodies.push(JSON.parse(init.body));
      expect(init.headers['x-test-signature']).toBe('signed');

      return new Response(
        JSON.stringify({
          scanned: 1,
          eligible: 1,
          compacted: 0,
          reclaimableBytes: 100,
          nextCursor: null,
        }),
      );
    }),
  );
  const store = {
    getAgent: () => ({}),
    getServerUrl: () => 'http://localhost:9898',
  } as ActionStore;
  const target = { drive: 'drive', plugin: 'connection' };
  await compactIntegrationActionHistory(store, target);
  await compactIntegrationActionHistory(store, target, {
    apply: true,
    cursor: 'page',
    includeCompleted: true,
    includeAutomation: true,
  });
  expect(bodies).toEqual([
    target,
    {
      ...target,
      apply: true,
      cursor: 'page',
      includeCompleted: true,
      includeAutomation: true,
    },
  ]);
});

it('abandonment sends the exact recorded run and reason through the signed API', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (_url, init) => {
      expect(init.headers['x-test-signature']).toBe('signed');
      expect(JSON.parse(init.body)).toEqual({
        drive: 'd',
        plugin: 'p',
        id: 'action',
        run: 'query:run',
        reason: 'No longer needed',
      });

      return new Response('true');
    }),
  );
  await abandonIntegrationConsumer(
    {
      getAgent: () => ({}),
      getServerUrl: () => 'http://localhost:9898',
    } as ActionStore,
    { drive: 'd', plugin: 'p' },
    'action',
    'query:run',
    'No longer needed',
  );
});
