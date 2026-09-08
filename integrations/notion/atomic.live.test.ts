/** Installer HTTP coverage with authored Notion replies; never contacts Notion. */
import { it, expect, vi } from 'vitest';
import { readFile } from 'node:fs/promises';
import {
  Agent,
  Store,
  core,
  dataBrowser,
} from '../../browser/lib/src/index.js';
import { enableLoro } from '../../browser/lib/src/loro-loader.js';
import { install } from './atomic.js';
it.skipIf(!process.env.ATOMIC_NOTION_TEST_SERVER)(
  'installs native schema and views with stable property mappings',
  async () => {
    await enableLoro();
    const keys = await Agent.generateKeyPair();
    const agent = Agent.fromSecret(
      Agent.buildSecret(keys.privateKey, `did:ad:agent:${keys.publicKey}`),
      'js',
    );
    const store = new Store({
      serverUrl: process.env.ATOMIC_NOTION_TEST_SERVER!,
      agent,
    });
    store.setServerConnected(true);
    const drive = await store.createDrive('Notion installer test', {
      agentName: 'Test',
      description: '[atomic-data:dev-drive]',
    });
    store.setDrive(drive.subject);
    const id = '11111111-1111-1111-1111-111111111111',
      viewId = '22222222-2222-2222-2222-222222222222';
    const original = globalThis.fetch;
    const mock = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (url, init) => {
        if (String(url).endsWith('/plugin-external-read')) {
          const { intent } = JSON.parse(String(init?.body));
          const body =
            intent.operation === 'schema'
              ? {
                  id,
                  properties: {
                    Name: { id: 'title', name: 'Name', type: 'title' },
                    Count: { id: 'n', name: 'Count', type: 'number' },
                    Formula: { id: 'f', name: 'Formula', type: 'formula' },
                  },
                }
              : intent.operation === 'views'
                ? {
                    results: [{ id: viewId }],
                    has_more: false,
                    next_cursor: null,
                  }
                : {
                    id: viewId,
                    data_source_id: id,
                    name: 'Tasks',
                    type: 'table',
                    configuration: {
                      type: 'table',
                      properties: [
                        { property_id: 'title', visible: true },
                        { property_id: 'n', visible: true },
                      ],
                    },
                  };
          return new Response(
            JSON.stringify({ status: 200, body: JSON.stringify(body) }),
            {
              headers: { 'Content-Type': 'application/json' },
            },
          );
        }
        if (String(url).startsWith('https://api.notion.com'))
          throw new Error('Installer must use host-owned egress');
        return original(url, init);
      });
    try {
      const c = await install(
        store,
        drive.subject,
        id,
        await readFile('integrations/notion/plugin.js', 'utf8'),
        'local-fixture-token',
      );
      expect(c.fields.map(f => f.id)).toEqual(['title', 'n']);
      expect(c.views).toHaveLength(1);
      const table = await store.getResource(c.table);
      expect(table.get(dataBrowser.properties.tableViews)).toEqual([
        c.views[0].subject,
      ]);
      const view = await store.getResource(c.views[0].subject);
      expect(view.get(dataBrowser.properties.viewKind)).toBe('table');
      expect(view.get(dataBrowser.properties.viewColumns)).toEqual(
        c.fields.map(f => f.property),
      );
      const title = await store.getResource(c.fields[0].property);
      expect(title.get(core.properties.name)).toBe('Name');
    } finally {
      mock.mockRestore();
      store.disconnect();
    }
  },
  60000,
);
