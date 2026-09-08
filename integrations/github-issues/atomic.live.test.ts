import { it, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import {
  Agent,
  Store,
  core,
  dataBrowser,
} from '../../browser/lib/src/index.js';
import { enableLoro } from '../../browser/lib/src/loro-loader.js';
import { readExternalOperation } from '../../browser/lib/src/plugin-connection.js';
import { install } from './atomic.js';

it.skipIf(!process.env.ATOMIC_GITHUB_TEST_SERVER)(
  'installs a private package and real kanban, then reads and edits cards through Atomic',
  async () => {
    await enableLoro();
    const keys = await Agent.generateKeyPair();
    const agent = Agent.fromSecret(
      Agent.buildSecret(keys.privateKey, `did:ad:agent:${keys.publicKey}`),
      'js',
    );
    const store = new Store({
      serverUrl: process.env.ATOMIC_GITHUB_TEST_SERVER!,
      agent,
    });
    store.setServerConnected(true);
    const drive = await store.createDrive('GitHub pilot integration test', {
      agentName: 'Pilot test',
      description: '[atomic-data:dev-drive]',
    });
    store.setDrive(drive.subject);
    const connection = await install(
      store,
      drive.subject,
      'atomic-pilot-fixture/kanban',
      await readFile('integrations/github-issues/plugin.js', 'utf8'),
    );
    const table = await store.fetchResourceFromServer(connection.table, {
      noWebSocket: true,
    });
    const views = table.get(dataBrowser.properties.tableViews) as string[];
    expect(views).toHaveLength(1);
    const view = await store.getResource(views[0]);
    expect(view.get(dataBrowser.properties.viewKind)).toBe('kanban');
    expect(view.get(dataBrowser.properties.viewGroupBy)).toBe(
      connection.status,
    );

    await expect(
      readExternalOperation(store, {
        drive: connection.drive,
        plugin: connection.plugin,
        release: connection.release,
        run: 'preview',
        intent: {
          id: 'no-write',
          operation: 'update',
          method: 'PATCH',
          url: 'https://api.github.com/repos/atomic-pilot-fixture/kanban/issues/42',
          body: '{}',
        },
      }),
    ).rejects.toThrow('read operation');

    expect(connection.release).toMatch(/^blake3:/);
  },
  60000,
);

it.skipIf(!process.env.ATOMIC_GITHUB_TEST_SERVER)(
  'reads changing connection membership without merging obsolete query snapshots',
  async () => {
    const { readConnectionSubjects } =
      await import('../../browser/lib/src/plugin-connection.js');
    await enableLoro();
    const keys = await Agent.generateKeyPair();
    const agent = Agent.fromSecret(
      Agent.buildSecret(keys.privateKey, `did:ad:agent:${keys.publicKey}`),
      'js',
    );
    const store = new Store({
      serverUrl: process.env.ATOMIC_GITHUB_TEST_SERVER!,
      agent,
    });
    store.setServerConnected(true);
    const drive = await store.createDrive('Membership snapshot test', {
      agentName: 'Test',
      description: '[atomic-data:dev-drive]',
    });
    store.setDrive(drive.subject);
    const parent = await store.newResource({
      parent: drive.subject,
      propVals: { [core.properties.name]: 'Inbox' },
    });
    await parent.save();
    const expected: string[] = [];
    for (let i = 0; i < 5; i++) {
      const child = await store.newResource({
        parent: parent.subject,
        propVals: { [core.properties.name]: `Notification ${i}` },
      });
      await child.save();
      expected.push(child.subject);
      expect(
        (
          await readConnectionSubjects(
            store,
            drive.subject,
            core.properties.parent,
            parent.subject,
          )
        ).sort(),
      ).toEqual([...expected].sort());
    }
  },
  60000,
);
