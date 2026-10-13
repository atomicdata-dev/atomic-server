import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startServer, type ServerHandle } from './server-fixture.js';
import { Agent } from '../src/agent.js';
import { Store } from '../src/store.js';
import { core } from '../src/ontologies/core.js';
import { attachTestDb } from '../src/test-store.js';

// A real HTTP server accepts the write; only its response is lost. The local
// storage double isolates the outbox contract (OPFS has separate crash tests).
describe('lost durable acknowledgement', () => {
  let server: ServerHandle;
  beforeAll(async () => {
    server = await startServer();
  }, 120_000);
  afterAll(async () => {
    await server?.stop();
  });

  it('retries a lost genesis acknowledgement and preserves a later edit', async () => {
    const agent = await Agent.fromSecret(server.agentSecret);
    const store = new Store({ serverUrl: server.serverUrl, agent });
    store.disconnect();
    store.setServerConnected(true);
    attachTestDb(store);
    const accepted: string[] = [];
    let loseNext = true;
    store.injectFetch(async (input, init) => {
      const response = await fetch(input, init);

      if (init?.method === 'POST' && String(input).endsWith('/commit')) {
        expect(response.status).toBe(200);
        accepted.push(String(init.body));

        if (loseNext) {
          loseNext = false;
          // Consume the response to prove the server reached durable success,
          // but never hand it to the client.
          await response.text();
          throw new TypeError('Failed to fetch');
        }
      }

      return response;
    });

    try {
      const doc = await store.newResource({
        isA: 'https://atomicdata.dev/classes/Drive',
        noParent: true,
        propVals: {
          [core.properties.name]: 'Before lost acknowledgement',
          [core.properties.read]: [agent.subject],
          [core.properties.write]: [agent.subject],
        },
      });
      expect(await doc.save()).toBe('offline');
      expect(accepted).toHaveLength(1);
      expect(store.outbox.hasPending(doc.subject)).toBe(true);
      await doc.set(core.properties.name, 'Edit made before retry', false);
      store.setServerConnected(true);
      await expect
        .poll(
          async () => {
            await store.syncDirtyResources();

            return store.outbox.hasPending(doc.subject);
          },
          { timeout: 10_000 },
        )
        .toBe(false);
      expect(doc.commitError).toBeUndefined();
      expect(accepted.length).toBeGreaterThanOrEqual(2);
      // The original genesis is retried, never minted as another resource.
      expect(accepted[1]).toBe(accepted[0]);
      const fresh = new Store({ serverUrl: server.serverUrl, agent });
      fresh.disconnect();
      fresh.setServerConnected(true);

      try {
        const remote = await fresh.getResource(doc.subject);
        expect(remote.error).toBeUndefined();
        expect(remote.get(core.properties.name)).toBe('Edit made before retry');
      } finally {
        fresh.disconnect();
      }
    } finally {
      store.disconnect();
    }
  });
});
