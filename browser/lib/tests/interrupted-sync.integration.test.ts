import { afterAll, beforeAll, expect, it, vi } from 'vitest';
import { resolve } from 'node:path';
import { startServer, type ServerHandle } from './server-fixture.js';
import { Agent } from '../src/agent.js';
import { Store } from '../src/store.js';
import { NodeClientDb } from '../src/client-db.node.js';
import type { ClientDbWorker } from '../src/client-db.js';
import { core } from '../src/ontologies/core.js';
import { Tag, decodeSyncPush, encodeSyncPush } from '../src/ws-v2.js';

let server: ServerHandle;
beforeAll(async () => {
  server = await startServer();
}, 120_000);
afterAll(async () => {
  await server?.stop();
});

it.each([
  { queueRetained: true, skipEntry: false },
  { queueRetained: false, skipEntry: false },
  { queueRetained: false, skipEntry: true },
])(
  'preserves disjoint offline edits after interrupted reconciliation ($queueRetained, skipped entry: $skipEntry)',
  async ({ queueRetained, skipEntry }) => {
    const owner = await Agent.fromSecret(server.agentSecret);
    const keys = await Agent.generateKeyPair();
    const guest = await Agent.fromSecret(
      Agent.buildSecret(keys.privateKey, `did:ad:agent:${keys.publicKey}`),
    );
    const clients: Store[] = [];

    const makeClient = async (agent: Agent, retainedDb?: NodeClientDb) => {
      localStorage.setItem('ws-disconnected', '1');
      const db =
        retainedDb ??
        new NodeClientDb({
          wasmPath: resolve('../../wasm/pkg/atomic_wasm_bg.wasm'),
          baseUrl: server.serverUrl,
        });
      if (!retainedDb) await db.init();
      const store = new Store({ serverUrl: server.serverUrl, agent });
      store.setClientDb(db as unknown as ClientDbWorker);
      store.diagnostics.start();
      clients.push(store);

      return { store, db };
    };

    const a = await makeClient(owner);
    const b = await makeClient(guest);
    // Values are specified independently of either replica, before any writes.
    const ledger = {
      name: 'Final offline name from A',
      description: 'Offline description from B',
      rows: ['Row created by A', 'Row created by B'],
    };
    const acknowledged: Array<{ subject: string; result: string }> = [];

    try {
      a.store.setServerConnected(true);
      const drive = await a.store.newResource({
        isA: 'https://atomicdata.dev/classes/Drive',
        noParent: true,
        propVals: {
          [core.properties.name]: 'Partition fixture',
          [core.properties.read]: [owner.subject, guest.subject],
          [core.properties.write]: [owner.subject, guest.subject],
        },
      });
      expect(await drive.save()).toBe('persisted');
      a.store.setDrive(drive.subject);
      b.store.setDrive(drive.subject);
      const doc = await a.store.newResource({
        parent: drive.subject,
        propVals: {
          [core.properties.name]: 'Before partition',
          [core.properties.description]: 'Before partition',
        },
      });
      expect(await doc.save()).toBe('persisted');
      b.store.setServerConnected(true);
      const otherDoc = await b.store.getResource(doc.subject);
      expect(otherDoc.error).toBeUndefined();
      expect(otherDoc.get(core.properties.name)).toBe('Before partition');
      await b.store.getResource(drive.subject);

      for (const { store } of [a, b]) {
        store.setServerConnected(false);
        store.injectFetch(async () => {
          throw new TypeError('Failed to fetch');
        });
      }

      await doc.set(core.properties.name, 'First offline name from A', false);
      await otherDoc.set(
        core.properties.description,
        ledger.description,
        false,
      );

      for (const resource of [doc, otherDoc]) {
        const result = await resource.save();
        expect(result).toBe('offline');
        acknowledged.push({ subject: resource.subject, result });
      }

      const rows: string[] = [];

      for (const [index, { store }] of [a, b].entries()) {
        const row = await store.newResource({
          parent: drive.subject,
          propVals: { [core.properties.name]: ledger.rows[index] },
        });
        const result = await row.save();
        expect(result).toBe('offline');
        rows.push(row.subject);
        acknowledged.push({ subject: row.subject, result });
      }

      expect(acknowledged).toHaveLength(4);

      // Forward an actual SYNC probe, then close before its response can be
      // delivered. No sleeps or probabilistic disconnect timing.
      let interrupted = false;
      const send = WebSocket.prototype.send;
      const intercept = vi
        .spyOn(WebSocket.prototype, 'send')
        .mockImplementation(function (this: WebSocket, data) {
          send.call(this, data);

          if (
            !interrupted &&
            data instanceof Uint8Array &&
            data[0] === Tag.SYNC
          ) {
            interrupted = true;
            a.store.disconnect();
          }
        });
      a.store.injectFetch(fetch);
      await a.store.reconnect();
      await expect.poll(() => interrupted).toBe(true);
      intercept.mockRestore();
      // A further acknowledged edit has not reached the server when JS state
      // is discarded. Recovery must rehydrate and drain this persisted work.
      a.store.setServerConnected(false);
      a.store.injectFetch(async () => {
        throw new TypeError('Failed to fetch');
      });
      await doc.set(core.properties.name, ledger.name, false);
      const pendingResult = await doc.save();
      expect(pendingResult).toBe('offline');
      acknowledged.push({ subject: doc.subject, result: pendingResult });
      expect(a.store.outbox.hasPending(doc.subject)).toBe(true);
      a.store.outbox.flush();
      expect(
        JSON.parse((await a.db.getResource(doc.subject))!)[
          core.properties.name
        ],
      ).toBe(ledger.name);

      if (!queueRetained) {
        // The outbox is persisted in the client database (localStorage only
        // holds a queue that has no database), so lose it there.
        localStorage.removeItem(`atomic.outbox.${owner.subject}`);
        const queued = await a.db.outboxEntries(owner.subject);
        await a.db.outboxWrite(
          {
            agent: owner.subject,
            puts: [],
            deletes: queued.map(row => JSON.parse(row).subject as string),
          },
          true,
        );
        expect(await a.db.outboxEntries(owner.subject)).toEqual([]);
      }

      // Recreate all JS Store/resource/outbox state, retaining only the local
      // database and persisted outbox. This is not an OS/OPFS crash test.
      const restarted = await makeClient(owner, a.db);
      restarted.store.setDrive(drive.subject);
      // The queue is loaded from the database asynchronously after the
      // restart; reading it earlier would report an empty queue.
      await restarted.store.outbox.whenHydrated();
      expect(restarted.store.outbox.hasPending(doc.subject)).toBe(
        queueRetained,
      );
      b.store.injectFetch(fetch);
      await b.store.reconnect();
      await expect
        .poll(() => b.store.getSyncStatus().lastDriveSync, { timeout: 15_000 })
        .toBeTruthy();
      restarted.store.subscribe(doc.subject, () => {});
      let skipped = false;
      let retried = false;
      const dropEntry = vi
        .spyOn(WebSocket.prototype, 'send')
        .mockImplementation(function (this: WebSocket, data) {
          if (
            skipEntry &&
            data instanceof Uint8Array &&
            data[0] === Tag.SYNC_PUSH
          ) {
            const message = decodeSyncPush(data.subarray(1))!;

            if (message.entries.some(entry => entry.subject === doc.subject)) {
              if (!skipped) {
                skipped = true;
                // Forward a valid chunk without one update: the real server
                // acknowledges it, but its stored vector cannot cover that edit.
                send.call(
                  this,
                  new Uint8Array(
                    encodeSyncPush(
                      message.drive,
                      message.entries.filter(
                        entry => entry.subject !== doc.subject,
                      ),
                      message.last,
                    ),
                  ),
                );

                return;
              }

              retried = true;
            }
          }

          send.call(this, data);
        });
      await restarted.store.reconnect();
      await expect
        .poll(() => restarted.store.getSyncStatus().lastDriveSync, {
          timeout: 15_000,
        })
        .toBeTruthy();
      dropEntry.mockRestore();
      expect(skipped).toBe(skipEntry);
      expect(retried).toBe(skipEntry);
      // Completion verifies the server has the exported operations.

      // A single independent read must already see it; do not poll away a race.
      const completedReader = new Store({
        serverUrl: server.serverUrl,
        agent: owner,
        connect: false,
      });
      const completedResource = await completedReader.fetchResourceFromServer(
        doc.subject,
        { noWebSocket: true },
      );
      expect(completedResource.get(core.properties.name)).toBe(ledger.name);
      // B may have reconciled before A's final push; reconcile once more.
      await b.store.reconnect();
      await expect
        .poll(
          async () => {
            const states = [];

            for (const { db } of [restarted, b]) {
              const raw = await db.getResource(doc.subject);
              states.push(raw ? JSON.parse(raw) : null);
            }

            return states.map(state => [
              state?.[core.properties.name],
              state?.[core.properties.description],
            ]);
          },
          { timeout: 15_000 },
        )
        .toEqual([
          [ledger.name, ledger.description],
          [ledger.name, ledger.description],
        ]);

      // A fresh HTTP-only reader independently checks the server, while local
      // DB reads above cannot hide divergence through network fallback.
      const reader = await makeClient(owner);
      reader.store.setServerConnected(true);

      for (const { db, store } of [restarted, b]) {
        expect(store.getSyncStatus().blockedCount).toBe(0);
        await expect
          .poll(() => store.getSyncStatus().pendingDirtyCount)
          .toBe(0);

        for (const [index, subject] of rows.entries()) {
          await expect
            .poll(async () => {
              const raw = await db.getResource(subject);

              return raw ? JSON.parse(raw)[core.properties.name] : undefined;
            })
            .toBe(ledger.rows[index]);
        }
      }

      const remote = await reader.store.getResource(doc.subject);
      expect(remote.get(core.properties.name)).toBe(ledger.name);
      expect(remote.get(core.properties.description)).toBe(ledger.description);

      for (const [index, subject] of rows.entries()) {
        const row = await reader.store.getResource(subject);
        expect(row.get(core.properties.name)).toBe(ledger.rows[index]);
        expect(row.get(core.properties.parent)).toBe(drive.subject);
      }
    } catch (error) {
      console.error(
        'Interrupted sync evidence',
        JSON.stringify({
          ledger,
          acknowledged,
          clients: clients.map(store => ({
            status: store.getSyncStatus(),
            diagnostics: store.diagnostics.capture(),
          })),
        }),
      );
      throw error;
    } finally {
      vi.restoreAllMocks();
      for (const store of clients) store.disconnect();
      // WASM is released with this isolated Vitest process, after WS callbacks.
    }
  },
);
