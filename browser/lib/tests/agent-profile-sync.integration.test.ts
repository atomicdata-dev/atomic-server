/**
 * A rename must reach a server that only ever received the agent's drive.
 *
 * The profile is written on server A, then the same browser works against
 * server B, which auto-creates a bare agent stub on the first commit. The first
 * rename is refused there (it depends on ops B never had); the outbox retries
 * with a self-contained snapshot, which B can merge. This pins that recovery.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

import { startServer, type ServerHandle } from './server-fixture.js';
import { Agent } from '../src/agent.js';
import { JSCryptoProvider } from '../src/CryptoProvider.js';
import { Store } from '../src/store.js';
import { NodeClientDb } from '../src/client-db.node.js';
import type { ClientDbWorker } from '../src/client-db.js';
import { core } from '../src/ontologies/core.js';
import { server as serverOnt } from '../src/ontologies/server.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const wasmPath = path.resolve(here, '../../../wasm/pkg/atomic_wasm_bg.wasm');

/** Every store the tests opened, closed in `afterAll`: a store left connected
 * logs "Server disconnected" (and its outbox retries) after the server stops,
 * and a log that lands in the worker's teardown fails the run. */
const openStores: Store[] = [];

async function storeFor(url: string, agent: Agent): Promise<Store> {
  const clientDb = new NodeClientDb({ wasmPath, baseUrl: url });
  await clientDb.init();
  const store = new Store({ serverUrl: url, agent });
  store.setClientDb(clientDb as unknown as ClientDbWorker);
  openStores.push(store);
  await delay(500);

  return store;
}

/**
 * Waits until the server itself reports `expected` as the agent's name and
 * returns the last name it saw. Reads the server's authoritative snapshot over
 * HTTP, so no local cache or fixed sleep decides the answer: a write takes as
 * long as the box lets it, and the wall only has to tell "slow" from "never".
 */
async function nameOn(
  url: string,
  viewer: Agent,
  subject: string,
  expected: string,
  wallMs = 60_000,
) {
  const store = new Store({ serverUrl: url, agent: viewer, connect: false });
  openStores.push(store);
  const deadline = Date.now() + wallMs;
  let last: unknown;

  while (Date.now() < deadline) {
    try {
      const snapshot = await store.readServerSnapshot(subject);
      last = snapshot[core.properties.name];

      if (last === expected) return last;
    } catch (e) {
      last = `read failed: ${String(e)}`;
    }

    await delay(500);
  }

  return last;
}

describe('agent profile across servers', () => {
  let a: ServerHandle;
  let b: ServerHandle;

  beforeAll(async () => {
    [a, b] = await Promise.all([startServer(), startServer()]);
  }, 180_000);

  afterAll(async () => {
    for (const store of openStores) {
      store.disconnect();
      store.setServerConnected(false);
    }

    await delay(500);
    await a?.stop();
    await b?.stop();
  });

  it('shows the owner name and renames on a server that only got the drive', async () => {
    const keys = await Agent.generateKeyPair();
    const owner = new Agent(
      new JSCryptoProvider(keys.privateKey),
      `did:ad:agent:${keys.publicKey}`,
    );
    const viewer = await Agent.fromSecret(a.agentSecret);

    // The owner's profile is written on server A.
    const storeA = await storeFor(a.serverUrl, owner);
    const home = await storeA.ensurePrivateDrive('Owner home', {
      agentName: 'Old name',
    });
    expect(home.error).toBeUndefined();
    expect(
      await nameOn(a.serverUrl, viewer, owner.subject!, 'Old name'),
    ).toBe('Old name');

    // The same browser then works against server B, which has never seen the
    // agent resource.
    storeA.setServerUrl(b.serverUrl, { connect: true });
    await delay(1000);
    const driveOnB = await storeA.newResource({
      isA: serverOnt.classes.drive,
      noParent: true,
      propVals: {
        [core.properties.name]: 'Team drive',
        [core.properties.write]: [owner.subject],
        [core.properties.read]: [owner.subject],
      },
    });
    await driveOnB.save();

    const agentResource = await storeA.getResource(owner.subject!);
    await agentResource.set(core.properties.name, 'New name');
    await agentResource.save().catch(() => undefined);

    // The first save is refused (it depends on ops B never had); the outbox
    // retries with a snapshot B can merge, so the name arrives on its own.
    const viewerB = await Agent.fromSecret(b.agentSecret);
    expect(
      await nameOn(b.serverUrl, viewerB, owner.subject!, 'New name'),
    ).toBe('New name');
  }, 120_000);
});
