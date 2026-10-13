/**
 * A member who may only append to a chat can add, change and remove their own
 * entries in a ChatLog page and nobody else's (planning/chat-log.md), checked
 * against a real server with two agents. The Rust tests cover the rule per
 * commit; this one covers the client path: the Loro delta a browser signs.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { setTimeout as delay } from 'node:timers/promises';
import { startServer, type ServerHandle } from './server-fixture.js';
import { Agent } from '../src/agent.js';
import { JSCryptoProvider } from '../src/CryptoProvider.js';
import { Store } from '../src/store.js';
import { core } from '../src/ontologies/core.js';
import { dataBrowser } from '../src/ontologies/dataBrowser.js';
import { server as serverOnt } from '../src/ontologies/server.js';
import type { Resource } from '../src/resource.js';

const APPEND = 'https://atomicdata.dev/properties/append';

async function agent(): Promise<Agent> {
  const keys = await Agent.generateKeyPair();

  return new Agent(
    new JSCryptoProvider(keys.privateKey),
    `did:ad:agent:${keys.publicKey}`,
  );
}

/** Every store the tests opened, closed in `afterAll`: a commit the server
 * refused is retried by its outbox, and that retry (and its log) would
 * otherwise outlive the server and land in the worker's teardown. */
const openStores: Store[] = [];

function storeFor(url: string, who: Agent): Store {
  const store = new Store({ serverUrl: url, agent: who });
  store.setServerConnected(true);
  openStores.push(store);

  return store;
}

/** The entries as the server has them, read through a store of its own. */
async function serverEntries(url: string, who: Agent, subject: string) {
  const page = await storeFor(url, who).getResource(subject);

  return Object.fromEntries(
    page.listChatLogEntries().map(({ key, entry }) => [key, entry.t]),
  );
}

describe('chat log rights against a live server', () => {
  let handle: ServerHandle;

  beforeAll(async () => {
    handle = await startServer();
  }, 120_000);

  afterAll(async () => {
    for (const store of openStores) {
      store.disconnect();
      store.setServerConnected(false);
    }

    await new Promise(resolve => setTimeout(resolve, 500));
    await handle?.stop();
  });

  it('lets an appender change only their own entries', async () => {
    const alice = await agent();
    const bob = await agent();
    const url = handle.serverUrl;
    const aliceStore = storeFor(url, alice);

    const drive = await aliceStore.newResource({
      isA: serverOnt.classes.drive,
      noParent: true,
      propVals: {
        [core.properties.name]: 'Chat log rights',
        [core.properties.write]: [alice.subject],
        [core.properties.read]: [alice.subject, bob.subject],
      },
    });
    await drive.save();
    await aliceStore.syncDirtyResources();
    // Bob can read the chat and append to it, but not write it.
    const chat = await aliceStore.newResource({
      isA: dataBrowser.classes.chatroom,
      parent: drive.subject,
      propVals: {
        [core.properties.name]: 'Rights chat',
        [APPEND]: [bob.subject],
      },
    });
    await chat.save();
    await aliceStore.syncDirtyResources();

    const page = await aliceStore.newResource({
      isA: dataBrowser.classes.chatLog,
      parent: chat.subject,
    });
    const aliceKey = page.addChatLogEntry({ t: 'from alice' })!;
    await page.save();
    await aliceStore.syncDirtyResources();
    await delay(500);

    // Bob appends his own entry.
    const bobStore = storeFor(url, bob);
    const bobPage: Resource = await bobStore.getResource(page.subject);
    expect(bobPage.error).toBeUndefined();
    expect(bobPage.getChatLogEntry(aliceKey)?.t).toBe('from alice');
    const bobKey = bobPage.addChatLogEntry({ t: 'from bob' })!;
    await bobPage.save();
    await delay(500);
    expect(await serverEntries(url, alice, page.subject)).toEqual({
      [aliceKey]: 'from alice',
      [bobKey]: 'from bob',
    });

    // He may edit it ...
    bobPage.putChatLogEntry(bobKey, {
      ...bobPage.getChatLogEntry(bobKey)!,
      t: 'from bob, edited',
    });
    await bobPage.save();
    await delay(500);
    expect((await serverEntries(url, alice, page.subject))[bobKey]).toBe(
      'from bob, edited',
    );

    // ... but not rewrite or remove Alice's: the server refuses the commit
    // and her entry is as it was.
    const before = await serverEntries(url, alice, page.subject);
    bobPage.putChatLogEntry(aliceKey, {
      ...bobPage.getChatLogEntry(aliceKey)!,
      t: 'bob was here',
    });
    await bobPage.save().catch(() => undefined);
    await delay(1500);
    expect(await serverEntries(url, alice, page.subject)).toEqual(before);

    const bobStore2 = storeFor(url, bob);
    const fresh = await bobStore2.getResource(page.subject);
    fresh.removeChatLogEntry(aliceKey);
    await fresh.save().catch(() => undefined);
    await delay(1500);
    expect(await serverEntries(url, alice, page.subject)).toEqual(before);

    // Alice, who can write the chat, can moderate: remove Bob's entry.
    const alicePage = await storeFor(url, alice).getResource(page.subject);
    alicePage.removeChatLogEntry(bobKey);
    await alicePage.save();
    await delay(500);
    expect(await serverEntries(url, alice, page.subject)).toEqual({
      [aliceKey]: 'from alice',
    });
  }, 90_000);
});
