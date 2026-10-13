import { afterEach, beforeAll, describe, it, vi } from 'vitest';
import { Collection } from './collection.js';
import { core } from './ontologies/core.js';
import { collections } from './index.js';
import { LoroLoader } from './loro-loader.js';
import { Resource } from './resource.js';
import { Store } from './store.js';
import { WSClient } from './websockets.js';
import { Flags, Tag } from './ws-v2.js';

/**
 * A `/query` answer is derived state: the server builds it per request, in a
 * fresh Loro doc that shares no history with the copy the store holds. Merging
 * two such docs resolves `members` as a concurrent last-writer-wins by lamport
 * and then random peer id, so a refresh returned the previous member list
 * about half the time. `Collection.fetchPageFromServer` therefore asks for
 * replace semantics (`forceOverride`), on the HTTP path and the WebSocket path.
 */

const SERVER = 'https://example.com';
const PARENT = 'did:ad:test-parent';
const ROUNDS = 30;
const MEMBERS = collections.properties.members;

const memberList = (round: number) => [
  `did:ad:member-${round}-a`,
  `did:ad:member-${round}-b`,
];

beforeAll(async () => {
  await LoroLoader.initializeLoro();
});

function makeCollection(store: Store): Collection {
  return new Collection(
    store,
    SERVER,
    {
      page_size: '30',
      include_nested: false,
      property: core.properties.parent,
      value: PARENT,
    },
    true,
  );
}

async function pageMembers(collection: Collection): Promise<string[]> {
  return collection.getMembersOnPage(0);
}

function freshQueryDoc(members: string[]) {
  const { LoroDoc } = LoroLoader.Loro;
  const doc = new LoroDoc();
  doc.getMap('properties').set(MEMBERS, members);
  doc
    .getMap('properties')
    .set(collections.properties.totalMembers, members.length);
  doc.getMap('properties').set(collections.properties.totalPages, 1);
  doc.commit();

  return doc;
}

function connectedStore(): Store {
  const store = new Store({ serverUrl: SERVER });
  store.setServerConnected(true);

  return store;
}

describe('Collection.refresh replaces the /query answer instead of merging it', () => {
  const original = globalThis.WebSocket;

  afterEach(() => {
    globalThis.WebSocket = original;
    vi.restoreAllMocks();
  });

  it('HTTP: every refresh shows the newest member list', async ({ expect }) => {
    const store = connectedStore();
    let round = 0;

    // The server's answer: a brand-new doc each time, no shared ancestry.
    vi.spyOn(store.client, 'fetchResourceHTTP').mockImplementation(
      async subject => {
        const resource = new Resource(subject);
        resource.setStore(store);
        await resource.set(MEMBERS, memberList(round), false);
        await resource.set(collections.properties.totalMembers, 2, false);
        await resource.set(collections.properties.totalPages, 1, false);

        return { resource, createdResources: [], cancelled: false };
      },
    );

    const collection = makeCollection(store);
    await collection.waitForReady();
    expect(await pageMembers(collection)).toEqual(memberList(0));

    for (round = 1; round <= ROUNDS; round++) {
      await collection.refresh();
      expect(await pageMembers(collection), `round ${round}`).toEqual(
        memberList(round),
      );
    }
  });

  it('WebSocket: every refresh shows the newest member list', async ({
    expect,
  }) => {
    class FakeWebSocket {
      public static readonly OPEN = 1;
      public protocol = 'atomicdata-ws.v2';
      public binaryType = 'arraybuffer';
      public readyState = 1;
      public sent: Uint8Array[] = [];
      public onGet?: (frame: Uint8Array) => void;
      readonly #listeners = new Map<string, Set<(e: unknown) => void>>();

      constructor(public url: string) {}

      addEventListener(type: string, cb: (e: unknown) => void) {
        const set = this.#listeners.get(type) ?? new Set();
        set.add(cb);
        this.#listeners.set(type, set);
      }

      removeEventListener(type: string, cb: (e: unknown) => void) {
        this.#listeners.get(type)?.delete(cb);
      }

      send(data: Uint8Array | string) {
        if (typeof data === 'string') return;
        const frame = new Uint8Array(data);
        this.sent.push(frame);
        if (frame[0] === Tag.GET) this.onGet?.(frame);
      }

      close() {
        this.readyState = 3;
      }

      receive(frame: Uint8Array) {
        const data = frame.buffer.slice(
          frame.byteOffset,
          frame.byteOffset + frame.byteLength,
        );

        for (const cb of this.#listeners.get('message') ?? []) cb({ data });
      }
    }

    globalThis.WebSocket = FakeWebSocket as unknown as typeof WebSocket;
    const store = connectedStore();
    const ws = new WSClient('wss://example.com/ws', store);
    const socket = (ws as unknown as { ws: FakeWebSocket }).ws;
    vi.spyOn(ws, 'authenticate').mockResolvedValue(undefined);
    vi.spyOn(store, 'getWebSocketForSubject').mockReturnValue(ws);
    const http = vi.spyOn(store.client, 'fetchResourceHTTP');
    let round = 0;
    const enc = new TextEncoder();

    // The server's GET reply: SNAPSHOT of a brand-new doc (engine.rs answer_get).
    socket.onGet = frame => {
      const view = new DataView(frame.buffer, frame.byteOffset);
      const requestId = view.getUint16(1);
      const subject = new TextDecoder().decode(frame.subarray(3));
      const bytes = freshQueryDoc(memberList(round)).export({
        mode: 'snapshot',
      });
      const s = enc.encode(subject);
      const reply = new Uint8Array(6 + s.length + bytes.length);
      const rv = new DataView(reply.buffer);
      reply[0] = Tag.UPDATE;
      reply[1] = Flags.SNAPSHOT;
      rv.setUint16(2, requestId);
      rv.setUint16(4, s.length);
      reply.set(s, 6);
      reply.set(bytes, 6 + s.length);
      queueMicrotask(() => socket.receive(reply));
    };

    const collection = makeCollection(store);
    await collection.waitForReady();
    expect(await pageMembers(collection)).toEqual(memberList(0));

    for (round = 1; round <= ROUNDS; round++) {
      await collection.refresh();
      expect(await pageMembers(collection), `round ${round}`).toEqual(
        memberList(round),
      );
    }

    // The page really travelled over the socket, not HTTP.
    expect(http).not.toHaveBeenCalled();
    expect(socket.sent.filter(f => f[0] === Tag.GET).length).toBeGreaterThan(
      ROUNDS,
    );
  });
});
