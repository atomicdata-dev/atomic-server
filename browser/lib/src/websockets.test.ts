import { Resource } from './resource.js';
import { AtomicError, ErrorType } from './error.js';
import { describe, it, vi, afterEach } from 'vitest';
import { testStore } from './test-store.js';
import { WSClient } from './websockets.js';
import {
  Tag,
  ErrorCode,
  CLIENT_CAPABILITIES,
  decodeCommit,
  decodeHelloCaps,
  encodeChallenge,
  encodeCommitOkSlim,
  encodeSyncResend,
  encodeEphemeral,
  decodeEphemeral,
  EphemeralKind,
  encodeCommitOk,
  encodeError,
  encodeAuthOk,
} from './ws-v2.js';
import type { Commit } from './commit.js';
import { serializeDeterministically } from './commit.js';

/**
 * Frame-level tests for the client side of the COMMIT round trip and the
 * connection handshake, against a fake socket: what the client sends on
 * open, how it binds its AUTH proof to the server's CHALLENGE, and how a
 * `COMMIT_OK` (either form) or an `ERROR` settles exactly the pending
 * commit it names. Until 2026-09 this layer was only exercised through the
 * store's HTTP fallback, with `client.postCommit` mocked out.
 */
class FakeWebSocket {
  public static readonly OPEN = 1;
  public url: string;
  public protocol = 'atomicdata-ws.v2';
  public binaryType = 'arraybuffer';
  public readyState = 0;
  public sent: Uint8Array[] = [];
  readonly #listeners = new Map<string, Set<(e: unknown) => void>>();

  constructor(url: string) {
    this.url = url;
  }

  public addEventListener(type: string, cb: (e: unknown) => void): void {
    const set = this.#listeners.get(type) ?? new Set();
    set.add(cb);
    this.#listeners.set(type, set);
  }

  public removeEventListener(type: string, cb: (e: unknown) => void): void {
    this.#listeners.get(type)?.delete(cb);
  }

  public send(data: Uint8Array | string): void {
    if (typeof data === 'string') {
      this.sent.push(new TextEncoder().encode(data));
    } else {
      this.sent.push(new Uint8Array(data));
    }
  }

  public close(): void {}

  public fire(type: string, event: unknown): void {
    for (const cb of this.#listeners.get(type) ?? []) cb(event);
  }

  /** Deliver a binary frame from the "server". */
  public receive(frame: Uint8Array): void {
    const data = frame.buffer.slice(
      frame.byteOffset,
      frame.byteOffset + frame.byteLength,
    );
    this.fire('message', { data });
  }

  public open(): void {
    this.readyState = FakeWebSocket.OPEN;
    this.fire('open', {});
  }
}

const socketOf = (client: WSClient): FakeWebSocket =>
  (client as unknown as { ws: FakeWebSocket }).ws;

const framesWithTag = (socket: FakeWebSocket, tag: number) =>
  socket.sent.filter(f => f[0] === tag);

const signedCommit = (): Commit =>
  ({
    subject: 'did:ad:doc',
    set: { 'https://atomicdata.dev/properties/name': 'v1' },
    signer: 'did:ad:agent:alice',
    createdAt: 1,
    signature: 'sig-abc',
  }) as unknown as Commit;

async function connectedClient() {
  globalThis.WebSocket = FakeWebSocket as unknown as typeof WebSocket;
  const { store } = await testStore();
  // Keep the open handler's side effects (drain, drive sync, auth) out of
  // these frame-level tests.
  vi.spyOn(store, 'syncDirtyResources').mockResolvedValue(undefined);
  vi.spyOn(store, 'getDrive').mockReturnValue(undefined);
  const client = new WSClient('wss://example.com/ws', store);
  const socket = socketOf(client);
  socket.open();
  await Promise.resolve();

  return { client, socket, store };
}

describe('WSClient handshake', () => {
  const original = globalThis.WebSocket;

  afterEach(() => {
    globalThis.WebSocket = original;
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('a replaced socket cannot mark the new connection offline on its late close', async ({
    expect,
  }) => {
    const { client, socket, store } = await connectedClient();
    // Match the primary origin checked by reportConnected.
    vi.spyOn(store, 'getServerUrl').mockReturnValue('https://example.com');
    client.close();
    store.setServerConnected(true);
    socket.fire('close', { code: 1000, reason: '', wasClean: true });
    expect(store.serverConnected).toBe(true);
  });

  it.each([
    ['Resource not found. did:ad:missing', ErrorType.NotFound],
    ['Unauthorized. did:ad:private', ErrorType.Unauthorized],
    ['Storage unavailable', ErrorType.Server],
  ])('classifies legacy GET errors: %s', async (message, errorType) => {
    const { expect } = await import('vitest');
    const { client, socket } = await connectedClient();
    vi.spyOn(client, 'authenticate').mockResolvedValue(undefined);
    const result = client.fetch('did:ad:missing');
    const rejected = expect(result).rejects.toMatchObject({ type: errorType });
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.GET)).toHaveLength(1),
    );
    const frame = framesWithTag(socket, Tag.GET)[0];
    const requestId = new DataView(frame.buffer, frame.byteOffset).getUint16(1);
    socket.receive(encodeError(requestId, ErrorCode.UNKNOWN, message));
    await rejected;
    client.close();
  });

  it('introduces itself with a HELLO listing its capabilities on open', async ({
    expect,
  }) => {
    const { client, socket } = await connectedClient();

    const hellos = framesWithTag(socket, Tag.HELLO);
    expect(hellos).toHaveLength(1);
    expect(decodeHelloCaps(hellos[0].subarray(1))).toEqual([
      ...CLIENT_CAPABILITIES,
    ]);
    client.close();
  });

  it('does not send presence until the current identity is authenticated', async ({
    expect,
  }) => {
    const { client, socket } = await connectedClient();
    socket.receive(encodeChallenge('presence-test'));
    client.subscribePresence('did:ad:drive');
    client.sendPresenceUpdate('did:ad:drive', new Uint8Array([1]));
    const presenceSubscriptions = () =>
      socket.sent.filter(frame =>
        new TextDecoder().decode(frame).startsWith('PRESENCE_SUBSCRIBE '),
      );
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.AUTH)).toHaveLength(1),
    );
    expect(presenceSubscriptions()).toHaveLength(0);
    expect(framesWithTag(socket, Tag.EPHEMERAL)).toHaveLength(0);
    socket.receive(encodeAuthOk([]));
    await vi.waitFor(() => expect(presenceSubscriptions()).toHaveLength(1));
    client.sendPresenceUpdate('did:ad:drive', new Uint8Array([2]));
    expect(framesWithTag(socket, Tag.EPHEMERAL)).toHaveLength(1);
    client.close();
  });

  it('signs the AUTH proof for `{origin}#{nonce}` once a CHALLENGE arrived', async ({
    expect,
  }) => {
    const { client, socket } = await connectedClient();
    socket.receive(encodeChallenge('0badf00d'));
    expect(client.challengeNonce).toBe('0badf00d');

    const auth = client.authenticate();
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.AUTH)).toHaveLength(1),
    );
    const payload = JSON.parse(
      new TextDecoder().decode(framesWithTag(socket, Tag.AUTH)[0].subarray(1)),
    );
    expect(
      payload['https://atomicdata.dev/properties/auth/requestedSubject'],
    ).toBe('https://example.com#0badf00d');

    socket.receive(encodeAuthOk(['auth-nonce', 'commit-ok-slim']));
    await auth;
    expect(client.serverCapabilities).toEqual(['auth-nonce', 'commit-ok-slim']);
    client.close();
  });

  it('falls back to a timestamp-only proof when no CHALLENGE comes', async ({
    expect,
  }) => {
    vi.useFakeTimers();
    const { client, socket } = await connectedClient();

    const auth = client.authenticate();
    // The client waits briefly for the nonce, then signs the bare origin.
    await vi.advanceTimersByTimeAsync(400);
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.AUTH)).toHaveLength(1),
    );
    const payload = JSON.parse(
      new TextDecoder().decode(framesWithTag(socket, Tag.AUTH)[0].subarray(1)),
    );
    expect(
      payload['https://atomicdata.dev/properties/auth/requestedSubject'],
    ).toBe('https://example.com');

    socket.receive(encodeAuthOk([]));
    await auth;
    client.close();
  });
});

describe('WSClient drive sync probe', () => {
  const original = globalThis.WebSocket;

  afterEach(() => {
    globalThis.WebSocket = original;
    vi.restoreAllMocks();
  });

  it('does not send a sync probe computed for a previous identity', async ({
    expect,
  }) => {
    const { client, socket, store } = await connectedClient();
    vi.spyOn(store, 'computeDriveSyncState').mockImplementation(async () => {
      store.setAgent(undefined);

      return {
        drive: 'did:ad:drive',
        driveHash: 'hash',
        peers: [],
        resources: {},
      } as never;
    });
    await (
      client as unknown as { startVVSync: (drive: string) => Promise<void> }
    ).startVVSync('did:ad:drive');
    expect(framesWithTag(socket, Tag.SYNC)).toHaveLength(0);
    client.close();
  });

  it('stops range reconciliation when the identity changes between replies', async ({
    expect,
  }) => {
    const { client, socket, store } = await connectedClient();
    socket.receive(encodeChallenge('cancel-sync'));
    const auth = client.authenticate();
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.AUTH)).toHaveLength(1),
    );
    socket.receive(encodeAuthOk([]));
    await auth;
    vi.spyOn(store, 'computeDriveSyncState').mockResolvedValue({
      drive: 'did:ad:drive',
      driveHash: 'hash',
      peers: [],
      resources: {},
    } as never);
    const internal = client as unknown as {
      sendReducedSyncState: (drive: string) => Promise<void>;
      startVVSync: (drive: string) => Promise<void>;
      rbsrFingerprints: () => Promise<string[]>;
      rbsrItems: () => Promise<never[]>;
    };
    vi.spyOn(internal, 'rbsrFingerprints').mockImplementation(async () => {
      store.setAgent(undefined);

      return ['ff'.repeat(32)];
    });
    const items = vi.spyOn(internal, 'rbsrItems').mockResolvedValue([]);
    const warning = vi.spyOn(console, 'warn');
    await internal.startVVSync('did:ad:drive');
    await internal.sendReducedSyncState('did:ad:drive');
    expect(items).not.toHaveBeenCalled();
    expect(framesWithTag(socket, Tag.SYNC)).toHaveLength(1);
    expect(warning).not.toHaveBeenCalled();
    client.close();
  });

  it('probes with a binary SYNC and reconciles on SYNC_RESEND', async ({
    expect,
  }) => {
    const { client, socket, store } = await connectedClient();
    vi.spyOn(store, 'computeDriveSyncState').mockResolvedValue({
      drive: 'did:ad:drive',
      driveHash: 'abc123',
      peers: [],
      resources: {},
    } as unknown as Awaited<ReturnType<typeof store.computeDriveSyncState>>);
    const reduced = vi
      .spyOn(
        client as unknown as {
          sendReducedSyncState: (d: string) => Promise<void>;
        },
        'sendReducedSyncState',
      )
      .mockResolvedValue(undefined);

    await (
      client as unknown as { startVVSync: (d: string) => Promise<void> }
    ).startVVSync('did:ad:drive');

    const syncs = framesWithTag(socket, Tag.SYNC);
    expect(syncs).toHaveLength(1);
    const frame = syncs[0];
    const dl = (frame[1] << 8) | frame[2];
    expect(new TextDecoder().decode(frame.subarray(3, 3 + dl))).toBe(
      'did:ad:drive',
    );
    const ho = 3 + dl;
    const hl = (frame[ho] << 8) | frame[ho + 1];
    expect(new TextDecoder().decode(frame.subarray(ho + 2, ho + 2 + hl))).toBe(
      'abc123',
    );
    expect(
      JSON.parse(new TextDecoder().decode(frame.subarray(ho + 2 + hl))),
    ).toEqual({ peers: [], resources: {}, probe: true });

    socket.receive(encodeSyncResend('did:ad:drive'));
    expect(reduced).toHaveBeenCalledWith('did:ad:drive');
    client.close();
  });
});

describe('WSClient live collaboration', () => {
  const original = globalThis.WebSocket;

  afterEach(() => {
    globalThis.WebSocket = original;
    vi.restoreAllMocks();
  });

  it('sends and receives cursors, edits and presence as EPHEMERAL frames', async ({
    expect,
  }) => {
    const { client, socket, store } = await connectedClient();

    socket.receive(encodeChallenge('collaboration'));
    const auth = client.authenticate();
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.AUTH)).toHaveLength(1),
    );
    socket.receive(encodeAuthOk([]));
    await auth;

    // Outbound: one binary frame per channel, agent left for the server.
    client.sendLoroEphemeralUpdate('did:ad:doc', new Uint8Array([1]));
    client.sendLoroSyncUpdate('did:ad:doc', new Uint8Array([2]));
    client.sendPresenceUpdate('did:ad:drive', new Uint8Array([3]));
    const sent = framesWithTag(socket, Tag.EPHEMERAL).map(f =>
      decodeEphemeral(f.subarray(1)),
    );
    expect(sent.map(f => [f?.kind, f?.subject, f?.agent])).toEqual([
      [EphemeralKind.LORO, 'did:ad:doc', ''],
      [EphemeralKind.DOC, 'did:ad:doc', ''],
      [EphemeralKind.PRESENCE, 'did:ad:drive', ''],
    ]);

    // Inbound: each kind reaches its own subscriber map on the store.
    const cursors: number[][] = [];
    const edits: number[][] = [];
    const presence: number[][] = [];
    store.subscribeLoroEphemeral('did:ad:doc', u => cursors.push([...u]));
    store.subscribeLoroSync('did:ad:doc', u => edits.push([...u]));
    store.subscribePresenceUpdates('did:ad:drive', u => presence.push([...u]));
    socket.receive(
      encodeEphemeral(
        EphemeralKind.LORO,
        'did:ad:doc',
        'did:ad:agent:bob',
        new Uint8Array([4]),
      ),
    );
    socket.receive(
      encodeEphemeral(EphemeralKind.DOC, 'did:ad:doc', '', new Uint8Array([5])),
    );
    socket.receive(
      encodeEphemeral(
        EphemeralKind.PRESENCE,
        'did:ad:drive',
        '',
        new Uint8Array([6]),
      ),
    );
    expect(cursors).toEqual([[4]]);
    expect(edits).toEqual([[5]]);
    expect(presence).toEqual([[6]]);
    client.close();
  });
});

describe('WSClient drive subscription', () => {
  const original = globalThis.WebSocket;

  afterEach(() => {
    globalThis.WebSocket = original;
    vi.restoreAllMocks();
  });

  it('UNSUBs the previous drive when the store switches drives', async ({
    expect,
  }) => {
    const { client, socket, store } = await connectedClient();
    socket.receive(encodeChallenge('drive-subscription'));
    const auth = client.authenticate();
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.AUTH)).toHaveLength(1),
    );
    socket.receive(encodeAuthOk([]));
    await auth;
    vi.spyOn(store, 'isLiveSyncedDrive').mockReturnValue(true);
    const subscribe = (
      client as unknown as { subscribeToDrive: () => void }
    ).subscribeToDrive.bind(client);

    vi.spyOn(store, 'getDrive').mockReturnValue('did:ad:drive-a');
    subscribe();
    expect(framesWithTag(socket, Tag.SUB)).toHaveLength(1);
    expect(framesWithTag(socket, Tag.UNSUB)).toHaveLength(0);

    // Same drive again: idempotent, nothing is unsubscribed.
    subscribe();
    expect(framesWithTag(socket, Tag.UNSUB)).toHaveLength(0);

    vi.spyOn(store, 'getDrive').mockReturnValue('did:ad:drive-b');
    subscribe();
    const unsubs = framesWithTag(socket, Tag.UNSUB);
    expect(unsubs).toHaveLength(1);
    expect(new TextDecoder().decode(unsubs[0].subarray(1))).toBe(
      'did:ad:drive-a',
    );
    expect(framesWithTag(socket, Tag.SUB)).toHaveLength(3);
    const missingDrive = new Resource('did:ad:missing-drive');
    missingDrive.setError(new AtomicError('Not here', ErrorType.NotFound));
    store.resources.set(missingDrive.subject, missingDrive);
    vi.spyOn(store, 'getDrive').mockReturnValue('did:ad:missing-drive');
    subscribe();
    expect(framesWithTag(socket, Tag.SUB)).toHaveLength(3);
    client.close();
  });
});

describe('WSClient.postCommit', () => {
  const original = globalThis.WebSocket;

  afterEach(() => {
    globalThis.WebSocket = original;
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  async function postingClient() {
    const ctx = await connectedClient();
    // Authentication has its own tests above; here it is a no-op.
    vi.spyOn(ctx.client, 'authenticate').mockResolvedValue(undefined);

    return ctx;
  }

  const sentRequestIds = (socket: FakeWebSocket) =>
    framesWithTag(socket, Tag.COMMIT).map(
      f => decodeCommit(f.subarray(1))!.requestId,
    );

  it('resolves a slim COMMIT_OK with the local commit carrying the server id', async ({
    expect,
  }) => {
    const { client, socket } = await postingClient();
    const commit = signedCommit();

    const pending = client.postCommit(commit);
    await vi.waitFor(() => expect(sentRequestIds(socket)).toHaveLength(1));
    const [rid] = sentRequestIds(socket);
    const wire = decodeCommit(framesWithTag(socket, Tag.COMMIT)[0].subarray(1));
    expect(wire?.commitJson).toBe(
      serializeDeterministically({ ...commit }, true),
    );

    socket.receive(encodeCommitOkSlim(rid, 'did:ad:commit:sig-abc'));
    const created = await pending;
    expect(created.id).toBe('did:ad:commit:sig-abc');
    expect(created.signature).toBe('sig-abc');
    expect(created.subject).toBe('did:ad:doc');
    client.close();
  });

  it('still accepts the legacy full-JSON COMMIT_OK', async ({ expect }) => {
    const { client, socket } = await postingClient();

    const pending = client.postCommit(signedCommit());
    await vi.waitFor(() => expect(sentRequestIds(socket)).toHaveLength(1));
    const [rid] = sentRequestIds(socket);

    socket.receive(
      encodeCommitOk(
        rid,
        JSON.stringify({
          '@id': 'https://example.com/commits/sig-abc',
          'https://atomicdata.dev/properties/subject': 'did:ad:doc',
          'https://atomicdata.dev/properties/signer': 'did:ad:agent:alice',
          'https://atomicdata.dev/properties/createdAt': 1,
          'https://atomicdata.dev/properties/signature': 'sig-abc',
        }),
      ),
    );
    const created = await pending;
    expect(created.id).toBe('https://example.com/commits/sig-abc');
    expect(created.signature).toBe('sig-abc');
    client.close();
  });

  it('an ERROR settles only the commit whose request id it names', async ({
    expect,
  }) => {
    const { client, socket } = await postingClient();

    const first = client.postCommit(signedCommit());
    const second = client.postCommit({
      ...signedCommit(),
      signature: 'sig-def',
    } as Commit);
    await vi.waitFor(() => expect(sentRequestIds(socket)).toHaveLength(2));
    const [ridA, ridB] = sentRequestIds(socket);
    expect(ridA).not.toBe(ridB);

    // Acks may come back in any order; the second commit is refused.
    socket.receive(
      encodeError(ridB, ErrorCode.UNAUTHORIZED_WRITE, 'no write right'),
    );
    await expect(second).rejects.toMatchObject({
      message: 'no write right',
      code: ErrorCode.UNAUTHORIZED_WRITE,
    });

    socket.receive(encodeCommitOkSlim(ridA, 'did:ad:commit:sig-abc'));
    await expect(first).resolves.toMatchObject({
      id: 'did:ad:commit:sig-abc',
    });
    client.close();
  });

  it('a malformed COMMIT_OK rejects its pending commit instead of hanging', async ({
    expect,
  }) => {
    const { client, socket } = await postingClient();

    const pending = client.postCommit(signedCommit());
    await vi.waitFor(() => expect(sentRequestIds(socket)).toHaveLength(1));
    const [rid] = sentRequestIds(socket);

    // Legacy form without an `@id`.
    socket.receive(encodeCommitOk(rid, '{"a":1}'));
    await expect(pending).rejects.toThrow('Malformed COMMIT_OK');
    client.close();
  });
});

describe('WSClient SYNC_DIFF and the outbox', () => {
  const original = globalThis.WebSocket;

  afterEach(() => {
    globalThis.WebSocket = original;
    vi.restoreAllMocks();
  });

  it('does not push a subject the outbox still owns', async ({ expect }) => {
    const { client, socket, store } = await connectedClient();
    store.outbox.markDirty('did:ad:dirty');

    const exported: string[] = [];
    // Both subjects would have bytes to push; only the clean one may go.
    vi.spyOn(store.resources, 'get').mockImplementation(
      (subject: string) =>
        ({
          getLoroDoc: () => ({ subject }),
        }) as unknown as ReturnType<typeof store.resources.get>,
    );
    vi.spyOn(Resource, 'exportLoroBytesForSync').mockImplementation(
      (doc: unknown) => {
        exported.push((doc as { subject: string }).subject);

        return new Uint8Array([1]);
      },
    );

    await (
      client as unknown as {
        handleSyncDiff: (d: unknown) => Promise<void>;
      }
    ).handleSyncDiff({
      drive: 'did:ad:drive',
      pull: ['did:ad:dirty', 'did:ad:clean'],
      push: [],
    });

    expect(exported).toEqual(['did:ad:clean']);
    expect(framesWithTag(socket, Tag.SYNC_PUSH)).toHaveLength(1);
    client.close();
  });
});
