import { Resource } from './resource.js';
import { AtomicError, ErrorType } from './error.js';
import { describe, it, vi, afterEach, expect as assert } from 'vitest';
import { testStore } from './test-store.js';
import { WSClient } from './websockets.js';
import {
  Tag,
  ErrorCode,
  CLIENT_CAPABILITIES,
  decodeCommit,
  encodeEphemeral,
  decodeEphemeral,
  EphemeralKind,
  Flags,
} from './ws-v2.js';
import {
  decodeHelloCaps,
  encodeChallenge,
  encodeCommitOkSlim,
  encodeSyncResend,
  encodeCommitOk,
  encodeError,
  encodeAuthOk,
} from './test-ws-v2-server.js';
import { LoroLoader } from './loro-loader.js';
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
  public static readonly CONNECTING = 0;
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
    if (this.readyState !== FakeWebSocket.OPEN)
      throw new Error('send on closed socket');

    if (typeof data === 'string') {
      this.sent.push(new TextEncoder().encode(data));
    } else {
      this.sent.push(new Uint8Array(data));
    }
  }

  public close(): void {
    this.readyState = 3;
  }

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

const enc = new TextEncoder();

/** A complete UPDATE frame carrying a Loro snapshot, as the server builds it. */
const updateFrame = (requestId: number, subject: string, loro: Uint8Array) => {
  const s = enc.encode(subject);
  const buf = new Uint8Array(6 + s.length + loro.length);
  const view = new DataView(buf.buffer);
  buf[0] = Tag.UPDATE;
  buf[1] = Flags.SNAPSHOT;
  view.setUint16(2, requestId);
  view.setUint16(4, s.length);
  buf.set(s, 6);
  buf.set(loro, 6 + s.length);

  return buf;
};

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

WSClient.syncProbeDelayMs = 0;

describe('WSClient handshake', () => {
  const original = globalThis.WebSocket;

  afterEach(() => {
    globalThis.WebSocket = original;
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('cancels immediately but closes a connecting socket only after it opens', async () => {
    globalThis.WebSocket = FakeWebSocket as unknown as typeof WebSocket;
    const { store } = await testStore();
    const client = new WSClient('wss://example.com/ws', store);
    const socket = socketOf(client);
    const close = vi.spyOn(socket, 'close');
    client.close();
    assert(close).not.toHaveBeenCalled();
    socket.open();
    await Promise.resolve();
    assert(close).toHaveBeenCalledOnce();
    assert(socket.sent).toEqual([]);
  });

  it.each(['disconnect', 'identity', 'database', 'current'])(
    'fences a pending blob read against %s changes',
    async mode => {
      const { client, socket, store } = await connectedClient();
      let finish!: (value: Uint8Array | null) => void;
      const db = {
        getBlob: () =>
          new Promise<Uint8Array | null>(resolve => {
            finish = resolve;
          }),
      };
      const database = vi
        .spyOn(store, 'getClientDb')
        .mockReturnValue(db as never);
      const resource = new Resource('did:ad:file');
      vi.spyOn(resource, 'get').mockReturnValue(
        `did:ad:blob:${'ab'.repeat(32)}`,
      );
      const read = (
        client as unknown as {
          checkForMissingBlobs(r: Resource): Promise<void>;
        }
      ).checkForMissingBlobs(resource);
      if (mode === 'disconnect') client.close();
      if (mode === 'identity')
        vi.spyOn(store, 'getAgent').mockReturnValue(undefined);
      if (mode === 'database') database.mockReturnValue({} as never);
      finish(null);
      await read;
      assert(framesWithTag(socket, Tag.BLOB_REQUEST)).toHaveLength(
        mode === 'current' ? 1 : 0,
      );
      client.close();
    },
  );

  it.each([
    'atomic:workspace',
    'did:ad:workspace',
    'https://example.com/drive',
  ])('attributes a rejected sync to the complete subject %s', async drive => {
    const { client, socket, store } = await connectedClient();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const failed = vi.spyOn(store, 'failDriveSync');
    const message = `SYNC_PUSH rejected for drive ${drive}: not enrolled`;
    socket.receive(encodeError(0, ErrorCode.SYNC_REJECTED, message));
    await vi.waitFor(() => assert(failed).toHaveBeenCalledWith(drive, message));
    client.close();
  });

  it('cancels authentication when closed while awaiting the server challenge', async ({
    expect,
  }) => {
    const { client, socket } = await connectedClient();
    const authentication = client.authenticate();
    const rejected = expect(authentication).rejects.toThrow(/closed/i);
    await Promise.resolve();
    client.close();
    await rejected;
    expect(framesWithTag(socket, Tag.AUTH)).toHaveLength(0);
  });

  it('settles authentication immediately when closed during signing', async ({
    expect,
  }) => {
    const { client, socket, store } = await connectedClient();
    socket.receive(encodeChallenge('delayed-signature'));
    let finish!: (signature: string) => void;
    const signing = vi
      .spyOn(store.getAgent()!, 'createSignature')
      .mockImplementation(
        () =>
          new Promise(resolve => {
            finish = resolve;
          }),
      );
    let cancelled = false;
    const authentication = client.authenticate().catch(() => {
      cancelled = true;
    });
    await vi.waitFor(() => expect(signing).toHaveBeenCalled());
    client.close();

    try {
      await vi.waitFor(() => expect(cancelled).toBe(true), { timeout: 200 });
    } finally {
      finish('late-signature');
      await authentication;
    }

    expect(framesWithTag(socket, Tag.AUTH)).toHaveLength(0);
  });

  it('does not warn or subscribe when closed before index-status authentication completes', async ({
    expect,
  }) => {
    const { client, socket } = await connectedClient();
    const warning = vi.spyOn(console, 'warn').mockImplementation(() => {});
    client.subscribeIndexStatus('did:ad:drive');
    client.close();
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(
      socket.sent.some(frame =>
        new TextDecoder().decode(frame).startsWith('SUBSCRIBE_INDEX_STATUS'),
      ),
    ).toBe(false);
    expect(warning).not.toHaveBeenCalled();
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

  it('rejects an invalid GET snapshot instead of leaving its caller waiting', async () => {
    const { client, socket } = await connectedClient();
    vi.spyOn(client, 'authenticate').mockResolvedValue(undefined);
    const settled = vi.fn();
    const subject = 'https://example.com/query?drive=atomic:home';
    const result = client.fetch(subject).then(
      value => settled(value),
      error => settled(error),
    );

    try {
      await vi.waitFor(() =>
        assert(framesWithTag(socket, Tag.GET)).toHaveLength(1),
      );
      const frame = framesWithTag(socket, Tag.GET)[0];
      const requestId = new DataView(frame.buffer, frame.byteOffset).getUint16(
        1,
      );
      socket.receive(updateFrame(requestId, subject, new Uint8Array([0])));
      await vi.waitFor(() =>
        assert(settled).toHaveBeenCalledWith(
          assert.objectContaining({
            type: ErrorType.Server,
            message: `Invalid resource update for ${subject}`,
          }),
        ),
      );
      await result;
    } finally {
      client.close();
    }
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

  /** Frames in send order, reduced to what the presence ordering needs. */
  const presenceFrames = (socket: FakeWebSocket) =>
    socket.sent
      .filter(
        frame =>
          frame[0] === Tag.EPHEMERAL ||
          new TextDecoder().decode(frame).startsWith('PRESENCE_SUBSCRIBE '),
      )
      .map(frame =>
        frame[0] === Tag.EPHEMERAL
          ? `update:${[...(decodeEphemeral(frame.subarray(1))?.payload ?? [])]}`
          : 'subscribe',
      );

  it('puts PRESENCE_SUBSCRIBE before a presence update sent right after it', async ({
    expect,
  }) => {
    const { client, socket } = await connectedClient();
    socket.receive(encodeChallenge('presence-order'));
    const auth = client.authenticate();
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.AUTH)).toHaveLength(1),
    );
    socket.receive(encodeAuthOk([]));
    await auth;

    client.subscribePresence('did:ad:drive');
    client.sendPresenceUpdate('did:ad:drive', new Uint8Array([1]));
    client.sendPresenceUpdate('did:ad:drive', new Uint8Array([2]));
    await vi.waitFor(() =>
      expect(presenceFrames(socket)).toEqual([
        'subscribe',
        'update:1',
        'update:2',
      ]),
    );
    // Once subscribed, updates go straight out.
    client.sendPresenceUpdate('did:ad:drive', new Uint8Array([3]));
    expect(presenceFrames(socket).at(-1)).toBe('update:3');
    client.close();
  });

  it('subscribes before the rebroadcast that follows authentication', async ({
    expect,
  }) => {
    const { client, socket, store } = await connectedClient();
    vi.spyOn(store, 'getPresenceSubjects').mockReturnValue(['did:ad:drive']);
    vi.spyOn(store, '__rebroadcastPresence').mockImplementation(() =>
      client.sendPresenceUpdate('did:ad:drive', new Uint8Array([7])),
    );
    socket.receive(encodeChallenge('presence-reconnect'));
    const auth = client.authenticate();
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.AUTH)).toHaveLength(1),
    );
    socket.receive(encodeAuthOk([]));
    await auth;
    await vi.waitFor(() =>
      expect(presenceFrames(socket)).toEqual(['subscribe', 'update:7']),
    );
    client.close();
  });

  it('drops a held presence update when the subscription is withdrawn', async ({
    expect,
  }) => {
    const { client, socket } = await connectedClient();
    socket.receive(encodeChallenge('presence-withdrawn'));
    const auth = client.authenticate();
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.AUTH)).toHaveLength(1),
    );
    socket.receive(encodeAuthOk([]));
    await auth;

    client.subscribePresence('did:ad:drive');
    client.sendPresenceUpdate('did:ad:drive', new Uint8Array([1]));
    client.unsubscribePresence('did:ad:drive');
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(presenceFrames(socket)).not.toContain('update:1');
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
    vi.useRealTimers();
  });

  it.each([true, false])(
    'recovers a planned restart and an in-flight save (clean=%s)',
    async wasClean => {
      const { client, socket, store } = await connectedClient();
      const warning = vi.spyOn(console, 'warn').mockImplementation(() => {});
      vi.spyOn(store, 'getDrive').mockReturnValue('https://example.com/drive');
      vi.spyOn(store, 'isLiveSyncedDrive').mockReturnValue(true);
      const compute = vi
        .spyOn(store, 'computeDriveSyncState')
        .mockResolvedValue({
          drive: 'https://example.com/drive',
          driveHash: 'current',
          peers: [],
          resources: {},
        } as never);
      socket.receive(encodeChallenge('first'));
      await vi.waitFor(() =>
        assert(framesWithTag(socket, Tag.AUTH)).toHaveLength(1),
      );
      socket.receive(encodeAuthOk([]));
      await vi.waitFor(() =>
        assert(framesWithTag(socket, Tag.SYNC)).toHaveLength(1),
      );
      compute.mockClear();
      vi.spyOn(
        store as unknown as {
          getWebSocketForEndpoint(endpoint: string): WSClient;
        },
        'getWebSocketForEndpoint',
      ).mockReturnValue(client);
      const commit = signedCommit();
      const saving = store.postCommit(commit, 'https://example.com/commit');
      await vi.waitFor(() =>
        assert(framesWithTag(socket, Tag.COMMIT)).toHaveLength(1),
      );

      vi.useFakeTimers();
      socket.close();
      socket.fire('close', { code: 1012, reason: '', wasClean });
      assert((await saving).signature).toBe(commit.signature);
      assert(store.serverConnected).toBe(false);
      await vi.advanceTimersByTimeAsync(1000);
      vi.useRealTimers();
      const replacement = socketOf(client);
      assert(replacement).not.toBe(socket);
      replacement.open();
      replacement.receive(encodeChallenge('restart'));
      await vi.waitFor(() =>
        assert(framesWithTag(replacement, Tag.AUTH)).toHaveLength(1),
      );
      replacement.receive(encodeAuthOk([]));
      await vi.waitFor(() =>
        assert(framesWithTag(replacement, Tag.SYNC)).toHaveLength(1),
      );
      assert(framesWithTag(replacement, Tag.SUB).length).toBeGreaterThan(0);
      assert(compute).toHaveBeenCalledWith('https://example.com/drive', {
        sparse: false,
      });
      assert(store.serverConnected).toBe(true);
      client.close();
      assert(warning).not.toHaveBeenCalled();
    },
  );

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

  it('does not send a sync probe after the socket closes during computation', async ({
    expect,
  }) => {
    const { client, socket, store } = await connectedClient();
    vi.spyOn(store, 'computeDriveSyncState').mockImplementation(async () => {
      socket.readyState = 3;

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

  it('does not revive an old sync computation when the same client reconnects', async ({
    expect,
  }) => {
    const { client, socket, store } = await connectedClient();
    vi.useFakeTimers();
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(store, 'getAgent').mockReturnValue(undefined);
    let finish!: (
      value: Awaited<ReturnType<typeof store.computeDriveSyncState>>,
    ) => void;
    vi.spyOn(store, 'computeDriveSyncState').mockImplementation(
      () =>
        new Promise(resolve => {
          finish = resolve;
        }),
    );
    const pending = (
      client as unknown as { startVVSync: (drive: string) => Promise<void> }
    ).startVVSync('did:ad:drive');
    await vi.advanceTimersByTimeAsync(0);
    socket.close();
    socket.fire('close', { code: 1006, reason: '', wasClean: false });
    await vi.advanceTimersByTimeAsync(1000);
    const replacement = socketOf(client);
    replacement.open();
    finish({
      drive: 'did:ad:drive',
      driveHash: 'old',
      peers: [],
      resources: {},
    } as never);
    await pending;
    expect(replacement).not.toBe(socket);
    expect(framesWithTag(replacement, Tag.SYNC)).toHaveLength(0);
    client.close();
  });

  it.each(['identity change', 'disconnect'])(
    'does not answer SYNC_RESEND after %s',
    async reason => {
      const expect = assert;
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
        sendFullSyncState: (drive: string) => void;
        startVVSync: (drive: string) => Promise<void>;
      };
      await internal.startVVSync('did:ad:drive');
      if (reason === 'disconnect') client.close();
      else store.setAgent(undefined);
      internal.sendFullSyncState('did:ad:drive');
      expect(framesWithTag(socket, Tag.SYNC)).toHaveLength(1);
      client.close();
    },
  );

  it('probes with a binary SYNC and sends the full state on SYNC_RESEND', async ({
    expect,
  }) => {
    const { client, socket, store } = await connectedClient();
    vi.spyOn(store, 'computeDriveSyncState').mockResolvedValue({
      drive: 'did:ad:drive',
      driveHash: 'abc123',
      peers: [],
      resources: {},
    } as unknown as Awaited<ReturnType<typeof store.computeDriveSyncState>>);
    const full = vi
      .spyOn(
        client as unknown as {
          sendFullSyncState: (d: string) => void;
        },
        'sendFullSyncState',
      )
      .mockReturnValue(undefined);

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
    expect(full).toHaveBeenCalledWith('did:ad:drive');
    client.close();
  });
});

describe('WSClient legacy scheme sync', () => {
  const original = globalThis.WebSocket;
  afterEach(() => {
    globalThis.WebSocket = original;
    vi.restoreAllMocks();
  });

  it('uses legacy nested subjects in the full sync', async () => {
    const { client, socket, store } = await connectedClient();
    const internal = client as unknown as {
      _pendingSyncState: Map<string, unknown>;
      sendFullSyncState: (drive: string) => void;
    };
    internal._pendingSyncState.set('atomic:drive', {
      state: {
        drive: 'atomic:drive',
        driveHash: 'hash',
        peers: ['1'],
        resources: { 'atomic:doc': [1] },
      },
      current: () => true,
    });
    store.setDrive('atomic:other-drive');
    internal.sendFullSyncState('did:ad:drive');
    const frame = framesWithTag(socket, Tag.SYNC).at(-1)!;
    const dl = (frame[1] << 8) | frame[2];
    const ho = 3 + dl;
    const hl = (frame[ho] << 8) | frame[ho + 1];
    const body = JSON.parse(
      new TextDecoder().decode(frame.subarray(ho + 2 + hl)),
    );
    assert(body).toEqual({ peers: ['1'], resources: { 'did:ad:doc': [1] } });
    client.close();
  });

  it('exports canonical in-memory snapshots when a legacy peer requests them', async () => {
    const { client, socket, store } = await connectedClient();
    const resource = store.getResourceLoading('atomic:doc');
    await resource.set(
      'https://atomicdata.dev/properties/name',
      'offline edit',
    );
    await (
      client as unknown as { handleSyncDiff: (diff: unknown) => Promise<void> }
    ).handleSyncDiff({
      drive: 'did:ad:drive',
      pull: ['did:ad:doc'],
      push: [],
    });
    assert(framesWithTag(socket, Tag.SYNC_PUSH)).toHaveLength(1);
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

  it('subscribes mounted agent profiles, restores them on reconnect, and releases the last reader', async ({
    expect,
  }) => {
    const { client, socket, store } = await connectedClient();
    socket.receive(encodeChallenge('profile-subscription'));
    const auth = client.authenticate();
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.AUTH)).toHaveLength(1),
    );
    socket.receive(encodeAuthOk([]));
    await auth;
    vi.spyOn(store, 'getWebSocketForSubject').mockReturnValue(client);
    store.setServerConnected(true);
    const subject = 'did:ad:agent:other-user';
    const changed = vi.fn();
    const stopFirst = store.subscribe(subject, changed);
    const stopSecond = store.subscribe(subject, vi.fn());
    const subjects = (tag: number) =>
      framesWithTag(socket, tag).map(frame =>
        new TextDecoder().decode(frame.subarray(1)),
      );
    expect(subjects(Tag.SUB)).toEqual([subject]);
    stopFirst();
    expect(subjects(Tag.UNSUB)).toEqual([]);
    // Connection-open/auth replay restores mounted profiles as well as drives.
    (client as unknown as { reSubscribeAll(): void }).reSubscribeAll();
    expect(subjects(Tag.SUB)).toEqual([subject, subject]);
    stopSecond();
    expect(subjects(Tag.UNSUB)).toEqual([subject]);
    (client as unknown as { reSubscribeAll(): void }).reSubscribeAll();
    expect(subjects(Tag.SUB)).toHaveLength(2);
    // Legacy callers release through Store.unsubscribe rather than the disposer.
    store.subscribe(subject, changed);
    store.unsubscribe(subject, changed);
    expect(subjects(Tag.UNSUB)).toEqual([subject, subject]);
    // Ordinary resources continue using drive-wide fan-out.
    const stopDocument = store.subscribe('did:ad:document', vi.fn());
    expect(subjects(Tag.SUB)).toEqual([subject, subject, subject]);
    stopDocument();
    expect(subjects(Tag.UNSUB)).toEqual([subject, subject]);
    client.close();
  });

  it('recovers a missed profile edit after reconnect without replacing the live resource', async () => {
    const { client, socket, store } = await connectedClient();
    socket.receive(encodeChallenge('profile-catchup'));
    const auth = client.authenticate();
    await vi.waitFor(() =>
      assert(framesWithTag(socket, Tag.AUTH)).toHaveLength(1),
    );
    socket.receive(encodeAuthOk([]));
    await auth;
    vi.spyOn(store, 'getWebSocketForSubject').mockReturnValue(client);
    store.setServerConnected(true);
    await LoroLoader.initializeLoro();
    const doc = new LoroLoader.Loro.LoroDoc();
    const name = 'https://atomicdata.dev/properties/name';
    const subject = 'did:ad:agent:missed-profile';
    doc.getMap('properties').set(name, 'Before disconnect');
    doc.commit();
    const initial = client.fetch(subject);
    await vi.waitFor(() =>
      assert(framesWithTag(socket, Tag.GET)).toHaveLength(1),
    );

    const respond = () => {
      const get = framesWithTag(socket, Tag.GET).at(-1)!;
      const requestId = new DataView(get.buffer, get.byteOffset).getUint16(1);
      socket.receive(
        updateFrame(requestId, subject, doc.export({ mode: 'snapshot' })),
      );
    };

    respond();
    const resource = await initial;
    const changed = vi.fn();
    const stop = store.subscribe(subject, changed);
    doc.getMap('properties').set(name, 'Renamed while disconnected');
    doc.commit();
    // SUB does not replay missed changes, and drive reconciliation excludes profiles.
    const replay = () =>
      (client as unknown as { reSubscribeAll(): void }).reSubscribeAll();
    replay();
    replay();
    await vi.waitFor(() =>
      assert(framesWithTag(socket, Tag.GET)).toHaveLength(2),
    );
    respond();
    await vi.waitFor(() =>
      assert(resource.get(name)).toBe('Renamed while disconnected'),
    );
    assert(store.resources.get(store.normalizeSubject(subject))).toBe(resource);
    assert(changed).toHaveBeenCalled();
    stop();
    client.close();
    doc.free();
  });

  it.each(['mount', 'dispose', 'unsubscribe', 'reconnect'])(
    'does not open a foreign socket for an ordinary cached reader on %s',
    async phase => {
      localStorage.setItem('ws-disconnected', '1');
      const { client, store } = await connectedClient();
      const subject = 'https://vocabulary.example/class/bird';
      store.setDriveServer(subject, 'https://vocabulary.example', {
        connect: false,
      });
      store.reportServerConnection('https://vocabulary.example', true);
      const open = vi
        .spyOn(store, 'openWebSocket')
        .mockImplementation(() => {});
      const callback = vi.fn();
      const stop = store.subscribe(subject, callback);
      if (phase !== 'mount') open.mockClear();
      localStorage.removeItem('ws-disconnected');
      if (phase === 'mount') store.subscribeWebSocket(subject);
      if (phase === 'dispose') stop();
      if (phase === 'unsubscribe') store.unsubscribe(subject, callback);

      if (phase === 'reconnect') {
        (client as unknown as { reSubscribeAll(): void }).reSubscribeAll();
      }

      assert(open).not.toHaveBeenCalled();
      localStorage.setItem('ws-disconnected', '1');
      client.close();
    },
  );

  it('keeps HTTP vocabulary reads on HTTP after learning their drive', async () => {
    const { client, store } = await connectedClient();
    const drive = 'https://vocabulary.example/drive';
    const subject = `${drive}/class/bird`;
    const requests: string[] = [];
    store.injectFetch(async input => {
      requests.push(String(input));

      return new Response(
        JSON.stringify({
          '@id': drive,
          'https://atomicdata.dev/properties/isA': [
            'https://atomicdata.dev/classes/Drive',
          ],
          'https://atomicdata.dev/properties/name': 'Vocabulary',
        }),
        { headers: { 'content-type': 'application/ad+json' } },
      );
    });
    const open = vi.spyOn(store, 'openWebSocket').mockImplementation(() => {});
    localStorage.removeItem('ws-disconnected');

    try {
      await store.fetchResourceFromServer(drive);
      store.rememberResourceDrive(subject, drive);
      await store.fetchResourceFromServer(subject);
      assert(requests).toEqual([drive, subject]);
      assert(open).not.toHaveBeenCalled();
    } finally {
      localStorage.setItem('ws-disconnected', '1');
      client.close();
    }
  });

  it('reconciles drives selected after authentication without reopening the socket', async ({
    expect,
  }) => {
    const { client, socket, store } = await connectedClient();
    socket.receive(encodeChallenge('late-drive'));
    const auth = client.authenticate();
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.AUTH)).toHaveLength(1),
    );
    socket.receive(encodeAuthOk([]));
    await auth;
    await new Promise(resolve => setTimeout(resolve, 10));
    vi.mocked(store.getDrive).mockRestore();
    vi.spyOn(store, 'isLiveSyncedDrive').mockImplementation(
      drive => drive !== 'did:ad:local',
    );
    vi.spyOn(store, 'computeDriveSyncState').mockResolvedValue({
      drive: 'did:ad:a',
      driveHash: 'hash',
      resources: {},
      peers: [],
    });

    for (const drive of ['did:ad:a', 'did:ad:b']) {
      const before = framesWithTag(socket, Tag.SYNC).length;
      store.setDrive(drive);
      await vi.waitFor(() =>
        expect(framesWithTag(socket, Tag.SYNC)).toHaveLength(before + 1),
      );
    }

    const before = framesWithTag(socket, Tag.SYNC).length;
    store.setDrive('did:ad:local');
    await new Promise(resolve => setTimeout(resolve, 10));
    expect(framesWithTag(socket, Tag.SYNC)).toHaveLength(before);
    client.close();
  });

  it('reconciles the selected drive after reauthentication on an open socket', async ({
    expect,
  }) => {
    const { client, socket, store } = await connectedClient();
    socket.receive(encodeChallenge('signin-drive'));
    const initial = client.authenticate();
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.AUTH)).toHaveLength(1),
    );
    socket.receive(encodeAuthOk([]));
    await initial;
    await new Promise(resolve => setTimeout(resolve, 10));
    socket.sent.length = 0;
    vi.mocked(store.getDrive).mockReturnValue('did:ad:a');
    vi.spyOn(store, 'isLiveSyncedDrive').mockReturnValue(true);
    vi.spyOn(store, 'computeDriveSyncState').mockResolvedValue({
      drive: 'did:ad:a',
      driveHash: 'hash',
      resources: {},
      peers: [],
    });
    const auth = client.authenticate(true);
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.AUTH)).toHaveLength(1),
    );
    socket.receive(encodeAuthOk([]));
    await auth;
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.SYNC).length).toBeGreaterThan(0),
    );
    client.close();
  });

  it('waits for a new drive genesis acknowledgement before subscribing', async ({
    expect,
  }) => {
    const { client, socket, store } = await connectedClient();
    socket.receive(encodeChallenge('new-drive'));
    const auth = client.authenticate();
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.AUTH)).toHaveLength(1),
    );
    socket.receive(encodeAuthOk([]));
    await auth;
    await new Promise(resolve => setTimeout(resolve, 10));
    socket.sent.length = 0;
    const drive = new Resource('did:ad:new-drive');
    store.resources.set(drive.subject, drive);
    store.outbox.setGenesisCommit(drive.subject, signedCommit());
    // Locally stamped metadata does not prove the server has the genesis.
    drive.setLastCommitValue('did:ad:commit:local');
    vi.mocked(store.getDrive).mockReturnValue(drive.subject);
    vi.spyOn(store, 'computeDriveSyncState').mockResolvedValue({
      drive: drive.subject,
      driveHash: 'hash',
      resources: {},
      peers: [],
    });
    store.setDrive(drive.subject);
    await Promise.resolve();
    expect(framesWithTag(socket, Tag.SUB)).toHaveLength(0);
    expect(framesWithTag(socket, Tag.SYNC)).toHaveLength(0);
    store.outbox.clearGenesis(drive.subject);
    drive.setLastCommitValue('did:ad:commit:ack');
    await store.notifyResourceSaved(drive);
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.SYNC)).toHaveLength(1),
    );
    expect(framesWithTag(socket, Tag.SUB)).toHaveLength(1);
    client.close();
  });

  describe('a held subscription on a resource the reader cannot read yet', () => {
    const PRIVATE = 'did:ad:private-home';

    async function liveClient() {
      const { client, socket, store } = await connectedClient();
      vi.spyOn(store, 'getAgent').mockReturnValue(undefined);
      vi.spyOn(store, 'getWebSocketForSubject').mockReturnValue(client);
      const resource = new Resource(PRIVATE);
      store.resources.set(store.normalizeSubject(PRIVATE), resource);

      return { client, socket, store, resource };
    }

    it.each([ErrorType.NotFound, ErrorType.Unauthorized])(
      'sends no SUB while the resource is known to be %s',
      async errorType => {
        const { client, socket, store, resource } = await liveClient();
        resource.setError(new AtomicError('Not readable', errorType));
        store.subscribeLive(PRIVATE);
        assert(framesWithTag(socket, Tag.SUB)).toHaveLength(0);
        client.close();
      },
    );

    it('sends no SUB for an unsaved resource or one awaiting its genesis', async () => {
      const { client, socket, store, resource } = await liveClient();
      resource.new = true;
      store.outbox.setGenesisCommit(PRIVATE, signedCommit());
      store.subscribeLive(PRIVATE);
      assert(framesWithTag(socket, Tag.SUB)).toHaveLength(0);
      client.close();
    });

    it('sends no SUB for a resource that is not in the store yet, and sends it once it loads', async () => {
      const { client, socket, store } = await liveClient();
      store.resources.delete(store.normalizeSubject(PRIVATE));
      store.subscribeLive(PRIVATE);
      assert(framesWithTag(socket, Tag.SUB)).toHaveLength(0);
      const loaded = new Resource(PRIVATE);
      loaded.new = false;
      store.resources.set(store.normalizeSubject(PRIVATE), loaded);
      store.notifyResourceUpdated(loaded);
      assert(framesWithTag(socket, Tag.SUB)).toHaveLength(1);
      // Further updates do not repeat it.
      store.notifyResourceUpdated(loaded);
      assert(framesWithTag(socket, Tag.SUB)).toHaveLength(1);
      client.close();
    });

    it('sends the SUB once an errored resource loads without error', async () => {
      const { client, socket, store, resource } = await liveClient();
      resource.setError(new AtomicError('Not found', ErrorType.NotFound));
      store.subscribeLive(PRIVATE);
      assert(framesWithTag(socket, Tag.SUB)).toHaveLength(0);
      resource.setError(undefined as never);
      resource.new = false;
      store.notifyResourceUpdated(resource);
      assert(framesWithTag(socket, Tag.SUB)).toHaveLength(1);
      client.close();
    });
  });

  describe('a subject owned by both a live subscription and the drive SUB', () => {
    const PRIVATE = 'did:ad:private-home';
    const TEAM = 'did:ad:team-drive';

    async function setup() {
      const { client, socket, store } = await connectedClient();
      vi.spyOn(store, 'getAgent').mockReturnValue(undefined);
      vi.spyOn(store, 'getWebSocketForSubject').mockReturnValue(client);
      vi.spyOn(store, 'isLiveSyncedDrive').mockReturnValue(true);

      for (const subject of [PRIVATE, TEAM]) {
        const resource = new Resource(subject);
        resource.new = false;
        store.resources.set(store.normalizeSubject(subject), resource);
      }

      const subjects = (tag: number) =>
        framesWithTag(socket, tag).map(frame =>
          new TextDecoder().decode(frame.subarray(1)),
        );
      const internal = client as unknown as {
        subscribeToDrive(): void;
        reSubscribeAll(): void;
      };

      return { client, socket, store, subjects, internal };
    }

    it('sends the held SUB after ResourceSaved once the genesis is cleared', async () => {
      const { client, socket, store } = await setup();
      const resource = store.resources.get(store.normalizeSubject(PRIVATE))!;
      resource.new = true;
      store.outbox.setGenesisCommit(PRIVATE, signedCommit());
      store.subscribeLive(PRIVATE);
      assert(framesWithTag(socket, Tag.SUB)).toHaveLength(0);
      store.outbox.clearGenesis(PRIVATE);
      resource.new = false;
      // No ResourceUpdated fires, only ResourceSaved.
      await store.notifyResourceSaved(resource);
      assert(framesWithTag(socket, Tag.SUB)).toHaveLength(1);
      client.close();
    });

    it('does not UNSUB the private drive when the hook releases after the drive switch', async ({
      expect,
    }) => {
      const { client, store, subjects, internal } = await setup();
      vi.mocked(store.getDrive).mockReturnValue(TEAM);
      internal.subscribeToDrive();
      const release = store.subscribeLive(PRIVATE);
      expect(subjects(Tag.SUB)).toEqual([TEAM, PRIVATE]);
      // DriveChanged handler runs first, then the hook cleanup.
      vi.mocked(store.getDrive).mockReturnValue(PRIVATE);
      internal.subscribeToDrive();
      // Team drive is released; the private one is held by the live SUB.
      expect(subjects(Tag.UNSUB)).toEqual([TEAM]);
      release();
      expect(subjects(Tag.UNSUB)).toEqual([TEAM]);
      client.close();
    });

    it('UNSUBs the old drive on a switch only when no live subscription holds it', async ({
      expect,
    }) => {
      const { client, store, subjects, internal } = await setup();
      vi.mocked(store.getDrive).mockReturnValue(PRIVATE);
      internal.subscribeToDrive();
      const release = store.subscribeLive(PRIVATE);
      vi.mocked(store.getDrive).mockReturnValue(TEAM);
      internal.subscribeToDrive();
      expect(subjects(Tag.UNSUB)).toEqual([]);
      // The live SUB still works for reconnects and is not sent twice.
      const before = subjects(Tag.SUB).length;
      release();
      expect(subjects(Tag.UNSUB)).toEqual([PRIVATE]);
      expect(subjects(Tag.SUB)).toHaveLength(before);
      // Without a live holder the switch away UNSUBs.
      vi.mocked(store.getDrive).mockReturnValue(PRIVATE);
      internal.subscribeToDrive();
      vi.mocked(store.getDrive).mockReturnValue(TEAM);
      internal.subscribeToDrive();
      expect(subjects(Tag.UNSUB)).toEqual([PRIVATE, TEAM, PRIVATE]);
      client.close();
    });

    it('resends a held SUB once and a sent one once after a reconnect', async ({
      expect,
    }) => {
      const { client, store, subjects, internal } = await setup();
      store.subscribeLive(PRIVATE);
      const held = store.resources.get(store.normalizeSubject(TEAM))!;
      held.new = true;
      store.subscribeLive(TEAM);
      expect(subjects(Tag.SUB)).toEqual([PRIVATE]);
      internal.reSubscribeAll();
      expect(subjects(Tag.SUB)).toEqual([PRIVATE, PRIVATE]);
      held.new = false;
      store.notifyResourceUpdated(held);
      expect(subjects(Tag.SUB)).toEqual([PRIVATE, PRIVATE, TEAM]);
      store.notifyResourceUpdated(held);
      expect(subjects(Tag.SUB)).toHaveLength(3);
      internal.reSubscribeAll();
      expect(subjects(Tag.SUB).sort()).toEqual(
        [PRIVATE, PRIVATE, TEAM, PRIVATE, TEAM].sort(),
      );
      client.close();
    });
  });

  it.each([ErrorType.NotFound, ErrorType.Unauthorized])(
    'does not automatically sync an unreadable drive under its legacy alias (%s)',
    async errorType => {
      const { client, socket, store } = await connectedClient();
      const resource = new Resource('atomic:private-drive');
      resource.setError(new AtomicError('Not readable', errorType));
      store.resources.set('atomic:private-drive', resource);
      vi.spyOn(store, 'getAgent').mockReturnValue(undefined);
      vi.spyOn(store, 'getDrive').mockReturnValue('did:ad:private-drive');
      vi.spyOn(store, 'isLiveSyncedDrive').mockReturnValue(true);
      const compute = vi.spyOn(store, 'computeDriveSyncState');
      const internal = client as unknown as {
        subscribeToDrive(): void;
        startVVSync(drive: string): Promise<void>;
      };
      internal.subscribeToDrive();
      await internal.startVVSync('did:ad:private-drive');
      assert(framesWithTag(socket, Tag.SUB)).toHaveLength(0);
      assert(framesWithTag(socket, Tag.SYNC)).toHaveLength(0);
      assert(compute).not.toHaveBeenCalled();
      client.close();
    },
  );

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
          get: () => undefined,
          hasClasses: () => false,
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

    expect(exported).toEqual(['atomic:clean']);
    expect(framesWithTag(socket, Tag.SYNC_PUSH)).toHaveLength(1);
    client.close();
  });
});

describe('WSClient.fetchMany', () => {
  const original = globalThis.WebSocket;

  afterEach(() => {
    globalThis.WebSocket = original;
    vi.restoreAllMocks();
  });

  /** `[0x16] [request_id] [count] ([frame_len: u32] [frame])*` */
  const resultFrame = (requestId: number, frames: Uint8Array[]) => {
    const buf = new Uint8Array(
      5 + frames.reduce((sum, f) => sum + 4 + f.length, 0),
    );
    const view = new DataView(buf.buffer);
    buf[0] = Tag.GET_MANY_RESULT;
    view.setUint16(1, requestId);
    view.setUint16(3, frames.length);
    let off = 5;

    for (const frame of frames) {
      view.setUint32(off, frame.length);
      buf.set(frame, off + 4);
      off += 4 + frame.length;
    }

    return buf;
  };

  const requestIdOf = (frame: Uint8Array) =>
    new DataView(frame.buffer, frame.byteOffset).getUint16(1);

  it.each(['single', 'batch'])(
    "rejects a %s GET answer claiming another server's drive",
    async kind => {
      const { client, socket, store } = await connectedClient();
      vi.spyOn(client, 'authenticate').mockResolvedValue(undefined);
      socket.receive(encodeAuthOk(['get-many']));
      store.setDriveServer('atomic:protected', 'https://other.example.com', {
        connect: false,
      });
      await LoroLoader.initializeLoro();
      const doc = new LoroLoader.Loro.LoroDoc();
      doc
        .getMap('properties')
        .set('https://atomicdata.dev/properties/drive', 'atomic:protected');
      doc.commit();
      const subject = 'atomic:cold-forged-child';
      const result =
        kind === 'batch'
          ? client.fetchMany([subject])
          : client.fetch(subject).then(
              r => [r],
              error => [error],
            );
      const tag = kind === 'batch' ? Tag.GET_MANY : Tag.GET;
      await vi.waitFor(() =>
        assert(framesWithTag(socket, tag)).toHaveLength(1),
      );
      const id = requestIdOf(framesWithTag(socket, tag)[0]);
      const update = updateFrame(
        kind === 'batch' ? 0 : id,
        subject,
        doc.export({ mode: 'snapshot' }),
      );
      socket.receive(kind === 'batch' ? resultFrame(id, [update]) : update);

      assert((await result)[0]).toBeInstanceOf(Error);
      assert(store.resources.has(subject)).toBe(false);
      assert(store.getServerUrlForSubject('atomic:protected')).toBe(
        'https://other.example.com',
      );
      client.close();
      doc.free();
    },
  );

  it('sends one GET_MANY and settles every entry in order', async ({
    expect,
  }) => {
    const { client, socket, store } = await connectedClient();
    vi.spyOn(client, 'authenticate').mockResolvedValue(undefined);
    socket.receive(encodeAuthOk(['get-many']));
    expect(client.supportsGetMany).toBe(true);

    await LoroLoader.initializeLoro();
    const { LoroDoc } = LoroLoader.Loro;
    const doc = new LoroDoc();
    doc
      .getMap('properties')
      .set('https://atomicdata.dev/properties/name', 'Batched');
    doc.commit();

    const results = client.fetchMany([
      'did:ad:found',
      'did:ad:missing',
      'did:ad:private',
    ]);
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.GET_MANY)).toHaveLength(1),
    );
    expect(framesWithTag(socket, Tag.GET)).toHaveLength(0);
    const requestId = requestIdOf(framesWithTag(socket, Tag.GET_MANY)[0]);
    socket.receive(
      resultFrame(requestId, [
        updateFrame(
          requestId,
          'did:ad:found',
          doc.export({ mode: 'snapshot' }),
        ),
        encodeError(
          requestId,
          ErrorCode.UNKNOWN,
          'Resource not found. did:ad:missing',
        ),
        encodeError(
          requestId,
          ErrorCode.UNKNOWN,
          'Unauthorized. did:ad:private',
        ),
      ]),
    );

    const [found, missing, unauthorized] = await results;
    expect(found).toBeInstanceOf(Resource);
    // Asked and answered in the legacy spelling; the store keys canonically.
    expect((found as Resource).subject).toBe('atomic:found');
    expect(
      (found as Resource).get('https://atomicdata.dev/properties/name'),
    ).toBe('Batched');
    expect(store.resources.get('atomic:found')).toBe(found);
    expect(missing).toMatchObject({ type: ErrorType.NotFound });
    expect(unauthorized).toMatchObject({ type: ErrorType.Unauthorized });
    client.close();
  });

  it('does not present cached data as a successful invalid batch response', async () => {
    const { client, socket, store } = await connectedClient();
    vi.spyOn(client, 'authenticate').mockResolvedValue(undefined);
    socket.receive(encodeAuthOk(['get-many']));
    const subject = 'https://example.com/query?drive=atomic:home';
    const cached = new Resource(subject);
    store.addResource(cached);
    const results = client.fetchMany([subject]);
    await vi.waitFor(() =>
      assert(framesWithTag(socket, Tag.GET_MANY)).toHaveLength(1),
    );
    const requestId = requestIdOf(framesWithTag(socket, Tag.GET_MANY)[0]);
    socket.receive(
      resultFrame(requestId, [
        updateFrame(requestId, subject, new Uint8Array([0])),
      ]),
    );
    const [result] = await results;
    assert(result).toMatchObject({
      type: ErrorType.Server,
      message: `Invalid resource update for ${subject}`,
    });
    assert(store.resources.get(subject)).toBe(cached);
    client.close();
  });

  it('falls back to single GETs when the server lacks the capability', async ({
    expect,
  }) => {
    const { client, socket } = await connectedClient();
    vi.spyOn(client, 'authenticate').mockResolvedValue(undefined);
    socket.receive(encodeAuthOk([]));
    expect(client.supportsGetMany).toBe(false);

    const results = client.fetchMany(['did:ad:a', 'did:ad:b']);
    await vi.waitFor(() =>
      expect(framesWithTag(socket, Tag.GET)).toHaveLength(2),
    );
    expect(framesWithTag(socket, Tag.GET_MANY)).toHaveLength(0);

    for (const frame of framesWithTag(socket, Tag.GET)) {
      socket.receive(
        encodeError(
          requestIdOf(frame),
          ErrorCode.UNKNOWN,
          'Resource not found. did:ad:x',
        ),
      );
    }

    const settled = await results;
    expect(settled).toHaveLength(2);
    expect(settled[0]).toMatchObject({ type: ErrorType.NotFound });
    client.close();
  });
});
