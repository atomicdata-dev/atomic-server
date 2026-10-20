import { authorizeBrowserInvite } from './browser-peer-invite.js';
import type { Agent } from './agent.js';
import type { ClientDbWorker } from './client-db.js';
import type { Store } from './store.js';
import { createAuthentication } from './authentication.js';
import { WebRtcPeer } from './webrtc-peer.js';
import { Tag, decodeCommit, encodeAuth, encodeSync } from './ws-v2.js';
import type { WebRtcTransport } from './webrtc-transport.js';

export interface BrowserPeerOptions {
  drive: string;
  room: string;
  signalingUrl: string;
  /** Trusted agent for bootstrapping an unknown drive; stored drive ACLs govern subsequent peers. */
  expectedPeer?: string;
  /** Signed bearer invite; sent only after authenticating expectedPeer. */
  invitation?: string;
  iceServers?: RTCIceServer[];
  onStatus?: (status: string) => void;
}

export function randomPeerToken(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)), byte =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
}

const BROWSER_SECRET_KEY = 'atomic-peer-browser';

/** Hex chars of a peer id shared by every tab of one browser in one room. */
const BROWSER_PREFIX_LENGTH = 16;

/**
 * A peer id whose first {@link BROWSER_PREFIX_LENGTH} hex chars are the same
 * for every tab of this browser, for this agent and room, and unlinkable
 * across rooms. Tabs of one browser share one local database, so pairing them
 * only spends peer sessions (a capped budget that all tabs share).
 */
export async function browserPeerId(
  agent: string,
  room: string,
): Promise<string> {
  let secret: string | null = null;

  try {
    secret = localStorage.getItem(BROWSER_SECRET_KEY);

    if (!secret) {
      secret = randomPeerToken();
      localStorage.setItem(BROWSER_SECRET_KEY, secret);
    }
  } catch {
    // No storage: this tab gets its own prefix and pairs like any browser.
  }

  if (!secret) return randomPeerToken();
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(`${secret}:${agent}:${room}`),
  );
  const prefix = Array.from(new Uint8Array(digest), byte =>
    byte.toString(16).padStart(2, '0'),
  )
    .join('')
    .slice(0, BROWSER_PREFIX_LENGTH);

  return prefix + randomPeerToken().slice(BROWSER_PREFIX_LENGTH);
}

/** How long a connection must stay ready before its retry backoff resets. */
const STABLE_CONNECTION_MS = 30_000;

/** A bounded full mesh: each remote browser has its own authenticated session.
 * Received frames are never rebroadcast; reconciliation catches up persisted state. */
export class BrowserPeerSync {
  private socket?: WebSocket;
  private readonly connections = new Map<string, BrowserPeerConnection>();
  private readonly members = new Set<string>();
  private readonly retries = new Map<string, ReturnType<typeof setTimeout>>();
  private readonly retryDelays = new Map<string, number>();
  private readonly readyAt = new Map<string, number>();
  private reconnect?: ReturnType<typeof setTimeout>;
  private stopped = false;
  private lastError = '';
  private iceServers: RTCIceServer[] = [];
  private peerId = randomPeerToken();
  private identity?: Promise<string>;
  private readonly agent: Agent;
  private readonly db: ClientDbWorker;

  constructor(
    private readonly store: Store,
    private readonly options: BrowserPeerOptions,
  ) {
    const agent = store.getAgent();
    const db = store.getClientDb();
    if (!agent?.subject || !db)
      throw new Error('Sign in and enable local storage before peer sync');
    this.agent = agent;
    this.db = db;
    if (!/^[a-f0-9]{64}$/.test(options.room))
      throw new Error('Invalid peer invitation');
    const url = new URL(options.signalingUrl);
    if (
      url.protocol !== 'wss:' &&
      !(
        url.protocol === 'ws:' &&
        ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
      )
    )
      throw new Error('Peer discovery requires a secure WebSocket URL');
    this.connect();
  }

  close(): void {
    this.stopped = true;
    clearTimeout(this.reconnect);
    for (const timer of this.retries.values()) clearTimeout(timer);
    this.retries.clear();
    this.retryDelays.clear();
    this.readyAt.clear();
    for (const connection of this.connections.values()) connection.close();
    this.connections.clear();
    // Closing during the handshake emits a browser network warning. The open
    // handler closes a stopped socket before it can join the discovery room.
    if (this.socket?.readyState !== WebSocket.CONNECTING) this.socket?.close();
    this.options.onStatus?.('Disconnected');
  }

  private status(): void {
    // Several tabs of one remote browser share an id prefix and each has its
    // own connection; count the browsers, not the connections.
    const browsers = new Map<string, boolean>();

    for (const [id, connection] of this.connections) {
      if (!connection.ready) continue;
      const prefix = id.slice(0, BROWSER_PREFIX_LENGTH);
      browsers.set(
        prefix,
        (browsers.get(prefix) ?? true) && connection.path === 'relayed',
      );
    }

    const relayed = [...browsers.values()].filter(Boolean).length;
    this.options.onStatus?.(
      browsers.size
        ? `Connected to ${browsers.size} ${browsers.size === 1 ? 'browser' : 'browsers'}${relayed ? ` (${relayed} relayed)` : ''}`
        : this.lastError
          ? `Waiting for a peer (last attempt failed: ${this.lastError.slice(0, 120)})`
          : 'Waiting for a peer',
    );
  }

  private send(message: object): void {
    if (this.socket?.readyState !== WebSocket.OPEN)
      throw new Error('Discovery unavailable');
    this.socket.send(JSON.stringify(message));
  }

  private connect(): void {
    if (
      this.stopped ||
      this.store.getAgent() !== this.agent ||
      this.store.getClientDb() !== this.db
    ) {
      this.close();

      return;
    }

    this.status();
    const socket = new WebSocket(this.options.signalingUrl);
    this.socket = socket;
    socket.addEventListener('open', () => {
      if (this.stopped || this.socket !== socket) {
        socket.close();

        return;
      }

      this.identity ??= browserPeerId(this.agent.subject!, this.options.room);
      void this.identity
        .then(id => {
          if (this.stopped || this.socket !== socket) return;
          this.peerId = id;
          this.send({ type: 'join', room: this.options.room, peer: id });
        })
        .catch(error => this.options.onStatus?.(String(error)));
    });
    socket.addEventListener('message', event => {
      if (this.socket !== socket || this.stopped) return;

      try {
        if (typeof event.data !== 'string' || event.data.length > 64 * 1024)
          throw new Error('Invalid signaling response');
        const message = JSON.parse(event.data);

        if (message.type === 'joined') {
          if (!Array.isArray(message.peers) || message.peers.length > 7)
            throw new Error('Invalid peer list');
          this.iceServers = this.options.iceServers ?? message.iceServers ?? [];
          this.members.clear();
          for (const id of message.peers) this.addMember(id);
        } else if (message.type === 'peer') {
          this.addMember(message.peer);
        } else if (message.type === 'left') {
          this.members.delete(message.peer);
          clearTimeout(this.retries.get(message.peer));
          this.retries.delete(message.peer);
          this.retryDelays.delete(message.peer);
          // A live data channel can outlast its signaling socket.
          const connection = this.connections.get(message.peer);
          if (connection && !connection.ready)
            this.remove(message.peer, connection);
        } else if (
          message.type === 'offer' &&
          this.members.has(message.from) &&
          message.from < this.peerId
        ) {
          const existing = this.connections.get(message.from);
          if (existing) this.remove(message.from, existing);
          const connection = this.createConnection(message.from);
          void connection.peer
            .acceptOffer({ type: 'offer', sdp: message.sdp })
            .then(answer => {
              if (this.connections.get(message.from) === connection)
                this.send({
                  type: 'answer',
                  to: message.from,
                  sdp: answer.sdp,
                });
            })
            .catch(error => this.failed(message.from, connection, error));
        } else if (message.type === 'answer') {
          const connection = this.connections.get(message.from);
          if (connection && message.from > this.peerId)
            void connection.peer
              .acceptAnswer({ type: 'answer', sdp: message.sdp })
              .catch(error => this.failed(message.from, connection, error));
        }
      } catch (error) {
        this.options.onStatus?.(String(error));
        socket.close();
      }
    });
    socket.addEventListener('close', () => {
      if (!this.stopped && this.socket === socket)
        this.reconnect = setTimeout(() => this.connect(), 3000);
    });
    socket.addEventListener('error', () =>
      this.options.onStatus?.('Discovery unavailable; retrying'),
    );
  }

  private addMember(id: string): void {
    if (
      typeof id !== 'string' ||
      !/^[a-f0-9]{64}$/.test(id) ||
      id === this.peerId
    )
      throw new Error('Invalid peer identity');
    // Another tab of this browser: same database, nothing to sync.
    if (
      id.slice(0, BROWSER_PREFIX_LENGTH) ===
      this.peerId.slice(0, BROWSER_PREFIX_LENGTH)
    )
      return;
    if (!this.members.has(id) && this.members.size >= 7)
      throw new Error('Peer room is full');
    this.members.add(id);
    this.dial(id);
  }

  private dial(id: string): void {
    // A deterministic initiator avoids simultaneous offers and retry glare.
    if (
      this.stopped ||
      id < this.peerId ||
      this.connections.has(id) ||
      this.retries.has(id) ||
      !this.members.has(id) ||
      this.socket?.readyState !== WebSocket.OPEN
    )
      return;
    const connection = this.createConnection(id);
    void connection.peer
      .createOffer()
      .then(offer => {
        if (this.connections.get(id) === connection)
          this.send({ type: 'offer', to: id, sdp: offer.sdp });
      })
      .catch(error => this.failed(id, connection, error));
  }

  private createConnection(id: string): BrowserPeerConnection {
    if (this.connections.size >= 7) {
      const stale = [...this.connections].find(
        ([peerId]) => !this.members.has(peerId),
      );
      if (stale) this.remove(...stale);
      else throw new Error('Peer connection limit reached');
    }

    const connection = new BrowserPeerConnection(
      this.store,
      this.agent,
      this.db,
      { ...this.options, onStatus: undefined, iceServers: this.iceServers },
      () => {
        this.readyAt.set(id, Date.now());
        this.lastError = '';
        this.status();
      },
      error => this.failed(id, connection, error),
    );
    this.connections.set(id, connection);

    return connection;
  }

  private remove(id: string, connection: BrowserPeerConnection): void {
    if (this.connections.get(id) !== connection) return;
    this.connections.delete(id);
    // Only a connection that stayed up resets the backoff; one that
    // authenticates and dies within seconds keeps backing off.
    const since = this.readyAt.get(id);
    this.readyAt.delete(id);
    if (since !== undefined && Date.now() - since >= STABLE_CONNECTION_MS)
      this.retryDelays.delete(id);
    connection.close();
    this.status();
  }

  private failed(
    id: string,
    connection: BrowserPeerConnection,
    error: unknown,
  ): void {
    if (this.stopped || this.connections.get(id) !== connection) return;
    const message = error instanceof Error ? error.message : String(error);
    // Kept so the next status() does not wipe it with a bare "Waiting".
    this.lastError = message;
    this.remove(id, connection);
    this.options.onStatus?.(message);

    if (this.members.has(id) && id > this.peerId && !this.retries.has(id)) {
      const delay = this.retryDelays.get(id) ?? 3000;
      this.retryDelays.set(id, Math.min(delay * 2, 60_000));
      this.retries.set(
        id,
        setTimeout(() => {
          this.retries.delete(id);
          this.dial(id);
        }, delay),
      );
    }
  }
}

class BrowserPeerConnection {
  readonly peer: WebRtcPeer;
  ready = false;
  path = 'unknown';
  private session?: number;
  private reconcileTimer?: ReturnType<typeof setInterval>;
  private unsubscribe?: () => void;
  private stopped = false;

  constructor(
    private readonly store: Store,
    private readonly agent: Agent,
    private readonly db: ClientDbWorker,
    private readonly options: BrowserPeerOptions,
    private readonly changed: () => void,
    private readonly failure: (error: unknown) => void,
  ) {
    this.peer = new WebRtcPeer({ iceServers: options.iceServers });
    void this.peer.transport
      .then(pipe => this.run(this.peer, pipe))
      .catch(error => this.fail(error));
  }

  private onReady(path: string): void {
    this.ready = true;
    this.path = path;
    this.changed();
  }

  close(): void {
    this.stopped = true;
    this.ready = false;
    clearInterval(this.reconcileTimer);
    this.unsubscribe?.();
    this.peer.close();
    if (this.session !== undefined)
      void this.db.closePeerSession(this.session).catch(() => {});
  }

  private async run(peer: WebRtcPeer, pipe: WebRtcTransport): Promise<void> {
    const current = () =>
      !this.stopped &&
      this.store.getAgent() === this.agent &&
      this.store.getClientDb() === this.db;
    const binding = await peer.channelBinding();
    const challenge = `${binding}:${randomPeerToken()}`;
    const hasSnapshot = !!(
      await this.db.getResourceWithSnapshot(this.options.drive)
    ).snapshot;
    const invitation = hasSnapshot ? undefined : this.options.invitation;
    const session = await this.db!.createPeerSession(
      this.options.drive,
      hasSnapshot && !invitation ? undefined : this.options.expectedPeer,
      challenge,
    );

    if (!current()) {
      await this.db!.closePeerSession(session);

      return;
    }

    this.session = session;
    await pipe.send(
      new Uint8Array([Tag.CHALLENGE, ...new TextEncoder().encode(challenge)]),
    );
    let challenged = false;
    let authenticated = false;
    let accepted = false;
    let started = false;
    let pendingAuth: Record<string, unknown> | undefined;
    const timeout = setTimeout(() => {
      if (!started) this.fail(new Error('Peer authentication timed out'));
    }, 15000);

    try {
      while (current()) {
        const frame = await pipe.recv();
        if (!frame) break;
        if (!current()) break;

        if (frame[0] === Tag.CHALLENGE) {
          if (challenged || frame.length > 256)
            throw new Error('Invalid peer challenge');
          const remoteChallenge = new TextDecoder().decode(frame.subarray(1));
          if (!new RegExp(`^${binding}:[a-f0-9]{64}$`).test(remoteChallenge))
            throw new Error('WebRTC channel binding mismatch');
          challenged = true;
          const auth = await createAuthentication(
            `${this.options.drive}#${remoteChallenge}`,
            this.agent!,
            // Not the did:ad: spelling servers get: this session compares the
            // agent to the invite's issuer and to ephemeral frames by string.
            { agentSubject: this.agent!.subject },
          );

          if (invitation) {
            if (!this.options.expectedPeer)
              throw new Error('Invite issuer is required');
            pendingAuth = { ...auth, browserInvite: invitation };
          } else {
            await pipe.send(encodeAuth(JSON.stringify(auth)));
          }
        } else if (frame[0] === Tag.AUTH_OK) {
          if (!challenged || accepted)
            throw new Error('Unexpected authentication acknowledgement');
          accepted = true;
        } else {
          if (frame[0] === Tag.AUTH && !authenticated) {
            if (frame.length > 8192)
              throw new Error('Peer authentication is too large');
            const auth = JSON.parse(
              new TextDecoder().decode(frame.subarray(1)),
            );

            if (auth.browserInvite !== undefined) {
              if (typeof auth.browserInvite !== 'string')
                throw new Error('Invalid browser invite');
              await authorizeBrowserInvite(
                this.store,
                this.options.drive,
                auth.browserInvite,
                auth,
                `${this.options.drive}#${challenge}`,
              );
            }
          }

          const output = await this.db!.handlePeerFrame(session, frame);

          if (frame[0] === Tag.AUTH) {
            authenticated = true;

            // Rust verified the issuer against the link's pinned identity. Only
            // now may this connection receive the bearer invitation.
            if (pendingAuth) {
              await pipe.send(encodeAuth(JSON.stringify(pendingAuth)));
              pendingAuth = undefined;
            }
          }

          for (const bytes of output.frames)
            await pipe.send(Uint8Array.from(bytes));

          for (const subject of output.changed) {
            const stored = await this.db!.getResourceWithSnapshot(subject);
            if (stored.snapshot)
              this.store.applyIncoming({
                subject,
                loroBytes: stored.snapshot,
                source: 'peer-sync',
                forceNotify: true,
              });
            else this.store.removeResource(subject);
          }

          if (output.ephemeral)
            this.store.receivePeerEphemeral(Uint8Array.from(output.ephemeral));
        }

        if (authenticated && accepted && !started) {
          started = true;
          clearTimeout(timeout);
          const path = await peer.connectionPath();
          this.onReady(path);
          let syncing = false;

          const reconcile = async () => {
            if (!current() || syncing) return;
            syncing = true;

            try {
              const state = await this.store.computeDriveSyncState(
                this.options.drive,
              );
              if (
                Object.keys(state.resources).length &&
                !(await this.db.canSendPeerFrame(session, this.options.drive))
              )
                throw new Error('Peer access removed');
              if (current())
                await pipe.send(
                  encodeSync(
                    this.options.drive,
                    state.driveHash,
                    JSON.stringify({
                      peers: state.peers,
                      resources: state.resources,
                    }),
                  ),
                );
            } finally {
              syncing = false;
            }
          };

          this.unsubscribe = this.store.subscribePeerFrames(
            (subject, bytes) => {
              if (!current()) return;
              const resource = this.store.resources.get(subject);
              const drive = resource?.get(
                'https://atomicdata.dev/properties/drive',
              );
              if (
                subject === this.options.drive ||
                drive === this.options.drive
              )
                void this.db
                  .canSendPeerFrame(session, subject)
                  .then(allowed => {
                    if (!allowed) {
                      // A signed deletion has removed its subject; authorization
                      // for that last frame is the drive's remaining read grant.
                      if (bytes[0] === Tag.COMMIT) {
                        const commit = decodeCommit(bytes.subarray(1));
                        if (
                          commit &&
                          JSON.parse(commit.commitJson)[
                            'https://atomicdata.dev/properties/destroy'
                          ] === true
                        )
                          return this.db.canSendPeerFrame(
                            session,
                            this.options.drive,
                          );
                      }

                      return false;
                    }

                    return true;
                  })
                  .then(allowed => {
                    if (!allowed) throw new Error('Peer access removed');
                    if (current()) return pipe.send(bytes);
                  })
                  .catch(error => this.fail(error));
            },
          );
          this.reconcileTimer = setInterval(() => {
            void reconcile().catch(error => this.fail(error));
          }, 2000);
          // Both loops need to keep receiving while the initial reconcile runs.
          void reconcile().catch(error => this.fail(error));
        }
      }
    } finally {
      clearTimeout(timeout);
    }

    if (current()) this.fail(new Error('Peer disconnected; reconnecting'));
  }

  private fail(error: unknown): void {
    if (!this.stopped) this.failure(error);
  }
}
