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

/** A bounded full mesh: each remote browser has its own authenticated session.
 * Received frames are never rebroadcast; reconciliation catches up persisted state. */
export class BrowserPeerSync {
  private socket?: WebSocket;
  private readonly connections = new Map<string, BrowserPeerConnection>();
  private readonly members = new Set<string>();
  private readonly retries = new Map<string, ReturnType<typeof setTimeout>>();
  private reconnect?: ReturnType<typeof setTimeout>;
  private stopped = false;
  private iceServers: RTCIceServer[] = [];
  private readonly peerId = randomPeerToken();
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
    for (const connection of this.connections.values()) connection.close();
    this.connections.clear();
    this.socket?.close();
    this.options.onStatus?.('Disconnected');
  }

  private status(): void {
    const ready = [...this.connections.values()].filter(
      connection => connection.ready,
    );
    const relayed = ready.filter(
      connection => connection.path === 'relayed',
    ).length;
    this.options.onStatus?.(
      ready.length
        ? `Connected to ${ready.length} ${ready.length === 1 ? 'browser' : 'browsers'}${relayed ? ` (${relayed} relayed)` : ''}`
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
    socket.addEventListener('open', () =>
      this.send({ type: 'join', room: this.options.room, peer: this.peerId }),
    );
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
      () => this.status(),
      error => this.failed(id, connection, error),
    );
    this.connections.set(id, connection);

    return connection;
  }

  private remove(id: string, connection: BrowserPeerConnection): void {
    if (this.connections.get(id) !== connection) return;
    this.connections.delete(id);
    connection.close();
    this.status();
  }

  private failed(
    id: string,
    connection: BrowserPeerConnection,
    error: unknown,
  ): void {
    if (this.stopped || this.connections.get(id) !== connection) return;
    this.remove(id, connection);
    this.options.onStatus?.(
      error instanceof Error ? error.message : String(error),
    );

    if (this.members.has(id) && id > this.peerId && !this.retries.has(id)) {
      this.retries.set(
        id,
        setTimeout(() => {
          this.retries.delete(id);
          this.dial(id);
        }, 3000),
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
