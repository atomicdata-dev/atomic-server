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
  expectedPeer?: string;
  iceServers?: RTCIceServer[];
  onStatus?: (status: string) => void;
}

export function randomPeerToken(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)), byte =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
}

/** One explicitly enabled drive link. Signaling only exchanges SDP. The WASM
 * node authenticates and authorizes all data before it reaches the JS store. */
export class BrowserPeerSync {
  private socket?: WebSocket;
  private peer?: WebRtcPeer;
  private pipe?: WebRtcTransport;
  private session?: number;
  private reconnect?: ReturnType<typeof setTimeout>;
  private reconcileTimer?: ReturnType<typeof setInterval>;
  private unsubscribe?: () => void;
  private stopped = false;
  private iceServers: RTCIceServer[] = [];
  private generation = 0;
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
    ) {
      throw new Error('Peer discovery requires a secure WebSocket URL');
    }

    this.connect();
  }

  close(): void {
    this.stopped = true;
    clearTimeout(this.reconnect);
    this.resetPeer();
    this.socket?.close();
    this.options.onStatus?.('Disconnected');
  }

  private resetPeer(): void {
    this.generation++;
    clearInterval(this.reconcileTimer);
    this.unsubscribe?.();
    this.unsubscribe = undefined;
    this.pipe = undefined;
    this.peer?.close();
    this.peer = undefined;
    if (this.session !== undefined)
      void this.db!.closePeerSession(this.session).catch(() => {});
    this.session = undefined;
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

    this.options.onStatus?.('Waiting for a peer');
    const socket = new WebSocket(this.options.signalingUrl);
    this.socket = socket;
    socket.addEventListener('open', () =>
      socket.send(
        JSON.stringify({
          type: 'join',
          room: this.options.room,
          peer: this.peerId,
        }),
      ),
    );
    let queue = Promise.resolve();
    socket.addEventListener('message', event => {
      queue = queue
        .then(async () => {
          if (typeof event.data !== 'string' || event.data.length > 64 * 1024)
            throw new Error('Invalid signaling response');
          const message = JSON.parse(event.data);
          if (message.type === 'joined')
            this.iceServers =
              this.options.iceServers ?? message.iceServers ?? [];

          if (
            message.type === 'joined' &&
            Array.isArray(message.peers) &&
            message.peers.length === 1
          ) {
            const peer = this.newPeer();
            const offer = await peer.createOffer();
            socket.send(
              JSON.stringify({
                type: 'offer',
                to: message.peers[0],
                sdp: offer.sdp,
              }),
            );
          } else if (message.type === 'offer') {
            const peer = this.newPeer();
            const answer = await peer.acceptOffer({
              type: 'offer',
              sdp: message.sdp,
            });
            socket.send(
              JSON.stringify({
                type: 'answer',
                to: message.from,
                sdp: answer.sdp,
              }),
            );
          } else if (message.type === 'answer' && this.peer) {
            await this.peer.acceptAnswer({ type: 'answer', sdp: message.sdp });
          } else if (message.type === 'left' && !this.pipe) {
            this.resetPeer();
          }
        })
        .catch(error => this.fail(error));
    });
    socket.addEventListener('close', () => {
      if (this.stopped) return;
      // The established data channel survives a signaling restart.
      this.reconnect = setTimeout(() => {
        if (!this.pipe) this.resetPeer();
        this.connect();
      }, 3000);
    });
    socket.addEventListener('error', () =>
      this.options.onStatus?.('Discovery unavailable; retrying'),
    );
  }

  private newPeer(): WebRtcPeer {
    this.resetPeer();
    const peer = new WebRtcPeer({ iceServers: this.iceServers });
    this.peer = peer;
    const generation = this.generation;
    void peer.transport
      .then(pipe => this.run(peer, pipe, generation))
      .catch(error => {
        if (generation === this.generation) this.fail(error);
      });

    return peer;
  }

  private async run(
    peer: WebRtcPeer,
    pipe: WebRtcTransport,
    generation: number,
  ): Promise<void> {
    const current = () =>
      generation === this.generation &&
      !this.stopped &&
      this.store.getAgent() === this.agent &&
      this.store.getClientDb() === this.db;
    const binding = await peer.channelBinding();
    const challenge = `${binding}:${randomPeerToken()}`;
    const session = await this.db!.createPeerSession(
      this.options.drive,
      this.options.expectedPeer,
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
          await pipe.send(encodeAuth(JSON.stringify(auth)));
        } else if (frame[0] === Tag.AUTH_OK) {
          if (!challenged || accepted)
            throw new Error('Unexpected authentication acknowledgement');
          accepted = true;
        } else {
          const output = await this.db!.handlePeerFrame(session, frame);
          if (frame[0] === Tag.AUTH) authenticated = true;
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
          this.pipe = pipe;
          const path = await peer.connectionPath();
          this.options.onStatus?.(
            path === 'relayed'
              ? 'Connected through relay'
              : path === 'direct'
                ? 'Connected directly'
                : 'Connected',
          );
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
    if (this.stopped) return;
    this.options.onStatus?.(
      error instanceof Error ? error.message : String(error),
    );
    this.resetPeer();
    this.socket?.close();
  }
}
