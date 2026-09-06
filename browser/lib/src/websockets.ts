/**
 * High-level WebSocket client (auth, pending requests, subscriptions,
 * commit-over-WS). Wire format is defined by `ws-v2.ts` and
 * documented in `docs/src/websockets.md` — the canonical spec.
 * Server counterpart: `server/src/handlers/web_sockets.rs`.
 */

import { createAuthentication } from './authentication.js';
import { Resource } from './resource.js';
import { recordServerVersionFromWsProtocol } from './serverCapabilities.js';
import { StoreEvents, type Store, type DriveSyncState } from './store.js';
import { reconcile, type Item, type RemoteRange } from './rbsr.js';
import { AtomicError, ErrorType } from './error.js';
import {
  type Commit,
  parseCommitJSON,
  serializeDeterministically,
} from './commit.js';
import {
  Tag,
  Flags,
  ErrorCode,
  encodeAuth,
  encodeCommit,
  encodeGet,
  encodeHello,
  encodeSub,
  encodeUnsub,
  encodeKeepalive,
  decodeAuthOk,
  decodeChallenge,
  decodeCommit,
  decodeCommitOk,
  decodeSyncResend,
  decodeUpdate,
  encodeSync,
  encodeEphemeral,
  decodeEphemeral,
  EphemeralKind,
  CLIENT_CAPABILITIES,
  CLIENT_HELLO_NAME,
  decodeError,
  decodeSyncOk,
  decodeSyncDiff,
  decodeSyncPush,
  decodeBlobRequest,
  decodeBlobResponse,
  decodeSubject,
  encodeBlobResponse,
  encodeBlobRequest,
  encodeSyncPushChunks,
  debugFrameInfo,
} from './ws-v2.js';
import { BLOB } from './urls.js';
import { hexToBytes } from './value.js';
import {
  livenessAction,
  LIVENESS_CHECK_MS,
  LIVENESS_DEADLINE_MS,
} from './liveness.js';
import { perfMark, perfSpan } from './perf-trace.js';

// 5s is too tight for a shared atomic-server under suite-wide e2e load
// (auth race + drive sub + several parallel GETs queue up). Above ~10s, the
// failure mode is a real server hang or stuck WS, not transient slowness.
const REQUEST_TIMEOUT = 10000;
/** How long `authenticate` waits for the server's `CHALLENGE` before signing
 *  a timestamp-only proof (a server that predates the frame never sends it). */
const CHALLENGE_WAIT_MS = 300;
const WS_PROTOCOL = 'atomicdata-ws.v2';

const connectionFailedMessage = (url: URL): string =>
  `Could not connect to ${url.origin}. Check that the server is running and reachable.`;

// Optional perf-profiler hook. The data-browser app installs an object
// at `window.__atomicProfiler` that aggregates render + event counts;
// when it's present we feed WS frame traffic through it. Reverse-lookup
// of the Tag enum is cached so the hot path is just two property reads.
const TAG_NAMES: Record<number, string> = (() => {
  const out: Record<number, string> = {};

  for (const [name, value] of Object.entries(Tag)) {
    out[value as number] = name;
  }

  return out;
})();

function tagName(tag: number): string {
  return TAG_NAMES[tag] ?? `0x${tag.toString(16)}`;
}

function profilerTick(name: string, payload?: unknown): void {
  const w = globalThis as {
    __atomicProfiler?: { tick: (n: string, p?: unknown) => void };
  };
  w.__atomicProfiler?.tick(name, payload);
}

/**
 * Render one WS frame to the console as a collapsible group:
 *
 *   ▸ → UPDATE did:ad:abc... [snapshot] (820B)        ← always visible
 *       └─ { subject, flags, commitId, properties: { name: "...", ...} }
 *                                                     ← console.debug,
 *                                                       hidden unless the
 *                                                       DevTools log level
 *                                                       includes "Verbose".
 *
 * Modern browsers gate `console.debug` behind the verbose level by default,
 * so users get the headline they want without their console drowning in
 * snapshot blobs unless they ask for it. The group itself collapses by
 * default so multiple frames stay one line each.
 */
function logFrame(data: Uint8Array, direction: '→' | '←', color: string): void {
  const info = debugFrameInfo(data, direction);

  if (info.details === undefined) {
    console.debug(`%c${info.headline}`, `color: ${color}`);

    return;
  }

  console.groupCollapsed(`%c${info.headline}`, `color: ${color}`);

  try {
    const details = info.details() as Record<string, unknown>;
    // For UPDATE frames the raw `loroSnapshot` Uint8Array isn't useful at a
    // glance. Materialize it through a throwaway Resource and replace it
    // with a `properties` object containing the snapshot's propvals — same
    // shape the Sync page commit log uses, just inline in the console.
    const enriched = decodeUpdateProperties(details);
    console.debug(enriched);
  } catch (e) {
    console.debug('(failed to decode frame details)', e);
  }

  console.groupEnd();
}

/**
 * If the details payload looks like an UPDATE frame (has `loroSnapshot`),
 * decode the snapshot into propvals and swap it in. Falls back to the raw
 * details on any decode failure so a malformed snapshot can't break the
 * frame log.
 */
function decodeUpdateProperties(
  details: Record<string, unknown>,
): Record<string, unknown> {
  const snapshot = details.loroSnapshot;
  const subject = details.subject;

  if (!(snapshot instanceof Uint8Array) || typeof subject !== 'string') {
    return details;
  }

  try {
    const tmp = new Resource(subject);
    tmp.importLoroUpdate(snapshot);
    const properties: Record<string, unknown> = {};

    for (const [prop, value] of tmp.getEntries()) {
      // Skip the loro snapshot field itself — it's the bytes we just decoded.
      if (prop === 'https://atomicdata.dev/properties/loroUpdate') continue;
      properties[shortPropName(prop)] = value;
    }

    // Mutating-ish: keep the order so loroSnapshot stays at the bottom for
    // anyone who still wants to see the raw bytes.
    const { loroSnapshot, ...rest } = details;

    return { ...rest, properties, loroSnapshot };
  } catch {
    return details;
  }
}

function shortPropName(url: string): string {
  // `https://atomicdata.dev/properties/name` → `name`. For non-atomicdata.dev
  // properties (custom ontologies) the fragment after the last `/` is still
  // the most readable thing without a property cache.
  const lastSlash = url.lastIndexOf('/');

  return lastSlash >= 0 ? url.slice(lastSlash + 1) : url;
}

/**
 * A WebSocket client using the v2 binary protocol.
 * All messages are binary frames — no JSON-AD parsing on the hot path.
 */
export class WSClient {
  private ws: WebSocket;
  private store: Store;
  private authPromise: Promise<void>;
  private openPromise: Promise<void>;

  private authenticatedWith: string | undefined;
  private isAuthenticating = false;

  private _closed = false;
  private _retryDelay = 1000;
  private _retryTimer: ReturnType<typeof setTimeout> | undefined;
  private _onlineListener: (() => void) | undefined;
  private _driveUnsub: (() => void) | undefined;
  /** Drive-sync state computed for a hash-first probe, kept until the server
   *  either accepts it (`SYNC_OK`) or asks for a reconcile (`SYNC_RESEND`). */
  private _pendingSyncState = new Map<
    string,
    Awaited<ReturnType<Store['computeDriveSyncState']>>
  >();
  /** Pending RBSR range-query responses. The reconcile issues these one at a
   *  time, so at most one of each is in flight; FIFO queues stay correct even
   *  if that changes. */
  private _rbsrFpQueue: Array<(fps: string[]) => void> = [];
  private _rbsrItemsQueue: Array<(items: Item[]) => void> = [];
  /** What the server said it speaks, from its `AUTH_OK` payload. */
  private _serverCaps: string[] = [];
  /** Liveness: when the last inbound frame arrived, whether a `KEEPALIVE`
   *  probe is outstanding, and the timer that checks both. A browser cannot
   *  observe the server's protocol-level pings, so without this a socket
   *  the network silently dropped stays "connected" until the next write
   *  fails — every subscription push in between is lost. */
  private _lastFrameAt = 0;
  private _probeSent = false;
  private _livenessTimer: ReturnType<typeof setInterval> | undefined;

  /** When true, all WS frames are logged to the console in human-readable form. */
  public debug =
    typeof localStorage !== 'undefined' &&
    localStorage.getItem('ws-debug') === '1';

  /** Pending GET requests awaiting a response, keyed by request_id. */
  private pendingGets = new Map<
    number,
    {
      subject: string;
      resolve: (r: Resource) => void;
      reject: (e: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  /** Pending COMMIT requests awaiting a `COMMIT_OK` (or `ERROR`),
   *  keyed by request_id. */
  private pendingCommits = new Map<
    number,
    {
      /** The commit as we signed and sent it. A slim `COMMIT_OK` carries
       *  only the server's id for it, so this is what the caller gets back
       *  (with that id filled in). */
      commit: Commit;
      resolve: (c: Commit) => void;
      reject: (e: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  private nextRequestId = 1;
  /** The nonce the server sent in its `CHALLENGE` (0x42) on this socket.
   *  `authenticate` signs `{origin}#{nonce}` so the proof is good here
   *  only. Reset with every new socket. */
  private _challengeNonce: string | undefined;
  /** The drive this socket currently holds a `SUB` for, so a drive switch
   *  can `UNSUB` it. Reset with every new socket (the server forgets
   *  subscriptions with the connection). */
  private _subscribedDrive: string | undefined;

  /** Take a pending GET out of the queue, cancel its timer. Caller
   *  invokes resolve/reject on the returned entry. */
  private takePending(requestId: number) {
    const pending = this.pendingGets.get(requestId);
    if (!pending) return undefined;
    clearTimeout(pending.timer);
    this.pendingGets.delete(requestId);

    return pending;
  }

  /** Take a pending COMMIT out of the queue, cancel its timer. */
  private takePendingCommit(requestId: number) {
    const pending = this.pendingCommits.get(requestId);
    if (!pending) return undefined;
    clearTimeout(pending.timer);
    this.pendingCommits.delete(requestId);

    return pending;
  }

  /** Fail every in-flight GET. Called on WS close so callers don't
   *  hang for REQUEST_TIMEOUT (10 s) when the socket dies mid-flight
   *  — the next reconnect will fetch fresh state anyway. */
  private rejectAllPending(reason: string): void {
    const err = new AtomicError(reason, ErrorType.Server);

    // Fail any in-flight `waitForTag` calls (e.g. an AUTH_OK that
    // will never arrive because the socket died mid-handshake).
    if (this.tagRejectors.size > 0) {
      const rejectors = [...this.tagRejectors];
      this.tagRejectors.clear();
      this.tagListeners.clear();
      for (const r of rejectors) r(err);
    }

    if (this.pendingGets.size > 0) {
      const entries = [...this.pendingGets.values()];
      this.pendingGets.clear();

      for (const p of entries) {
        clearTimeout(p.timer);
        p.reject(err);
      }
    }

    if (this.pendingCommits.size > 0) {
      const entries = [...this.pendingCommits.values()];
      this.pendingCommits.clear();

      for (const p of entries) {
        clearTimeout(p.timer);
        p.reject(err);
      }
    }
  }

  constructor(url: string, store: Store) {
    this.store = store;
    this.handleMessage = this.handleMessage.bind(this);
    this.handleOpen = this.handleOpen.bind(this);

    // Switching (or first setting) the drive must (re)subscribe for live
    // commit fan-out. The drive is often chosen AFTER the socket opens — a
    // returning user's `setDrive` on hydration, or a deep-linked/anonymous
    // session adopting a drive once the resource resolves — so subscribing
    // only inside the connect handshake misses it. Idempotent server-side.
    this._driveUnsub = store.on(StoreEvents.DriveChanged, () =>
      this.subscribeToDrive(),
    );

    const wsURL = new URL(url);
    wsURL.protocol = wsURL.protocol === 'http:' ? 'ws' : 'wss';
    wsURL.pathname = '/ws';

    this.authPromise = Promise.resolve();

    const createSocket = () => {
      const ws = new WebSocket(wsURL.toString(), [WS_PROTOCOL]);
      ws.binaryType = 'arraybuffer';
      let opened = false;

      ws.addEventListener('message', this.handleMessage);
      ws.addEventListener('error', () => {
        if (!opened) {
          console.warn('[WS] Connection failed');
        }

        this.reportConnected(false, connectionFailedMessage(wsURL));
        // Some environments fire error without an immediately-following
        // close. Reject anyway — if close does fire later, the second
        // rejectAllPending sees an empty Map and is a no-op.
        this.rejectAllPending('WebSocket error before response arrived');
      });
      ws.addEventListener('close', (ev: CloseEvent) => {
        // Surface CloseEvent metadata so an unexplained reconnect loop
        // names its own cause: code 1000=normal, 1001=going away,
        // 1006=abnormal (no close frame seen — usually network drop or
        // TCP RST), 1009=message too big, 1011=server unexpected
        // condition. `reason` is whatever the server sent; `wasClean`
        // tells us if the closing handshake completed. Without this the
        // user-visible "Connection ... closed" line gives no signal of
        // what actually killed the connection.
        if (!this._closed) {
          console.warn(
            `[WS] close code=${ev.code} reason=${JSON.stringify(ev.reason)} wasClean=${ev.wasClean} opened=${opened}`,
          );
        }

        const error = this._closed
          ? undefined
          : opened
            ? `Connection to ${wsURL.origin} closed (code=${ev.code}${ev.reason ? `, reason=${ev.reason}` : ''}).`
            : connectionFailedMessage(wsURL);

        this.reportConnected(false, error);
        this.rejectAllPending('WebSocket closed before response arrived');
        this.stopLiveness();
        this._serverCaps = [];
        this._challengeNonce = undefined;
        this._subscribedDrive = undefined;

        if (!this._closed) {
          this._retryTimer = setTimeout(() => {
            this.authenticatedWith = undefined;
            createSocket();
          }, this._retryDelay);
          this._retryDelay = Math.min(this._retryDelay * 2, 30000);
        }
      });
      this.openPromise = new Promise((resolve, reject) => {
        // A socket that dies before opening must REJECT this, not leave it
        // pending forever. `authenticate()` awaits it while holding
        // `isAuthenticating`, and its `finally` — the only thing that clears
        // that flag — is downstream of this await. A never-settling promise
        // therefore pins the flag for the lifetime of the client: the retry
        // loop reconnects, the new socket opens, and its `authenticate()`
        // takes the `if (this.isAuthenticating) await this.authPromise` branch
        // onto the dead promise and waits forever. Auth never completes, so
        // `reportConnected(true)` never fires and the app sits on "Offline"
        // next to a server answering in milliseconds, with every `ws.fetch`
        // hung because `REQUEST_TIMEOUT` only starts after auth.
        //
        // Reproduced on a cold start where the webview is ready before the
        // embedded server binds: one `close code=1006 opened=false`, and no
        // recovery until a reload builds a fresh client.
        ws.addEventListener('close', () => {
          if (!opened) {
            reject(
              new AtomicError(
                `WebSocket to ${wsURL.origin} closed before it opened`,
                ErrorType.Server,
              ),
            );
          }
        });
        ws.addEventListener('open', () => {
          opened = true;
          this._retryDelay = 1000;
          resolve();
          // setServerConnected(true) is deliberately NOT called here.
          // Firing it on WS open creates a race window between OPEN and
          // AUTH_OK: useResource(drive) can fire during that gap, see
          // `_serverConnected === true`, take the online fetch path, and
          // call ws.fetch — which itself awaits `authenticate()`. If the
          // auth handshake is slow (Rosetta-translated crypto, busy
          // server), the GET frame is never sent until auth completes,
          // and ws.fetch's REQUEST_TIMEOUT only starts AFTER auth, so a
          // stalled handshake hangs every fetch indefinitely. `handleOpen`
          // below flips the flag at the right moment: immediately when
          // there's no agent to authenticate, otherwise after AUTH_OK.
          this.handleOpen();
        });
      });
      // Nobody awaits `openPromise` until an auth or fetch needs it, so a
      // rejection that arrives first would surface as an unhandled rejection.
      // This derived catch absorbs that; awaiters still see the rejection.
      this.openPromise.catch(() => undefined);

      this.ws = ws;
    };

    createSocket();

    // Wake the retry loop immediately when the OS reports network back
    // up — otherwise we wait out the current backoff (up to 30 s) before
    // even trying. Matches the dagger-flake pattern where `setOffline(false)`
    // doesn't reconnect within the test timeout. No-op outside the browser.
    if (
      typeof window !== 'undefined' &&
      typeof window.addEventListener === 'function'
    ) {
      this._onlineListener = () => {
        // Skip if the WS is already trying or up. Without the CONNECTING
        // guard, a fast online-then-timer race can spawn two sockets:
        // the retry timer fires first → socket1 created → online event
        // fires next → my handler creates socket2 → socket1 leaks.
        if (this._closed) return;
        const rs = this.ws.readyState;
        if (rs === WebSocket.OPEN || rs === WebSocket.CONNECTING) return;

        if (this._retryTimer) {
          clearTimeout(this._retryTimer);
          this._retryTimer = undefined;
        }

        this._retryDelay = 1000;
        this.authenticatedWith = undefined;
        createSocket();
      };

      window.addEventListener('online', this._onlineListener);
    }
  }

  public get readyState(): number {
    return this.ws.readyState;
  }

  public close(): void {
    this._closed = true;

    if (this._retryTimer) {
      clearTimeout(this._retryTimer);
    }

    this._driveUnsub?.();
    this._driveUnsub = undefined;

    if (
      this._onlineListener &&
      typeof window !== 'undefined' &&
      typeof window.removeEventListener === 'function'
    ) {
      window.removeEventListener('online', this._onlineListener);
      this._onlineListener = undefined;
    }

    // Flip the flag and fail in-flight requests NOW, synchronously — we
    // initiated this close, so we don't need to wait for the `close`
    // event to tell us the connection is gone. Relying on the event is
    // fragile: once the transport is already blocked (offline toggle, a
    // dropped link), Chromium can suppress or delay `close`, leaving
    // `serverConnected` stuck at true and pending GETs/commits hanging
    // until their own timeouts. The event handler still runs if it fires,
    // but both calls are idempotent (flag re-set to false, empty maps).
    this.reportConnected(false);
    this.rejectAllPending('WebSocket closed by client');
    this.stopLiveness();

    this.ws.close();
  }

  // ---- Authentication ----

  public async authenticate(fetchAll?: boolean): Promise<void> {
    const agent = this.store.getAgent();

    if (!agent?.subject) return;
    if (this.authenticatedWith === agent.subject && !fetchAll) return;

    // An in-flight auth might be for a DIFFERENT (e.g. now-stale) agent. Wait
    // for it to settle, then check whether we still need to authenticate as
    // the current agent. Without this re-check, calling `setAgent(newAgent)`
    // mid-flight (e.g. onboarding swapping the dev-drive agent for a freshly-
    // created one) silently keeps the WS bound to the old agent, and the next
    // `ws.fetch(newAgent.subject)` returns 401 because the old agent has no
    // read rights on the new agent's resource.
    if (this.isAuthenticating) {
      try {
        await this.authPromise;
      } catch {}

      if (this.authenticatedWith === agent.subject && !fetchAll) return;
    }

    this.isAuthenticating = true;

    this.authPromise = (async () => {
      try {
        await this.openPromise;
        // The server's CHALLENGE is its first frame; on a current server it
        // has arrived by the time anyone calls `authenticate`. The short wait
        // covers the race, and costs its full length only against a server
        // that predates the frame — which then gets the timestamp-only proof
        // it expects.
        const nonce = await this.awaitChallenge();
        const subject = nonce
          ? `${this.serverOrigin}#${nonce}`
          : this.serverOrigin;
        const json = await createAuthentication(subject, agent);

        this.sendBinary(encodeAuth(JSON.stringify(json)));

        // Wait for AUTH_OK — rejected by the close handler if the socket
        // dies mid-handshake, otherwise waits as long as needed.
        await this.waitForTag(Tag.AUTH_OK);

        this.authenticatedWith = agent.subject;
        recordServerVersionFromWsProtocol(
          this.ws.protocol || WS_PROTOCOL,
          this.serverOrigin,
        );

        // Re-subscribe to the drive + active Loro sync and ephemeral channels.
        // `reSubscribeAll` now owns the drive SUB (for both authenticated and
        // anonymous sessions), so there's no separate `encodeSub` here.
        this.reSubscribeAll();

        // Refetch resources that had 401 errors
        if (fetchAll) {
          for (const resource of this.store.resources.values()) {
            if (resource.isUnauthorized()) {
              this.fetch(resource.subject).catch(() => {});
            }
          }
        }
      } finally {
        this.isAuthenticating = false;
      }
    })();

    return this.authPromise;
  }

  /** The nonce from this socket's `CHALLENGE`, waiting briefly for it if
   *  the server has not sent one yet. `undefined` on a server that never
   *  will. */
  private async awaitChallenge(): Promise<string | undefined> {
    if (this._challengeNonce) return this._challengeNonce;

    await this.waitForTag(Tag.CHALLENGE, CHALLENGE_WAIT_MS).catch(
      () => undefined,
    );

    return this._challengeNonce;
  }

  /** The nonce this socket's AUTH proofs answer, once the server sent it.
   *  Exposed for tests. */
  public get challengeNonce(): string | undefined {
    return this._challengeNonce;
  }

  // ---- Resource operations ----

  /**
   * Cancel the drive-wide subscription `subscribeToDrive` registered
   * (binary `UNSUB`, 0x21). The server stops fanning that drive's commits
   * to this connection; nothing is answered. Per-resource `SUBSCRIBE` /
   * `UNSUBSCRIBE` text frames are not used by the browser (it is drive-`SUB`
   * only), so there is no per-resource counterpart here.
   */
  public unsubscribeFromDrive(drive: string): void {
    if (this.readyState !== WebSocket.OPEN) {
      return;
    }

    this.sendBinary(encodeUnsub(drive));
  }

  /** Capability names the server advertised on `AUTH_OK` (see
   *  `ServerCapability`). Empty before authentication and for servers older
   *  than 2026-09. */
  public get serverCapabilities(): string[] {
    return [...this._serverCaps];
  }

  /** Subscribe to vector index status updates for a drive root (see server `SUBSCRIBE_INDEX_STATUS`). */
  public subscribeIndexStatus(drive: string): void {
    this.authPromise
      .catch(() => {
        // Authentication errors are handled in authenticate()
      })
      .finally(() => {
        if (this.readyState !== WebSocket.OPEN) {
          console.warn(
            'WebSocket is not open, cannot subscribe to index status',
          );

          return;
        }

        this.ws.send('SUBSCRIBE_INDEX_STATUS ' + JSON.stringify({ drive }));
      });
  }

  public unsubscribeIndexStatus(drive: string): void {
    if (this.readyState !== WebSocket.OPEN) {
      return;
    }

    this.ws.send('UNSUBSCRIBE_INDEX_STATUS ' + JSON.stringify({ drive }));
  }

  /** Subscribe to the ephemeral presence channel of a drive (issue #1229).
   *  Waits for auth like `subscribeIndexStatus`: the server checks drive
   *  read access at subscribe time, so subscribing pre-auth would get
   *  refused for any non-public drive. */
  public subscribePresence(drive: string): void {
    this.authPromise
      .catch(() => {
        // Authentication errors are handled in authenticate()
      })
      .finally(() => {
        if (this.readyState !== WebSocket.OPEN) {
          console.warn('WebSocket is not open, cannot subscribe to presence');

          return;
        }

        this.ws.send(
          'PRESENCE_SUBSCRIBE ' + JSON.stringify({ subject: drive }),
        );
      });
  }

  public unsubscribePresence(drive: string): void {
    if (this.readyState !== WebSocket.OPEN) {
      return;
    }

    this.ws.send('PRESENCE_UNSUBSCRIBE ' + JSON.stringify({ subject: drive }));
  }

  /** Broadcast presence bytes for `drive` as an `EPHEMERAL` frame. */
  public sendPresenceUpdate(drive: string, update: Uint8Array): void {
    this.sendEphemeral(EphemeralKind.PRESENCE, drive, update);
  }

  /** One `EPHEMERAL (0x40)` frame; `kind` says which channel. The agent
   *  field is left empty: the server attributes the frame to this
   *  connection's authenticated identity and stamps that on the way out. */
  private sendEphemeral(kind: number, subject: string, update: Uint8Array) {
    if (this.readyState !== WebSocket.OPEN) return;
    this.sendBinary(encodeEphemeral(kind, subject, '', update));
  }

  /** Sends a GET message for some resource over websockets. */
  public async fetch(subject: string): Promise<Resource> {
    // Ensure auth has been kicked off before sending the GET. `authPromise`
    // starts as a resolved promise (not undefined), so `await this.authPromise`
    // alone is a no-op when nobody has called `authenticate()` yet — that
    // races with `handleOpen` and `setAgent`. The server then returns a
    // PublicAgent view of permissioned resources (typically just `description`,
    // `isA`, `lastCommit`, `loroUpdate` — `name`/`read`/`write` are filtered
    // out), the resource gets cached as `loading=false, name=undefined`, and
    // the UI never recovers because nothing flags it as unauthorized to
    // refetch on the next `setAgent`. `authenticate()` is idempotent: it
    // returns immediately if there's no agent or we've already authenticated
    // as the current one, and reuses the in-flight promise otherwise.
    await this.authenticate();

    if (this.readyState !== WebSocket.OPEN) {
      throw new AtomicError(
        `WebSocket not open, cannot fetch ${subject}`,
        ErrorType.Server,
      );
    }

    const requestId = this.nextRequestId++;

    if (this.nextRequestId > 0xffff) {
      this.nextRequestId = 1;
    }

    return new Promise((resolve, reject) => {
      const close = perfSpan('ws.GET', { subject: subject.slice(0, 200) });
      const timer = setTimeout(() => {
        this.pendingGets.delete(requestId);
        close({ err: 'timeout' });
        reject(
          new Error(`GET "${subject}" timed out after ${REQUEST_TIMEOUT}ms.`),
        );
      }, REQUEST_TIMEOUT);

      this.pendingGets.set(requestId, {
        subject,
        resolve: (r: Resource) => {
          close('ok');
          resolve(r);
        },
        reject: (e: unknown) => {
          close({ err: e instanceof Error ? e.message : String(e) });
          reject(e);
        },
        timer,
      });
      this.sendBinary(encodeGet(requestId, subject));
    });
  }

  /**
   * Send a signed commit over the WebSocket. Resolves with the
   * server's created commit resource (same shape as HTTP `/commit`
   * returns) once a `COMMIT_OK` with a matching request id arrives.
   *
   * Throws `AtomicError` on `ERROR` with the same request id, on
   * socket close mid-flight (`rejectAllPending`), or on timeout.
   *
   * The server stores the commit's `connection_id` as the event
   * source and suppresses broadcasts back to this connection — the
   * client never receives its own commit as a subscription push.
   * HTTP `/commit` remains the fallback when the WS isn't usable.
   */
  public async postCommit(commit: Commit): Promise<Commit> {
    await this.authenticate();

    if (this.readyState !== WebSocket.OPEN) {
      throw new AtomicError(
        'WebSocket not open, cannot post commit',
        ErrorType.Server,
      );
    }

    // `true`: keep the genesis subject in the network body so the server uses
    // the real (cert-minted) DID instead of re-deriving it from the signature.
    const serialized = serializeDeterministically({ ...commit }, true);
    const requestId = this.nextRequestId++;

    if (this.nextRequestId > 0xffff) {
      this.nextRequestId = 1;
    }

    return new Promise((resolve, reject) => {
      const close = perfSpan('ws.COMMIT');
      const timer = setTimeout(() => {
        this.pendingCommits.delete(requestId);
        close({ err: 'timeout' });
        reject(
          new AtomicError(
            `COMMIT timed out after ${REQUEST_TIMEOUT}ms.`,
            ErrorType.Server,
          ),
        );
      }, REQUEST_TIMEOUT);

      this.pendingCommits.set(requestId, {
        commit,
        resolve: (c: Commit) => {
          close('ok');
          resolve(c);
        },
        reject: (e: Error) => {
          close({ err: e.message });
          reject(e);
        },
        timer,
      });
      this.sendBinary(encodeCommit(requestId, serialized));
    });
  }

  // ---- Loro sync (real-time collaboration) ----

  /** Send a text frame `<prefix> <payload>` if the WS is open.
   *  Loro sync still uses text frames (low-frequency, will migrate
   *  to binary later). No-op on non-open sockets. */
  private sendText(prefix: string, payload: string): void {
    if (this.readyState !== WebSocket.OPEN) return;

    if (this.debug) {
      console.debug(`[WS] sendText: ${prefix} ${payload.slice(0, 100)}...`);
    }

    // Must send a string: `ws.send(Uint8Array)` emits a *binary* frame, which
    // the server routes by tag byte and drops as an unknown tag.
    this.ws.send(`${prefix} ${payload}`);
  }

  public subscribeLoroSync(subject: string): void {
    this.sendText('LORO_SYNC_SUBSCRIBE', JSON.stringify({ subject }));
  }

  public unsubscribeLoroSync(subject: string): void {
    this.sendText('LORO_SYNC_UNSUBSCRIBE', JSON.stringify({ subject }));
  }

  /** An edit in progress on `subject` (raw Loro update bytes). */
  public sendLoroSyncUpdate(subject: string, update: Uint8Array): void {
    this.sendEphemeral(EphemeralKind.DOC, subject, update);
  }

  /** Cursors for `subject` (raw `EphemeralStore` bytes). */
  public sendLoroEphemeralUpdate(subject: string, update: Uint8Array): void {
    this.sendEphemeral(EphemeralKind.LORO, subject, update);
  }

  /** Send a binary frame, logging it in debug mode. */
  private sendBinary(frame: Uint8Array) {
    if (this.debug) {
      logFrame(frame, '→', '#9bf');
    }

    if (frame.length > 0)
      profilerTick(`ws.out.${tagName(frame[0])}`, frame.length);

    this.ws.send(new Uint8Array(frame));
  }

  // ---- Private: message handling ----

  private get serverOrigin(): string {
    const url = new URL(this.ws.url);
    url.protocol = url.protocol === 'ws:' ? 'http:' : 'https:';

    return url.origin;
  }

  /**
   * Report this socket's health as the app's connection state — but only if
   * this socket IS the app's server.
   *
   * A client holds one socket per origin it talks to, and adopting drives from
   * a previous account adds origins the app does not depend on. Those servers
   * can be old (no v2 websocket protocol), unreachable, or simply gone, and
   * their sockets fail and retry forever. Ungated, each failure flipped the
   * whole store to disconnected — so the app showed "Working offline" and
   * queued writes while its own server sat there answering in under a
   * millisecond. On desktop, where no ClientDb backs the outbox, those queued
   * writes are then lost on restart.
   */
  private reportConnected(connected: boolean, error?: string): void {
    let isPrimary = false;

    try {
      isPrimary =
        new URL(this.store.getServerUrl()).origin === this.serverOrigin;
    } catch {
      isPrimary = false;
    }

    if (!isPrimary) return;

    this.store.setServerConnected(connected, error);
  }

  private handleMessage(ev: MessageEvent) {
    // Any inbound frame proves the socket is alive.
    this._lastFrameAt = Date.now();
    this._probeSent = false;

    if (ev.data instanceof ArrayBuffer) {
      this.handleBinary(new Uint8Array(ev.data));
    } else if (typeof ev.data === 'string') {
      // Legacy text messages (Loro sync, query updates) — handle minimally
      this.handleText(ev.data);
    }
  }

  private handleBinary(data: Uint8Array) {
    if (data.length === 0) return;

    if (this.debug) {
      logFrame(data, '←', '#6b9');
    }

    const tag = data[0];
    const payload = data.subarray(1);

    profilerTick(`ws.in.${tagName(tag)}`, data.length);

    switch (tag) {
      case Tag.AUTH_OK:
        // Resolved by waitForTag. The payload is the server's capability
        // list; remember it so features negotiate instead of guessing.
        this._serverCaps = decodeAuthOk(payload);
        break;

      case Tag.KEEPALIVE:
        // The echo of our liveness probe; `handleMessage` already noted the
        // arrival, which is all a keepalive is for.
        break;

      case Tag.ERROR: {
        const msg = decodeError(payload);
        if (!msg) break;

        // requestId 0 is the server's sentinel for connection-level errors
        // (e.g. AUTH failure) not tied to one specific pending GET/COMMIT —
        // `nextRequestId` starts at 1 and wraps back to 1, never 0, so this
        // is unambiguous. `if (msg.requestId)` used to treat 0 as falsy and
        // fall into the `else`, which only toasted the error — any pending
        // `waitForTag` (e.g. `authenticate()`'s AUTH_OK wait) was left to
        // hang until its own 30s internal timeout instead of failing
        // immediately on the error frame that already arrived.
        if (msg.requestId !== 0) {
          const err = new AtomicError(msg.message, ErrorType.Server, msg.code);
          const pendingGet = this.takePending(msg.requestId);

          if (pendingGet) {
            pendingGet.reject(err);
          } else {
            this.takePendingCommit(msg.requestId)?.reject(err);
          }
        } else if (msg.code === ErrorCode.SYNC_REJECTED) {
          // Our SYNC_PUSH was refused as a whole (no write right on the
          // drive, quota, not enrolled). Nothing we sent landed and no
          // SYNC_OK will follow for it. `handleSyncDiff` may already have
          // reported the drive as synced (it does so as soon as the
          // server has nothing left to push), so correct that: the drive
          // is NOT in sync and the local edits stay where they are, to be
          // offered again on the next handshake.
          console.error('[WS] SYNC_PUSH rejected:', msg.message);
          this.store.failDriveSync(
            this.driveFromRejection(msg.message),
            msg.message,
          );
        } else if (
          msg.code === ErrorCode.AUTH_REQUIRED ||
          msg.code === ErrorCode.UNAUTHORIZED_READ
        ) {
          // Session-level refusals of a single frame: a subscription or
          // push we sent without (enough) identity. The socket stays
          // open and every other pending request is unaffected, so
          // neither `rejectAllPending` nor a toast is right — an
          // anonymous viewer of a shared page would see one on every
          // navigation. Logged so it is diagnosable.
          console.warn('[WS] refused:', msg.message);
        } else {
          this.rejectAllPending(msg.message);
          this.store.notifyError(msg.message);
        }

        break;
      }

      case Tag.COMMIT_OK: {
        // Either form: the full commit JSON a server sends a client that did
        // not ask for slim acks, or the bare commit id this client asks for
        // in its HELLO. In both cases the caller gets the commit it signed,
        // carrying the server's id — the only thing it did not already have.
        const msg = decodeCommitOk(payload);

        if (!msg) {
          const raw = decodeCommit(payload);
          const pending = raw && this.takePendingCommit(raw.requestId);
          pending?.reject(
            new AtomicError('Malformed COMMIT_OK frame', ErrorType.Server),
          );
          break;
        }

        const pending = this.takePendingCommit(msg.requestId);
        if (!pending) break;

        try {
          const created = msg.commitJson
            ? parseCommitJSON(msg.commitJson)
            : ({ ...pending.commit, id: msg.commitId } as Commit);
          pending.resolve(created);
        } catch (e) {
          pending.reject(
            e instanceof Error
              ? e
              : new AtomicError(String(e), ErrorType.Server),
          );
        }

        break;
      }

      case Tag.CHALLENGE:
        this._challengeNonce = decodeChallenge(payload);
        break;

      case Tag.SYNC_RESEND: {
        // The hash-first probe missed: reconcile via RBSR (find only the
        // differing subjects) and send version vectors for just those.
        const drive = decodeSyncResend(payload);
        if (drive) void this.sendReducedSyncState(drive);
        break;
      }

      case Tag.EPHEMERAL: {
        // Live collaboration, relayed by the server without inspection:
        // each kind fans out to its own subscriber map on the store.
        const msg = decodeEphemeral(payload);
        if (!msg) break;

        switch (msg.kind) {
          case EphemeralKind.DOC:
            this.store.__handleLoroSyncMessage(msg.subject, msg.payload);
            break;
          case EphemeralKind.LORO:
            this.store.__handleLoroEphemeralMessage(msg.subject, msg.payload);
            break;
          case EphemeralKind.PRESENCE:
            this.store.__handlePresenceMessage(msg.subject, msg.payload);
            break;
          default:
            break;
        }

        break;
      }

      case Tag.UPDATE: {
        const msg = decodeUpdate(payload);

        if (!msg) break;

        // Pending-GET response: route through `applyIncoming` and
        // resolve the awaiting fetch promise. The previous
        // `getResourceLoading` + `importLoroUpdate` + `setLastCommit`
        // + `setSource` + `setLoading` + `addResources` chain is now
        // one call.
        const pending = msg.requestId
          ? this.takePending(msg.requestId)
          : undefined;

        if (pending) {
          this.store.applyIncoming({
            subject: msg.subject,
            loroBytes: msg.loroBytes,
            commitId: msg.commitId,
            source: 'ws-pending-get',
            // A GET response with the SNAPSHOT flag is authoritative full
            // state — replace any partial doc the client seeded from an
            // earlier SUB push, rather than merging (which can keep only the
            // seed's props and render the resource class-less).
            replaceLoroDocsFromRemote: !!(msg.flags & Flags.SNAPSHOT),
          });
          // The resource we just hydrated is what the GET caller is
          // waiting for — read it back from the store map.
          const resource = this.store.resources.get(msg.subject);
          if (resource) pending.resolve(resource);
          break;
        }

        // Subscription push: same call, different `source`. The
        // commit-id dedup inside `applyIncoming` replaces the
        // hand-rolled `isExisting + prevCommit` echo check that
        // used to live here. `addResource`'s `skipCommitCompare`
        // flag is still honoured for the rare case where the
        // pre-import lastCommit equals the post-import (e.g. a
        // properties-only push) — applyIncoming sets it
        // unconditionally, so the gate runs once at the top.
        this.store.applyIncoming({
          subject: msg.subject,
          loroBytes: msg.loroBytes,
          commitId: msg.commitId,
          source: msg.flags & Flags.PUSH ? 'ws-sub-push' : 'ws-pending-get',
        });

        const resource = this.store.resources.get(msg.subject);
        if (resource) this.checkForMissingBlobs(resource);

        break;
      }

      case Tag.DESTROY: {
        const subject = decodeSubject(payload.subarray(2));

        if (subject) {
          this.store.removeResource(subject);
        }

        break;
      }

      case Tag.SYNC_OK: {
        const msg = decodeSyncOk(payload);

        if (msg) {
          this.store.finishDriveSync(msg.drive, 0, Date.now());
        }

        break;
      }

      case Tag.SYNC_DIFF: {
        const msg = decodeSyncDiff(payload);

        if (msg) {
          // handleSyncDiff is async but unawaited here — catch any
          // unhandled rejection so it can't propagate to the WS pump.
          this.handleSyncDiff(msg).catch(e =>
            console.warn('[WS] handleSyncDiff failed:', e),
          );
        }

        break;
      }

      case Tag.SYNC_PUSH: {
        const msg = decodeSyncPush(payload);

        if (msg) {
          // Per-entry `getResourceLoading + importLoroUpdate +
          // setSource + addResources({skipCommitCompare:true})`
          // collapsed into one `applyIncoming` call per entry.
          // The chunked-final-chunk drive-sync signal stays here.
          for (const { subject, loroBytes } of msg.entries) {
            this.store.applyIncoming({
              subject,
              loroBytes,
              source: 'ws-sync-push',
            });
            const resource = this.store.resources.get(subject);
            if (resource) this.checkForMissingBlobs(resource);
          }

          // Only mark the drive sync as finished on the final chunk —
          // SYNC_PUSH is chunked and intermediate chunks shouldn't trigger
          // the "done" UI state.
          if (msg.last) {
            this.store.finishDriveSync(
              msg.drive,
              msg.entries.length,
              Date.now(),
            );
          }
        }

        break;
      }

      case Tag.BLOB_REQUEST: {
        const hash = decodeBlobRequest(payload);

        if (hash) {
          const clientDb = this.store.getClientDb();

          if (clientDb) {
            clientDb.getBlob(hash).then(bytes => {
              if (bytes) {
                this.sendBinary(encodeBlobResponse(hash, bytes));
              }
            });
          }
        }

        break;
      }

      case Tag.BLOB_RESPONSE: {
        const resp = decodeBlobResponse(payload);

        if (resp) {
          this.store.getClientDb()?.putBlob(resp.hash, resp.bytes);
        }

        break;
      }

      default:
        break;
    }

    // Emit raw tag for waitForTag listeners
    this.tagListeners.forEach((cb, t) => {
      if (t === tag) {
        cb();
        this.tagListeners.delete(t);
      }
    });
  }

  /** Handle the text frames that are still text: the RBSR answers and
   *  `INDEX_STATUS`. Loro and presence updates arrive as binary
   *  `EPHEMERAL` since 2026-09-04. */
  private handleText(text: string) {
    if (this.debug) {
      console.debug(`[WS] handleText: ${text.slice(0, 100)}...`);
    }

    // Prefix lengths include the trailing space delimiter. Match the
    // exact length sent by `sendText(prefix, payload)` which writes
    // `${prefix} ${payload}`.
    if (text.startsWith('INDEX_STATUS ')) {
      const json = text.slice('INDEX_STATUS '.length);

      try {
        const parsed = JSON.parse(json) as { drive: string; indexing: boolean };
        this.store.__notifyIndexingStatus(parsed.drive, parsed.indexing);
      } catch {
        console.warn('Invalid INDEX_STATUS message:', json);
      }
    } else if (text.startsWith('RBSR_FP ')) {
      try {
        const { fps } = JSON.parse(text.slice('RBSR_FP '.length)) as {
          fps: string[];
        };
        this._rbsrFpQueue.shift()?.(fps);
      } catch (e) {
        console.warn('Invalid RBSR_FP message:', e);
      }
    } else if (text.startsWith('RBSR_ITEMS ')) {
      try {
        const { items } = JSON.parse(text.slice('RBSR_ITEMS '.length)) as {
          items: Array<[string, Array<[string, number]>]>;
        };
        const parsed: Item[] = items.map(([subject, pairs]) => ({
          subject,
          vv: Object.fromEntries(pairs),
        }));
        this._rbsrItemsQueue.shift()?.(parsed);
      } catch (e) {
        console.warn('Invalid RBSR_ITEMS message:', e);
      }
    }
  }

  /** Subscribe to the current drive for live commit fan-out (UPDATE/DESTROY).
   *  Sent for authenticated AND anonymous connections — the server gates the
   *  subscription on read access to the drive, so a public drive is delivered
   *  to anyone and a private one is rejected. No-op with no drive set or a
   *  closed socket. Idempotent: the server dedups repeat SUBs for a drive. */
  private subscribeToDrive(): void {
    if (this.readyState !== WebSocket.OPEN) {
      return;
    }

    const drive = this.store.getDrive();

    // Switching drives: stop the old drive's fan-out first. Until 2026-09
    // the old subscription stayed registered for the life of the socket, so
    // every drive ever opened in a session kept pushing its commits here.
    if (this._subscribedDrive && this._subscribedDrive !== drive) {
      this.unsubscribeFromDrive(this._subscribedDrive);
      this._subscribedDrive = undefined;
    }

    // Local-only drives are unknown to the server — a SUB would only
    // produce an error frame (and leak the drive subject).
    if (drive && this.store.isLiveSyncedDrive(drive)) {
      this.sendBinary(encodeSub(drive));
      this._subscribedDrive = drive;
    }
  }

  private reSubscribeAll(): void {
    // Drive-wide live subscription. Previously sent only inside
    // `authenticate()`, so an anonymous session never subscribed at all.
    this.subscribeToDrive();

    // Loro and presence subscriptions carry an identity (peers see who
    // is editing), so the server refuses them before AUTH with
    // `AUTH_REQUIRED`. Don't send them for a session without an agent;
    // `authenticate()` calls back in here once one is set.
    if (!this.store.getAgent()) {
      return;
    }

    for (const subject of this.store.getLoroSyncSubjects()) {
      this.subscribeLoroSync(subject);
    }

    for (const drive of this.store.getPresenceSubjects()) {
      this.subscribePresence(drive);
    }

    // The fresh connection's server-side presence cache is empty; announce
    // ourselves again so peers (and the cache) pick us up immediately
    // instead of after the next heartbeat.
    this.store.__rebroadcastPresence();
  }

  // ---- Private: connection lifecycle ----

  /**
   * Start the liveness timer for the current socket. Only probes a server
   * that advertised `keepalive` (older servers do not echo the frame, and a
   * probe that is never answered would make an idle socket look dead every
   * `LIVENESS_DEADLINE_MS`). Anonymous sessions never authenticate, so they
   * learn no capabilities and keep the pre-2026-09 reactive behaviour.
   */
  private startLiveness() {
    this.stopLiveness();
    this._lastFrameAt = Date.now();
    this._probeSent = false;
    this._livenessTimer = setInterval(() => {
      if (this.readyState !== WebSocket.OPEN) return;
      if (!this._serverCaps.includes('keepalive')) return;

      const action = livenessAction(
        Date.now() - this._lastFrameAt,
        this._probeSent,
      );

      if (action === 'probe') {
        this._probeSent = true;
        this.sendBinary(encodeKeepalive());
      } else if (action === 'close') {
        console.warn(
          `[WS] no frame from the server for ${LIVENESS_DEADLINE_MS}ms (probe unanswered); closing so the reconnect loop takes over`,
        );
        this.stopLiveness();
        // Closing fires the `close` handler, which reports disconnection,
        // fails pending requests, and schedules the reconnect.
        this.ws.close();
      }
    }, LIVENESS_CHECK_MS);
  }

  private stopLiveness() {
    if (this._livenessTimer !== undefined) {
      clearInterval(this._livenessTimer);
      this._livenessTimer = undefined;
    }
  }

  private handleOpen() {
    perfMark('ws.open');
    // Introduce ourselves: the capabilities this client speaks (a slim
    // COMMIT_OK, for one). A server that predates client HELLOs drops the
    // frame unread.
    this.sendBinary(encodeHello(CLIENT_HELLO_NAME, CLIENT_CAPABILITIES));
    this.startLiveness();
    const drive = this.store.getDrive();

    const doSync = async () => {
      const dirtyClose = perfSpan('ws.syncDirtyResources');
      // Drain the outbox; failures are recorded per-entry inside
      // the outbox itself, so a thrown drain doesn't prevent VV
      // sync from running.
      await this.store.syncDirtyResources().catch(() => undefined);
      dirtyClose();
      // Refetch resources whose offline state needs a server check
      // (errored-offline, stuck-loading). Runs AFTER drain so any
      // queued commits land before we ask the server for the
      // current state of those subjects — otherwise the refetch
      // pulls the pre-drain snapshot and the UI flickers back to
      // the offline-stale view.
      this.store.refetchOfflineErroredResources();

      // No drive selected (e.g. anon share-link cold open, fresh
      // /app/welcome before the user picks a drive): there's
      // nothing to VV-sync. The server's `collect_drive_subjects`
      // on a bare host URL used to walk every resource in the
      // store and starved the per-conn actor for seconds (see the
      // `anon_ws_get_during_sync_vv_is_fast` bench in
      // `server/tests/ws_get_unauthorized_latency.rs`).
      // Local-only drives never reconcile with a server: a SYNC would
      // upload the whole local drive's version state for nothing.
      if (drive && this.store.isLiveSyncedDrive(drive)) {
        await this.startVVSync(drive);
      }
    };

    if (this.store.getAgent()?.subject) {
      const authClose = perfSpan('ws.authenticate');
      this.authenticate()
        .then(() => {
          authClose('ok');
          // Only flip `_serverConnected` AFTER AUTH_OK arrives. See the
          // comment in the `open` handler above for the race this closes.
          this.reportConnected(true);
          // Re-run subscriptions AFTER the connected flag flips. The
          // AUTH_OK handler already called reSubscribeAll(), but that runs
          // with `_serverConnected` still false — a subscription created
          // between that call and this flip (e.g. the presence manager
          // mounting during a slow cold load) would be silently skipped
          // and never retried. Duplicate subscribe frames are idempotent
          // server-side.
          this.reSubscribeAll();
        })
        .then(doSync)
        .catch(e => {
          authClose({ err: String(e) });
          console.error('Auth error:', e);
          // Auth failed (timeout, server rejection, socket closed mid-
          // handshake). The socket itself may still be open — surface
          // the connected state anyway so the UI can present a real
          // error instead of staying stuck in a "connecting" limbo. The
          // pending GETs already rejected via `rejectAllPending` if the
          // socket died; if it's still up, subsequent fetches will fail
          // unauthenticated and surface a 401 error to the user.
          this.reportConnected(true);
        });
    } else {
      // No agent to authenticate — the socket is open and we're ready
      // to serve anonymous fetches. Flip immediately.
      this.reportConnected(true);
      this.reSubscribeAll();
      doSync().catch(() => undefined);
    }
  }

  private async startVVSync(drive: string): Promise<void> {
    if (this.readyState !== WebSocket.OPEN) return;

    this.store.startDriveSync();
    const close = perfSpan('ws.computeDriveSyncState');

    try {
      // Hash-first: compute our state (needed for the hash) but send only the
      // hash as a probe. In the common "nothing changed" case the server
      // answers SYNC_OK and we never transmit the O(drive-size) version vector.
      // On a mismatch the server replies `SYNC_RESEND` and
      // `sendReducedSyncState` reconciles from the state stashed here.
      const syncState = await this.store.computeDriveSyncState(drive);
      close({ resourceCount: Object.keys(syncState.resources).length });
      this._pendingSyncState.set(drive, syncState);
      this.sendBinary(
        encodeSync(
          drive,
          syncState.driveHash,
          JSON.stringify({ peers: [], resources: {}, probe: true }),
        ),
      );
      perfMark('ws.SYNC.probe.sent');
    } catch (e) {
      close({ err: String(e) });
      console.warn('[WS] VV sync failed:', e);
    }
  }

  /** Force a fresh version-vector reconcile of a single drive with the
   *  server. Used to promote a drive that was previously local-only: the
   *  reconcile SYNC_PUSHes the drive's resources up (the server has none).
   *  No-op if the socket isn't open. */
  public async resyncDrive(drive: string): Promise<void> {
    if (this.readyState !== WebSocket.OPEN) return;

    await this.startVVSync(drive);
  }

  /** Respond to SYNC_RESEND. Instead of sending the whole drive's version
   *  vector, run RBSR against the server (range fingerprint exchange) to find
   *  only the differing subjects, and send version vectors for just those. On
   *  any RBSR failure, fall back to the full VV so the drive always reconciles.
   */
  private async sendReducedSyncState(drive: string): Promise<void> {
    if (this.readyState !== WebSocket.OPEN) return;

    const syncState =
      this._pendingSyncState.get(drive) ??
      (await this.store.computeDriveSyncState(drive).catch(() => undefined));
    this._pendingSyncState.delete(drive);

    if (!syncState) return;

    try {
      const local = syncStateToItems(syncState);
      const remote: RemoteRange = {
        fingerprint: async (lo, hi) =>
          (await this.rbsrFingerprints(drive, [[lo, hi ?? null]]))[0],
        items: (lo, hi) => this.rbsrItems(drive, lo, hi),
      };

      const diff = await reconcile(local, remote);
      // Subjects the outbox still owns are not offered for reconcile (see
      // `handleSyncDiff`): the drain delivers them signed.
      const differing = [
        ...diff.onlyLocal,
        ...diff.onlyRemote,
        ...diff.differ,
      ].filter(subject => !this.store.outbox.hasPending(subject));

      // Version vectors for the differing subjects the client actually holds
      // (only-remote subjects it doesn't have — the server pushes those).
      const reducedResources: Record<string, number[]> = {};

      for (const subject of [...diff.onlyLocal, ...diff.differ]) {
        if (syncState.resources[subject]) {
          reducedResources[subject] = syncState.resources[subject];
        }
      }

      this.sendBinary(
        encodeSync(
          drive,
          syncState.driveHash,
          JSON.stringify({
            peers: syncState.peers,
            resources: reducedResources,
            subjects: differing,
          }),
        ),
      );
    } catch (e) {
      // Safety net: any RBSR failure (query timeout, socket close, parse) falls
      // back to the full reconcile, which always converges. Never leave the
      // drive un-reconciled because the optimization stumbled.
      console.warn('[WS] RBSR reconcile failed, sending full VV:', e);

      if (this.readyState === WebSocket.OPEN) {
        this.sendBinary(
          encodeSync(
            drive,
            syncState.driveHash,
            JSON.stringify({
              peers: syncState.peers,
              resources: syncState.resources,
            }),
          ),
        );
      }
    }
  }

  /** Send an RBSR range-fingerprint query and await the server's fingerprints. */
  private rbsrFingerprints(
    drive: string,
    ranges: Array<[string, string | null]>,
  ): Promise<string[]> {
    return new Promise<string[]>((resolve, reject) => {
      if (this.readyState !== WebSocket.OPEN) {
        reject(new Error('WebSocket is not open'));

        return;
      }

      const timer = setTimeout(() => {
        const i = this._rbsrFpQueue.indexOf(settle);

        if (i >= 0) this._rbsrFpQueue.splice(i, 1);
        reject(new Error('RBSR_FP timed out'));
      }, 10000);

      const settle = (fps: string[]) => {
        clearTimeout(timer);
        resolve(fps);
      };

      this._rbsrFpQueue.push(settle);
      this.ws.send('RBSR_FP ' + JSON.stringify({ drive, ranges }));
    });
  }

  /** Send an RBSR range-items query and await the server's items. */
  private rbsrItems(drive: string, lo: string, hi?: string): Promise<Item[]> {
    return new Promise<Item[]>((resolve, reject) => {
      if (this.readyState !== WebSocket.OPEN) {
        reject(new Error('WebSocket is not open'));

        return;
      }

      const timer = setTimeout(() => {
        const i = this._rbsrItemsQueue.indexOf(settle);

        if (i >= 0) this._rbsrItemsQueue.splice(i, 1);
        reject(new Error('RBSR_ITEMS timed out'));
      }, 10000);

      const settle = (items: Item[]) => {
        clearTimeout(timer);
        resolve(items);
      };

      this._rbsrItemsQueue.push(settle);
      this.ws.send(
        'RBSR_ITEMS ' + JSON.stringify({ drive, lo, hi: hi ?? null }),
      );
    });
  }

  /**
   * Handle SYNC_DIFF: server tells us which resources differ.
   * We send Loro deltas for resources the server needs (pull list).
   *
   * For each `pull` subject we try the in-memory `Resource` first, then
   * fall back to the on-disk ClientDb snapshot. The fallback breaks the
   * "stale VV" stalemate where server thinks the client is ahead but
   * the client has only just opened the WS — none of those resources
   * are in `store.resources` yet, so the old in-memory-only loop sent
   * nothing back, the server stayed behind, and the next reconnect
   * re-issued the same diff forever.
   */
  private async handleSyncDiff(diff: {
    drive: string;
    pull: string[];
    push: string[];
    remove?: string[];
    pullFrom?: Record<string, Record<string, number>>;
    removeCommits?: Record<string, string>;
  }) {
    const clientDb = this.store.getClientDb();

    for (const subject of diff.remove ?? []) {
      const envelope = diff.removeCommits?.[subject];

      // The clientDb applies this as a local-cache write (no signature or
      // rights check happens in the browser), so a failure here is a local
      // error, not a refusal. The server already decided the subject is
      // gone: fall through to the in-memory removal either way, otherwise
      // the resource stays rendered and is re-listed on every reconcile.
      if (envelope && clientDb) {
        try {
          await clientDb.applyCommit(envelope);
        } catch (e) {
          console.warn(
            '[WS] SYNC_DIFF remove envelope not applied:',
            subject,
            e,
          );
        }
      }

      this.store.removeResource(subject);
    }

    const entries: Array<{ subject: string; loroBytes: Uint8Array }> = [];

    for (const subject of diff.pull) {
      // F1 interim (planning/unified-sync.md): a subject with a pending
      // outbox entry is the drain's to deliver, as a signed commit. Pushing
      // its raw bytes here — from memory or, worse, the clientDb fallback
      // below — would race the drain with an unsigned write. The
      // `computeDriveSyncState` side already hides these subjects from the
      // version vector we send; this closes the other half, where the
      // server names them in `pull`.
      if (this.store.outbox.hasPending(subject)) continue;

      let loroBytes: Uint8Array | undefined;
      const serverVv = diff.pullFrom?.[subject];
      const memDoc = this.store.resources.get(subject)?.getLoroDoc?.();

      if (memDoc) {
        loroBytes = Resource.exportLoroBytesForSync(memDoc, serverVv);
      }

      if ((!loroBytes || loroBytes.length === 0) && clientDb) {
        try {
          const stored = await clientDb.getLoroSnapshot(subject);

          if (stored && stored.length > 0) {
            loroBytes = stored;
          }
        } catch {
          // skip
        }
      }

      if (loroBytes && loroBytes.length > 0) {
        entries.push({ subject, loroBytes });
      }
    }

    if (entries.length > 0) {
      if (this.readyState !== WebSocket.OPEN) {
        return;
      }

      try {
        for (const frame of encodeSyncPushChunks(diff.drive, entries)) {
          this.sendBinary(frame);
        }
      } catch (e) {
        console.warn('[WS] SYNC_PUSH send failed:', e);

        return;
      }
    }

    // If server has nothing to push, sync is done
    if (diff.push.length === 0) {
      this.store.finishDriveSync(diff.drive, entries.length, Date.now());
    }
  }

  // ---- Private: helpers ----

  /** The drive a `SYNC_REJECTED` message is about. The server formats it
   *  as `SYNC_PUSH rejected for drive <drive>: <reason>`; when that shape
   *  is not recognised, fall back to the drive we are syncing. */
  private driveFromRejection(message: string): string {
    const match = /rejected for drive (\S+?):/.exec(message);

    return match?.[1] ?? this.store.getDrive() ?? '';
  }

  private async checkForMissingBlobs(resource: Resource) {
    const blobDid = resource.get(BLOB) as string | undefined;

    if (!blobDid) return;

    // Extract the hash from did:ad:blob:{hash}
    const hashStr = blobDid.startsWith('did:ad:blob:')
      ? blobDid.substring(12)
      : blobDid;

    const clientDb = this.store.getClientDb();

    if (clientDb) {
      const hash = hexToBytes(hashStr);
      const exists = await clientDb.getBlob(hash);

      if (!exists) {
        this.sendBinary(encodeBlobRequest(hash));
      }
    }
  }

  private tagListeners = new Map<number, () => void>();
  private tagRejectors = new Set<(reason: Error) => void>();

  /** Wait for a specific WS tag (e.g. AUTH_OK) to arrive. Rejects when
   *  the underlying WebSocket closes/errors, or after `timeoutMs` if no
   *  matching frame arrives. A stressed atomic-server (8 workers, slow
   *  CI container, Rosetta-translated crypto) can legitimately take
   *  several seconds to respond to AUTH; the default 30s budget waits
   *  that out without leaving downstream callers hung forever. Without
   *  this, `ws.fetch` (which `await`s `authenticate()` before sending
   *  the GET frame) would hang indefinitely on a stalled handshake,
   *  ignoring its own REQUEST_TIMEOUT.
   *
   *  Pass `0` to disable the timeout. */
  private waitForTag(tag: number, timeoutMs = 30000): Promise<void> {
    return new Promise((resolve, reject) => {
      const timer =
        timeoutMs > 0
          ? setTimeout(() => {
              this.tagListeners.delete(tag);
              this.tagRejectors.delete(rejector);
              reject(
                new AtomicError(
                  `Timed out waiting ${timeoutMs}ms for WS tag ${tag}`,
                  ErrorType.Server,
                ),
              );
            }, timeoutMs)
          : undefined;

      const rejector = (err: Error) => {
        if (timer) clearTimeout(timer);
        this.tagListeners.delete(tag);
        this.tagRejectors.delete(rejector);
        reject(err);
      };

      this.tagRejectors.add(rejector);
      this.tagListeners.set(tag, () => {
        if (timer) clearTimeout(timer);
        this.tagRejectors.delete(rejector);
        resolve();
      });
    });
  }
}

/** Convert a computed drive-sync state (compact peer-indexed counters) into the
 *  sorted `(subject, version vector)` items the RBSR reconcile runs over —
 *  the exact set the probe hash was computed from, so the client reconciles the
 *  same items it hashed. */
function syncStateToItems(state: DriveSyncState): Item[] {
  const items: Item[] = Object.entries(state.resources).map(
    ([subject, counters]) => {
      const vv: Record<string, number> = {};

      counters.forEach((c, i) => {
        if (c !== 0) {
          vv[state.peers[i]] = c;
        }
      });

      return { subject, vv };
    },
  );

  items.sort((a, b) => (a.subject < b.subject ? -1 : 1));

  return items;
}
