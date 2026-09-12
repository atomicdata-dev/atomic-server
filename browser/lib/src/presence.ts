import type { EphemeralStore } from 'loro-crdt';
import { LoroLoader } from './loro-loader.js';
import { randomUUID } from './random-uuid.js';
import type { Store } from './store.js';

/** What a session announces about itself on a drive's presence channel. */
export interface PresenceEntry<T = unknown> {
  /** Subject of the agent behind this session. */
  agent: string;
  /** Subject of the resource the session is currently viewing. */
  resource?: string;
  /** Subject of the agent this session is following (follow mode). */
  following?: string;
  /** Subject of the ChatRoom logging this agent's follow session, when
   *  they're being followed. Followers use it to open the session chat. */
  session?: string;
  /** When `false`, other sessions should not follow this one's agent.
   *  Absent means followable. */
  allowFollow?: boolean;
  /** View-specific payload (e.g. canvas XY, table cell, document cursor). */
  data?: T;
  /** Subject of the comment thread / chatroom this session is currently
   *  composing a message in, if any. Consumers show a "typing…" hint to the
   *  other sessions keyed on the same subject. Cleared when the composer goes
   *  idle, blurs, sends, or unmounts. Its own dedicated field (not `data`) so
   *  it never clobbers a view's cursor payload. */
  typing?: string;
  /** Milliseconds since epoch of this entry's last local write. Lets
   *  consumers prefer an agent's freshest session when several linger
   *  (e.g. a stale pre-reload session that hasn't hit its TTL yet). */
  updatedAt?: number;
}

/** A remote session's presence, as exposed to consumers. */
export interface PresenceItem<T = unknown> extends PresenceEntry<T> {
  /** Unique id of the browsing session (tab). One agent can have many. */
  sessionId: string;
}

/** Keys expire on all peers when not refreshed within this window. */
const PRESENCE_TTL_MS = 30_000;
/** Re-set the local entry well inside the TTL so it never expires while
 *  the tab is alive. */
const HEARTBEAT_MS = 10_000;

/**
 * Ephemeral "who is where" state for one drive (issue #1229).
 *
 * Wraps a Loro {@link EphemeralStore} in which every participating session
 * writes exactly one key — its own `sessionId` — holding a
 * {@link PresenceEntry}. Updates travel as opaque bytes through the
 * `PRESENCE_*` websocket frames; the server relays them per drive and
 * replays each connection's latest payload to late joiners. Loro's
 * per-key LWW timestamps make replays and reordering harmless, and its
 * TTL cleanup removes sessions that stop heartbeating (closed tab,
 * dropped connection) without any explicit leave message.
 *
 * Loro WASM loads lazily ({@link LoroLoader}); until it's ready, local
 * state and remote bytes are buffered and applied on init.
 *
 * Obtain instances via `store.getPresence(drive)` — the store keeps one
 * manager per drive and drops it when its last subscriber leaves.
 */
export class DrivePresenceManager {
  public readonly sessionId: string;

  private ephemeral?: EphemeralStore;
  /** Remote payloads received before the WASM module finished loading. */
  private pendingRemote: Uint8Array[] = [];
  /** Injected synthetic entries buffered until the WASM module loads. */
  private pendingInjected = new Map<string, PresenceEntry>();
  private local?: PresenceEntry;
  private listeners = new Set<() => void>();
  private snapshot: PresenceItem[] = [];
  private unsubTransport?: () => void;
  private unsubLoroReady?: () => void;
  private heartbeat?: ReturnType<typeof setInterval>;

  public constructor(
    private store: Store,
    private drive: string,
  ) {
    // Not `crypto.randomUUID`: that is secure-context-only, and this
    // constructor runs on every drive load, so over plain HTTP on a LAN it
    // threw before first paint and the app rendered its error screen instead.
    this.sessionId = randomUUID();
  }

  /**
   * Register a change listener (React: `useSyncExternalStore`). The first
   * subscriber opens the websocket subscription; when the last one leaves
   * the manager shuts down (transport + heartbeat), but stays registered
   * in the store: consumers memoize the instance across renders, and a
   * manager that replaced itself would leave them patching a dead object.
   */
  public subscribe(callback: () => void): () => void {
    if (this.listeners.size === 0) {
      this.start();
    }

    this.listeners.add(callback);

    return () => {
      this.listeners.delete(callback);

      if (this.listeners.size === 0) {
        this.stop();
      }
    };
  }

  /** Current presence of all sessions on the drive, including our own.
   *  Stable reference between changes (safe for `useSyncExternalStore`). */
  public getSnapshot(): PresenceItem[] {
    return this.snapshot;
  }

  /**
   * Announce (or update) this session's presence. Pass `undefined` to go
   * invisible (e.g. on sign-out). No-op broadcast-wise until the store's
   * agent is known — anonymous sessions don't announce.
   */
  public setLocal(entry: Omit<PresenceEntry, 'agent'> | undefined): void {
    const agent = this.store.getAgent()?.subject;

    if (!entry || !agent) {
      this.local = undefined;
      this.ephemeral?.delete(this.sessionId);

      return;
    }

    this.local = { ...entry, agent, updatedAt: Date.now() };
    this.ephemeral?.set(this.sessionId, this.local as never);
  }

  /**
   * Merge fields into this session's presence entry. Different features
   * own different fields (the resource announcement, follow mode, view
   * payloads) — patching lets them write concurrently without wiping each
   * other. Set a field to `undefined` to clear it.
   */
  public patchLocal(patch: Partial<Omit<PresenceEntry, 'agent'>>): void {
    const agent = this.store.getAgent()?.subject;

    if (!agent) {
      return;
    }

    this.local = { ...this.local, ...patch, agent, updatedAt: Date.now() };
    this.ephemeral?.set(this.sessionId, this.local as never);
  }

  /**
   * Write a synthetic remote session into the drive's presence store —
   * the seam for scripted "teammates" (demo workspace, tests). The
   * entry renders exactly like a real remote session: any key that is
   * not our own `sessionId` is a peer. Subject to the normal TTL —
   * refresh within 30s or the session reads as departed (which a
   * scripted leave can also do explicitly via {@link removeEntry}).
   *
   * On a local-only drive the write stays in this tab (the store's
   * transport guard drops the broadcast). On a synced drive it WOULD
   * go out over the websocket like any local write — injectors should
   * stick to local-only drives.
   */
  public injectEntry(sessionId: string, entry: PresenceEntry): void {
    const stamped = { ...entry, updatedAt: Date.now() };

    if (this.ephemeral) {
      this.ephemeral.set(sessionId, stamped as never);
    } else {
      this.pendingInjected.set(sessionId, stamped);
    }
  }

  /** Remove a synthetic session immediately — an explicit "leave",
   *  faster than waiting out the TTL. */
  public removeEntry(sessionId: string): void {
    if (this.ephemeral) {
      this.ephemeral.delete(sessionId);
    } else {
      this.pendingInjected.delete(sessionId);
    }
  }

  /** Re-send the local entry, bumping its LWW timestamp. Called by the
   *  heartbeat and after websocket reconnects (the server's per-connection
   *  cache starts empty on a fresh connection). */
  public rebroadcast(): void {
    if (!this.local || !this.ephemeral) {
      return;
    }

    // Bump our entry's LWW timestamp so peers' TTL cleanup keeps it alive…
    this.ephemeral.set(this.sessionId, this.local as never);
    // …and put the encoded entry on the wire ourselves. Relying on
    // `subscribeLocalUpdates` alone is fragile here: a value-identical
    // `set` may not emit one, and the very first broadcast can be dropped
    // while the websocket is still authenticating — this direct send makes
    // the heartbeat self-healing (it also repopulates the server's
    // per-connection cache for late-joiner replay).
    this.store.broadcastPresenceUpdate(
      this.drive,
      this.ephemeral.encode(this.sessionId),
    );
  }

  private start(): void {
    this.unsubTransport = this.store.subscribePresenceUpdates(
      this.drive,
      bytes => {
        if (this.ephemeral) {
          this.ephemeral.apply(bytes);
        } else {
          this.pendingRemote.push(bytes);
        }
      },
    );

    this.unsubLoroReady = LoroLoader.onReady(() => this.init());
  }

  private init(): void {
    const ephemeral = new LoroLoader.Loro.EphemeralStore(PRESENCE_TTL_MS);
    this.ephemeral = ephemeral;

    ephemeral.subscribeLocalUpdates(bytes => {
      this.store.broadcastPresenceUpdate(this.drive, bytes);
    });

    // Fires for local sets, applied remote bytes, and TTL expiry alike.
    ephemeral.subscribe(() => this.emit());

    for (const bytes of this.pendingRemote) {
      ephemeral.apply(bytes);
    }

    this.pendingRemote = [];

    for (const [sessionId, entry] of this.pendingInjected) {
      ephemeral.set(sessionId, entry as never);
    }

    this.pendingInjected.clear();

    if (this.local) {
      ephemeral.set(this.sessionId, this.local as never);
    }

    this.heartbeat = setInterval(() => this.rebroadcast(), HEARTBEAT_MS);
  }

  private stop(): void {
    if (this.heartbeat) {
      clearInterval(this.heartbeat);
      this.heartbeat = undefined;
    }

    this.unsubLoroReady?.();
    // Announce the departure so peers don't wait out the TTL. Must happen
    // while still subscribed: the server only relays updates from current
    // subscribers, so a delete sent after PRESENCE_UNSUBSCRIBE is dropped.
    this.ephemeral?.delete(this.sessionId);
    this.unsubTransport?.();
    this.ephemeral?.destroy();
    this.ephemeral = undefined;
    this.pendingRemote = [];
    this.pendingInjected.clear();
    this.snapshot = [];
  }

  private emit(): void {
    const next = this.computeSnapshot();

    // Heartbeats (ours and every peer's) fire ephemeral events without
    // changing anything visible; keep the snapshot reference stable so
    // `useSyncExternalStore` consumers don't re-render every few seconds.
    if (JSON.stringify(next) === JSON.stringify(this.snapshot)) {
      return;
    }

    this.snapshot = next;

    for (const listener of this.listeners) {
      try {
        listener();
      } catch (e) {
        console.error('[Presence] listener threw:', e);
      }
    }
  }

  private computeSnapshot(): PresenceItem[] {
    if (!this.ephemeral) {
      return [];
    }

    const states = this.ephemeral.getAllStates() as Record<
      string,
      PresenceEntry | undefined
    >;

    return Object.entries(states)
      .filter(
        (pair): pair is [string, PresenceEntry] =>
          typeof pair[1]?.agent === 'string',
      )
      .map(([sessionId, entry]) => ({ sessionId, ...entry }))
      .sort((a, b) => a.sessionId.localeCompare(b.sessionId));
  }
}
