// @wc-ignore-file
import { StoreEvents, type Store, type DiagnosticRecorder } from '@tomic/lib';
import {
  cleanState,
  IndexedDiagnosticStorage,
  newDiagnosticId,
  type DiagnosticStorage,
  type StoredSession,
} from './diagnostic-storage';

const controllers = new WeakMap<DiagnosticRecorder, PersistentDiagnostics>();

export const getPersistentDiagnostics = (recorder: DiagnosticRecorder) =>
  controllers.get(recorder);

/** Browser app policy; standalone library Stores remain side-effect free. */
export class PersistentDiagnostics {
  private epoch?: string;
  private id = newDiagnosticId();
  private history: StoredSession[] = [];
  private generation = 0;
  private flushing = false;
  private writes: Promise<unknown> = Promise.resolve();
  private timer?: ReturnType<typeof setInterval>;
  private channel?: BroadcastChannel;
  private offAgent?: () => void;
  private subject?: string;
  private listeners = new Set<() => void>();
  private enabled = true;
  private savedSequence = 0;
  private state:
    | 'loading'
    | 'persistent'
    | 'memory-only'
    | 'paused'
    | 'clear-failed' = 'loading';
  readonly ready: Promise<void>;
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);

    return () => {
      this.listeners.delete(listener);
    };
  };
  get status() {
    return this.state;
  }

  constructor(
    private store: Store,
    private storage: DiagnosticStorage = new IndexedDiagnosticStorage(),
    options: { reset?: boolean; broadcast?: boolean } = {},
  ) {
    controllers.set(store.diagnostics, this);
    this.subject = store.getAgent()?.subject;

    if (
      options.broadcast !== false &&
      typeof BroadcastChannel !== 'undefined'
    ) {
      try {
        this.channel = new BroadcastChannel('atomic-diagnostic-reset');
        this.channel.onmessage = () => this.pause();
      } catch {
        // Epoch checks still fence writes when browser messaging is unavailable.
      }
    }

    this.offAgent = store.on(StoreEvents.AgentChanged, agent => {
      if (this.subject === agent?.subject) return;
      this.subject = agent?.subject;
      void this.reset();
    });
    this.ready = this.initialize(options.reset ?? false);
    this.timer = setInterval(() => {
      void this.flush();
    }, 2000);
  }

  private broadcastReset() {
    try {
      this.channel?.postMessage('reset');
    } catch {
      /* IDB epochs still fence stale writes. */
    }
  }
  private notify() {
    for (const listener of this.listeners) {
      try {
        listener();
      } catch {
        /* diagnostic UI cannot affect application work */
      }
    }
  }
  private start() {
    this.id = newDiagnosticId();
    this.savedSequence = 0;
    this.store.diagnostics.start({ continuous: true });
    this.store.diagnostics.connection(this.store.serverConnected);
    const status = this.store.getSyncStatus();
    this.store.diagnostics.queue(
      status.pendingDirtyCount,
      status.blockedCount,
      status.serverConnected,
    );
  }
  private async initialize(reset: boolean) {
    const generation = this.generation;
    if (reset) this.broadcastReset();

    try {
      const state = await this.storage.update(current =>
        reset
          ? { ...current, epoch: newDiagnosticId(), sessions: [] }
          : current,
      );
      if (generation !== this.generation) return;
      this.epoch = state.epoch;
      this.enabled = state.enabled;
      this.history = state.sessions;
      this.state = 'persistent';
    } catch {
      if (generation !== this.generation) return;
      this.state = 'memory-only';
    }

    if (this.enabled) this.start();
    this.notify();
  }
  private pause() {
    this.generation++;
    this.history = [];
    this.epoch = undefined;
    this.state = 'paused';
    this.store.diagnostics.clear();
    this.notify();
  }
  setEnabled(enabled: boolean): Promise<void> {
    // A stale tab must reload the current identity before collecting again.
    if (this.state === 'paused') return Promise.resolve();

    return this.reset(enabled);
  }
  private reset(enabled?: boolean): Promise<void> {
    const generation = ++this.generation;
    if (enabled !== undefined) this.enabled = enabled;
    this.history = [];
    this.store.diagnostics.clear();
    this.broadcastReset();

    const run = async () => {
      try {
        const state = await this.storage.update(stored => ({
          epoch: newDiagnosticId(),
          enabled: enabled ?? stored.enabled,
          sessions: [],
        }));
        if (generation !== this.generation) return;
        this.epoch = state.epoch;
        this.enabled = state.enabled;
        this.state = 'persistent';
        if (this.enabled) this.start();
      } catch {
        if (generation !== this.generation) return;
        this.epoch = undefined;
        this.state = 'clear-failed';
        // Never expose previously loaded history after an account change or failed clear.
      }

      this.notify();
    };

    this.writes = this.writes.then(run, run);

    return this.writes as Promise<void>;
  }
  private current(): StoredSession {
    const recorder = this.store.diagnostics;
    const { events, completeness } = recorder.capture();

    return {
      id: this.id,
      startedAt: recorder.startedAt,
      savedAt: Date.now(),
      events: [...events],
      totalEvents: completeness.totalEvents,
      droppedAge: completeness.droppedAge,
      droppedCapacity: completeness.droppedCapacity,
      droppedOperations: completeness.droppedOperations,
      unfinishedOperations: completeness.unfinishedOperations,
      build: `${__APP_VERSION__}+${__GIT_COMMIT__}`,
    };
  }
  flush(): Promise<void> {
    if (
      !this.epoch ||
      !this.store.diagnostics.active ||
      this.state === 'loading'
    )
      return Promise.resolve();
    if (this.flushing) return this.writes as Promise<void>;
    this.flushing = true;
    const generation = this.generation;
    const epoch = this.epoch;
    const current = this.current();

    const run = async () => {
      if (generation !== this.generation) return;

      try {
        const state = await this.storage.update(stored =>
          stored.epoch === epoch && stored.enabled
            ? {
                ...stored,
                sessions: [
                  ...stored.sessions.filter(s => s.id !== current.id),
                  current,
                ],
              }
            : stored,
        );
        if (generation !== this.generation) return;

        if (state.epoch !== epoch || !state.enabled) {
          this.pause();

          return;
        }

        this.history = state.sessions;
        this.savedSequence = current.totalEvents;
        const changed = this.state !== 'persistent';
        this.state = 'persistent';
        if (changed) this.notify();
      } catch {
        if (generation !== this.generation) return;
        this.state = 'memory-only';
        this.notify();
      }
    };

    this.writes = this.writes.then(run, run).finally(() => {
      this.flushing = false;
    });

    return this.writes as Promise<void>;
  }
  capture() {
    const recorder = this.store.diagnostics;
    const current = recorder.capture();
    const combined = cleanState({
      epoch: '',
      enabled: recorder.active,
      sessions: [...this.history.filter(s => s.id !== this.id), this.current()],
    });
    const active = combined.sessions.find(s => s.id === this.id);

    return {
      ...current,
      events: active?.events ?? [],
      completeness: {
        ...current.completeness,
        firstRetainedSequence: active?.events[0]?.sequence ?? null,
        lastRetainedSequence: active?.events.at(-1)?.sequence ?? null,
        droppedCapacity:
          active?.droppedCapacity ?? current.completeness.droppedCapacity,
        droppedAge: active?.droppedAge ?? current.completeness.droppedAge,
      },
      storage: {
        state: this.state,
        batchIntervalMs: 2000,
        maxStoredSessions: 20,
        pendingEvents: Math.max(
          0,
          current.completeness.totalEvents - this.savedSequence,
        ),
        limitations:
          'Best effort. Browser eviction, storage failure, or a crash before the batch commits can lose events. Background tabs may delay writes. Expired disk records are pruned on the next read/write; no deletion runs while the app is closed.',
      },
      previousSessions: combined.sessions
        .filter(s => s.id !== this.id)
        .map((session, index) => ({
          session: index + 1,
          build: session.build,
          lastPersistedAgeMs: Math.max(0, Date.now() - session.savedAt),
          events: session.events,
          completeness: {
            totalEvents: session.totalEvents,
            droppedCapacity: session.droppedCapacity,
            droppedAge: session.droppedAge,
            droppedOperations: session.droppedOperations,
            unfinishedOperationsAtLastWrite: session.unfinishedOperations,
          },
        })),
    };
  }
  dispose() {
    if (this.timer) clearInterval(this.timer);
    this.generation++;
    this.offAgent?.();
    this.channel?.close();
    this.store.diagnostics.clear();
    controllers.delete(this.store.diagnostics);
  }
}
