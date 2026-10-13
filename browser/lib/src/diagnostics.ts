/** Content-free, opt-in diagnostics. No storage, network, or arbitrary payloads. */
export enum DiagnosticCode {
  SaveStarted = 'save-started',
  SavePersisted = 'save-persisted',
  SaveOffline = 'save-offline',
  SaveQueued = 'save-queued',
  SaveNoop = 'save-noop',
  SaveError = 'save-error',
  SaveSlow = 'save-slow',
  Connected = 'connected',
  Disconnected = 'disconnected',
  Queue = 'queue',
  QueueStalled = 'queue-stalled',
  DrainStarted = 'drain-started',
  DrainSettled = 'drain-settled',
  DrainError = 'drain-error',
  LocalStarted = 'local-persist-started',
  LocalAcknowledged = 'local-persist-acknowledged',
  LocalError = 'local-persist-error',
  LocalSkipped = 'local-persist-skipped',
  ServerStarted = 'server-request-started',
  ServerAcknowledged = 'server-acknowledged',
  ServerUnconfirmed = 'server-unconfirmed',
  ReconcileStarted = 'reconcile-started',
  ReconcileCompleted = 'reconcile-completed',
  ReconcileError = 'reconcile-error',
  OperationCancelled = 'operation-cancelled',
}

export interface DiagnosticEvent {
  readonly sequence: number;
  readonly elapsedMs: number;
  readonly code: DiagnosticCode;
  readonly resource?: number;
  readonly operation?: number;
  readonly pending?: number;
  readonly blocked?: number;
  readonly attempt?: number;
}

export type DiagnosticBoundary = 'local' | 'server' | 'drain' | 'reconcile';
export type DiagnosticBoundaryOutcome =
  | 'ok'
  | 'error'
  | 'skipped'
  | 'cancelled';
const boundaryCodes = {
  local: [
    DiagnosticCode.LocalStarted,
    DiagnosticCode.LocalAcknowledged,
    DiagnosticCode.LocalError,
  ],
  server: [
    DiagnosticCode.ServerStarted,
    DiagnosticCode.ServerAcknowledged,
    DiagnosticCode.ServerUnconfirmed,
  ],
  drain: [
    DiagnosticCode.DrainStarted,
    DiagnosticCode.DrainSettled,
    DiagnosticCode.DrainError,
  ],
  reconcile: [
    DiagnosticCode.ReconcileStarted,
    DiagnosticCode.ReconcileCompleted,
    DiagnosticCode.ReconcileError,
  ],
} as const;

type SaveOutcome = 'persisted' | 'offline' | 'queued' | 'noop' | 'error';
const outcomes: Record<SaveOutcome, DiagnosticCode> = {
  persisted: DiagnosticCode.SavePersisted,
  offline: DiagnosticCode.SaveOffline,
  queued: DiagnosticCode.SaveQueued,
  noop: DiagnosticCode.SaveNoop,
  error: DiagnosticCode.SaveError,
};
const count = (value: number) =>
  Number.isFinite(value)
    ? Math.min(100_000, Math.max(0, Math.floor(value)))
    : 0;

/** One instance per Store. Aliases cannot link identities across recording sessions. */
export class DiagnosticRecorder {
  private events: DiagnosticEvent[] = [];
  private aliases = new WeakMap<object, number>();
  private nextAlias = 0;
  private nextOperation = 0;
  private sequence = 0;
  private droppedCapacity = 0;
  private droppedAge = 0;
  private droppedOperations = 0;
  private pendingBoundaries = new Set<number>();
  private attempts = new WeakMap<
    object,
    Partial<Record<DiagnosticBoundary, number>>
  >();
  private started = 0;
  private continuous = false;

  /** Local retention bookkeeping only; never include wall-clock time in exports. */
  get startedAt(): number {
    return this.started;
  }
  private timer: ReturnType<typeof setInterval> | undefined;
  private generation = 0;
  private saves = new Map<
    number,
    { resource: number; since: number; warned: boolean }
  >();
  private queueState = {
    pending: 0,
    blocked: 0,
    connected: false,
    since: 0,
    warned: false,
  };
  private listeners = new Set<() => void>();

  get active(): boolean {
    return this.timer !== undefined;
  }
  /** Changes only on start/clear/expiry; suitable for useSyncExternalStore. */
  get session(): number {
    return this.generation;
  }
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);

    return () => {
      this.listeners.delete(listener);
    };
  };

  start(options: { continuous?: boolean } = {}): void {
    this.clear();
    this.continuous = options.continuous ?? false;
    this.started = Date.now();
    this.timer = setInterval(() => this.tick(), 10_000);
    this.generation++;
    this.changed();
  }

  clear(): void {
    if (this.timer !== undefined) clearInterval(this.timer);
    this.timer = undefined;
    this.events = [];
    this.saves.clear();
    this.aliases = new WeakMap();
    this.nextAlias = 0;
    this.nextOperation = 0;
    this.sequence = 0;
    this.droppedCapacity = 0;
    this.droppedAge = 0;
    this.droppedOperations = 0;
    this.pendingBoundaries.clear();
    this.attempts = new WeakMap();
    this.queueState = {
      pending: 0,
      blocked: 0,
      connected: false,
      since: 0,
      warned: false,
    };
    this.generation++;
    this.changed();
  }

  private changed(): void {
    for (const listener of this.listeners) {
      // Diagnostics consumers must never break a save or account switch.
      try {
        listener();
      } catch {
        /* best effort UI notification */
      }
    }
  }

  private tick(): void {
    if (!this.active) return;

    if (!this.continuous && Date.now() - this.started >= 30 * 60_000) {
      this.clear();

      return;
    }

    const before = this.events.length;
    this.events = this.events.filter(
      event => event.elapsedMs > Date.now() - this.started - 10 * 60_000,
    );

    this.droppedAge += before - this.events.length;

    for (const [operation, save] of this.saves) {
      if (!save.warned && Date.now() - save.since >= 30_000) {
        save.warned = true;
        this.push(DiagnosticCode.SaveSlow, save.resource, operation);
      }
    }

    const queue = this.queueState;

    if (
      queue.connected &&
      queue.pending > 0 &&
      !queue.warned &&
      Date.now() - queue.since >= 60_000
    ) {
      queue.warned = true;
      this.push(
        DiagnosticCode.QueueStalled,
        undefined,
        undefined,
        queue.pending,
        queue.blocked,
      );
    }
  }

  private push(
    code: DiagnosticCode,
    resource?: number,
    operation?: number,
    pending?: number,
    blocked?: number,
    attempt?: number,
  ): void {
    if (!this.active) return;

    if (!this.continuous && Date.now() - this.started >= 30 * 60_000) {
      this.clear();

      return;
    }

    // Explicit construction: never copy arbitrary objects into a report.
    this.events.push({
      sequence: ++this.sequence,
      elapsedMs: Math.max(0, Date.now() - this.started),
      code,
      resource,
      operation,
      pending,
      blocked,
      attempt,
    });

    if (this.events.length > 500) {
      this.events.shift();
      this.droppedCapacity++;
    }
  }

  snapshot(): readonly DiagnosticEvent[] {
    this.tick();

    return this.events.map(event => ({ ...event }));
  }

  connection(connected: boolean): void {
    if (!this.active) return;
    this.push(
      connected ? DiagnosticCode.Connected : DiagnosticCode.Disconnected,
    );
    this.queue(this.queueState.pending, this.queueState.blocked, connected);
  }

  queue(pending: number, blocked: number, connected: boolean): void {
    if (!this.active) return;
    pending = count(pending);
    blocked = count(blocked);
    const previous = this.queueState;
    if (
      previous.pending === pending &&
      previous.blocked === blocked &&
      previous.connected === connected
    )
      return;
    this.queueState = {
      pending,
      blocked,
      connected,
      since: Date.now(),
      warned: false,
    };
    this.push(DiagnosticCode.Queue, undefined, undefined, pending, blocked);
  }

  /** Snapshot once so completeness and the event window describe the same instant. */
  capture() {
    const events = this.snapshot();

    return {
      events,
      completeness: {
        recordingActive: this.active,
        recordingAgeMs: this.active
          ? Math.max(0, Date.now() - this.started)
          : 0,
        firstRetainedSequence: events[0]?.sequence ?? null,
        lastRetainedSequence: events.at(-1)?.sequence ?? null,
        totalEvents: this.sequence,
        droppedCapacity: this.droppedCapacity,
        droppedAge: this.droppedAge,
        droppedOperations: this.droppedOperations,
        unfinishedOperations: this.saves.size + this.pendingBoundaries.size,
        maxEvents: 500,
        maxTrackedOperationsPerKind: 500,
        retentionMs: 10 * 60_000,
        recordingLimitMs: this.continuous ? null : 30 * 60_000,
        saveSlowMs: 30_000,
        queueStalledMs: 60_000,
        timerResolutionMs: 10_000,
      },
    };
  }

  private alias(target?: object): number | undefined {
    if (!target) return undefined;
    let alias = this.aliases.get(target);

    if (alias === undefined) {
      alias = ++this.nextAlias;
      this.aliases.set(target, alias);
    }

    return alias;
  }

  beginBoundary(
    boundary: DiagnosticBoundary,
    target?: object,
  ): (outcome: DiagnosticBoundaryOutcome) => void {
    if (!this.active) return () => {};
    const codes = boundaryCodes[boundary];
    const session = this.session;
    const resource = this.alias(target);
    const operation = ++this.nextOperation;
    let attempt: number | undefined;

    if (target) {
      const attempts = this.attempts.get(target) ?? {};
      attempt = (attempts[boundary] ?? 0) + 1;
      attempts[boundary] = attempt;
      this.attempts.set(target, attempts);
    }

    if (this.pendingBoundaries.size >= 500) {
      this.pendingBoundaries.delete(
        this.pendingBoundaries.values().next().value!,
      );
      this.droppedOperations++;
    }

    this.pendingBoundaries.add(operation);
    this.push(codes[0], resource, operation, undefined, undefined, attempt);

    return outcome => {
      if (session !== this.session || !this.pendingBoundaries.delete(operation))
        return;
      const code =
        outcome === 'cancelled'
          ? DiagnosticCode.OperationCancelled
          : outcome === 'skipped' && boundary === 'local'
            ? DiagnosticCode.LocalSkipped
            : outcome === 'ok'
              ? codes[1]
              : codes[2];
      this.push(code, resource, operation, undefined, undefined, attempt);
    };
  }

  beginDrain(target?: object): (failed: boolean) => void {
    const finish = this.beginBoundary('drain', target);

    return failed => finish(failed ? 'error' : 'ok');
  }

  beginSave(target: object): (outcome: SaveOutcome) => void {
    if (!this.active) return () => {};
    const resource = this.alias(target)!;

    const operation = ++this.nextOperation;
    const session = this.session;

    // Bound unfinished operation tracking too, even if promises never settle.
    if (this.saves.size >= 500) {
      this.saves.delete(this.saves.keys().next().value!);
      this.droppedOperations++;
    }

    this.saves.set(operation, { resource, since: Date.now(), warned: false });
    this.push(DiagnosticCode.SaveStarted, resource, operation);

    return outcome => {
      if (session !== this.session || !this.saves.delete(operation)) return;
      this.push(
        Object.hasOwn(outcomes, outcome)
          ? outcomes[outcome]
          : DiagnosticCode.SaveError,
        resource,
        operation,
      );
    };
  }
}
