import { ResourceEvents, type Resource } from './resource.js';
import { ScheduledSave, type ResourceSaveState } from './scheduled-save.js';
import type { OutboxEntry } from './local-outbox.js';

interface SaveStatusDependencies {
  getOutboxEntry: (
    subject: string,
  ) => Pick<OutboxEntry, 'blocked' | 'lastAttemptError'> | undefined;
  isConnected: () => boolean;
  changePending: (delta: number) => void;
  subscribeSync: (callback: () => void) => () => void;
  onError: (error: Error) => void;
}

/** Derives save status and owns scheduler accounting, never persistence itself. */
export class SaveStatusCoordinator {
  constructor(private dependencies: SaveStatusDependencies) {}

  private scheduledByResource = new WeakMap<Resource, number>();
  private saveSnapshots = new WeakMap<Resource, ResourceSaveState>();

  /** One owner per debounce slot. Resource identity survives genesis renaming. */
  createScheduler(
    resource: Resource,
    options: {
      shouldSave?: () => boolean;
      onError?: (error: Error) => void;
    } = {},
  ): ScheduledSave {
    const target = resource.__internalObject;

    return new ScheduledSave(
      async () => {
        if (options.shouldSave?.() !== false) await target.save();
      },
      delta => {
        this.scheduledByResource.set(
          target,
          (this.scheduledByResource.get(target) ?? 0) + delta,
        );
        this.dependencies.changePending(delta);
      },
      options.onError ?? (error => this.dependencies.onError(error)),
    );
  }

  /** Read status is separate: a queued offline edit can still be fully readable. */
  getState(resource: Resource): ResourceSaveState {
    const target = resource.__internalObject;
    const scheduledCount = this.scheduledByResource.get(target) ?? 0;
    const entry = this.dependencies.getOutboxEntry(target.subject);
    const error = entry?.lastAttemptError ?? target.commitError?.message;
    let kind: ResourceSaveState['kind'];
    if (target.isSaving) kind = 'saving';
    else if (scheduledCount) kind = 'scheduled';
    else if (entry?.blocked) kind = 'error';
    else if (entry) kind = 'queued';
    else if (error) kind = 'error';
    else if (target.hasUnsavedChanges()) kind = 'dirty';
    else kind = 'idle';
    const queuedReason = this.dependencies.isConnected() ? 'retry' : 'offline';
    const reason = kind === 'queued' ? queuedReason : undefined;
    const previous = this.saveSnapshots.get(target);
    if (
      previous?.kind === kind &&
      previous.scheduledCount === scheduledCount &&
      previous.error === error &&
      previous.reason === reason
    )
      return previous;
    const state = Object.freeze({ kind, scheduledCount, error, reason });
    this.saveSnapshots.set(target, state);

    return state;
  }

  subscribe(resource: Resource, callback: () => void): () => void {
    const target = resource.__internalObject;
    const unsubscribers = [
      this.dependencies.subscribeSync(callback),
      target.on(ResourceEvents.LocalChange, callback),
      target.on(ResourceEvents.SaveStateChange, callback),
    ];

    return () => unsubscribers.forEach(unsubscribe => unsubscribe());
  }
}
