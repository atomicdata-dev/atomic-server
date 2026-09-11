/** Owns one debounce slot and any saves already started from it.
 * Cancellation affects only the slot; in-flight persistence always settles.
 */
export class ScheduledSave {
  private timer: ReturnType<typeof setTimeout> | undefined;
  private running = new Set<Promise<void>>();

  constructor(
    private save: () => Promise<unknown>,
    private changePending: (delta: number) => void,
    private onError: (error: Error) => void,
  ) {}

  setErrorHandler(handler: (error: Error) => void): void {
    this.onError = handler;
  }

  schedule(delay: number): void {
    const newlyQueued = this.timer === undefined;
    if (!newlyQueued) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      void this.flush();
    }, delay);
    // Publish only after cancel/flush can see the slot. Subscribers can run synchronously.
    if (newlyQueued) this.changePending(1);
  }

  cancel(): void {
    if (this.timer === undefined) return;
    clearTimeout(this.timer);
    this.timer = undefined;
    this.changePending(-1);
  }

  /** Flush on unmount when cancelling would discard the owner's last edit. */
  async flush(): Promise<void> {
    if (this.timer !== undefined) {
      clearTimeout(this.timer);
      this.timer = undefined;
      const task = Promise.resolve()
        .then(async () => {
          await this.save();
        })
        .catch(error => {
          this.onError(
            error instanceof Error ? error : new Error(String(error)),
          );
        })
        .finally(() => {
          this.running.delete(task);
          this.changePending(-1);
        });
      this.running.add(task);
    }

    await Promise.all(this.running);
  }
}

export interface ResourceSaveState {
  readonly kind: 'idle' | 'dirty' | 'scheduled' | 'saving' | 'queued' | 'error';
  readonly scheduledCount: number;
  readonly error: string | undefined;
  readonly reason: 'offline' | 'retry' | undefined;
}
