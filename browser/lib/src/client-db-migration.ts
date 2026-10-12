/**
 * Progress of a one-off migration of the local database: the rebuild of its
 * indexes when it was written with an older key layout, then the move of old
 * chat messages into chat log pages. The database is not usable until they are
 * done, so the app shows this while they run.
 */
export interface IndexMigrationProgress {
  /** Resources handled so far. */
  done: number;
  /** Resources to handle; 0 until the worker has counted them. */
  total: number;
  finished: boolean;
  /** What is being done; the index rebuild when absent. */
  phase?: 'messages';
}

type Listener = (progress: IndexMigrationProgress | undefined) => void;

let current: IndexMigrationProgress | undefined;
const listeners = new Set<Listener>();

/** The rebuild under way, or `undefined` when none is. */
export function getIndexMigration(): IndexMigrationProgress | undefined {
  return current;
}

/** Called with every step, and with `undefined` once it is over. */
export function subscribeIndexMigration(listener: Listener): () => void {
  listeners.add(listener);

  return () => {
    listeners.delete(listener);
  };
}

/** Used by the database wrapper; not for app code. */
export function publishIndexMigration(progress: IndexMigrationProgress): void {
  current = progress.finished ? undefined : progress;
  listeners.forEach(listener => listener(current));
}
