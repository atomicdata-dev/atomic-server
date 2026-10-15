import {
  HYDRATION_COMMIT_MESSAGE,
  normalizeLoroChangeTimestampMs,
  type Resource,
} from '@tomic/react';

/** Changes walked back per peer past hydration commits before giving up. */
const MAX_STEPS_PER_PEER = 8;

/**
 * Millisecond timestamp of the newest change in the resource's own Loro
 * oplog (one `getChangeAt` per peer, no commit fetch), falling back to its
 * creation time. Hydration commits (a doc seeded from server propvals, stamped
 * with the import time) are not edits and are skipped. `undefined` when
 * nothing is loaded or the only known time would be the import.
 */
export function lastEditedAt(resource: Resource): number | undefined {
  const doc = resource.getLoroDoc();
  let latest = 0;

  if (doc) {
    try {
      for (const [peer, end] of doc.oplogVersion().toJSON()) {
        if (end > 0) {
          let counter = end - 1;

          for (let i = 0; i < MAX_STEPS_PER_PEER && counter >= 0; i++) {
            const change = doc.getChangeAt({ peer, counter });

            if (change.message !== HYDRATION_COMMIT_MESSAGE) {
              latest = Math.max(
                latest,
                normalizeLoroChangeTimestampMs(change.timestamp),
              );
              break;
            }

            counter = change.counter - 1;
          }
        }
      }
    } catch {
      // Unreadable oplog: fall back to the creation time below.
    }
  }

  return latest > 0 ? latest : resource.getCreatedAt();
}
