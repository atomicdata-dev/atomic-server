import { normalizeLoroChangeTimestampMs, type Resource } from '@tomic/react';

/**
 * Millisecond timestamp of the newest change in the resource's own Loro
 * oplog (one `getChangeAt` per peer, no commit fetch), falling back to its
 * creation time. `undefined` while nothing is loaded.
 */
export function lastEditedAt(resource: Resource): number | undefined {
  const doc = resource.getLoroDoc();
  let latest = 0;

  if (doc) {
    try {
      for (const [peer, end] of doc.oplogVersion().toJSON()) {
        if (end > 0) {
          const { timestamp } = doc.getChangeAt({ peer, counter: end - 1 });

          latest = Math.max(latest, normalizeLoroChangeTimestampMs(timestamp));
        }
      }
    } catch {
      // Unreadable oplog: fall back to the creation time below.
    }
  }

  return latest > 0 ? latest : resource.getCreatedAt();
}
