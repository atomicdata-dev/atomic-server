import type { RestoreOutcome } from './vault';

/** Recovery state must not depend on whether translated warning copy exists. */
export function restoreIsIncomplete(outcome: RestoreOutcome): boolean {
  return (
    outcome.completeness === 'partial' ||
    outcome.objectsUnreadable > 0 ||
    (outcome.objectsMissing ?? 0) > 0 ||
    outcome.incomplete !== undefined
  );
}

export function incompleteRestoreMessage(outcome: RestoreOutcome): string {
  // This last-resort copy must survive an empty/missing translation catalog.
  return (
    outcome.incomplete?.trim() ||
    /* @wc-ignore */
    'Restore incomplete. Recovered data was kept. Retry with a complete backup and its current key.'
  );
}
