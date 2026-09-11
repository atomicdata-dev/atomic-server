import type { Page } from '@playwright/test';

/** Metadata only: never serialize agent secrets, resource bodies or commit payloads. */
export async function collectFailureState(page: Page): Promise<unknown> {
  return page.evaluate(() => {
    const store = window.store;
    if (!store) return { url: location.href, store: 'unavailable' };
    const subject = new URL(location.href).searchParams.get('subject');
    const resources = Array.from(store.resources.values());
    const relevant = resources.filter(
      r =>
        r.subject === subject ||
        r.hasUnsavedChanges() ||
        r.isSaving ||
        r.error ||
        r.commitError,
    );

    return {
      url: location.href,
      sync: store.getSyncStatus(),
      resourceCount: resources.length,
      resources: relevant.slice(0, 50).map(r => ({
        subject: r.subject,
        readState: r.readState,
        dirty: r.hasUnsavedChanges(),
        saving: r.isSaving,
        pending: r.hasPendingCommits,
        readError: r.error?.name,
        saveError: r.commitError?.name,
        properties: r
          .getEntries()
          .map(([key]) => key)
          .slice(0, 50),
      })),
      recentCommits: store
        .getCommitLog()
        .slice(0, 20)
        .map(entry => ({
          timestamp: entry.timestamp,
          subject: entry.subject,
          direction: entry.direction,
          status: entry.status,
          destroy: entry.destroy,
          hasLoroUpdate: entry.hasLoroUpdate,
        })),
    };
  });
}
