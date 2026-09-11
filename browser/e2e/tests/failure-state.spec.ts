import { test, expect } from './fixtures';
import { collectFailureState } from './failure-state';

test('failure state is bounded and excludes values and signed payloads', async ({
  page,
}) => {
  await page.evaluate(() => {
    const resource = {
      subject: 'did:ad:test',
      readState: 'ready',
      isSaving: false,
      hasPendingCommits: true,
      hasUnsavedChanges: () => true,
      getEntries: () => [['secret', 'DO_NOT_ATTACH']],
    };
    window.store = {
      resources: new Map(
        Array.from({ length: 100 }, (_, i) => [String(i), resource]),
      ),
      getSyncStatus: () => ({ pendingDirtyCount: 1 }),
      getCommitLog: () =>
        Array.from({ length: 100 }, () => ({
          subject: 'did:ad:test',
          direction: 'outgoing',
          status: 'pending',
          summary: 'DO_NOT_ATTACH',
          loroUpdate: 'DO_NOT_ATTACH',
        })),
    } as unknown as typeof window.store;
  });
  const state = (await collectFailureState(page)) as {
    resources: unknown[];
    recentCommits: unknown[];
  };
  expect(state.resources).toHaveLength(50);
  expect(state.recentCommits).toHaveLength(20);
  expect(JSON.stringify(state)).not.toContain('DO_NOT_ATTACH');
});
