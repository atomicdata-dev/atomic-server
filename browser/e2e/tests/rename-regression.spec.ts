/**
 * Regression: when a user edits a resource's title via character-by-character
 * typing, every commit must land on the server. Prior bugs in this chain:
 *
 *   1. `resource.ts` reset the Loro doc on every JSON-AD hydration, so each
 *      save got a fresh peer whose ops were concurrent with stored state.
 *   2. The client exported Loro deltas whose Lamport timestamps could be
 *      behind stored state, causing the server's LWW merge to silently
 *      discard the client's writes.
 *
 * Both are fixed: the doc is preserved across hydrations, and the client
 * now exports full Loro snapshots per commit. The server's causality guard
 * (see `lib/src/commit.rs::validate_loro_causality`) catches any remaining
 * concurrent-write commits with a clear error.
 */
import { test, expect, Page } from '@playwright/test';
import { before, editableTitle, newDrive } from './test-utils';

async function renameDrive(page: Page, text: string) {
  await editableTitle(page).click();
  await expect(editableTitle(page)).toHaveRole('textbox', { timeout: 10000 });
  await editableTitle(page).fill('');
  await editableTitle(page).type(text, { delay: 30 });
  await page.keyboard.press('Escape');
  // Bumped from 15s → 30s. Under parallel load (many tests hammering the
  // server at once) the dirty-sync can take longer than the original budget.
  // In isolation, this completes in <1s.
  await page.waitForFunction(
    () => {
      const status = window.store?.getSyncStatus();

      return status.serverConnected && status.pendingDirtyCount === 0;
    },
    undefined,
    { timeout: 30000 },
  );
}

test.describe('drive rename regression', () => {
  test.beforeEach(before);

  test('multi-character rename persists across reload', async ({ page }) => {
    // `/app/dev-drive` opens the agent's private drive, whose title is locked
    // (it is derived from the key, not a project). Rename a project drive.
    await newDrive(page);
    await expect(editableTitle(page)).toBeVisible({ timeout: 15000 });

    await renameDrive(page, 'Persistent Drive Name');
    await expect(editableTitle(page)).toHaveText('Persistent Drive Name');

    await page.reload();
    await expect(editableTitle(page)).toHaveText('Persistent Drive Name', {
      timeout: 15000,
    });
  });

  test('two sequential renames both persist across reload', async ({
    page,
  }) => {
    await newDrive(page);
    await expect(editableTitle(page)).toBeVisible({ timeout: 15000 });

    await renameDrive(page, 'First Name');
    await expect(editableTitle(page)).toHaveText('First Name');

    await renameDrive(page, 'Second Name');
    await expect(editableTitle(page)).toHaveText('Second Name');

    await page.reload();
    await expect(editableTitle(page)).toHaveText('Second Name', {
      timeout: 15000,
    });
  });
});
