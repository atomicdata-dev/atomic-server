import { test, expect } from './fixtures';
import {
  before,
  contextMenuClick,
  editableTitle,
  editTitle,
  newResource,
} from './test-utils';

/**
 * A *draft* is unpublished new content — not a class, but a place. "New draft"
 * creates a resource in the drive's private Drafts folder; publishing it later
 * is simply moving it somewhere publicly readable. This is distinct from a Fork
 * (see `forks.spec.ts`), which proposes a change to an existing resource.
 */
test.describe('drafts (unpublished new content)', () => {
  test.beforeEach(before);

  // The "New draft" context-menu action was removed; drafts are meant to be
  // created through the New page instead, which doesn't offer them yet.
  // Re-enable (and re-route) this test when the New page grows that flow.
  test.fixme('New draft creates content in the drive’s Drafts folder', async ({
    page,
  }) => {
    // Start on a resource so the app has a drive context.
    await newResource('folder', page);
    await editTitle('Anchor', page);

    // "New draft" opens the new-resource picker parented to the Drafts folder.
    await contextMenuClick('newDraft', page);
    await expect(page).toHaveURL(/\/app\/new(\?|$)/);

    // Pick a class for the draft, then name it.
    const classButton = page.locator('button:has-text("Folder")');
    await classButton.waitFor({ state: 'visible', timeout: 30000 });
    await classButton.click();
    await editTitle('My unpublished post', page);

    // It lives in the auto-created, private "Drafts" folder — its parent.
    await contextMenuClick('parent', page);
    await expect(editableTitle(page)).toHaveText('Drafts');
  });
});
