import { test, expect } from './fixtures';
import { before, newDrive, newResource, setTitle } from './test-utils';

test.describe('tags', () => {
  test.beforeEach(before);

  test('a tagged resource appears in the tag collection', async ({ page }) => {
    // Fresh drive so we don't pollute the shared dev drive, and so the tag
    // lookup has to be answered from this drive's own (local OPFS) index.
    await newDrive(page);

    // Create a resource and give it a recognizable title.
    await newResource('folder', page);
    const folderTitle = `Tagged folder ${Date.now()}`;
    await setTitle(page, folderTitle);

    // Add a tag via the navbar: Tags → type a name → the "+" (Add tag).
    const tagName = 'e2etag';
    await page.getByTestId('navbar-tags-button').click();
    await page.getByPlaceholder('New tag').fill(tagName);
    await page.getByRole('button', { name: 'Add tag' }).click();

    // Creating the tag also applies it to the resource, so it shows as a chip.
    // Close the popover and open the tag's page via that chip.
    await page.keyboard.press('Escape');
    await page.getByRole('link', { name: tagName }).click();

    // The tag page lists the resources referencing it (ReferenceUsage). On a
    // local-first drive this is only correct if the lookup hits the OPFS index
    // (property + value) — the bug this guards against. Scope to <main> so we
    // assert against the reference card, not the sidebar tree (which also
    // contains the folder as a drive child).
    const main = page.getByRole('main');
    await expect(main.getByText(folderTitle)).toBeVisible({ timeout: 15000 });
    await expect(main.getByText('No resources')).toHaveCount(0);
  });
});
