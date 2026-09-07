import { test, expect } from './fixtures';
import {
  before,
  contextMenuClick,
  editableTitle,
  editTitle,
  getCurrentSubject,
  openSubject,
  newResource,
} from './test-utils';

/**
 * The fork flow end to end against a real server: Edit as fork forks a
 * resource, editing the fork leaves the original alone, and Merge writes the
 * fork's change back onto the original. Also exercises the `forks` ontology
 * being seeded on the server and in the WASM client store.
 *
 * Concurrent-merge correctness (three-way, conflict detection) is covered
 * deterministically by the unit tests in `@tomic/lib` — `forks.test.ts`.
 */
test.describe('forks', () => {
  test.beforeEach(before);

  test('edit as fork, then merge, applies the change to the original', async ({
    page,
  }) => {
    await newResource('folder', page);
    await editTitle('Original Cheese', page);
    const originalSubject = await getCurrentSubject(page);

    // Fork it. Lands on the fork's normal view with the fork bar above it.
    await contextMenuClick('editAsFork', page);
    await expect(page.getByText('Fork of')).toBeVisible();

    const forkSubject = await getCurrentSubject(page);
    expect(forkSubject).not.toBe(originalSubject);

    // The original is untouched while the fork is edited.
    await editTitle('Revised Cheese', page);

    // Merge from the fork bar.
    await page.getByRole('button', { name: 'Merge' }).click();

    // Back on the original, now carrying the fork's title, with no fork bar.
    await expect(page).toHaveURL(
      new RegExp(encodeURIComponent(originalSubject)),
    );
    await expect(editableTitle(page)).toHaveText('Revised Cheese');
    await expect(page.getByText('Fork of')).toBeHidden();
  });

  test('the original shows the forks that propose changes to it', async ({
    page,
  }) => {
    await newResource('folder', page);
    await editTitle('Reviewable', page);
    const originalSubject = await getCurrentSubject(page);

    await contextMenuClick('editAsFork', page);
    await expect(page.getByText('Fork of')).toBeVisible();
    await editTitle('Proposed rename', page);

    // A reviewer opening the original discovers the fork with no inbox — a
    // reverse query over the drive, surfaced above the resource.
    await openSubject(page, originalSubject);
    await expect(
      page.getByText('1 fork proposes a change to this'),
    ).toBeVisible();
    await expect(
      page.getByRole('link', { name: 'Proposed rename' }),
    ).toBeVisible();
  });

  test('discard removes the fork and returns to the original', async ({
    page,
  }) => {
    await newResource('folder', page);
    await editTitle('Keep Me', page);
    const originalSubject = await getCurrentSubject(page);

    await contextMenuClick('editAsFork', page);
    await expect(page.getByText('Fork of')).toBeVisible();
    const forkSubject = await getCurrentSubject(page);

    await page.getByRole('button', { name: 'Discard' }).click();

    // Back on the original, unchanged, and the fork is gone.
    await expect(page).toHaveURL(
      new RegExp(encodeURIComponent(originalSubject)),
    );
    await expect(editableTitle(page)).toHaveText('Keep Me');
    await expect(page.getByText('Fork of')).toBeHidden();
    expect(forkSubject).not.toBe(originalSubject);
  });

  // A document's text lives in a Loro `doc` container, not in propvals, so its
  // fork carries a `forkVersion` and the merge is a CRDT body merge — not the
  // three-way propval squash the other tests exercise. The fork bar must offer
  // Merge on the strength of the body alone (no changed property), and the
  // body edit must land on the original.
  test('edit a document body as a fork, then merge, applies the body edit', async ({
    page,
  }) => {
    test.slow();

    await newResource('document', page);
    await editTitle('Manifesto', page);
    const originalSubject = await getCurrentSubject(page);

    await expect(page.getByText('loading...')).not.toBeVisible();
    const editor = page.getByLabel('Rich Text Editor');
    await expect(editor).toBeVisible({ timeout: 30000 });
    await editor.click();
    await page.keyboard.type('The seed line.');
    await expect(page.getByText('The seed line.')).toBeVisible();

    // Fork the document. The fork renders through the same document view, its
    // body seeded from the original, with the fork bar above it.
    await contextMenuClick('editAsFork', page);
    await expect(page.getByText('Fork of')).toBeVisible();
    const forkSubject = await getCurrentSubject(page);
    expect(forkSubject).not.toBe(originalSubject);

    // The seeded body came along.
    const forkEditor = page.getByLabel('Rich Text Editor');
    await expect(forkEditor).toBeVisible({ timeout: 30000 });
    await expect(page.getByText('The seed line.')).toBeVisible();

    // Add a paragraph on the fork only.
    await forkEditor.click();
    await page.keyboard.press('End');
    await page.keyboard.press('Enter');
    await page.keyboard.type('Added on the fork.');
    await expect(page.getByText('Added on the fork.')).toBeVisible();

    // No propval changed — Merge is offered purely because the body did.
    const mergeButton = page.getByRole('button', { name: 'Merge' });
    await expect(mergeButton).toBeEnabled();
    await mergeButton.click();

    // Back on the original, now carrying the fork's body edit, no fork bar.
    await expect(page).toHaveURL(
      new RegExp(encodeURIComponent(originalSubject)),
    );
    await expect(page.getByText('Fork of')).toBeHidden();
    await expect(page.getByText('The seed line.')).toBeVisible();
    await expect(page.getByText('Added on the fork.')).toBeVisible();
  });
});
