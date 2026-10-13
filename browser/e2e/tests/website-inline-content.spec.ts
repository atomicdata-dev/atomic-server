import { test, expect } from '@playwright/test';
import { before, waitForSynced } from './test-utils';
import { createBakery } from './website-inline-fixture';

test('inline website editing saves rich documents and typed prices to Atomic', async ({
  page,
}) => {
  // The 60s default is not enough for this journey. It creates a website with a
  // table, a Property and a document, opens the preview, edits a typed field and
  // a rich-text document through it, then reloads and checks both survived.
  // Measured over eight four-worker rounds on a 4-core box, the test itself:
  //
  //     40873  44664  46061  46298  49503  50259  51255  52214 ms
  //
  // 52.2s of 60s leaves nothing for a slow step anywhere, and one round in
  // fourteen died on the wall while the post-reload wait was still running,
  // which reports the wall rather than the step that was late. Two of the six
  // rounds run after this change went to 59.6s and 60.0s, so the old wall was
  // being won rather than met. 120s matches `website-inline-rte.spec.ts`, the
  // other test that drives this preview, and keeps the individual action limits
  // doing the work of naming a failure.
  test.setTimeout(120_000);
  await before({ page });
  const fixture = await createBakery(page);
  const { frame, editor, clear } = fixture;
  const priceField = frame.locator('dd [contenteditable]').nth(1);
  await expect(priceField).toHaveText('4.5');
  await priceField.fill('5.75');
  await page.getByText('Click an outlined field', { exact: false }).click();
  await expect
    .poll(() =>
      page.evaluate(
        async ({ row, price }) =>
          (await window.store.getResource(row)).get(price),
        { row: fixture.row, price: fixture.price },
      ),
    )
    .toBe(5.75);
  await expect(editor).toContainText('Fresh bread every morning.');
  await expect(editor.locator('..').locator('..')).toHaveCSS(
    'background-color',
    'rgba(0, 0, 0, 0)',
  );
  await clear();
  await editor.pressSequentially('/heading');
  await expect(frame.getByText('Heading 1', { exact: true })).toBeVisible();
  await editor.press('Enter');
  await editor.pressSequentially('A heading');
  await expect(editor.locator('h1')).toHaveText('A heading');
  await clear();
  await editor.press('ControlOrMeta+Alt+0');
  await editor.pressSequentially('# ');
  await editor.pressSequentially('Markdown heading');
  await expect(editor.locator('h1')).toHaveText('Markdown heading');
  await clear();
  await editor.pressSequentially('@');
  await expect(
    frame.getByText('Products', { exact: true }).last(),
  ).toBeVisible();
  await editor.press('Escape');
  await editor.fill('Fresh pastries every morning.');
  await page.getByText('Click an outlined field', { exact: false }).click();
  await waitForSynced(page);
  await page.getByRole('button', { name: 'Done editing', exact: true }).click();
  await expect(frame.getByText('Fresh pastries every morning.')).toBeVisible();
  await page.reload();
  // The same assertion as the line above, but a reload costs the whole cold path
  // again: the app boots, reads the website config and runs buildWebsiteArtifact
  // before the preview iframe has any content. Measured over eight four-worker
  // rounds on this container, that is the entire difference:
  //
  //     before the reload    613 to 1484 ms
  //     after the reload    2643 to 9990 ms
  //
  // 9990 ms of the 10 s default is a test that passed by ten milliseconds, and
  // the same round it exceeded it outright, with the text never appearing. The
  // "Page edit" click waits on this same build and is already on 30 s for the
  // same reason (`clickPageEdit` in test-utils), so this matches it rather than
  // being a new allowance.
  await expect(frame.getByText('Fresh pastries every morning.')).toBeVisible({
    timeout: 30_000,
  });
  await expect(frame.locator('dd').nth(1)).toHaveText('5.75');
});
