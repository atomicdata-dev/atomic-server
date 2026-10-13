import { expect, type Page } from '@playwright/test';
import { clickPageEdit, waitForSynced } from './test-utils';

/**
 * A bakery website with one document and one product row, opened in
 * "Page edit" mode. Returns locators scoped to the preview iframe.
 */
export async function createBakery(page: Page) {
  await page
    .getByRole('button', { name: 'New Document', exact: true })
    .first()
    .click();
  await page.locator('#document-editor').fill('Fresh bread every morning.');
  await page.getByRole('button', { name: 'More', exact: true }).click();
  await page.keyboard.press('Escape');
  await waitForSynced(page);
  const documentSubject = new URL(page.url()).searchParams.get('subject')!;
  const fixture = await page.evaluate(async document => {
    const store = window.store;
    const props = Object.fromEntries(
      ['name', 'shortname', 'datatype', 'description', 'classtype'].map(
        name => [name, 'https://atomicdata.dev/properties/' + name],
      ),
    );
    const { createWebsite, starterWebsite } = window.atomicE2E.websiteModel;
    const price = await store.newResource({
      parent: store.getDrive(),
      isA: ['https://atomicdata.dev/classes/Property'],
      propVals: {
        [props.name]: 'Price',
        [props.shortname]: 'bread-price',
        [props.datatype]: 'https://atomicdata.dev/datatypes/float',
        [props.description]: 'Bread price',
      },
    });
    await price.save();
    const table = await store.newResource({
      parent: store.getDrive(),
      isA: ['https://atomicdata.dev/classes/Table'],
      propVals: {
        [props.name]: 'Products',
        [props.classtype]: 'https://atomicdata.dev/classes/Resource',
      },
    });
    await table.save();
    const row = await store.newResource({
      parent: table.subject,
      propVals: { [props.name]: 'Sourdough', [price.subject]: 4.5 },
    });
    await row.save();
    const config = starterWebsite('RTE bakery');
    config.pages[0].documents = [document];
    config.pages[0].tables = [
      {
        table: table.subject,
        title: 'Products',
        layout: 'grid',
        rows: [row.subject],
        columns: [
          { property: props.name, label: 'Product' },
          { property: price.subject, label: 'Price' },
        ],
      },
    ];
    const site = await createWebsite(store, store.getDrive()!, config);

    return { subject: site.subject, row: row.subject, price: price.subject };
  }, documentSubject);
  // The @ menu searches the server index; wait until the row is findable so
  // the mention step does not race indexing.
  await expect
    .poll(
      () =>
        page.evaluate(async () =>
          window.store.search('sour', {
            limit: 5,
            include: false,
            parents: [window.store.getDrive()!],
          }),
        ),
      { timeout: 20_000 },
    )
    .toContain(fixture.row);
  // Finish fixture writes before navigation, then wait for the generated
  // preview before switching modes. Startup refreshes can disable the toggle.
  await waitForSynced(page);
  await page.goto(
    `${new URL(page.url()).origin}/app/show?subject=${encodeURIComponent(fixture.subject)}`,
  );
  const frame = page.frameLocator('iframe[title="Website preview"]');
  await expect(
    frame.getByText('Fresh bread every morning.', { exact: true }),
  ).toBeVisible();
  await clickPageEdit(page);
  await expect(
    page.getByRole('button', { name: 'Done editing', exact: true }),
  ).toBeVisible();
  const editor = frame.getByLabel('Rich Text Editor', { exact: true });
  // Deliberately left on the 10 s default: raising it would hide nothing. Over
  // 11 measured rounds this wait is 394, 421, 427, 433, 461, 521, 566, 643, 729
  // or 1031 ms, and in the one round it failed it was 10047 ms with the editor
  // never existing at all. There is no middle, so it is binary rather than slow
  // and a bigger number would only wait longer before failing the same way.
  // Two causes for that have been tested and ruled out already; if it fails
  // here, read `e2e-website-inline-rte-two-flakes` before touching this number.
  await expect(editor).toContainText('Fresh bread every morning.');

  // Emptying the editor commits, and the server echoes that commit back into
  // the live Loro doc. loro-prosemirror rebuilds the whole ProseMirror document
  // on any import, which closes whatever popup the next keystroke just opened
  // (mention list, slash menu, image picker) and can swallow a markdown input
  // rule. Let the echo land before typing into the cleared editor.
  const clear = async () => {
    await expect(async () => {
      // Not `fill('')`: Playwright's fill leaves atom nodes (mention cards)
      // and formatted blocks behind in ProseMirror. The editor's own keys
      // delete whatever the selection covers.
      await editor.press('ControlOrMeta+a');
      await editor.press('Backspace');
      await waitForSynced(page);
      // The echo can rebuild the document with the old text still in it;
      // only an editor that is empty after the sync is really cleared.
      await expect(editor).toHaveText('');
    }).toPass({ timeout: 20_000 });
  };

  return { ...fixture, frame, editor, clear };
}
