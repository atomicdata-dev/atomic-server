import { test, expect, type Page } from './fixtures';
import { before, FRONTEND_URL, newDrive, signIn } from './test-utils';

const props = {
  name: 'https://atomicdata.dev/properties/name',
  shortname: 'https://atomicdata.dev/properties/shortname',
  description: 'https://atomicdata.dev/properties/description',
  datatype: 'https://atomicdata.dev/properties/datatype',
  recommends: 'https://atomicdata.dev/properties/recommends',
};

/**
 * A class with one JSON property, built in the drive under test.
 *
 * This used to point at a class hosted on the public `atomicdata.dev`, which
 * made the test fail whenever that server was slow or unreachable — and fail
 * as "the form never rendered", which names neither the server nor the
 * network. Nothing here needs a *remote* class, only a JSON-typed field, so
 * build one locally and keep the test's dependencies inside its own drive.
 */
async function createClassWithJsonProp(page: Page): Promise<string> {
  await page.waitForFunction(
    () =>
      window.store?.getClientDb()?.isReady === true &&
      window.store?.getSyncStatus().serverConnected === true,
    undefined,
    { timeout: 30_000 },
  );

  return page.evaluate(async p => {
    const store = window.store;
    const drive = store.getDrive();

    const jsonProp = await store.newResource({
      parent: drive,
      isA: 'https://atomicdata.dev/classes/Property',
      propVals: {
        [p.shortname]: 'test-json-prop',
        [p.datatype]: 'https://atomicdata.dev/datatypes/json',
        [p.description]: 'A JSON field, for testing the JSON editor',
      },
    });
    await jsonProp.save();

    const cls = await store.newResource({
      parent: drive,
      isA: 'https://atomicdata.dev/classes/Class',
      propVals: {
        [p.shortname]: 'test-class-with-json-prop',
        [p.description]: 'A class with a JSON prop, made for this test',
        [p.recommends]: [p.name, jsonProp.subject],
      },
    });
    await cls.save();

    return cls.subject;
  }, props);
}

test.describe('JSON prop', () => {
  test.beforeEach(before);

  test('create JSON prop', async ({ page }) => {
    await signIn(page);
    await newDrive(page);

    const classSubject = await createClassWithJsonProp(page);
    // Straight to the form for that class. `newResource` cannot be used here:
    // it treats anything not starting with `https://` as a shortname, and a
    // class built in this drive has a `did:ad:` subject.
    await page.goto(
      `${FRONTEND_URL}/app/new?classSubject=${encodeURIComponent(classSubject)}`,
    );

    await expect(
      page.getByRole('heading', { name: 'new test-class-with-json-prop' }),
    ).toBeVisible();

    const name = `Instance: ${Date.now()}`;
    await page.getByLabel('Name').fill(name);

    const jsonEditor = page.getByLabel('Test-Json-Prop');
    await expect(jsonEditor).toBeVisible();
    await jsonEditor.fill('{"valid": false,}');

    const saveButton = page.getByRole('button', { name: 'Save' });
    await expect(saveButton).toBeDisabled();

    await jsonEditor.fill('{"valid": true}');
    await expect(saveButton).not.toBeDisabled();

    await saveButton.click();

    // After save, EditableTitle auto-enters edit mode (renders as a textbox);
    // match either the input or the h1 form via the test-id.
    await expect(
      page
        .getByTestId('editable-title')
        .and(page.locator(`:text-is("${name}"), [value="${name}"]`))
        .first(),
    ).toBeVisible();

    await expect(page.getByText('{\n  "valid": true\n  }')).toHaveRole('code');
  });
});
