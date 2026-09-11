import { test, expect } from './fixtures';
import { before, FRONTEND_URL, waitForSynced } from './test-utils';

test('data inspector reacts to an unsaved edit without replacing its resource', async ({
  page,
  context,
}) => {
  await before({ page });
  const subject = await page.evaluate(async () => {
    const resource = await window.store.newResource({
      isA: 'https://atomicdata.dev/classes/Folder',
      parent: window.store.getDrive(),
      propVals: {
        'https://atomicdata.dev/properties/name': 'Save-state inspection',
      },
    });
    await resource.save();

    return resource.subject;
  });
  await page.goto(
    `${FRONTEND_URL}/app/data?subject=${encodeURIComponent(subject)}`,
  );
  await expect(
    page.getByRole('heading', { name: /Save-state inspection/ }).first(),
  ).toBeVisible();
  await context.setOffline(true);
  await page.evaluate(async rowSubject => {
    const resource = window.store.getResourceLoading(rowSubject);
    await resource.set(
      'https://atomicdata.dev/properties/description',
      'An unsaved edit',
      false,
    );
  }, subject);
  const warning = page.getByRole('heading', {
    name: /contains uncommitted changes/,
  });
  await expect(warning).toBeVisible();
  await page.getByRole('button', { name: 'save', exact: true }).click();
  await expect(warning).toBeVisible();
  await context.setOffline(false);
  await waitForSynced(page);
  await expect(warning).not.toBeVisible();
});
