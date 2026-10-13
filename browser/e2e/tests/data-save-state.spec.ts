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
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(warning).toBeVisible();
  await context.setOffline(false);
  await waitForSynced(page);
  await expect(warning).not.toBeVisible();
});

test('unavailable local storage keeps the edit visible and offers retry', async ({
  page,
  browserDiagnostics,
}) => {
  await before({ page });
  const subject = await page.evaluate(() => window.store.getDrive());
  if (!subject) throw new Error('Dev drive missing');
  await page.goto(
    `${FRONTEND_URL}/app/data?subject=${encodeURIComponent(subject)}`,
  );
  await expect(
    page.getByRole('heading', { name: 'Code', exact: true }),
  ).toBeVisible();
  await page.waitForFunction(() => window.store.getClientDb()?.isReady);
  await page.evaluate(async targetSubject => {
    const store = window.store;
    store.disconnect();
    Object.defineProperty(store.getClientDb(), 'unsupportedEnvironment', {
      configurable: true,
      value: true,
    });
    const resource = await store.getResource(targetSubject);
    await resource.set(
      'https://atomicdata.dev/properties/description',
      'Keep my unsaved edit',
      false,
    );
  }, subject);
  browserDiagnostics.expect(
    'error',
    /Changes could not be saved on this device/,
    'Explicitly unavailable local storage must report save failure',
    1,
  );
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(
    page.getByText(/Changes could not be saved on this device/).first(),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Retry save', exact: true }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      targetSubject =>
        window.store
          .getResourceLoading(targetSubject)
          .get('https://atomicdata.dev/properties/description'),
      subject,
    ),
  ).toBe('Keep my unsaved edit');
  await page.evaluate(() => {
    Object.defineProperty(
      window.store.getClientDb(),
      'unsupportedEnvironment',
      { configurable: true, value: false },
    );
  });
  await page.getByRole('button', { name: 'Retry save', exact: true }).click();
  await expect(
    page.getByRole('button', { name: 'Retry save', exact: true }),
  ).not.toBeVisible();
  await page.reload();
  await page.waitForFunction(() => window.store?.getClientDb()?.isReady);
  expect(
    await page.evaluate(
      async targetSubject =>
        (await window.store.getResource(targetSubject)).get(
          'https://atomicdata.dev/properties/description',
        ),
      subject,
    ),
  ).toBe('Keep my unsaved edit');
});
