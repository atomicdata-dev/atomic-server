import { test, expect } from '@playwright/test';
import { before, waitForTableBuild } from './test-utils';
test.beforeEach(before);

test('creation catalog searches templates and creates a selected table inside a folder', async ({
  page,
}) => {
  const parent = await page.evaluate(async () => {
    const store = window.store!;
    const folder = await store.newResource({
      parent: store.getDrive(),
      isA: 'https://atomicdata.dev/classes/Folder',
      propVals: { 'https://atomicdata.dev/properties/name': 'My workspace' },
    });
    await folder.save();

    return folder.subject;
  });
  await page.goto(
    new URL(`/app/new?parentSubject=${encodeURIComponent(parent)}`, page.url())
      .href,
  );
  await expect(
    page.getByRole('heading', { name: 'Create something new' }),
  ).toBeVisible();
  const search = page.getByRole('searchbox', {
    name: 'Search templates and resource types',
  });
  await expect(
    page.getByRole('button', {
      name: 'Use Reading list template',
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Use Website template', exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: '/tmp/atomic-new-resource-desktop.png',
    fullPage: true,
    animations: 'disabled',
  });
  await search.fill('kanban issue');
  await expect(
    page.getByRole('button', { name: 'Use Issue Tracker template' }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Use Reading list template' }),
  ).toHaveCount(0);
  await search.fill('zz-no-such-template');
  await expect(page.getByText(/No matches. Try another search/)).toBeVisible();
  await search.fill('Reading list');
  await page.getByRole('button', { name: 'Use Reading list template' }).click();
  await expect(page.getByPlaceholder('New Table')).toHaveValue('Reading list');
  await page
    .locator('dialog[open]')
    .getByRole('button', { name: 'Create', exact: true })
    .click();
  await waitForTableBuild(page);
  const savedParent = await page.evaluate(async () => {
    const subject = new URL(location.href).searchParams.get('subject')!;

    return (await window.store!.readServerSnapshot(subject))[
      'https://atomicdata.dev/properties/parent'
    ];
  });
  expect(savedParent).toBe(parent);
});

test('creation prompt opens the assistant and keeps the request while setting up a model', async ({
  page,
}) => {
  const parent = await page.evaluate(() => window.store!.getDrive()!);
  await page.goto(
    new URL(`/app/new?parentSubject=${encodeURIComponent(parent)}`, page.url())
      .href,
  );
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(
    page.getByRole('button', { name: 'Create with assistant' }),
  ).toBeDisabled();
  const prompt = page.getByRole('textbox', {
    name: 'Describe what you want to create',
  });
  await prompt.fill('A project tracker for our volunteers');
  await page.screenshot({
    path: '/tmp/atomic-new-resource-mobile.png',
    fullPage: true,
    animations: 'disabled',
  });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.getByRole('button', { name: 'Create with assistant' }).click();
  await expect(
    page.getByText('Connect a model to use Atomic Assistant', { exact: true }),
  ).toBeVisible();
  await expect(
    page
      .locator('[contenteditable="true"]')
      .filter({ hasText: 'A project tracker for our volunteers' }),
  ).toBeVisible();
});

test('website template also installs inside the selected folder', async ({
  page,
}) => {
  const parent = await page.evaluate(async () => {
    const store = window.store!;
    const folder = await store.newResource({
      parent: store.getDrive(),
      isA: 'https://atomicdata.dev/classes/Folder',
      propVals: {
        'https://atomicdata.dev/properties/name': 'Website workspace',
      },
    });
    await folder.save();

    return folder.subject;
  });
  await page.goto(
    new URL(`/app/new?parent=${encodeURIComponent(parent)}`, page.url()).href,
  );
  await page.getByRole('button', { name: 'Use Website template' }).click();
  await page
    .getByRole('button', { name: 'Apply template', exact: true })
    .click();
  await expect(
    page.getByRole('heading', { name: 'website', exact: true, level: 1 }),
  ).toBeVisible({ timeout: 30000 });
  const actual = await page.evaluate(async () => {
    const subject = new URL(location.href).searchParams.get('subject')!;

    return (await window.store!.readServerSnapshot(subject))[
      'https://atomicdata.dev/properties/parent'
    ];
  });
  expect(actual).toBe(parent);
});
