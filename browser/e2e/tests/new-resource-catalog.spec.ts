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
  await expect(search).toBeFocused();
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
  await search.press('Enter');
  await expect(page.getByPlaceholder('New Table')).toHaveValue('Reading list');
  await page
    .locator('dialog[open]')
    .getByRole('button', { name: 'Create', exact: true })
    .click();
  await waitForTableBuild(page);
  const savedParent = await page.evaluate(async () => {
    const subject = new URL(location.href).searchParams.get('subject')!;

    return (
      await window.store!.fetchResourceFromServer(subject, {
        noWebSocket: true,
      })
    ).get('https://atomicdata.dev/properties/parent');
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

    return (
      await window.store!.fetchResourceFromServer(subject, {
        noWebSocket: true,
      })
    ).get('https://atomicdata.dev/properties/parent');
  });
  expect(actual).toBe(parent);
});

test('search selection follows arrows, resets on edits, and clear restores the catalog', async ({
  page,
}) => {
  await page.goto(new URL('/app/new', page.url()).href);
  const search = page.getByRole('searchbox', {
    name: 'Search templates and resource types',
  });
  await expect(search).toBeFocused();
  await search.fill('list');
  const selected = page.locator('[data-creation-result][data-selected="true"]');
  await expect(selected).toContainText('Reading list');
  await expect(selected).toHaveCSS('outline-style', 'solid');
  await expect(selected).toHaveCSS('outline-width', '2px');
  await expect(
    page.getByRole('heading', { name: 'Build with AI' }),
  ).toHaveCount(0);
  await expect(
    page.getByText('Drop files or click here to upload.', { exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByText('Choose a class by URL', { exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole('button', { name: 'Clear search', exact: true }),
  ).toHaveCount(1);
  await search.press('ArrowDown');
  await expect(selected).toContainText('Grocery list');
  await search.press('ArrowRight');
  await expect(selected).toContainText('Guest list');
  await search.press('ArrowUp');
  await expect(selected).toContainText('Grocery list');
  await search.press('Enter');
  await expect(page.getByPlaceholder('New Table')).toHaveValue('Grocery list');
  await page
    .locator('dialog[open]')
    .getByRole('button', { name: 'Cancel', exact: true })
    .click();
  // Cancel animates out before the page becomes interactive again.
  await expect(page.locator('body')).not.toHaveAttribute('inert', '');
  await search.fill('Reading');
  await expect(selected).toContainText('Reading list');
  await page.getByRole('button', { name: 'Clear search', exact: true }).click();
  await expect(search).toHaveValue('');
  await expect(search).toBeFocused();
  await expect(
    page.getByRole('heading', { name: 'Build with AI' }),
  ).toBeVisible();
  await expect(
    page.getByText('Drop files or click here to upload.', { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText('Choose a class by URL', { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Ask AI', exact: true }),
  ).toHaveCount(0);
});

test('mobile search hands its query to the assistant without overflowing', async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(new URL('/app/new', page.url()).href);
  const search = page.getByRole('searchbox', {
    name: 'Search templates and resource types',
  });
  await search.fill('A volunteer rota for our community');
  await expect(page.getByText(/No matches. Try another search/)).toBeVisible();
  await search.press('Enter');
  await expect(search).toHaveValue('A volunteer rota for our community');
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.getByRole('button', { name: 'Ask AI', exact: true }).click();
  await expect(
    page.getByText('Connect a model to use Atomic Assistant', { exact: true }),
  ).toBeVisible();
  await expect(
    page
      .locator('[contenteditable="true"]')
      .filter({ hasText: 'A volunteer rota for our community' }),
  ).toBeVisible();
});
