import { test, expect } from '@playwright/test';
import { before } from './test-utils';

test('opening Edit with AI preserves the preview document', async ({
  page,
}) => {
  await before({ page });
  const subject = await page.evaluate(async () => {
    const { createWebsite, starterWebsite } = window.atomicE2E.websiteModel;

    return (
      await createWebsite(
        window.store,
        window.store.getDrive()!,
        starterWebsite('Stable preview'),
      )
    ).subject;
  });
  await page.goto(
    `${new URL(page.url()).origin}/app/show?subject=${encodeURIComponent(subject)}`,
  );
  const preview = page.frameLocator('iframe[title="Website preview"]');
  await expect(
    preview.getByRole('heading', { name: 'Stable preview' }).first(),
  ).toBeVisible();
  await page
    .locator('iframe[title="Website preview"]')
    .evaluate((frame: HTMLIFrameElement) => {
      frame.contentDocument!.body.setAttribute('data-preserved-preview', 'yes');
    });
  await page.getByRole('button', { name: 'More', exact: true }).click();
  // The menu opens with the generic resource actions and prepends the
  // website ones a frame later, once the website class has resolved.
  // `evaluateAll` reads the DOM once with no auto-waiting, so snapshotting
  // straight after the click caught whichever half had rendered. Wait for
  // both ends to be present before reading the order.
  await expect(page.getByTestId('menu-item-website-download')).toBeVisible();
  await expect(page.getByTestId('menu-item-trash')).toBeVisible();
  const actionIds = await page
    .getByRole('menuitem')
    .evaluateAll(items => items.map(item => item.getAttribute('data-testid')));
  expect(
    actionIds.slice(0, 7).every(id => id?.startsWith('menu-item-website-')),
  ).toBe(true);
  expect(actionIds.slice(7).some(id => id === 'menu-item-trash')).toBe(true);
  await expect(page.getByTestId('menu-item-view')).toHaveCount(0);
  await expect(page.getByTestId('menu-item-data').locator('svg')).toHaveCount(
    1,
  );
  await expect(page.getByTestId('menu-item-website-design')).toBeVisible();
  await page.keyboard.press('Escape');
  const editWithAI = page.getByRole('button', {
    name: 'AI edit',
    exact: true,
  });
  await expect(
    editWithAI
      .locator('..')
      .getByRole('button', { name: 'Page edit', exact: true }),
  ).toBeVisible();
  await editWithAI.click();
  // Allow the panel's mount, context reads and resource notifications to settle.
  await page.waitForTimeout(2000);
  await expect(preview.locator('body')).toHaveAttribute(
    'data-preserved-preview',
    'yes',
  );
  await expect(page.getByText('Preparing preview…')).toHaveCount(0);
});
