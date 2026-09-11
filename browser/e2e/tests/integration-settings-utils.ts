import { expect, type Page } from '@playwright/test';

/** Opt in through Settings so integration tests exercise Atomic persistence. */
export async function enableIntegrationDiscovery(page: Page, api = false) {
  const previousUrl = page.url();
  await page.goto(new URL('/app/settings', previousUrl).href);
  await page.getByPlaceholder('Search settings...').fill('plugins');
  const experimental = page.getByRole('checkbox', {
    name: 'Show experimental plugins',
  });
  await experimental.check();
  await expect(experimental).toBeEnabled();

  if (api) {
    const apiCheckbox = page.getByRole('checkbox', {
      name: 'Show API plugins',
    });
    await apiCheckbox.check();
    await expect(apiCheckbox).toBeEnabled();
  }

  await page.goto(previousUrl);
}
