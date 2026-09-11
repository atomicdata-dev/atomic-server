import { test, expect } from '@playwright/test';
import { before } from './test-utils';

test.beforeEach(before);

test('integration categories default off and independent Atomic preferences survive reload', async ({
  page,
}) => {
  const catalogRequests: string[] = [];
  await page.route('**/catalog', route => route.fulfill({ json: ['pets'] }));
  await page.route('**/plugin-catalog', async route => {
    catalogRequests.push(route.request().url());
    await route.fulfill({
      json: [
        {
          metadata: {
            release: 'fixture-release',
            name: 'Community fixture',
            description: 'Test listing',
            publisher: 'test',
            domains: [],
            standards: [],
          },
          verification: 'unverified',
        },
      ],
    });
  });
  await page.goto(new URL('/app/integrations', page.url()).href);
  const apiPrompt = page.getByRole('link', {
    name: 'Consider enabling API plugins in Settings → Integration.',
  });
  const experimentalPrompt = page.getByRole('link', {
    name: 'Consider enabling experimental plugins in Settings → Integration.',
  });
  await expect(apiPrompt).toBeVisible();
  await expect(experimentalPrompt).toBeVisible();
  await expect(page.locator('[data-integration]')).toHaveCount(0);
  expect(catalogRequests).toHaveLength(0);

  await experimentalPrompt.click();
  await page.getByPlaceholder('Search settings...').fill('plugins');
  const api = page.getByRole('checkbox', { name: 'Show API plugins' });
  const experimental = page.getByRole('checkbox', {
    name: 'Show experimental plugins',
  });
  await expect(api).not.toBeChecked();
  await expect(experimental).not.toBeChecked();
  await experimental.check();
  await expect(experimental).toBeEnabled();
  await expect
    .poll(() =>
      page.evaluate(async () => {
        const store = window.store!;
        const subject = await store.getAgent()!.privateDriveSubject();
        const drive = await store.fetchResourceFromServer(subject, {
          noWebSocket: true,
        });
        const ontology = await store.getResource(
          drive.get(
            'https://atomicdata.dev/ontology/server/property/default-ontology',
          ) as string,
        );
        const terms = ontology.get(
          'https://atomicdata.dev/properties/properties',
        ) as string[];

        for (const term of terms) {
          const property = await store.getResource(term);
          if (
            property.get('https://atomicdata.dev/properties/shortname') ===
            'show-experimental-plugins'
          )
            return drive.get(term);
        }

        return undefined;
      }),
    )
    .toBe(true);
  await page.reload();
  await page.getByPlaceholder('Search settings...').fill('plugins');
  await expect(experimental).toBeChecked();
  await expect(api).not.toBeChecked();

  await page.goto(new URL('/app/integrations', page.url()).href);
  await expect(page.locator('[data-integration="mt940"]')).toBeVisible();
  await expect(page.locator('[data-release="fixture-release"]')).toBeVisible();
  await expect(apiPrompt).toBeVisible();
  await expect(experimentalPrompt).toHaveCount(0);
  expect(catalogRequests.length).toBeGreaterThan(0);

  await apiPrompt.click();
  await page.getByPlaceholder('Search settings...').fill('plugins');
  await experimental.uncheck();
  await expect(experimental).toBeEnabled();
  await api.check();
  await expect(api).toBeEnabled();
  await page.reload();
  await page.getByPlaceholder('Search settings...').fill('plugins');
  await expect(api).toBeChecked();
  await expect(experimental).not.toBeChecked();

  await page.goto(new URL('/app/integrations', page.url()).href);
  await expect(page.locator('[data-integration="proxy:pets"]')).toBeVisible();
  await expect(apiPrompt).toHaveCount(0);
  await expect(experimentalPrompt).toBeVisible();
  await expect(page.locator('[data-integration="mt940"]')).toHaveCount(0);
  await expect(page.locator('[data-release]')).toHaveCount(0);
});

test('existing connections remain visible while both discovery categories are hidden', async ({
  page,
}) => {
  await page.getByRole('button', { name: 'More' }).click();
  await page.getByPlaceholder(/filter/i).fill('plugin');
  await page.locator('[data-testid="menu-item-new-plugin"]').click();
  await expect(
    page
      .getByRole('main')
      .getByRole('heading', { name: 'New plugin', level: 1 }),
  ).toBeVisible();
  await page.goto(new URL('/app/integrations', page.url()).href);
  await expect(
    page
      .getByRole('region', { name: 'Your integrations' })
      .getByRole('link', { name: 'New plugin', exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole('link', {
      name: 'Consider enabling API plugins in Settings → Integration.',
    }),
  ).toBeVisible();
  await expect(
    page.getByRole('link', {
      name: 'Consider enabling experimental plugins in Settings → Integration.',
    }),
  ).toBeVisible();
  await expect(page.locator('[data-integration]')).toHaveCount(0);
});
