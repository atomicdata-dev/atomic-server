import { test, expect } from '@playwright/test';
import { before } from './test-utils';

/**
 * The whole manual-run path, which is otherwise only ever verified by hand:
 * create a plugin, run it, review what it proposes, apply, and find the run in
 * the log. Everything below the UI has unit tests; this is the part that only
 * a browser can answer.
 */
test.describe('plugins', () => {
  test.beforeEach(before);

  test('a plugin proposes changes, and nothing is written until you approve', async ({
    page,
  }) => {
    const main = page.getByRole('main');

    // `New plugin` is search-only: it creates the drive's plugin schema on
    // first use, so it stays out of the default listing.
    await page.getByRole('button', { name: 'More' }).click();
    await page.getByPlaceholder(/filter/i).fill('plugin');
    await page.locator('[data-testid="menu-item-new-plugin"]').click();

    await expect(
      main.getByRole('heading', { name: 'New plugin', level: 1 }),
    ).toBeVisible();

    // The starter source is what an author (or an LLM) reads first.
    await expect(main.getByText('export function run(input)')).toBeVisible();

    // Run appears once the drive's plugin class resolves — the menu subscribes
    // to the ontology, so no reload is needed after the schema is created.
    await page.getByRole('button', { name: 'More' }).click();

    const runItem = page.locator('[data-testid="menu-item-run-plugin"]');
    await expect(runItem).toBeVisible();
    await runItem.click();

    // The run has already happened: it holds no authority, so only writing
    // needs consent. The dialog is that boundary.
    const dialog = page.locator('dialog[open]');
    // The op is rendered lowercase and uppercased in CSS; `exact` keeps it
    // from also matching "created without a class…".
    await expect(dialog.getByText('create', { exact: true })).toBeVisible();
    await expect(dialog.getByText('Made by a plugin')).toBeVisible();

    const apply = dialog.getByRole('button', { name: /Apply 1 change/ });
    await expect(apply).toBeEnabled();

    // Running wrote nothing: the log behind the dialog still has no runs.
    await expect(main.getByText('This plugin has not run yet.')).toBeVisible();

    await apply.click();
    await expect(dialog).toBeHidden();

    // Now there is exactly one run, and it says what it did.
    await expect(main.getByRole('heading', { name: 'Runs' })).toBeVisible();
    // The status is rendered lowercase and uppercased in CSS; `exact` keeps it
    // from also matching the "1 applied" summary beside it.
    await expect(main.getByText('applied', { exact: true })).toBeVisible();
    await expect(main.getByText(/1 applied, 1 problem/)).toBeVisible();

    // Expanding it links to the resource the run actually created.
    await main.getByRole('button', { name: 'expand' }).first().click();
    await expect(main.getByRole('link', { name: 'example' })).toBeVisible();
  });

  test('a run whose target does not exist is blocked, and writes nothing', async ({
    page,
  }) => {
    const main = page.getByRole('main');

    await page.getByRole('button', { name: 'More' }).click();
    await page.getByPlaceholder(/filter/i).fill('plugin');
    await page.locator('[data-testid="menu-item-new-plugin"]').click();
    await expect(
      main.getByRole('heading', { name: 'New plugin', level: 1 }),
    ).toBeVisible();

    // Point the plugin at a resource that is not there. The source property is
    // drive-local, so it is found by its value rather than by a subject the
    // test would have to know — and only `window.store` is used, so this does
    // not couple the test to app module paths.
    await page.evaluate(async () => {
      const store = (
        window as unknown as {
          store: {
            getResource(s: string): Promise<{
              getPropVals(): Record<string, unknown>;
              set(p: string, v: unknown): Promise<void>;
              save(): Promise<unknown>;
            }>;
          };
        }
      ).store;

      const subject = decodeURIComponent(
        new URL(location.href).searchParams.get('subject')!,
      );
      const plugin = await store.getResource(subject);

      const sourceProp = Object.entries(plugin.getPropVals()).find(
        ([, value]) =>
          typeof value === 'string' && value.includes('export function run'),
      )?.[0];

      if (!sourceProp) throw new Error('plugin has no source property');

      await plugin.set(
        sourceProp,
        `export function run() {
          return {
            intents: [{ op: 'set', subject: 'https://example.com/ghost',
                        set: { 'https://atomicdata.dev/properties/name': 'nope' } }],
            problems: [],
          };
        }`,
      );
      await plugin.save();
    });

    await page.getByRole('button', { name: 'More' }).click();
    await page.locator('[data-testid="menu-item-run-plugin"]').click();

    const dialog = page.locator('dialog[open]');
    await expect(dialog.getByText(/does not exist/)).toBeVisible();
    await expect(dialog.getByRole('button', { name: /Apply/ })).toBeDisabled();

    // Cancelling a blocked run still records it: a refusal that leaves no
    // trace reads the same as a plugin that never ran.
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();

    await expect(main.getByText('blocked', { exact: true })).toBeVisible();
  });
  test('a plugin asks for the credentials it declares, and nothing else', async ({
    page,
  }) => {
    const main = page.getByRole('main');

    await newPlugin(page);

    // The starter needs no credentials, so it says so rather than showing an
    // empty heading with nowhere to type.
    await expect(main.getByText(/asks for no credentials/)).toBeVisible();

    await setSource(
      page,
      `export const manifest = {
         secrets: [{ name: 'notion', origin: 'https://api.notion.com',
                     description: 'Notion integration token' }],
       };
       export function run(ctx) {
         ctx.http({ url: 'https://api.notion.com/v1/search',
                    headers: { Authorization: 'Bearer secret:notion' } });
         return { intents: [], problems: [] };
       }`,
    );

    // A declared secret is one labelled field: the name and origin come from
    // the plugin, so neither is retyped.
    await expect(main.getByText('Notion integration token')).toBeVisible();
    await expect(
      main.getByPlaceholder(/Paste the value for notion/),
    ).toBeVisible();
  });

  test('a secret used but not declared still has somewhere to go', async ({
    page,
  }) => {
    const main = page.getByRole('main');

    await newPlugin(page);

    await setSource(
      page,
      `export function run(ctx) {
         ctx.http({ url: 'https://api.notion.com/v1/search',
                    headers: { Authorization: 'Bearer secret:tok' } });
         return { intents: [], problems: [] };
       }`,
    );

    // The author who forgot to declare is the one who cannot work out where to
    // enter it, so a slot appears anyway — with the origin read from the URL
    // rather than asked for.
    await expect(main.getByText(/sent only to/)).toBeVisible();
    await expect(main.getByText(/api\.notion\.com/).first()).toBeVisible();
    await expect(main.getByPlaceholder(/Value for tok/)).toBeVisible();
  });
});

async function newPlugin(page: import('@playwright/test').Page) {
  await page.getByRole('button', { name: 'More' }).click();
  await page.getByPlaceholder(/filter/i).fill('plugin');
  await page.locator('[data-testid="menu-item-new-plugin"]').click();
  await expect(
    page.getByRole('main').getByRole('heading', {
      name: 'New plugin',
      level: 1,
    }),
  ).toBeVisible();
}

/**
 * Replaces a plugin's source through `window.store`.
 *
 * The source property is drive-local and has no fixed subject, so it is found
 * by its value — which keeps the test off app module paths.
 */
async function setSource(
  page: import('@playwright/test').Page,
  source: string,
) {
  await page.evaluate(async (next: string) => {
    const store = (
      window as unknown as {
        store: {
          getResource(s: string): Promise<{
            getPropVals(): Record<string, unknown>;
            set(p: string, v: unknown): Promise<void>;
            save(): Promise<unknown>;
          }>;
        };
      }
    ).store;

    const subject = decodeURIComponent(
      new URL(location.href).searchParams.get('subject')!,
    );
    const plugin = await store.getResource(subject);

    const sourceProp = Object.entries(plugin.getPropVals()).find(
      ([, value]) =>
        typeof value === 'string' && value.includes('export function run'),
    )?.[0];

    if (!sourceProp) throw new Error('plugin has no source property');

    await plugin.set(sourceProp, next);
    await plugin.save();
  }, source);
}
