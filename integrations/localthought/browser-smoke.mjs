/** Run against Vite + the mock proxy, with VITE_ATOMIC_SERVER_URL on a closed port. */
import { chromium } from '../../browser/e2e/node_modules/@playwright/test/index.mjs';
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
page.setDefaultTimeout(45000);
await page.route('http://127.0.0.1:19999/**', route => route.abort());
const errors = [];
page.on('pageerror', e => errors.push(e.message));
try {
  console.log('Opening offline dev drive');
  await page.goto('http://localhost:6748/app/dev-drive');
  await page.waitForURL(/app\/show\?subject=/, { timeout: 120000 });
  console.log('Opening integrations');
  await page.getByRole('link', { name: 'Integrations', exact: true }).click();
  console.log('Opening Pets');
  const pets = page.locator('[data-integration=pets]');
  await pets.getByRole('button', { name: 'Set up connection' }).click();
  await page
    .getByRole('button', { name: 'Install and connect', exact: true })
    .click();
  await page
    .getByRole('button', {
      name: 'Use LocalThought to sync Pets with your Atomic Data Hub',
      exact: true,
    })
    .click();
  console.log('Fetching preview');
  await page.getByRole('button', { name: 'Fetch and preview' }).click();
  console.log('Applying preview');
  await page
    .getByRole('button', { name: 'Apply 5 changes', exact: true })
    .click();
  await page
    .getByRole('link', { name: 'Open imported records', exact: true })
    .click();
  for (const name of ['Rex', 'Whiskers', 'Tweety', 'Nibbles', 'Bubbles'])
    await page
      .getByRole('main')
      .getByText(name, { exact: true })
      .first()
      .waitFor();
  await page.reload();
  for (const name of ['Rex', 'Whiskers', 'Tweety', 'Nibbles', 'Bubbles'])
    await page
      .getByRole('main')
      .getByText(name, { exact: true })
      .first()
      .waitFor();
  console.log(
    'Browser-only OAuth, WASM import, review, OPFS apply and reload passed',
  );
} catch (error) {
  console.error(
    error.message,
    '\nURL:',
    page.url(),
    '\nUI:',
    (await page.locator('body').innerText()).slice(-7000),
    '\nErrors:',
    errors,
  );
  process.exitCode = 1;
} finally {
  await browser.close();
}
