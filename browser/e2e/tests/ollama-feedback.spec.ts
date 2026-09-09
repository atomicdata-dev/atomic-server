import { test, expect } from './fixtures';
import { before, FRONTEND_URL } from './test-utils';

test.beforeEach(async ({ page }) => {
  await page.route('http://localhost:3030/api/me', route =>
    route.fulfill({ status: 204 }),
  );
});
test.beforeEach(before);

test('feedback uses the sidebar hover background', async ({ page }) => {
  await page.getByTestId('sidebar').hover();
  const feedback = page.getByRole('button', { name: 'Feedback', exact: true });
  await page.mouse.move(1000, 300);
  const resting = await feedback.evaluate(
    el => getComputedStyle(el).backgroundColor,
  );
  await feedback.hover();
  await expect
    .poll(() => feedback.evaluate(el => getComputedStyle(el).backgroundColor))
    .not.toBe(resting);
});

test('settings detects local Ollama and accepts it with one click', async ({
  page,
  browserDiagnostics,
}) => {
  let probes = 0;
  if (!process.env.TEST_REAL_OLLAMA)
    await page.route('http://localhost:11434/api/tags', route => {
      probes++;

      return route.fulfill({
        json: { models: [{ name: 'qwen:test', model: 'qwen:test' }] },
      });
    });
  await page.goto(`${FRONTEND_URL}/app/settings`);
  expect(probes).toBe(0);

  if (await page.locator('script[src*="/@vite/client"]').count()) {
    browserDiagnostics.expect(
      'error',
      /Each child in a list should have a unique.*key.*AISettings/s,
      'Existing Wuchale React key warning when expanding AI settings in Vite',
      1,
    );
  }

  await page.getByText('AI', { exact: true }).click();
  await expect(
    page.getByText('Local Ollama detected', { exact: true }),
  ).toBeVisible();
  if (!process.env.TEST_REAL_OLLAMA) expect(probes).toBeGreaterThan(0);
  expect(
    await page.evaluate(() => localStorage.getItem('atomic.ai.ollama-url')),
  ).toBeNull();
  await page
    .getByRole('button', { name: 'Use local Ollama', exact: true })
    .click();
  await expect(page.locator('#ollama-url')).toHaveValue(
    'http://localhost:11434',
  );
  await page.reload();

  if (await page.locator('script[src*="/@vite/client"]').count()) {
    browserDiagnostics.expect(
      'error',
      /Each child in a list should have a unique.*key.*AISettings/s,
      'Existing Wuchale React key warning when expanding AI settings in Vite',
      1,
    );
  }

  await page.getByText('AI', { exact: true }).click();
  await expect(page.locator('#ollama-url')).toHaveValue(
    'http://localhost:11434',
  );
});
