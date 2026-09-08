import { test } from './fixtures';

test('diagnostics accepts a quiet page', async ({ page }) => {
  await page.setContent('<h1>Quiet page</h1>');
});

test('diagnostics records an explicitly expected warning', async ({
  page,
  browserDiagnostics,
}) => {
  browserDiagnostics.expect(
    'warning',
    /^Intentional warning$/,
    'Verifies the warning collector',
  );
  await page.evaluate(() => console.warn('Intentional warning'));
});

for (const kind of ['warning', 'error', 'pageerror'] as const) {
  test(`diagnostics rejects an unexpected ${kind}`, async ({ page }) => {
    test.fail(true, 'The diagnostic fixture must reject this synthetic signal');

    if (kind === 'pageerror') {
      const error = page.waitForEvent('pageerror');
      await page.evaluate(() => {
        setTimeout(() => {
          throw new Error('Synthetic uncaught exception');
        }, 0);
      });
      await error;
    } else {
      await page.evaluate(
        signalKind =>
          console[signalKind === 'warning' ? 'warn' : 'error'](
            'Synthetic unexpected diagnostic',
          ),
        kind,
      );
    }
  });
}

test('diagnostics observes additional contexts and tabs', async ({
  browser,
}) => {
  test.fail(true, 'Warnings from a second user context must fail too');
  const context = await browser.newContext();
  const first = await context.newPage();
  await first.setContent('<h1>First tab</h1>');
  const second = await context.newPage();
  await second.evaluate(() => console.warn('Second tab warning'));
  await context.close();
});

test('diagnostics rejects unused expectations', async ({
  browserDiagnostics,
}) => {
  test.fail(true, 'Stale exceptions must be removed');
  browserDiagnostics.expect(
    'warning',
    /^Never emitted$/,
    'Tests unused expectations',
  );
});

test('diagnostics rejects excess occurrences', async ({
  page,
  browserDiagnostics,
}) => {
  test.fail(true, 'An expected warning is not an unlimited suppression');
  browserDiagnostics.expect('warning', /^Repeated$/, 'Tests exact counts', 1);
  await page.evaluate(() => {
    console.warn('Repeated');
    console.warn('Repeated');
  });
});

test('diagnostics rejects a matching message from a different URL', async ({
  page,
  browserDiagnostics,
}) => {
  test.fail(
    true,
    'A network error expectation must not mask a different endpoint',
  );
  browserDiagnostics.expect(
    'error',
    /^Synthetic endpoint failure$/,
    'Tests URL scoping',
    1,
    /^https:\/\/expected.invalid\//,
  );
  await page.evaluate(() => console.error('Synthetic endpoint failure'));
});
