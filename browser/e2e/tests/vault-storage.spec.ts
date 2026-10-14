import { managedDriveTest as test, expect } from './deployment-fixtures';
import { FRONTEND_URL } from './test-utils';

for (const width of [1200, 390]) {
  test(`Vault usage is distinct from the server copy at ${width}px`, async ({
    page,
  }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const drive = await page.evaluate(() => window.store.getDrive());
    // This fixture supplies a usage inventory, not encrypted backup bodies.
    // Keep automatic backup/restore out of this presentation-only journey.
    await page.evaluate(subject => {
      localStorage.setItem('atomic.vault.optOut', JSON.stringify([subject]));
    }, drive);
    const enrollment = {
      id: 'storage-test',
      drive_subject: drive,
      drive_pseudonym: 'storage-test',
      status: 'active',
      used_bytes: 91 * 1024 ** 2,
      quota_bytes: 100 * 1024 ** 2,
      last_backup_at: Date.now(),
    };
    await page.route('**/api/me', route =>
      route.fulfill({ json: { email: 'storage-test@example.com' } }),
    );
    await page.route('**/api/sync-enrollments', route =>
      route.fulfill({ json: [] }),
    );
    await page.route('**/api/recovery-secret', route =>
      route.fulfill({ status: 204 }),
    );
    await page.route('**/api/cloud-vault/drives', route =>
      route.fulfill({ json: [enrollment] }),
    );
    await page.route('**/api/cloud-vault/storage-test/state', route =>
      route.fulfill({
        json: {
          enrollment,
          lanes: {},
          checkpoints: [],
          pending_uploads: 0,
          confirmed_objects: 657,
        },
      }),
    );
    await page.route('**/api/cloud-vault/storage-test/usage', route =>
      route.fulfill({
        json: {
          used_bytes: enrollment.used_bytes,
          quota_bytes: enrollment.quota_bytes,
          by_kind: [
            { kind: 'pack', bytes: 59 * 1024 ** 2, objects: 642 },
            { kind: 'checkpoint', bytes: 32 * 1024 ** 2, objects: 15 },
          ],
          pending_bytes: 0,
          unaccounted_bytes: 0,
          reclaimable_bytes: 0,
          undo_window_bytes: 27 * 1024 ** 2,
        },
      }),
    );
    await page.goto(`${FRONTEND_URL}/app/sync`);
    await expect(page.getByTestId('vault-storage-explanation')).toContainText(
      'current server copy',
    );
    await page.getByRole('button', { name: 'View Vault storage' }).click();
    const storage = page.getByTestId('vault-storage');
    await expect(storage.getByTestId('vault-storage-total')).toHaveText(
      '91 MB of 100 MB used',
    );
    await expect(storage.getByTestId('vault-storage-pack')).toContainText(
      '642 objects',
    );
    await expect(storage.getByTestId('vault-storage-checkpoint')).toContainText(
      '15 objects',
    );
    await expect(page.locator('body')).not.toContainText('[i18n-404:');
    await storage.screenshot({
      path: testInfo.outputPath('vault-storage.png'),
    });
    await expect
      .poll(() => page.evaluate(() => document.documentElement.scrollWidth))
      .toBeLessThanOrEqual(width);

    await page.goto(`${FRONTEND_URL}/app/storage`);
    await expect(
      page.getByRole('heading', { name: 'Server storage' }),
    ).toBeVisible();
    await expect(page.getByTestId('storage-scope')).toContainText(
      'Cloud Vault backup storage is shown separately',
    );
    await expect(page.getByTestId('storage-loading')).toBeHidden();
    await expect(page.getByTestId('storage-failed')).toBeHidden();
    await expect(page.getByTestId('storage-map')).toBeVisible();
    await expect(page.locator('#boot-splash')).toBeHidden();
    await page.getByRole('main').screenshot({
      path: testInfo.outputPath('server-storage.png'),
    });
    await expect(page.getByTestId('storage-map')).toBeVisible();
  });
}
