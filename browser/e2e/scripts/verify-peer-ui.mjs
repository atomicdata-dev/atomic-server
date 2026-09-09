import { chromium, expect } from '@playwright/test';
const browser = await chromium.launch();
try {
  const page = await browser.newPage({
    viewport: { width: 1280, height: 1000 },
  });
  await page.goto('http://localhost:6774/app/dev-drive');
  await page.waitForFunction(
    () => !!localStorage.getItem('atomic-test.dev-drive-secret'),
    undefined,
    { timeout: 90000 },
  );
  await page.evaluate(() =>
    localStorage.setItem('atomic-disable-client-db', '0'),
  );
  await page.goto('http://localhost:6774/app/sync');
  const panel = page.getByTestId('peer-sync-panel');
  await expect(
    page.getByRole('heading', { name: 'Peer sync', exact: true }),
  ).toBeVisible({ timeout: 90000 });
  await page
    .getByRole('button', { name: 'Create peer link', exact: true })
    .click();
  await expect(page.getByLabel('Peer link', { exact: true })).toHaveValue(
    /#peer=/,
  );
  await expect(
    panel.getByRole('button', { name: 'Disconnect', exact: true }),
  ).toBeVisible();
  await expect(
    panel.getByRole('button', { name: 'Copy link', exact: true }),
  ).toBeEnabled();
  await expect(panel.getByRole('status')).toContainText('Waiting for a peer', {
    timeout: 15000,
  });
  await page.screenshot({
    path: '/tmp/atomic-webrtc-ui/peer-sync.png',
    fullPage: true,
  });
  await panel.getByRole('button', { name: 'Disconnect', exact: true }).click();
  console.log(
    'PASS Sync page creates a peer invite and disconnects without a Cloud account',
  );
} finally {
  await browser.close();
}
