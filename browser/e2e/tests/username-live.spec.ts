import { test, expect } from './fixtures';
import {
  before,
  newResource,
  editTitle,
  getCurrentSubject,
  devDrive,
  openSubject,
  FRONTEND_URL,
} from './test-utils';

test.beforeEach(async ({ page }) => {
  await page.route('http://localhost:3030/api/me', route =>
    route.fulfill({ status: 204 }),
  );
});
test.beforeEach(before);

async function collaborator(
  page: import('@playwright/test').Page,
  browser: import('@playwright/test').Browser,
  subject: string,
) {
  const context = await browser.newContext();
  const peer = await context.newPage();
  await peer.route('http://localhost:3030/api/me', route =>
    route.fulfill({ status: 204 }),
  );
  await devDrive(peer);
  const agent = await peer.evaluate(() => window.store.getAgent()!.subject);
  const drive = await page.evaluate(async peerAgent => {
    const store = window.store;
    const driveResource = await store.getResource(store.getDrive()!);

    for (const property of [
      'https://atomicdata.dev/properties/read',
      'https://atomicdata.dev/properties/write',
    ]) {
      await driveResource.set(property, [
        ...((driveResource.get(property) as string[]) ?? []),
        peerAgent,
      ]);
    }

    await driveResource.save();

    return driveResource.subject;
  }, agent);
  await page.waitForFunction(
    () => window.store.getSyncStatus().pendingDirtyCount === 0,
  );
  await peer.evaluate(target => window.store.setDrive(target), drive);
  await openSubject(peer, subject);

  return peer;
}

test('remote username change updates existing chat author', async ({
  page,
  browser,
}) => {
  test.slow();
  await newResource('chatroom', page);
  await editTitle('Author name reproduction', page);
  await page.getByLabel('Chat input').fill('Message from renamed author');
  await page.getByLabel('Chat input').press('Enter');
  await expect(
    page.getByText('Message from renamed author', { exact: true }),
  ).toBeVisible();
  const subject = await getCurrentSubject(page);
  const peer = await collaborator(page, browser, subject!);
  const message = peer
    .getByText('Message from renamed author', { exact: true })
    .locator('xpath=ancestor::*[@about][1]');
  await expect(message).toContainText('Dev User');
  await page.goto(`${FRONTEND_URL}/app/agent`);
  await page
    .getByLabel('Your name', { exact: true })
    .fill('Renamed Collaborator');
  await page.getByLabel('Your name', { exact: true }).press('Enter');
  await page.waitForFunction(
    () => window.store.getSyncStatus().pendingDirtyCount === 0,
  );
  await expect(message).toContainText('Renamed Collaborator', {
    timeout: 15000,
  });
  // A fresh connection must restore the profile subscription as well.
  await peer.reload();
  await expect(message).toContainText('Renamed Collaborator');
  await page.getByLabel('Your name', { exact: true }).fill('Renamed Again');
  await page.getByLabel('Your name', { exact: true }).press('Enter');
  await expect(message).toContainText('Renamed Again', { timeout: 15000 });
});
