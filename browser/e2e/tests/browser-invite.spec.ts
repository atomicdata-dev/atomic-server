import { resolve } from 'node:path';
import { test, expect } from '@playwright/test';
import { devDrive, FRONTEND_URL } from './test-utils';

// Real app routes and real SaaS signaling; no data-node invite redemption.
// The separate peer harness additionally disables ALL data requests.
test('joins an unhosted drive through its signed browser invitation', async ({ browser }) => {
  test.setTimeout(90000);
  const owner = await browser.newPage();
  const guest = await browser.newPage();
  try {
    await devDrive(owner);
    await devDrive(guest);
    const invitation = await owner.evaluate(async inviteModule => {
      const { generateInviteToken } = await import(inviteModule);
      const { automaticPeerRoom, defaultPeerSignalingUrl, savePeerLink, resumePeerLinks } = await import('/src/helpers/browserPeerSync.ts');
      const store = window.store;
      const drive = await store.createDrive('Browser invite acceptance', { personal: false, localOnly: true });
      const token = await generateInviteToken(drive.subject, store.getAgent(), true, undefined, undefined, true);
      savePeerLink(store, { drive: drive.subject, room: await automaticPeerRoom(drive.subject), signalingUrl: defaultPeerSignalingUrl() });
      resumePeerLinks(store);
      return token;
    }, `/@fs${resolve(__dirname, '../../lib/src/invites.ts')}`);
    const inviteRequests: string[] = [];
    guest.on('request', request => { if (new URL(request.url()).pathname === '/invites') inviteRequests.push(request.method()); });
    await guest.goto(`${FRONTEND_URL}/app/invite?${new URLSearchParams({ token: invitation })}`);
    await expect(guest.getByRole('heading', { name: "You're invited to edit this drive" })).toBeVisible();
    await guest.getByRole('button', { name: 'Join drive', exact: true }).click();
    await expect(guest.getByRole('button', { name: 'Open drive', exact: true })).toBeVisible({ timeout: 45000 });
    expect(inviteRequests).toEqual([]);
    await guest.getByRole('button', { name: 'Open drive', exact: true }).click();
    await expect(guest).toHaveURL(/\/app\/show\?subject=/);
  } finally { await owner.close(); await guest.close(); }
});
