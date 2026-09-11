import { test, expect, type WebSocketRoute } from '@playwright/test';
import { devDrive, FRONTEND_URL, topBarShareButton } from './test-utils';

// Relay only discovery and SDP in-process. Authentication, invite redemption,
// resource sync and persistence still travel over real WebRTC data channels.
// This runs against the production bundle without Vite source imports or SaaS.
test('joins an unhosted drive through its signed browser invitation', async ({
  browser,
}) => {
  test.setTimeout(90000);
  const rooms = new Map<string, Map<string, WebSocketRoute>>();
  const ownerContext = await browser.newContext({
    permissions: ['clipboard-write'],
  });
  const guestContext = await browser.newContext();

  for (const context of [ownerContext, guestContext]) {
    await context.routeWebSocket('**/webrtc-signal', socket => {
      let room: Map<string, WebSocketRoute> | undefined;
      let peer: string | undefined;
      socket.onMessage(raw => {
        const message = JSON.parse(String(raw));

        if (message.type === 'join') {
          room = rooms.get(message.room) ?? new Map();
          rooms.set(message.room, room);
          peer = message.peer;
          socket.send(
            JSON.stringify({
              type: 'joined',
              peers: [...room.keys()],
              iceServers: [],
            }),
          );
          for (const other of room.values())
            other.send(JSON.stringify({ type: 'peer', peer }));
          room.set(peer!, socket);
        } else if (room && peer && ['offer', 'answer'].includes(message.type)) {
          room.get(message.to)?.send(
            JSON.stringify({
              type: message.type,
              from: peer,
              sdp: message.sdp,
            }),
          );
        }
      });
      socket.onClose(() => {
        if (!room || !peer) return;
        room.delete(peer);
        for (const other of room.values())
          other.send(JSON.stringify({ type: 'left', peer }));
      });
    });
  }

  const owner = await ownerContext.newPage();
  const guest = await guestContext.newPage();

  try {
    await devDrive(owner);
    await devDrive(guest);
    const drive = await owner.evaluate(async () => {
      const resource = await window.store.createDrive(
        'Browser invite acceptance',
        {
          personal: false,
          localOnly: true,
        },
      );

      return resource.subject;
    });
    await owner.goto(
      `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(drive)}`,
    );
    await topBarShareButton(owner).click();
    await owner
      .getByRole('button', { name: 'Create Invite', exact: true })
      .click();
    await owner.getByLabel('Full name', { exact: true }).fill('Drive Owner');
    await owner
      .getByRole('button', { name: 'Save and continue', exact: true })
      .click();
    await owner.getByLabel('Allow edits', { exact: true }).check();
    await owner.getByRole('button', { name: 'Create', exact: true }).click();
    const code = owner.locator('[data-code-content]');
    await expect(code).toHaveAttribute('data-code-content', /token=/);
    const invitation = new URL(
      (await code.getAttribute('data-code-content'))!,
    ).searchParams.get('token')!;
    const inviteRequests: string[] = [];
    guest.on('request', request => {
      if (new URL(request.url()).pathname === '/invites')
        inviteRequests.push(request.method());
    });
    await guest.goto(
      `${FRONTEND_URL}/app/invite?${new URLSearchParams({ token: invitation })}`,
    );
    await expect(
      guest.getByRole('heading', { name: "You're invited to edit this drive" }),
    ).toBeVisible();
    await guest
      .getByRole('button', { name: 'Join drive', exact: true })
      .click();
    await expect(
      guest.getByRole('button', { name: 'Open drive', exact: true }),
    ).toBeVisible({ timeout: 45000 });
    expect(inviteRequests).toEqual([]);
    await guest
      .getByRole('button', { name: 'Open drive', exact: true })
      .click();
    await expect(guest).toHaveURL(/\/app\/show\?subject=/);
    await expect
      .poll(() =>
        guest.evaluate(async driveSubject => {
          const resource = window.store?.resources.get(driveSubject);

          return {
            ready: resource?.isReady(),
            name: resource?.get('https://atomicdata.dev/properties/name'),
            writable: (
              await resource?.canWrite(window.store?.getAgent()?.subject)
            )?.[0],
          };
        }, drive),
      )
      .toEqual({
        ready: true,
        name: 'Browser invite acceptance',
        writable: true,
      });
  } finally {
    await ownerContext.close();
    await guestContext.close();
  }
});
