import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import type { Duplex } from 'node:stream';
import { test, expect } from './fixtures';
import { collectFailureState } from './failure-state';

test('failure state is bounded and excludes values and signed payloads', async ({
  page,
}) => {
  await page.evaluate(() => {
    const resource = {
      subject: 'did:ad:test',
      readState: 'ready',
      isSaving: false,
      hasPendingCommits: true,
      hasUnsavedChanges: () => true,
      getEntries: () => [['secret', 'DO_NOT_ATTACH']],
    };
    window.store = {
      resources: new Map(
        Array.from({ length: 100 }, (_, i) => [String(i), resource]),
      ),
      getSyncStatus: () => ({ pendingDirtyCount: 1 }),
      getSaveState: () => ({ kind: 'queued' }),
      getCommitLog: () =>
        Array.from({ length: 100 }, () => ({
          subject: 'did:ad:test',
          direction: 'outgoing',
          status: 'pending',
          summary: 'DO_NOT_ATTACH',
          loroUpdate: 'DO_NOT_ATTACH',
        })),
    } as unknown as typeof window.store;
  });
  const state = (await collectFailureState(page)) as {
    resources: unknown[];
    recentCommits: unknown[];
  };
  expect(state.resources).toHaveLength(50);
  expect(state.recentCommits).toHaveLength(20);
  expect(JSON.stringify(state)).not.toContain('DO_NOT_ATTACH');
});

for (const closePage of [false, true]) {
  test(`failure attachments retain transport metadata without frame payloads (closed=${closePage})`, async ({
    page,
  }) => {
    test.fail(
      true,
      'The synthetic warning triggers diagnostic attachment teardown',
    );
    const server = createServer();
    const sockets = new Set<Duplex>();
    server.on('upgrade', (request, socket) => {
      sockets.add(socket);
      const accept = createHash('sha1')
        .update(
          `${request.headers['sec-websocket-key']}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`,
        )
        .digest('base64');
      socket.write(
        `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`,
      );
      const payload = Buffer.from('DO_NOT_ATTACH');
      socket.write(
        Buffer.concat([Buffer.from([0x81, payload.length]), payload]),
      );
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string')
      throw new Error('Missing test socket');

    try {
      await page.evaluate(async port => {
        await new Promise<void>(resolve => {
          const socket = new WebSocket(`ws://127.0.0.1:${port}`);
          socket.onopen = () => socket.send('DO_NOT_ATTACH');

          socket.onmessage = () => {
            console.warn('Synthetic transport failure');
            socket.close();
            resolve();
          };
        });
      }, address.port);
      if (closePage) await page.close();
    } finally {
      sockets.forEach(socket => socket.destroy());
      await new Promise<void>(resolve => server.close(() => resolve()));
    }
  });
}
