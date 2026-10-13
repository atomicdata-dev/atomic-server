import { mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import {
  test,
  expect,
  installEmptyDiscoveryRoom,
  type BrowserContext,
} from './fixtures';
import {
  devDrive,
  newResource,
  getCurrentSubject,
  createTableFromDialog,
  setGridCell,
} from './test-utils';
import { DiagnosticCollector } from './diagnostic-collector';

// Full suite only: use a dedicated persistent profile, never the test runner's
// shared browser or a user's browser. SIGKILL bypasses unload/close flushes.
test('acknowledged document, table and attachment survive a browser process kill', async ({
  playwright,
  launchOptions,
}, testInfo) => {
  test.setTimeout(180_000);
  test.skip(
    process.platform === 'win32',
    'This crash probe uses POSIX SIGKILL',
  );
  const profile = testInfo.outputPath('crash-profile');
  await mkdir(profile, { recursive: true });
  let context: BrowserContext | undefined;
  let browserPid: number;
  const diagnostics = new DiagnosticCollector();
  diagnostics.expect(
    'warning',
    /^Service Worker registration blocked by Playwright$/,
    'The test blocks service workers on each of its four app navigations so network routes cannot be bypassed',
    4,
  );

  async function launch() {
    context = await playwright.chromium.launchPersistentContext(profile, {
      ...launchOptions,
      headless: true,
      serviceWorkers: 'block',
      viewport: { width: 1200, height: 800 },
    });
    diagnostics.start(context);
    await installEmptyDiscoveryRoom(context);
    await context.addInitScript(() =>
      localStorage.setItem('viewTransitionsDisabled', 'true'),
    );
    const browser = context.browser();
    if (!browser) throw new Error('Persistent browser connection missing');
    const session = await browser.newBrowserCDPSession();
    const { processInfo } = await session.send('SystemInfo.getProcessInfo');
    const process = processInfo.find(info => info.type === 'browser');
    if (!process) throw new Error('Dedicated browser PID missing');
    browserPid = process.id;
    await session.detach();

    return context.pages()[0] ?? (await context.newPage());
  }

  async function kill() {
    const browser = context!.browser()!;
    const disconnected = new Promise<void>(resolve =>
      browser.once('disconnected', () => resolve()),
    );
    process.kill(browserPid, 'SIGKILL');
    await disconnected;
    context = undefined;
  }

  async function prohibitRemoteData() {
    // Static app assets remain accessible so restart can load the app. Neither
    // HTTP data reads nor WebSocket sync may rescue an edit missing from OPFS.
    await context!.route('**/*', route => {
      const path = new URL(route.request().url()).pathname;

      if (
        /^\/(?:did(?::|\/|$)|commit(?:\/|$)|query(?:\/|$)|search(?:\/|$)|download(?:\/|$)|blob(?:\/|$))/.test(
          path,
        )
      ) {
        return route.fulfill({
          status: 503,
          body: 'Data access disabled by crash test',
        });
      }

      return route.continue();
    });
    await context!.routeWebSocket('**/ws', socket => {
      diagnostics.expect(
        'warning',
        /^\[WS\] close code=1000 reason="crash-test isolation" wasClean=true opened=false$/,
        'The test closes this socket to prohibit remote recovery',
        1,
      );
      socket.close({ code: 1000, reason: 'crash-test isolation' });
    });
  }

  try {
    let page = await launch();
    await devDrive(page);
    await page.waitForFunction(() => window.store?.getClientDb()?.isReady);
    await newResource('document', page);
    const documentSubject = await getCurrentSubject(page);
    const documentUrl = page.url();
    await page.evaluate(() => window.store.disconnect());
    await prohibitRemoteData();
    await page.getByLabel('Rich Text Editor').fill('Document survives SIGKILL');
    const documentResult = await page.evaluate(
      async subject => (await window.store.getResource(subject)).save(),
      documentSubject,
    );
    expect(['offline', 'noop']).toContain(documentResult);
    await kill();

    page = await launch();
    await prohibitRemoteData();
    await page.goto(documentUrl);
    await expect(page.getByLabel('Rich Text Editor')).toContainText(
      'Document survives SIGKILL',
    );
    expect(await page.evaluate(() => window.store.serverConnected)).toBe(false);

    await createTableFromDialog(page, { name: 'Crash-safe table' });
    const tableSubject = await getCurrentSubject(page);
    const tableUrl = page.url();
    await setGridCell(page, 2, 2, 'Row survives SIGKILL');
    const row = await page.evaluate(async parent => {
      const resource = [...window.store.resources.values()].find(
        candidate =>
          candidate.get('https://atomicdata.dev/properties/parent') ===
            parent &&
          candidate.get('https://atomicdata.dev/properties/name') ===
            'Row survives SIGKILL',
      );
      if (!resource) throw new Error('Edited row not found');

      const result = await resource.save();

      // Signing can replace an _new: subject. Record the acknowledged identity,
      // not the temporary identity evaluated before the save promise settles.
      return { subject: resource.subject, result };
    }, tableSubject);
    expect(['offline', 'noop']).toContain(row.result);
    expect(row.subject).toMatch(/^(atomic|did:ad):/);
    const attachmentBytes = Array.from({ length: 65537 }, (_, i) => i % 251);
    const expectedAttachmentHash = createHash('sha256')
      .update(Buffer.from(attachmentBytes))
      .digest('hex');
    const attachment = await page.evaluate(
      async ({ parent, bytes }) => {
        const [subject] = await window.store.uploadFiles(
          [
            new File([new Uint8Array(bytes)], 'crash-attachment.bin', {
              type: 'application/octet-stream',
            }),
          ],
          parent,
        );
        const file = await window.store.getResource(subject);

        return {
          subject,
          blob: file.get('https://atomicdata.dev/properties/blob') as string,
        };
      },
      { parent: tableSubject, bytes: attachmentBytes },
    );
    await testInfo.attach('acknowledgement-ledger', {
      body: JSON.stringify({
        documentSubject,
        documentText: 'Document survives SIGKILL',
        rowSubject: row.subject,
        rowText: 'Row survives SIGKILL',
        attachmentSubject: attachment.subject,
        attachmentSha256: expectedAttachmentHash,
      }),
      contentType: 'application/json',
    });
    await kill();

    page = await launch();
    await prohibitRemoteData();
    await page.goto(tableUrl);
    await expect(
      page.getByRole('gridcell', { name: 'Row survives SIGKILL', exact: true }),
    ).toBeVisible();
    expect(
      await page.evaluate(
        async subject =>
          (await window.store.getResource(subject)).get(
            'https://atomicdata.dev/properties/name',
          ),
        row.subject,
      ),
    ).toBe('Row survives SIGKILL');
    const restoredAttachment = await page.evaluate(
      async ({ subject, blob }) => {
        const file = await window.store.getResource(subject);
        if (file.get('https://atomicdata.dev/properties/blob') !== blob)
          throw new Error('Attachment metadata missing');
        const hex = blob.replace(/^(atomic|did:ad):blob:/, '');
        const hash = Uint8Array.from(hex.match(/../g)!, b => parseInt(b, 16));
        const bytes = await window.store.getClientDb()!.getBlob(hash);
        if (!bytes) throw new Error('Attachment bytes missing after crash');

        return Array.from(bytes);
      },
      attachment,
    );
    expect(
      createHash('sha256')
        .update(Buffer.from(restoredAttachment))
        .digest('hex'),
    ).toBe(expectedAttachmentHash);
    await page.goto(documentUrl);
    await expect(page.getByLabel('Rich Text Editor')).toContainText(
      'Document survives SIGKILL',
    );
  } finally {
    diagnostics.dispose();
    await testInfo.attach('crash-diagnostics', {
      body: JSON.stringify(diagnostics.snapshot(), null, 2),
      contentType: 'application/json',
    });
    await context?.close();
  }

  expect(diagnostics.snapshot().unexpected).toEqual([]);
  // Each injected close permits at most one precisely identified warning.
  // SIGKILL/navigation can preempt its delivery, so fewer warnings are valid;
  // requiring every warning would make this crash harness itself flaky.
});
