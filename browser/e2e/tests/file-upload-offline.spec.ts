/**
 * File upload — three scenarios that all need to round-trip:
 *
 *   1. Online: upload → resource lands with the right parent → blob bytes hit
 *      `/download/files/<hash>` immediately → preview renders.
 *   2. Offline-only: upload while disconnected → preview renders from the
 *      WASM clientDb's blob via a `blob:` URL (no network).
 *   3. Offline → reload → reconnect: upload while disconnected, do a full
 *      page reload (kills in-memory `_pendingCommits`), then reconnect →
 *      the persisted offline queue is re-attached, the commit POSTs, the
 *      blob bytes are pushed, and the server returns 200 for the download.
 */

import { test, expect } from './fixtures';
import { before, FRONTEND_URL } from './test-utils';

const PNG_HEADER = '89504e47'; // first 4 bytes of any PNG file

async function uploadGeneratedPng(
  page: import('@playwright/test').Page,
  name: string,
  parent?: string,
): Promise<string> {
  return page.evaluate(
    async ({ name: fileName, parent: parentArg }) => {
      const driveSubject = parentArg ?? window.store.getSyncStatus().drive;
      const canvas = new OffscreenCanvas(16, 16);
      const ctx = canvas.getContext('2d')!;
      ctx.fillStyle = 'red';
      ctx.fillRect(0, 0, 16, 16);
      const blob = await canvas.convertToBlob({ type: 'image/png' });
      const file = new File([await blob.arrayBuffer()], fileName, {
        type: 'image/png',
      });
      const subjects = await window.store.uploadFiles([file], driveSubject!);

      return subjects[0] as string;
    },
    { name, parent },
  );
}

test.describe('file upload + offline survival', () => {
  test.beforeEach(before);

  test('online upload round-trips through download URL', async ({ page }) => {
    const subject = await uploadGeneratedPng(page, 'online.png');

    const result = await page.evaluate(async (s: string) => {
      const r = window.store.resources.get(s)!;
      const downloadUrl = r.get(
        'https://atomicdata.dev/properties/downloadURL',
      );
      const parent = r.get('https://atomicdata.dev/properties/parent');
      const drive = window.store.getSyncStatus().drive;
      const resp = await fetch(downloadUrl);
      const buf = new Uint8Array(await resp.arrayBuffer());
      const hex = Array.from(buf.slice(0, 4))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

      return { status: resp.status, parent, drive, header: hex };
    }, subject);

    expect(result.parent).toBe(result.drive);
    expect(result.status).toBe(200);
    expect(result.header).toBe(PNG_HEADER);
  });

  test('offline upload renders from local blob (no network)', async ({
    page,
  }) => {
    await page.evaluate(() => window.store.disconnect());
    // syncStatus updates fire on the next event-loop tick after the WS
    // close is observed; under suite-wide load that can exceed the default
    // 5s waitForFunction timeout.
    await page.waitForFunction(
      () => window.store?.getSyncStatus().serverConnected === false,
      undefined,
      { timeout: 15000 },
    );

    const subject = await uploadGeneratedPng(page, 'pure-offline.png');

    // Navigate to the file page; the preview must render *without* any
    // /download/files/ request succeeding.
    await page.goto(
      `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(subject)}`,
    );

    // The img inside the file preview should have a blob: src and decode.
    await page.waitForFunction(() => {
      const img = document.querySelector(
        '[data-test="image-viewer"]',
      ) as HTMLImageElement | null;

      return !!img && img.src.startsWith('blob:') && img.naturalWidth > 0;
    });

    // Reconnect for cleanup so the next test starts clean.
    await page.evaluate(() => window.store.reconnect());
  });

  test('offline upload survives reload + reconnect', async ({ page }) => {
    await page.evaluate(() => window.store.disconnect());
    // syncStatus updates fire on the next event-loop tick after the WS
    // close is observed; under suite-wide load that can exceed the default
    // 5s waitForFunction timeout.
    await page.waitForFunction(
      () => window.store?.getSyncStatus().serverConnected === false,
      undefined,
      { timeout: 15000 },
    );

    const subject = await uploadGeneratedPng(page, 'survives-reload.png');

    // Persist the subject across the reload — sessionStorage survives F5.
    await page.evaluate(
      (s: string) => sessionStorage.setItem('test.fileSubject', s),
      subject,
    );

    // Full reload: kills the in-memory `_pendingCommits` queue. The persisted
    // `atomic.offline.<subject>` localStorage entry has to carry the load.
    await page.goto(
      `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(subject)}`,
    );

    // The store is set on window at module load; wait for it before the next eval.
    await page.waitForFunction(() => !!window.store);

    // Touch the resource so hydrateResourceFromJson fires for it.
    await page.evaluate(async (s: string) => {
      await window.store.getResource(s);
    }, subject);

    // After hydration the queue should be re-attached.
    await page.waitForFunction((s: string) => {
      const r = window.store.resources.get(s);

      return r?.hasPendingCommits === true;
    }, subject);

    // Reconnect and wait for the dirty queue to drain.
    await page.evaluate(() => window.store.reconnect());
    await page.waitForFunction(() => {
      const st = window.store?.getSyncStatus();

      return st.serverConnected && st.pendingDirtyCount === 0;
    });

    // Now the server should return the bytes.
    const result = await page.evaluate(async (s: string) => {
      const store = window.store;

      if (!store) {
        throw new Error('store missing');
      }

      const r = store.resources.get(s);

      if (!r) {
        throw new Error(`resource missing: ${s}`);
      }

      const downloadUrl = r.get(
        'https://atomicdata.dev/properties/downloadURL',
      );
      const resp = await fetch(downloadUrl);
      const buf = new Uint8Array(await resp.arrayBuffer());
      const hex = Array.from(buf.slice(0, 4))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

      return { status: resp.status, header: hex };
    }, subject);

    expect(result.status).toBe(200);
    expect(result.header).toBe(PNG_HEADER);
  });
});
