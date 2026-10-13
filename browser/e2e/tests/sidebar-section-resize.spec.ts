// oxlint-disable no-await-in-loop
import { test, expect, type Locator, type Page } from './fixtures';
import { before } from './test-utils';
import { enableAIForTesting, setupAIRouteMocks } from './ai-mock';

test.use({
  viewport: { width: 390, height: 844 },
  hasTouch: true,
  isMobile: true,
});

async function dragHeader(page: Page, header: Locator, dy: number) {
  await header.scrollIntoViewIfNeeded();
  const box = (await header.boundingBox())!;
  const x = box.x + 30;
  const y = box.y + box.height / 2;
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('Input.dispatchTouchEvent', {
    type: 'touchStart',
    touchPoints: [{ x, y }],
  });

  for (let step = 1; step <= 8; step++) {
    await cdp.send('Input.dispatchTouchEvent', {
      type: 'touchMove',
      touchPoints: [{ x, y: y + (dy * step) / 8 }],
    });
    // Deliver a real gesture across frames instead of an instantaneous fling.
    await page.evaluate(
      () =>
        new Promise<void>(resolve => requestAnimationFrame(() => resolve())),
    );
  }

  await cdp.send('Input.dispatchTouchEvent', {
    type: 'touchEnd',
    touchPoints: [],
  });
  await cdp.detach();
  // Chromium suppresses taps for 500ms after a synthetic touch fling, even on
  // a plain touch-action:none button. Finish this gesture before the next one.
  await page.waitForTimeout(600);
}

test('mobile section headers resize without collapsing, persist height and retain actions', async ({
  page,
}) => {
  await setupAIRouteMocks(page);
  await enableAIForTesting(page);
  await before({ page });
  await page.evaluate(async () => {
    const store = window.store;
    const parent = await store.getAgent()!.privateDriveSubject();

    for (let index = 0; index < 14; index++) {
      const chat = await store.newResource({
        parent,
        isA: 'https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/class/ai-chat',
        propVals: {
          'https://atomicdata.dev/properties/name': `Resize chat ${index}`,
        },
      });
      await chat.save();
    }
  });
  const sidebar = page.getByTestId('sidebar');
  const toggle = page.getByRole('button', { name: /Show \/ hide sidebar/ });
  if (await sidebar.evaluate(el => getComputedStyle(el).opacity === '0'))
    await toggle.tap();
  const section = sidebar.getByTestId('ai-chats-panel');
  await expect(section.getByRole('link')).toHaveCount(14);
  const header = section.locator('button[aria-expanded]');
  await header.scrollIntoViewIfNeeded();
  // Panel headers share the touch bar height (SIDEBAR_BAR_HEIGHT_TOUCH, 2.5rem).
  expect((await header.boundingBox())!.height).toBeGreaterThanOrEqual(40);
  const start = (await section.boundingBox())!.height;
  await dragHeader(page, header, 90);
  await expect(header).toHaveAttribute('aria-expanded', 'true');
  await expect
    .poll(async () => (await section.boundingBox())!.height)
    .toBeCloseTo(start - 90, 0);
  await expect
    .poll(() =>
      page.evaluate(() =>
        JSON.parse(localStorage.getItem('aiChatsPanelHeight')!),
      ),
    )
    .toBe(230);

  await dragHeader(page, header, -60);
  await expect
    .poll(async () => (await section.boundingBox())!.height)
    .toBeCloseTo(start - 30, 0);
  await header.tap();
  await expect(header).toHaveAttribute('aria-expanded', 'false');
  await section
    .getByRole('button', { name: 'Expand AI Chats', exact: true })
    .tap();
  await expect(header).toHaveAttribute('aria-expanded', 'true');
  await page.reload();
  if (await sidebar.evaluate(el => getComputedStyle(el).opacity === '0'))
    await toggle.tap();
  await expect
    .poll(async () => (await section.boundingBox())!.height)
    .toBeCloseTo(start - 30, 0);
  await section.getByRole('button', { name: 'New Chat', exact: true }).tap();
  await expect(page.getByTestId('ai-sidebar')).toHaveAttribute('data-open', '');
  await expect(header).toHaveAttribute('aria-expanded', 'true');
});
