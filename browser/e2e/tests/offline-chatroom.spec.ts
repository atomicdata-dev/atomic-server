// oxlint-disable no-await-in-loop
/**
 * Offline chatroom: messages must survive a disconnect → reconnect → reload
 * round trip with the original ordering and no duplicates.
 *
 * Why this exists: chat messages are individual resources whose ordering is
 * carried by the chatroom's `messages` ResourceArray. The interesting failure
 * modes are
 *   1. an offline-queued message resource never reaching the server,
 *   2. the chatroom's `messages` array losing an entry during sync,
 *   3. a sync replay double-applying a queued commit and creating duplicates,
 *   4. the array surviving but in the wrong order because the offline queue
 *      drained out of order.
 *
 * The test creates a chatroom + 3 messages while offline, reconnects, waits
 * for the dirty queue to drain, reloads, and re-fetches the chatroom from
 * the server. It then asserts each message appears exactly once and in the
 * order it was sent.
 */

import { test, expect, type Page } from '@playwright/test';
import {
  before,
  FRONTEND_URL,
  getCurrentSubject,
  newResource,
} from './test-utils';

const MESSAGES = [
  'Offline message #1 — first',
  'Offline message #2 — second',
  'Offline message #3 — third',
] as const;

async function waitForReady(page: Page) {
  await page.waitForFunction(
    () => {
      return (
        window.store?.getClientDb()?.isReady === true &&
        window.store?.getSyncStatus().serverConnected === true
      );
    },
    undefined,
    { timeout: 30000 },
  );
}

async function disconnect(page: Page) {
  await page.evaluate(() => window.store.disconnect());
  // syncStatus updates fire on the next event-loop tick after the WS close;
  // under suite-wide load that can run past the default 5s budget.
  await page.waitForFunction(
    () => window.store?.getSyncStatus().serverConnected === false,
    undefined,
    { timeout: 15000 },
  );
}

async function reconnectAndDrain(page: Page) {
  await page.evaluate(() => window.store.reconnect());
  await page.waitForFunction(
    () => {
      return (
        window.store?.getSyncStatus().serverConnected === true &&
        window.store?.getSyncStatus().pendingDirtyCount === 0
      );
    },
    undefined,
    { timeout: 30000 },
  );
}

test.describe('offline chatroom', () => {
  test.beforeEach(before);

  test('messages survive offline create + reload after sync', async ({
    page,
  }) => {
    test.slow();
    await waitForReady(page);

    // Go offline before doing any work — the chatroom and all messages must
    // be created against the local store only.
    await disconnect(page);

    // Create a chatroom. `newResource` clicks the sidebar buttons and waits
    // for the editable title to focus — that flow doesn't hit the network.
    await newResource('chatroom', page);
    await page.keyboard.type('Offline Chat');
    await page.keyboard.press('Enter');
    await expect(
      page.getByRole('heading', { name: 'Offline Chat' }),
    ).toBeVisible({ timeout: 10000 });

    // Stash the chatroom's resolved subject so we can re-open it after the
    // reload (the URL might still carry a `_new:` placeholder pre-sign).
    const chatSubject = await getCurrentSubject(page);
    expect(chatSubject).toMatch(/^did:ad:/);

    const chatInput = page.getByLabel('Chat input');
    await expect(chatInput).toBeFocused();

    // Send the messages sequentially. We block on the input clearing AND the
    // sent text appearing in the DOM before moving on; otherwise the next
    // fill can race with React's optimistic-clear and produce out-of-order
    // commits, which would muddy the assertion at the end.
    for (const text of MESSAGES) {
      await chatInput.fill(text);
      // Pressing Enter submits via the chatroom's keyboard handler. Avoids
      // the Send button being intercepted by the "chatroom created" toast.
      await chatInput.press('Enter');
      await expect(chatInput).toHaveValue('');
      await expect(page.locator(`text=${text}`).first()).toBeVisible({
        timeout: 10000,
      });
    }

    // Sanity: the dirty-sync queue must contain pending work for the
    // chatroom + each message before we go online. If this is 0 we're not
    // actually offline-creating anything (the test would silently pass).
    const pendingBeforeReconnect = await page.evaluate(
      () => window.store.getSyncStatus().pendingDirtyCount,
    );
    expect(pendingBeforeReconnect).toBeGreaterThan(0);

    // Go online and wait for the queue to fully drain.
    await reconnectAndDrain(page);

    // Reload (kills the in-memory store; what we see next must come from
    // the server through the normal subscribe/sync path).
    await page.goto(
      `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(chatSubject)}`,
    );
    await page.waitForFunction(
      () => window.store?.getSyncStatus().serverConnected === true,
      undefined,
      { timeout: 15000 },
    );

    // Wait for all three messages to render after the fresh fetch.
    for (const text of MESSAGES) {
      await expect(page.locator(`text=${text}`).first()).toBeVisible({
        timeout: 15000,
      });
    }

    // Author + date must survive the reload here too. These were created
    // OFFLINE and only materialized on sync, so this guards the
    // offline → reconnect → reload path: createdBy (= signing agent, "Dev
    // User" via `devDrive`) and createdAt come from the genesis certificate
    // materialized into propvals — not from a refetched commit. Walk up from
    // the message text to its `[about]` wrapper.
    const firstMessage = page
      .getByText(MESSAGES[0], { exact: true })
      .first()
      .locator('xpath=ancestor::*[@about][1]');
    await expect(
      firstMessage,
      'Message author missing after offline→sync→reload',
    ).toContainText('Dev User');
    const year = new Date().getFullYear().toString();
    await expect(
      firstMessage.locator('time'),
      'Message date missing after offline→sync→reload',
    ).toHaveAttribute('datetime', new RegExp(`^${year}-`));

    // No duplicates: each message must appear exactly once. `getByText` with
    // `exact: true` ensures we don't accidentally match substrings of a
    // longer message.
    for (const text of MESSAGES) {
      const count = await page.getByText(text, { exact: true }).count();
      expect(count, `message "${text}" appeared ${count}× — expected 1`).toBe(
        1,
      );
    }

    // Correct order: walk the DOM and collect the FIRST text occurrence of
    // each expected message in document order. Using `getByText(m).first()`
    // gives us the message's own `<Markdown>` rendering, which sits
    // exactly once per message.
    const positions: Array<{ text: string; y: number }> = [];

    for (const text of MESSAGES) {
      const box = await page
        .getByText(text, { exact: true })
        .first()
        .boundingBox();
      expect(box, `message "${text}" has no bounding box`).toBeTruthy();
      positions.push({ text, y: box!.y });
    }

    const orderedByPosition = positions
      .slice()
      .sort((a, b) => a.y - b.y)
      .map(p => p.text);

    expect(
      orderedByPosition,
      'rendered message order does not match send order',
    ).toEqual([...MESSAGES]);
  });
});
