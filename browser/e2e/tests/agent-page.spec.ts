/**
 * The Agent page: profile, your private notes on someone, your messages with
 * them, and what they created where you can read it.
 */
import { core, dataBrowser } from '@tomic/lib';
import { test, expect, type Page } from './fixtures';
import {
  before,
  contextMenuClick,
  devDrive,
  installCommitWatcher,
  openSubject,
  SERVER_URL,
  waitForSynced,
} from './test-utils';

async function agentSubject(page: Page): Promise<string> {
  await page.waitForFunction(() => !!window.store?.getAgent()?.subject);

  return page.evaluate(() => window.store.getAgent()!.subject!);
}

async function waitForEncryptionKey(agent: string) {
  await expect
    .poll(
      async () => {
        const res = await fetch(`${SERVER_URL}/${agent}`, {
          headers: { Accept: 'application/ad+json' },
        }).catch(() => undefined);

        return res?.ok ? (await res.text()).includes('encryptionKey') : false;
      },
      { timeout: 30_000 },
    )
    .toBe(true);
}

test.describe('agent page', () => {
  test.beforeEach(before);

  test('shows a profile, private notes, messages and what they created', async ({
    page,
    browser,
  }) => {
    test.slow();

    const alice = await agentSubject(page);
    const bobContext = await browser.newContext();
    const bob = await bobContext.newPage();
    await installCommitWatcher(bob);
    await devDrive(bob);
    const bobSubject = await agentSubject(bob);
    await waitForEncryptionKey(bobSubject);

    // Alice makes a folder both can write in; Bob creates a document in it.
    const folder = await page.evaluate(
      async ({ a, b, name, read, write, folderClass }) => {
        const store = window.store;
        const parent = await store.privateDriveSubject();
        const res = await store.newResource({
          parent,
          isA: folderClass,
          propVals: {
            [name]: 'Shared folder',
            [read]: [a, b],
            [write]: [a, b],
          },
        });
        await res.save();
        store.notifyResourceManuallyCreated(res);

        return res.subject;
      },
      {
        a: alice,
        b: bobSubject,
        name: core.properties.name,
        read: core.properties.read,
        write: core.properties.write,
        folderClass: dataBrowser.classes.folder,
      },
    );
    await bob.evaluate(
      async ({ parent, name, folderClass }) => {
        const store = window.store;
        await store.getResource(parent);
        const res = await store.newResource({
          parent,
          isA: folderClass,
          propVals: { [name]: 'Bobs plan' },
        });
        await res.save();
        store.notifyResourceManuallyCreated(res);
      },
      {
        parent: folder,
        name: core.properties.name,
        folderClass: dataBrowser.classes.folder,
      },
    );
    // `save()` can resolve before the server has the commit; the Created list
    // below is a server query, so wait until his write has left his outbox.
    await waitForSynced(bob);

    // Alice starts a conversation with Bob from his page.
    await openSubject(page, bobSubject);
    await expect(
      page.getByRole('button', { name: 'Send message' }),
    ).toBeVisible({
      timeout: 30_000,
    });
    await page.getByRole('button', { name: 'Send message' }).click();
    await expect(page.getByText('End-to-end encrypted')).toBeVisible({
      timeout: 30_000,
    });

    // Back on his page: the conversation is listed, her note is saved, and
    // his document shows up.
    await openSubject(page, bobSubject);
    // The sidebar's Messages panel lists the same conversation, so a bare
    // test id is ambiguous as soon as both have rendered (strict mode error
    // under load). Scope it to his page.
    await expect(
      page.getByRole('main').getByTestId('conversation-item'),
    ).toBeVisible({
      timeout: 30_000,
    });
    // The query runs on the server, which may not have his commit yet.
    await expect(async () => {
      await page.reload();
      await expect(page.getByText('Bobs plan')).toBeVisible({ timeout: 5_000 });
    }).toPass({ timeout: 60_000 });
    await page.getByRole('button', { name: 'Add a note' }).click();
    const editor = page.locator(
      'section[aria-label="Your notes"] [contenteditable="true"]',
    );
    await editor.click();
    await page.keyboard.type('Real name: Robert');
    await page.getByRole('button', { name: 'Save' }).click();
    // A reload before the note is on the server and on disk loses it.
    await waitForSynced(page);
    await page.reload();
    await expect(page.getByText('Real name: Robert')).toBeVisible({
      timeout: 30_000,
    });

    // Alice favorites Bob from his page; he shows in her sidebar by name.
    await contextMenuClick('favorite', page);
    await expect(
      page.getByTestId('favorites').getByTestId('favorite-item'),
    ).toBeVisible({ timeout: 15_000 });

    // Bob cannot see the note on his own page.
    await openSubject(bob, bobSubject);
    await expect(bob.getByText('Real name: Robert')).toHaveCount(0);

    // Your own page has no messages and no notes.
    await openSubject(page, alice);
    await expect(
      page.getByRole('button', { name: 'Send message' }),
    ).toHaveCount(0);
    await expect(page.getByText('Your notes')).toHaveCount(0);

    await bobContext.close();
  });
});
