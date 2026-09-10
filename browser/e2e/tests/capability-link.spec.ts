import { test, expect } from './fixtures';
import {
  FRONTEND_URL,
  before,
  editableTitle,
  getCurrentSubject,
  installCommitWatcher,
  newResource,
  setTitle,
  topBarShareButton,
  waitForSynced,
} from './test-utils';

/**
 * A capability link opens one resource for whoever holds it: no account, no
 * invitation to accept. The right is the link. Here the owner mints one from
 * the Share dialog and a browser that has never seen this server opens it.
 */
test.describe('capability links', () => {
  test.beforeEach(before);

  const mintLink = async (
    page: Parameters<typeof setTitle>[0],
    context: { grantPermissions: (p: string[], o?: { origin: string }) => Promise<void> },
    mode: 'View' | 'Edit',
  ): Promise<string> => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], {
      origin: new URL(FRONTEND_URL).origin,
    });
    await topBarShareButton(page).click();
    await page.getByRole('button', { name: 'Create link' }).click();
    await page.getByRole('radio', { name: mode }).check();
    await page.getByRole('button', { name: 'Create link' }).click();
    await expect(page.getByText('Link created and copied')).toBeVisible();

    const link = await page.evaluate(() =>
      document
        .querySelector('[data-code-content]')
        ?.getAttribute('data-code-content'),
    );
    expect(link).toBeTruthy();
    expect(link).toContain('/app/open?');
    expect(link).toContain('cap=');

    // The link's agent and its grant have to reach the server before a
    // stranger asks for the resource with it.
    await waitForSynced(page);

    return link as string;
  };

  test('a browser with no account opens a view link', async ({
    page,
    context,
    browser,
  }) => {
    const title = `Shared by link ${Date.now()}`;
    await newResource('document', page);
    await setTitle(page, title);
    const subject = await getCurrentSubject(page);

    const link = await mintLink(page, context, 'View');

    const guest = await browser.newContext();
    const page2 = await guest.newPage();
    await page2.goto(link);
    await page2.waitForURL(/\/app\/show/, { timeout: 20_000 });
    await expect(page2.getByText(title).first()).toBeVisible({ timeout: 20_000 });
    expect(await getCurrentSubject(page2)).toBe(subject);

    // The right survives a reload: the link's identity is kept for this
    // browser, as the demo guest's is.
    await page2.reload();
    await expect(page2.getByText(title).first()).toBeVisible({ timeout: 20_000 });
    await guest.close();
  });

  test('an edit link lets the holder change the resource, and the owner sees it', async ({
    page,
    context,
    browser,
  }) => {
    const title = `Editable by link ${Date.now()}`;
    await newResource('document', page);
    await setTitle(page, title);

    const link = await mintLink(page, context, 'Edit');

    const guest = await browser.newContext();
    const page2 = await guest.newPage();
    // `setTitle` waits for the rename's commit; over WebSocket that needs the
    // watcher `before()` installs on the owner's page.
    await installCommitWatcher(page2);
    await page2.goto(link);
    await page2.waitForURL(/\/app\/show/, { timeout: 20_000 });
    await expect(page2.getByText(title).first()).toBeVisible({ timeout: 20_000 });

    const renamed = `${title} (edited by guest)`;
    await setTitle(page2, renamed);
    await waitForSynced(page2);
    await guest.close();

    await page.reload();
    await expect(editableTitle(page)).toContainText(renamed, { timeout: 20_000 });
  });
});
