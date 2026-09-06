/**
 * These End to End tests of AtomicServer are where we test if the server and the browser integrate well.
 * Since these tests are relatively slow, try to utilize unit tests to catch bugs earlier.
 * Use the devDrive helpers to quickly setup an agent + drive and start with a clean slate.
 * Keeping these tests as fast as possible is essential.
 * Try not to rely on hardcoded timeouts, as this is likely to lead to race conditions and flakiness in CI (slower hardware).
 */

import { test, expect, type Page } from '@playwright/test';
import {
  FRONTEND_URL,
  spaUrl,
  before,
  changeDrive,
  contextMenuClick,
  currentDialogOkButton,
  currentDriveTitle,
  editProfileAndCommit,
  editTitle,
  editableTitle,
  getCurrentSubject,
  newDrive,
  newResource,
  openConfigureDrive,
  openNewSubjectWindow,
  openSubject,
  publicReadRightLocator,
  setTitle,
  signIn,
  timestamp,
  waitForCommit,
  waitForSynced,
  openAgentPage,
  fillSearchBox,
  selectHistoryVersionShowing,
  inDialog,
  acceptInvite,
  topBarShareButton,
  SEARCHBOX_PROPERTY_PLACEHOLDER,
  smoke,
} from './test-utils';

test.describe('data-browser', async () => {
  test.beforeEach(before);

  test('sidebar mobile', async ({ page }) => {
    await page.setViewportSize({ width: 500, height: 800 });
    await page.reload();
    await page.click('[data-test="sidebar-toggle"]');
    await expect(currentDriveTitle(page)).toBeVisible();
  });

  test('switch Server URL', async ({ page }) => {
    await changeDrive('https://atomicdata.dev', page);
    await expect(currentDriveTitle(page)).toContainText('atomicdata.dev');
  });

  test(
    'sign in with secret, edit profile, sign out',
    smoke,
    async ({ page }) => {
      await signIn(page);
      await editProfileAndCommit(page);

      page.on('dialog', d => {
        d.accept();
      });

      await openAgentPage(page);
      await page.click('[data-test="sign-out"]');
      await expect(
        page.getByRole('button', { name: 'Create account' }),
      ).toBeVisible();
      await expect(
        page.getByRole('button', { name: 'Sign in', exact: true }),
      ).toBeVisible();
      await page.reload();
      await expect(
        page.getByRole('button', { name: 'Create account' }),
      ).toBeVisible();
    },
  );

  /**
   * We remove public read rights from drive, create an invite, open that
   * invite, and add the public read right again.
   */
  test(
    'authorization, invite, share menu',
    smoke,
    async ({ page, browser, context }) => {
      // `acceptInvite` (test-utils.ts) waits through two sequential server
      // round trips (new agent genesis commit save, then invite accept POST)
      // before its dialog opens — see the comment at that call site. Give the
      // whole test a wider budget to match, same as plugin.spec.ts's install
      // flow.
      test.slow();

      await signIn(page);
      const { driveURL, driveTitle } = await newDrive(page);
      await currentDriveTitle(page).click();
      await contextMenuClick('share', page);
      expect(publicReadRightLocator(page)).not.toBeChecked();

      // Initialize unauthorized page for reader. An anonymous user landing on a
      // private drive is redirected to the welcome flow (ErrorPage redirects on
      // unauthorized when no agent), so check for the sign-in card buttons that
      // GettingStartedFlow renders instead of a literal "Unauthorized" string.
      const context2 = await browser.newContext();
      const page2 = await context2.newPage();
      await page2.setViewportSize({ width: 1000, height: 400 });
      // Navigate straight to the private drive. Do NOT use `openSubject` here:
      // it waits for `main[about=drive]`, but an unauthorized anonymous user is
      // redirected to /welcome — `main[about]` only renders as a sub-second
      // flash (ResourcePage wraps ErrorPage in <Main> before the redirect
      // effect fires). Dev is slow enough to catch that flash; on a production
      // bundle the redirect wins the race. The correct readiness signal is the
      // welcome card itself, asserted below.
      await page2.goto(
        `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(driveURL)}`,
      );
      await expect(
        page2.getByRole('button', { name: 'Create account' }),
      ).toBeVisible({ timeout: 15000 });

      // Create invite
      await page.click('button:has-text("Create Invite")');
      context.grantPermissions(['clipboard-read', 'clipboard-write']);
      await page.click('button:has-text("Create")');
      await expect(
        page.locator('text=Invite created and copied '),
      ).toBeVisible();
      const inviteUrl = await page.evaluate(() =>
        document
          ?.querySelector('[data-code-content]')
          ?.getAttribute('data-code-content'),
      );
      expect(inviteUrl).not.toBeFalsy();

      // The invite resource needs to be persisted server-side before the
      // invitee opens its URL — otherwise the server returns 404. Wait for
      // the dirty queue to drain rather than guessing a fixed 200ms.
      await page.waitForFunction(
        () => window.store?.getSyncStatus().pendingDirtyCount === 0,
        undefined,
        { timeout: 10000 },
      );

      // Open invite
      const page3 = await openNewSubjectWindow(browser, inviteUrl as string);
      await acceptInvite(page3);
      await page3.waitForURL(/\/app\/show/, { timeout: 15000 });
      await page3.reload();
      await expect(page3.getByText(driveTitle).first()).toBeVisible();
      // Accepting must also make the invited drive the ACTIVE one. Showing the
      // resource while the sidebar still points at the invitee's own drive is
      // the failure this guards: the sidebar lists the wrong children and the
      // drive-wide subscription goes to a drive nobody is looking at.
      await expect(page3.getByTestId('current-drive-title')).toHaveText(
        driveTitle,
      );
    },
  );

  test('chatroom', smoke, async ({ page, browser, context }) => {
    // This test also goes through `acceptInvite`'s two-round-trip agent
    // creation flow (see that call site) partway through, on top of its own
    // multi-round-trip chat/reload/invite steps — give it the same wider
    // budget as the invite test above.
    test.slow();

    const inputLocator = (currentPage: Page) =>
      currentPage.getByLabel('Chat input');

    await newResource('chatroom', page);
    // EditableTitle auto-focuses on creation, but the chat input also
    // mounts and may grab focus first — racing the early keystrokes into
    // the wrong element ("est Chat" in the title, "T" in the input).
    // Explicitly click the title and assert it's a textbox first.
    await editableTitle(page).click();
    await expect(editableTitle(page)).toHaveRole('textbox');
    await page.keyboard.press(
      process.platform === 'darwin' ? 'Meta+a' : 'Control+a',
    );
    await page.keyboard.type('Test Chat');
    await page.keyboard.press('Enter');
    await expect(
      page.getByRole('heading', { name: 'Test Chat' }),
    ).toBeVisible();
    await expect(inputLocator(page)).toBeFocused();
    const teststring = `My test: ${timestamp()}`;
    await inputLocator(page).fill(teststring);
    await expect(page.getByRole('button', { name: 'Send' })).toBeEnabled();
    await page.getByRole('button', { name: 'Send' }).click();
    await expect(
      inputLocator(page),
      'Text input not cleared after send',
    ).toHaveText('');
    await expect(
      page.locator(`text=${teststring}`),
      'Chat message not appearing directly after sending',
    ).toBeVisible({ timeout: 15_000 });

    // The message's CommitDetail row should show the author's name AND the
    // date. Both come from the message resource (genesis certificate), not
    // from fetching a `did:ad:commit:` envelope. Scope to the
    // message element (the styled <div> wrapping the message body +
    // CommitDetail; it carries `about={subject}` in the DOM) by walking
    // up from the message paragraph, so we don't accidentally match
    // some unrelated "Dev User" elsewhere on the page.
    const messageLocator = page
      .getByText(teststring)
      .locator('xpath=ancestor::*[@about][1]');
    await expect(messageLocator).toBeVisible();
    await expect(
      messageLocator,
      'Message author "Dev User" missing — genesis createdBy not retrievable',
    ).toContainText('Dev User');
    // The visible label is intentionally relative ("now", "1 minute ago").
    // Assert the semantic timestamp instead so the test proves `createdAt`
    // exists without coupling to presentation text.
    const year = new Date().getFullYear().toString();
    await expect(
      messageLocator.locator('time'),
      'Message date missing — genesis createdAt not retrievable',
    ).toHaveAttribute('datetime', new RegExp(`^${year}-`));

    // Regression: author + date must SURVIVE A REFRESH. They are derived from
    // the message's genesis certificate, materialized server-side into
    // propvals and served in JSON-AD — NOT refetched from a
    // `did:ad:commit:<sig>` resource. A hard reload drops the in-memory store,
    // so this proves the metadata round-trips from the DB.
    await page.reload();
    const messageAfterReload = page
      .getByText(teststring)
      .locator('xpath=ancestor::*[@about][1]');
    await expect(messageAfterReload).toBeVisible({ timeout: 15_000 });
    await expect(
      messageAfterReload,
      'Message author "Dev User" missing after refresh — creation metadata did not survive the round-trip',
    ).toContainText('Dev User');
    await expect(
      messageAfterReload.locator('time'),
      'Message date missing after refresh — createdAt did not survive the round-trip',
    ).toHaveAttribute('datetime', new RegExp(`^${year}-`));

    // Build the chatroom fallback URL on the SPA origin the guest already
    // accepted the invite on. Mixing FRONTEND_URL (Vite) with SERVER_URL
    // (embedded bundle) drops the guest's localStorage agent.
    const chatSubject = await getCurrentSubject(page);
    const showFallback = new URL('/app/show', FRONTEND_URL);
    showFallback.searchParams.set('subject', chatSubject);
    const chatRoomHref = showFallback.href;

    // Owner: Share → invite. Guest: open invite URL only (new agent via acceptInvite).
    await topBarShareButton(page).click();
    await expect(
      page.getByRole('button', { name: 'Create Invite' }),
    ).toBeVisible({ timeout: 10000 });

    context.grantPermissions(['clipboard-read', 'clipboard-write'], {
      origin: new URL(FRONTEND_URL).origin,
    });
    await page.getByRole('button', { name: 'Create Invite' }).click();
    await page.getByLabel('Allow edits').check();
    await page.getByRole('button', { name: 'Create' }).click();
    await expect(page.locator('text=Invite created and copied ')).toBeVisible();
    const inviteUrl = await page.evaluate(() =>
      document
        .querySelector('[data-code-content]')
        ?.getAttribute('data-code-content'),
    );
    expect(inviteUrl).toBeTruthy();
    await waitForSynced(page);

    const context2 = await browser.newContext();
    await context2.grantPermissions(['clipboard-read', 'clipboard-write'], {
      origin: new URL(FRONTEND_URL).origin,
    });
    const page2 = await context2.newPage();
    await page2.goto(spaUrl(inviteUrl as string));

    await acceptInvite(page2);
    await page2.waitForURL(/\/app\//, { timeout: 15_000 });

    try {
      await expect(page2.locator(`text=${teststring}`)).toBeVisible({
        timeout: 10_000,
      });
    } catch {
      // Redirect may land outside the chatroom; open the same /app/show?subject=… URL as the owner.
      await page2.goto(chatRoomHref);
      await expect(page2.locator(`text=${teststring}`)).toBeVisible({
        timeout: 15_000,
      });
    }

    await expect(page2.getByTestId('current-drive-title')).toContainText(
      "'s Drive",
    );
    await expect(page2.getByTestId('shared-with-me')).toBeVisible();
    await expect(
      page2.getByTestId('shared-with-me').getByTestId('shared-with-me-item'),
    ).toContainText('Test Chat');

    const teststring2 = `My reply: ${timestamp()}`;
    await inputLocator(page2).fill(teststring2);
    await expect(page2.getByRole('button', { name: 'Send' })).toBeEnabled();
    await page2.getByRole('button', { name: 'Send' }).click();
    await expect(page.locator(`text=${teststring2}`)).toBeVisible();
    await expect(page2.locator(`text=${teststring2}`)).toBeVisible();
  });

  test('bookmark', async ({ page }) => {
    await newResource('bookmark', page);

    const input = page.locator('[placeholder="https\\:\\/\\/example\\.com"]');
    await input.click();
    await input.fill('https://ontola.io');
    await page.locator(currentDialogOkButton).click();

    // Verify the bookmark imported page content. Use a substring + role
    // pairing that the live site is unlikely to change in casing or layout
    // (the `:text-is("Full-service")` strict match was already brittle and
    // fails now that the site uses "full-service" inline rather than as its
    // own element).
    await expect(
      page.getByRole('heading', { name: /software development/i }).first(),
      'Page contents not properly imported',
    ).toBeVisible();
  });

  // Resource-level favorites. Favoriting writes the `favorites` ResourceArray
  // on the user's PRIVATE DRIVE (home index), which the sidebar's bottom
  // "Favorites" panel reads back. Requires a server whose default store defines
  // the `favorites` property.
  test('favorite a resource shows it in the Favorites panel', async ({
    page,
  }) => {
    await newResource('folder', page);

    // No Favorites panel before anything is favorited.
    await expect(page.getByTestId('favorites')).toBeHidden();

    // Favorite the current resource via its context menu.
    await contextMenuClick('favorite', page);

    // The Favorites panel appears with the favorited resource.
    await expect(page.getByTestId('favorites')).toBeVisible({ timeout: 15000 });
    await expect(
      page.getByTestId('favorites').getByTestId('favorite-item').first(),
    ).toBeVisible();

    // Toggling it off (same menu item) removes the panel again.
    await contextMenuClick('favorite', page);
    await expect(page.getByTestId('favorites')).toBeHidden();
  });

  test('quick edit text typing ux', async ({ page }) => {
    await newResource('folder', page);

    // We automatically focus the title input after creating a new resource.
    // await editableTitle(page).click();

    const alphabet = 'abcdefghijklmnopqrstuvwxyz';

    // Set up listener BEFORE typing so it catches commits sent during the delay
    // between keystrokes (debounce fires during type()'s delay option).
    const firstCommit = waitForCommit(page);

    for (const letter of alphabet) {
      await editableTitle(page).type(letter, { delay: Math.random() * 300 });
    }

    // The last keystroke's debounce may not have been scheduled yet at loop
    // exit, so `pendingDirtyCount === 0` can be briefly true before the
    // final character is applied. Wait until the store holds the full
    // string — that's `useValue` applying the change — then drain the save
    // before Escape (which would otherwise race a still-armed debounce).
    await page.waitForFunction(
      expected => {
        const main = document.querySelector('main[about]');
        const subject = main?.getAttribute('about');

        if (!subject) {
          return false;
        }

        const resource = window.store?.resources.get(subject);

        return (
          resource?.get?.('https://atomicdata.dev/properties/name') === expected
        );
      },
      alphabet,
      { timeout: 15_000 },
    );
    await waitForSynced(page);
    await page.keyboard.press('Escape');

    await expect(
      page.locator(`text=${alphabet}`).first(),
      'String not correct after typing, bad typing UX. Maybe views are notified of changes twice?',
    ).toBeVisible();

    // Ensure at least one commit reached the server (proves saving is working).
    await firstCommit;

    await page.reload();
    await expect(
      page.locator(`text=${alphabet}`).first(),
      'Text not correct after reload',
    ).toBeVisible();
  });

  // FLAKY (dagger CI): the created document `RAM Downloading
  // Strategies` doesn't appear inside the folder view within 10 s after
  // creation. Locator was
  // `getByRole('main').getByText('RAM Downloading Strategies').first()`.
  // Likely a children-collection invalidation race after the `newResource`
  // commit. Investigate: subscribe directly to the folder's `useChildren`
  // collection ready state instead of waiting for the DOM.
  test('folder', smoke, async ({ page }) => {
    await newResource('folder', page);
    const folderTitle = 'TestFolder-uniqueName';
    await setTitle(page, folderTitle);
    // The sidebar no longer lists drive children — capture the folder URL
    // so we can navigate back after creating the child document.
    const folderUrl = page.url();

    // Create a child document via the empty-folder quick-create.
    await page
      .getByRole('main')
      .getByRole('button', { name: 'New Document' })
      .first()
      .click();
    // Wait for navigation onto the new document before editing — under
    // suite-wide load the folder page can still be active and `editTitle`
    // would otherwise rename the folder instead of the new document.
    await page.waitForURL(url => url.toString() !== folderUrl, {
      timeout: 10000,
    });
    const docTitle = 'RAM Downloading Strategies';
    await editTitle(docTitle, page);

    // Wait for the doc's save to flush before navigating away.
    await waitForSynced(page);

    // Back to the folder — assert the child appears in the main page.
    await page.goto(folderUrl);
    await expect(
      page.getByRole('main').getByText(docTitle).first(),
      'Created document not visible in folder',
    ).toBeVisible({ timeout: 10000 });
  });

  test('folder title auto-edits on creation', async ({ page }) => {
    await newResource('folder', page);
    await expect(editableTitle(page)).toHaveRole('textbox');
  });

  test('user drives page', async ({ page }) => {
    const initialDriveSubject = await getCurrentSubject(page);
    const initialDriveTitle = await currentDriveTitle(page).textContent();

    await openConfigureDrive(page);
    await expect(
      page.getByRole('heading', { name: 'My drives' }),
    ).toBeVisible();
    // Personal and saved drives don't count as "recently visited"; with no
    // other drives opened yet the section hides entirely.
    await expect(
      page.getByRole('heading', { name: 'Recently visited' }),
    ).not.toBeVisible();

    const { driveTitle: secondDriveTitle } = await newDrive(page);
    await expect(currentDriveTitle(page)).toHaveText(secondDriveTitle);

    // Switch back through the open-by-URL input on the drives page. The field
    // is behind an "Open" disclosure — the section leads with the drive
    // list and "New drive" — so it is not in the DOM until this is clicked.
    await openConfigureDrive(page);
    await page.locator('[data-test="open-drive-by-url"]').click();
    await page
      .getByLabel('Open a drive by URL or DID')
      .fill(initialDriveSubject);
    await page.locator('[data-test="drive-url-save"]').click();
    await expect(currentDriveTitle(page)).toHaveText(initialDriveTitle ?? '');

    // Opening a drive that is neither personal nor saved lands it in
    // Recently visited, which makes the section appear.
    await changeDrive('https://atomicdata.dev', page);
    await openConfigureDrive(page);
    await expect(
      page.getByRole('heading', { name: 'Recently visited' }),
    ).toBeVisible();
  });

  test('form validation', async ({ page }) => {
    await newResource('https://atomicdata.dev/classes/Class', page);
    const shortnameInput = '[data-test="input-shortname"]';
    await page.click(shortnameInput);
    // The field sanitizes as you type rather than rejecting: a space becomes a
    // dash, and the trailing dash is settled away on blur. Typing must survive
    // this — a per-keystroke strip of trailing dashes ate the separator before
    // the next character arrived, so "not valid-" came out as "notvalid" and
    // hyphenated shortnames were untypeable.
    await page.keyboard.type('not valid-');
    await page.locator(shortnameInput).blur();
    await expect(page.locator(shortnameInput)).toHaveValue('not-valid');
    await page.locator(shortnameInput).fill('');
    await page.keyboard.type('is-valid');
    await expect(page.locator('text=Not a valid slug')).not.toBeVisible();
    await page.getByRole('button', { name: 'advanced' }).click();
    await fillSearchBox(
      page,
      SEARCHBOX_PROPERTY_PLACEHOLDER,
      'https://atomicdata.dev/properties/invite/usagesLeft',
    );
    await page.keyboard.press('Enter');
    await expect(page.locator('text=Usages-left').first()).toBeVisible();
    // Integer validation
    await page.click('[data-test="input-usages-left"]');
    await page.keyboard.type('asdf1');
    await expect(page.locator('text=asdf')).not.toBeVisible();

    await expect(page.getByRole('button', { name: 'Save' })).toBeDisabled();

    await page.getByLabel('Description').click();
    await page.keyboard.type('This is a test class');
    await page.click('button:has-text("Save")');

    await expect(page.locator('text=Resource Saved')).toBeVisible();
  });

  test('delete resource', smoke, async ({ page }) => {
    await newResource('folder', page);
    const parentResource = await getCurrentSubject(page);
    // Empty-folder quick-create now renders dedicated "New Folder" / "New
    // Document" buttons instead of a generic "New Resource" + class picker.
    const parentUrl = page.url();
    await page
      .getByRole('main')
      .getByRole('button', { name: 'New Folder' })
      .first()
      .click();
    // QuickCreateRow's onClick fires createNewResource without awaiting, so
    // the click returns before the navigation. Reading the subject here
    // without waiting gives the PARENT's — which this test then destroyed and
    // asserted was gone, passing without once exercising the cascade it
    // exists to cover. Whether the navigation had landed depended on load,
    // which is what made it look flaky.
    await page.waitForURL(url => url.toString() !== parentUrl, {
      timeout: 10000,
    });
    const nestedResource = await getCurrentSubject(page);
    expect(nestedResource).not.toBe(parentResource);
    await openSubject(page, parentResource);
    await contextMenuClick('delete', page);
    // Confirm the destroy in the dialog. Scoping to `dialog[open]` is needed
    // because the menu's "Delete" entry can still match `button:has-text` on
    // some renders before it unmounts, leading to flaky no-ops.
    await page.locator('dialog[open] button:has-text("Delete")').click();

    // Wait for the destroy to actually land before reloading. The reload is
    // what makes this a barrier and not a nicety: it abandons whatever the
    // page still had in flight, so returning too early cancels the destroy and
    // the resource is simply still there afterwards.
    //
    // This used to wait on the "Resource deleted" toast alone, which is why
    // the test was marked flaky. A success toast expires after about two
    // seconds, so under suite load it can be raised and gone before the first
    // poll — the delete having worked perfectly — and the assertion then waits
    // out its timeout on an element that will never come back.
    //
    // So accept either signal: the toast if we catch it, or the sidebar having
    // dropped the folder, which is the same fact in a form that does not
    // expire. Whichever arrives first, the destroy has been applied.
    await expect
      .poll(
        async () => {
          const toast = await page.locator('text=Resource deleted').count();
          const listed = await page
            .getByTestId('sidebar')
            .getByText('Folder')
            .count();

          return toast > 0 || listed === 0;
        },
        { timeout: 15000, message: 'Destroy never landed' },
      )
      .toBe(true);

    // Neither signal above says anything about the child. `destroy()` posts the
    // parent's commit and awaits it, so the toast means the server applied
    // THAT; the child is removed by the server's cascade, and this client only
    // learns of it when that removal arrives over its drive subscription.
    // Until then the child is still in the store, still in the local database,
    // and a reload brings it back.
    await page.waitForFunction(
      nested => !window.store.resources?.get?.(nested),
      nestedResource,
      { timeout: 15000 },
    );

    // And then for that removal to be durable: tombstoning the child in the
    // local database is queued work, and a reload before it lands resurrects
    // it from OPFS. `pendingDirtyCount === 0` is the app's own "safe to
    // reload" signal, and it covers that write.
    await waitForSynced(page);

    await page.reload();
    await openSubject(page, nestedResource);

    // ErrorPage renders `Could not open <subject>` for missing resources.
    // The destroy + cascade may take a moment to propagate over WS, so allow
    // a longer poll than the default.
    await expect(
      page.getByRole('heading').filter({ hasText: /Could not open/ }),
      'Nested resource not deleted',
    ).toBeVisible({ timeout: 15000 });
  });

  test('sidebar subresource', async ({ page }) => {
    const klass = 'folder';
    await newResource(klass, page);
    await expect(page.getByTestId('sidebar').getByText(klass)).toBeVisible();
    const d0 = 'depth0';
    await setTitle(page, d0);

    // Create a child folder via the FolderPage's quick-create row — the old
    // `new-resource-folder` testid + class-picker dialog were replaced by
    // direct icon buttons in the QuickCreateRow.
    const depth0Url = page.url();
    await page
      .getByRole('main')
      .getByRole('button', { name: 'New Folder' })
      .first()
      .click();
    // QuickCreateRow's onClick fires createNewResource without awaiting, so
    // navigation happens after the click returns. Wait for the URL to change
    // before editing — otherwise editTitle would edit depth0's title.
    await page.waitForURL(url => url.toString() !== depth0Url, {
      timeout: 10000,
    });
    const d1 = 'depth1';

    // editTitle (not setTitle) — newly-created resources auto-enter edit mode,
    // and setTitle's `waitForCommitOnCurrentResource` would still see
    // depth0's subject if it ran before the navigation settled.
    await editTitle(d1, page);

    // Wait for all pending commits to be acked by the server. Without this the
    // page can tear down its in-memory store before the depth1 commit reaches
    // the server, and the sidebar query (post-reload below) misses depth1.
    await page.waitForFunction(
      () => window.store?.getSyncStatus().pendingDirtyCount === 0,
      undefined,
      { timeout: 10000 },
    );

    const sidebar = page.getByTestId('sidebar');
    await expect(
      sidebar.getByText(d0),
      "Sidebar doesn't show updated parent resource title",
    ).toBeVisible({ timeout: 10000 });
    // The optimistic-add path for the sidebar's depth0 children collection
    // races with navigation and the server's QUERY_UPDATE round-trip; under
    // load depth0 can render collapsed without an expand control before
    // the new child reaches the collection. Reload to get a deterministic
    // server-authoritative tree before asserting depth1.
    await page.reload();
    await expect(
      sidebar.getByText(d0),
      "Sidebar doesn't show parent resource title after refresh",
    ).toBeVisible({ timeout: 10000 });
    await sidebar.getByRole('button', { name: 'Expand folder' }).click();
    await expect(
      sidebar.getByText(d1),
      "Sidebar doesn't show child resource title after refresh",
    ).toBeVisible({ timeout: 10000 });
  });

  // FLAKY (dagger CI + remote CI): the imported resource's link
  // (`getByRole('link', { name: 'blaat', exact: true })`) doesn't show
  // up within 10 s. Likely a children-collection refresh race after the
  // import commit batch — same pattern as `folder` above. Investigate:
  // poll the store for the imported subject under the parent rather
  // than DOM text.
  test('import', async ({ page }) => {
    await newResource('folder', page);
    await contextMenuClick('import', page);

    const parentSubject = await page.getByLabel('Target Parent').inputValue();

    const localID = 'localIDtest';
    const name = 'blaat';
    const importStr = {
      'https://atomicdata.dev/properties/localId': localID,
      'https://atomicdata.dev/properties/name': name,
    };
    await expect(page.getByRole('button', { name: 'Import' })).toBeDisabled();
    await page
      .getByPlaceholder('Paste your JSON-AD...')
      .pressSequentially(JSON.stringify(importStr));
    await page.getByRole('button', { name: 'Import' }).click();
    await expect(page.locator('text=Imported!')).toBeVisible();

    // DID-parent imports get fresh DIDs (signed genesis commits), not a
    // path-derived subject. Navigate to the parent and click through to the
    // imported child; HTTP-parent imports still produce `<parent>/<id>`.
    if (parentSubject.startsWith('did:')) {
      await openSubject(page, parentSubject);
      const childLink = page
        .getByRole('main')
        .getByRole('link', { name, exact: true });
      await expect(childLink).toBeVisible({ timeout: 10000 });
      await childLink.click();
    } else {
      await openSubject(page, `${parentSubject}/${localID}`);
    }

    await expect(page.getByRole('heading', { name })).toBeVisible();
  });

  test('dialog', async ({ page }) => {
    await newResource('https://atomicdata.dev/classes/Class', page);

    await page.getByLabel('Shortname').fill('test-shortname');
    await page.getByLabel('Description').fill('test-description');
    await page.getByRole('button', { name: 'Save' }).click();
    // Save fires sign+commit+navigate-to-/show. The next step opens the
    // resource context menu, which only exists on /show. Without this
    // wait the click hit the form page's context menu (or an in-flight
    // /new), and the subsequent "edit" menu item didn't navigate to
    // /app/edit — leaving the test on /show and missing the
    // "Add an item to the recommends list" button.
    await page.waitForURL(/\/app\/show/, { timeout: 15000 });
    await contextMenuClick('edit', page);
    // `contextMenuClick('edit')` fires `navigate(editURL(subject))` which is
    // async. Wait for /app/edit so the recommends input has rendered.
    await page.waitForURL(/\/app\/edit/, { timeout: 10000 });

    await page
      .locator('[title="Add an item to the recommends list"]')
      .first()
      .click();

    const clickOption = await fillSearchBox(
      page,
      SEARCHBOX_PROPERTY_PLACEHOLDER,
      'test-prop',
      { nth: 0 },
    );

    await clickOption('Create test-prop');

    await inDialog(page, async (dialog, closeDialogWith) => {
      await expect(
        dialog.getByRole('heading', { name: 'new property' }),
      ).toBeVisible();

      const selectDatatypeOption = await fillSearchBox(
        dialog,
        'Datatype',
        'boolean',
      );
      await selectDatatypeOption('booleanEither `true` or `false`');

      await dialog.getByLabel('Description').fill('This is a test prop');

      await closeDialogWith('Save');
    });

    // Scope to the main content area — once test-prop lands as a child of
    // test-shortname, the sidebar ALSO renders it as a `button "test-prop"`,
    // and an unscoped `getByRole` would resolve to two elements and trip
    // playwright's strict-mode check.
    await expect(
      page
        .getByRole('main')
        .getByRole('button', { name: 'test-prop', exact: true }),
    ).toBeVisible();
  });

  test('history page', smoke, async ({ page }) => {
    await newResource('document', page);

    const firstTitleCommit = waitForCommit(page, {
      set: {
        ['https://atomicdata.dev/properties/name']: 'First Title',
      },
    });

    await editTitle('First Title', page);
    await firstTitleCommit;

    await expect(
      page.getByRole('heading', { name: 'First Title', level: 1 }),
    ).toBeVisible();

    const secondTitleCommit = waitForCommit(page, {
      set: {
        ['https://atomicdata.dev/properties/name']: 'Second Title',
      },
    });
    await editTitle('Second Title', page);
    await secondTitleCommit;

    await expect(
      page.getByRole('heading', { name: 'Second Title', level: 1 }),
    ).toBeVisible();

    await contextMenuClick('history', page);

    await expect(
      page.getByRole('heading', { name: 'History of Second Title', level: 1 }),
    ).toBeVisible();

    // The current version is signed by this session's agent and the server
    // kept its envelope (`Tree::Envelopes`, `latest` retention), so History
    // attributes it as Verified once `/history-attribution` answers.
    await expect(page.getByTestId('version-attribution')).toHaveText(
      'Verified',
      { timeout: 15_000 },
    );

    await selectHistoryVersionShowing(page, 'First Title');

    await expect(
      page.getByText('First Title', { exact: true }).first(),
    ).toBeVisible();

    // Under `latest` retention only the newest envelope is kept, so the
    // older version has no proof and must say so rather than guess.
    await expect(page.getByTestId('version-attribution')).toHaveText(
      'Unattributed',
    );

    // Enabled only once the selected version differs from the current one, so
    // wait for that rather than racing the selection above.
    const restore = page.getByRole('button', { name: 'Restore this version' });
    await expect(restore).toBeEnabled({ timeout: 15_000 });
    await restore.click();

    await expect(page.locator('text=Resource version updated')).toBeVisible();
    // After restore the page navigates back to the resource. EditableTitle
    // may render either an `<h1>First Title</h1>` or an
    // `<input value="First Title">` depending on whether the resource is in
    // auto-edit mode — match either form via the test-id.
    await expect(page.getByTestId('editable-title').first()).toBeVisible();
    await expect(
      page.getByRole('heading', { name: 'History of First Title', level: 1 }),
    ).not.toBeVisible();
  });
});
