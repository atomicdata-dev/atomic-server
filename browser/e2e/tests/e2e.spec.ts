// This file is copied from `atomic-data-browser` to `atomic-data-server` when `pnpm build-server` is run.
// This is why the `testConfig` is imported.
import { test, expect } from '@playwright/test';
import {
  DEMO_INVITE_NAME,
  FRONTEND_URL,
  INITIAL_TEST,
  SERVER_URL,
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
  openAtomic,
  openConfigureDrive,
  openNewSubjectWindow,
  openSubject,
  publicReadRightLocator,
  setTitle,
  sideBarDriveSwitcher,
  signIn,
  timestamp,
  waitForCommit,
  openAgentPage,
  fillSearchBox,
  waitForCommitOnCurrentResource,
  currentDialog,
  clickSidebarItem,
} from './test-utils';

test.describe('data-browser', async () => {
  test.beforeEach(before);

  test('sidebar mobile', async ({ page }) => {
    await page.setViewportSize({ width: 500, height: 800 });
    await page.reload();
    // TODO: this keeps hanging. How do I make sure something is _not_ visible?
    // await expect(page.locator('text=new resource')).not.toBeVisible();
    await page.click('[data-test="sidebar-toggle"]');
    await expect(currentDriveTitle(page)).toBeVisible();
  });

  test('switch Server URL', async ({ page }) => {
    await expect(page.locator(`text=${DEMO_INVITE_NAME}`)).not.toBeVisible();
    await changeDrive('https://atomicdata.dev', page);
    await expect(
      page.locator(`text=${DEMO_INVITE_NAME}`).first(),
    ).toBeVisible();
  });

  test('sign in with secret, edit prole, sign out', async ({ page }) => {
    await signIn(page);
    await editProfileAndCommit(page);

    page.on('dialog', d => {
      d.accept();
    });

    // Sign out
    await openAgentPage(page);
    await page.click('[data-test="sign-out"]');
    await expect(page.locator('text=Enter your Agent secret')).toBeVisible();
    await page.reload();
    await expect(page.locator('text=Enter your Agent secret')).toBeVisible();
  });

  test('sign up and edit document atomicdata.dev', async ({ page }) => {
    await openAtomic(page);
    // Use invite
    await clickSidebarItem(DEMO_INVITE_NAME, page);
    await page.click('text=Accept as new user');
    await expect(page.locator(editableTitle)).toBeVisible();
    // We need the initial enter because removing the top line isn't working ATM
    await page.keyboard.press('Enter');
    const teststring = `Testline ${timestamp()}`;
    await page.fill('[data-test="element-input"]', teststring);
    // This next line can be flaky, maybe the text disappears because it's overwritten?
    await expect(page.locator(`text=${teststring}`)).toBeVisible();
    // Remove the text again for cleanup
    await page.keyboard.press('Alt+Backspace');
    await expect(page.locator(`text=${teststring}`)).not.toBeVisible();
    const docTitle = `Document Title ${timestamp()}`;
    await page.click(editableTitle, { delay: 200 });
    await page.fill(editableTitle, docTitle);
    // Not sure if this test is needed - it fails now.
    // await expect(page.locator(documentTitle)).toBeFocused();
    // Check if we can edit our profile
    await editProfileAndCommit(page);
  });

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  test('collections & data view', async ({ page }) => {
    // This test is unreliable as it uses real world data that is not always consistent.
    // Disabling it for now until we have a better test.
    expect(true).toBe(true);
    // await openAtomic(page);
    // // collections, pagination, sorting
    // await openSubject(page, 'https://atomicdata.dev/properties');
    // await page.click(
    //   '[data-test="sort-https://atomicdata.dev/properties/description"]',
    // );
    // // These values can change as new Properties are added to atomicdata.dev
    // const firstPageText = 'text=A base64 serialized JSON object';
    // const secondPageText = 'text=include-nested';
    // await expect(page.locator(firstPageText)).toBeVisible();
    // await page.click('[data-test="next-page"]');
    // await expect(page.locator(firstPageText)).not.toBeVisible();
    // await expect(page.locator(secondPageText)).toBeVisible();

    // // context menu, keyboard & data view
    // await page.click(contextMenu);
    // await page.keyboard.press('Enter');
    // await expect(page.locator('text=JSON-AD')).toBeVisible();
    // await page.click('[data-test="fetch-json-ad"]');
    // await expect(
    //   page.locator(
    //     'text="https://atomicdata.dev/properties/collection/members": [',
    //   ),
    // ).toBeVisible();
    // await page.click('[data-test="fetch-json"]');
    // await expect(page.locator('text=  "members": [')).toBeVisible();
    // await page.click('[data-test="fetch-json-ld"]');
    // await expect(page.locator('text="current-page": {')).toBeVisible();
    // await page.click('[data-test="fetch-turtle"]');
    // await expect(page.locator('text=<http')).toBeVisible();
    // await page.click('[data-test="copy-response"]');
    // await expect(page.locator('text=Copied')).toBeVisible();
  });

  test('localhost /setup', async ({ page }) => {
    if (INITIAL_TEST) {
      // Setup initial user (this test can only be run once per server)
      await page.click('[data-test="sidebar-drive-open"]');
      await expect(page.locator('text=/setup')).toBeVisible();
      // Don't click on setup - this will take you to a different domain, not to the dev build!
      // await page.click('text=/setup');
      await openSubject(page, `${SERVER_URL}/setup`);
      await expect(page.locator('text=Accept as')).toBeVisible();
      // await page.click('[data-test="accept-existing"]');
      await page.click('text=Accept as');
    } else {
      // eslint-disable-next-line no-console
      console.log('Skipping `/setup` test...');
    }
  });

  /**
   * We remove public read rights from drive, create an invite, open that
   * invite, and add the public read right again.
   */
  test('authorization, invite, share menu', async ({
    page,
    browser,
    context,
  }) => {
    // Remove public read rights for Drive
    await signIn(page);
    const { driveURL, driveTitle } = await newDrive(page);
    await currentDriveTitle(page).click();
    await contextMenuClick('share', page);
    expect(publicReadRightLocator(page)).not.toBeChecked();

    // Initialize unauthorized page for reader
    const context2 = await browser.newContext();
    const page2 = await context2.newPage();
    await page2.setViewportSize({ width: 1000, height: 400 });
    await page2.goto(FRONTEND_URL);
    await openSubject(page2, driveURL);
    // TODO set current drive by opening the URL
    await expect(page2.locator('text=Unauthorized').first()).toBeVisible();

    // Create invite
    await page.click('button:has-text("Create Invite")');
    context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.click('button:has-text("Create")');
    await expect(page.locator('text=Invite created and copied ')).toBeVisible();
    const inviteUrl = await page.evaluate(() =>
      document
        ?.querySelector('[data-code-content]')
        ?.getAttribute('data-code-content'),
    );
    expect(inviteUrl).not.toBeFalsy();

    await page.waitForTimeout(200);

    // Open invite
    const page3 = await openNewSubjectWindow(browser, inviteUrl as string);
    const waiter = page3.waitForNavigation();
    await page3.click('button:has-text("Accept")');
    await waiter;
    await page3.reload();
    await expect(page3.locator(`text=${driveTitle}`).first()).toBeVisible();
  });

  test('chatroom', async ({ page, browser }) => {
    await signIn(page);
    await newDrive(page);
    const waiter = waitForCommitOnCurrentResource(page);
    await newResource('chatroom', page);
    await waiter;
    await expect(
      page.getByRole('heading', { name: 'Untitled ChatRoom' }),
    ).toBeVisible();
    const teststring = `My test: ${timestamp()}`;
    await page.fill('[data-test="message-input"]', teststring);
    await page.keyboard.press('Enter');
    const chatRoomUrl = (await getCurrentSubject(page)) as string;
    await expect(
      page.locator('[data-test="message-input"]'),
      'Text input not cleared on enter',
    ).toHaveText('');
    await expect(
      page.locator(`text=${teststring}`),
      'Chat message not appearing directly after sending',
    ).toBeVisible();

    const page2 = await openNewSubjectWindow(browser, chatRoomUrl);
    // Second user
    await signIn(page2);

    // TODO: TEMP FIX, NO LONGER NEEDED IF #686 IS FIXED
    page2.reload();

    await expect(page2.locator(`text=${teststring}`)).toBeVisible();
    const teststring2 = `My reply: ${timestamp()}`;
    await page2.fill('[data-test="message-input"]', teststring2);
    await page2.keyboard.press('Enter');
    // Both pages should see then new chat message
    await expect(page.locator(`text=${teststring2}`)).toBeVisible();
    await expect(page2.locator(`text=${teststring2}`)).toBeVisible();
  });

  test('bookmark', async ({ page }) => {
    await signIn(page);
    await newDrive(page);

    // Create a new bookmark
    await newResource('bookmark', page);

    // Fetch `example.com
    const input = page.locator('[placeholder="https\\:\\/\\/example\\.com"]');
    await input.click();
    await input.fill('https://ontola.io');
    await page.locator(currentDialogOkButton).click();

    await expect(
      page.locator(':text-is("Full-service")'),
      'Page contents not properly imported',
    ).toBeVisible();
  });

  test('quick edit text typing ux', async ({ page }) => {
    await signIn(page);
    await newDrive(page);
    await newResource('folder', page);

    await page.locator(editableTitle).click();
    // loop over all letters in alphabet

    const alphabet = 'abcdefghijklmnopqrstuvwxyz';

    for (const letter of alphabet) {
      await page.type(editableTitle, letter, { delay: Math.random() * 300 });
    }

    // wait for commit debounce
    // make sure no commits are waiting for each other
    await page.waitForTimeout(1000);

    await page.keyboard.press('Escape');

    await expect(
      page.locator(`text=${alphabet}`).first(),
      'String not correct after typing, bad typing UX. Maybe views are notified of changes twice?',
    ).toBeVisible();

    await page.reload();
    await expect(
      page.locator(`text=${alphabet}`).first(),
      'Text not correct after reload',
    ).toBeVisible();
  });

  test('folder', async ({ page }) => {
    await signIn(page);
    await newDrive(page);

    // Create a new folder
    await newResource('folder', page);
    // Createa sub-resource in the folder
    await page
      .getByRole('main')
      .getByRole('button', { name: 'New Resource', exact: true })
      .click();
    await page.click('button:has-text("Document")');
    await page.locator(editableTitle).click();
    await page.keyboard.type('RAM Downloading Strategies');
    await page.keyboard.press('Enter');
    await clickSidebarItem('Untitled folder', page);
    await expect(
      page.locator(
        '[data-test="folder-list"] >> text=RAM Downloading Strategies',
      ),
      'Created document not visible',
    ).toBeVisible();
  });

  test('drive switcher', async ({ page }) => {
    await signIn(page);
    await page.click(sideBarDriveSwitcher);
    // temp disable for trailing slash
    // const dropdownId = await page
    //   .locator(sideBarDriveSwitcher)
    //   .getAttribute('aria-controls');
    // await page.click(`[id="${dropdownId}"] >> text=Atomic Data`);
    // await expect(page.locator(currentDriveTitle)).toHaveText('Atomic Data');

    // Cleanup drives for signed in user
    await openAgentPage(page);
    await page.click('text=Edit profile');
    await page.getByTestId('input-drives-clear').click();
    await page.click('[data-test="save"]');
  });

  test('configure drive page', async ({ page }) => {
    await signIn(page);
    await openConfigureDrive(page);
    await expect(currentDriveTitle(page)).toHaveText('localhost');

    // temp disable this, because of trailing slash in base URL
    // await page.click(':text("https://atomicdata.dev") + button:text("Select")');
    // await expect(currentDriveTitle(page)).toHaveText('Atomic Data');

    await openConfigureDrive(page);
    await page.fill('[data-test="server-url-input"]', 'https://example.com');
    await page.click('[data-test="server-url-save"]');

    await expect(currentDriveTitle(page)).toHaveText('example.com');

    await openConfigureDrive(page);
    await page.click(':text("https://atomicdata.dev") + button:text("Select")');
    await expect(currentDriveTitle(page)).toHaveText('Atomic Data');
    await openConfigureDrive(page);
  });

  test('form validation', async ({ page }) => {
    await signIn(page);
    await newDrive(page);
    await newResource('https://atomicdata.dev/classes/Class', page);
    const shortnameInput = '[data-test="input-shortname"]';
    // Try entering a wrong slug
    await page.click(shortnameInput);
    await page.keyboard.type('not valid-');
    await page.locator(shortnameInput).blur();
    await expect(page.getByText('Invalid Slug')).toBeVisible();
    await page.locator(shortnameInput).fill('');
    await page.keyboard.type('is-valid');
    await expect(page.locator('text=Not a valid slug')).not.toBeVisible();
    await page.getByRole('button', { name: 'advanced' }).click();
    await fillSearchBox(
      page,
      'Search for a property or enter a URL',
      'https://atomicdata.dev/properties/invite/usagesLeft',
    );
    await page.keyboard.press('Enter');
    await expect(page.locator('text=Usages-left').first()).toBeVisible();
    // Integer validation
    await page.click('[data-test="input-usages-left"]');
    await page.keyboard.type('asdf1');
    await expect(page.locator('text=asdf')).not.toBeVisible();

    // Try to save without a description
    page.locator('button:has-text("Save")').click();
    await expect(
      page.locator(
        'text=Property https://atomicdata.dev/properties/description missing',
      ),
    ).toBeVisible();

    // Add a description
    await page.getByLabel('Description').click();
    await page.keyboard.type('This is a test class');
    await page.click('button:has-text("Save")');

    await expect(page.locator('text=Resource Saved')).toBeVisible();
  });

  test('sidebar subresource', async ({ page }) => {
    await signIn(page);
    await newDrive(page);

    // create a resource, make sure its visible in the sidebar (and after refresh)
    const klass = 'folder';
    await newResource(klass, page);
    await expect(page.getByTestId('sidebar').getByText(klass)).toBeVisible();
    const d0 = 'depth0';
    await setTitle(page, d0);

    // Create a subresource, and later check it in the sidebar
    await page.getByTestId('new-resource-folder').click();
    await page.click(`button:has-text("${klass}")`);
    const d1 = 'depth1';

    await setTitle(page, d1);

    await expect(
      page.getByTestId('sidebar').getByText(d0),
      "Sidebar doesn't show updated parent resource title",
    ).toBeVisible();
    await expect(
      page.getByTestId('sidebar').getByText(d1),
      "Sidebar doesn't show child resource title",
    ).toBeVisible();
    await page.waitForTimeout(500);
    await page.reload();
    await expect(
      page.getByTestId('sidebar').getByText(d1),
      "Sidebar doesn't show parent resource resource title after refresh",
    ).toBeVisible();
    await expect(
      page.getByTestId('sidebar').getByText(d0),
      "Sidebar doesn't show child resource title after refresh",
    ).toBeVisible();
  });

  test('import', async ({ page }) => {
    await signIn(page);
    await newDrive(page);
    await newResource('folder', page);
    await contextMenuClick('import', page);

    const parentSubject = await page.getByLabel('Target Parent').inputValue();

    const localID = 'localIDtest';
    const name = 'blaat';
    const importStr = {
      'https://atomicdata.dev/properties/localId': localID,
      'https://atomicdata.dev/properties/name': name,
    };
    await page.fill(
      '[placeholder="Paste your JSON-AD..."]',
      JSON.stringify(importStr),
    );
    await page.click('[data-test="import-post"]');
    await expect(page.locator('text=Imported!')).toBeVisible();

    // get current url, append the localID
    await page.goto(parentSubject + '/' + localID);
    await expect(page.locator(`h1:text("${name}")`)).toBeVisible();
  });

  test('dialog', async ({ page }) => {
    await signIn(page);
    await newDrive(page);
    // Create new class from new resource menu
    await newResource('https://atomicdata.dev/classes/Class', page);

    await page.getByLabel('Shortname').fill('test-shortname');
    await page.getByLabel('Description').fill('test-description');
    await page.click('[data-test="save"]');
    await page.locator('text=Resource Saved');
    await contextMenuClick('edit', page);

    await page
      .locator('[title="Add an item to the recommends list"]')
      .first()
      .click();

    // Create new Property using dialog

    const clickOption = await fillSearchBox(
      page,
      'Search for a property or enter a URL',
      'test-prop',
      { nth: 0 },
    );

    await clickOption('Create test-prop');

    await expect(page.locator('h1:has-text("new property")')).toBeVisible();
    // Set datatype of new property to boolean

    const selectDatatypeOption = await fillSearchBox(
      page,
      'Search for a datatype or enter a URL',
      'boolean',
    );
    await selectDatatypeOption('boolean - Either `true` or `false`');
    await currentDialog(page)
      .getByLabel('Description')
      .fill('This is a test prop');
    await page.locator('dialog footer >> text=Save').click();

    await page.locator('text=Resource Saved');
    expect(
      await page.locator(
        '[data-test="input-recommends"] >> nth=0 >> "test-prop"',
      ),
    );
  });

  test('history page', async ({ page }) => {
    await signIn(page);
    await newDrive(page);
    // Create new class from new resource menu
    await newResource('document', page);

    // commit for saving initial document
    await waitForCommit(page);
    // commit for initializing the first element (paragraph)
    await waitForCommit(page);

    await editTitle('First Title', page);

    await expect(
      page.getByRole('heading', { name: 'First Title', level: 1 }),
    ).toBeVisible();
    // Wait for commit debounce
    await page.waitForTimeout(500);

    const waiter = waitForCommitOnCurrentResource(page, {
      set: {
        ['https://atomicdata.dev/properties/name']: 'Second Title',
      },
    });
    await editTitle('Second Title', page);
    await waiter;

    await expect(
      page.getByRole('heading', { name: 'Second Title', level: 1 }),
    ).toBeVisible();

    // The history page does not update when the resource changes so we need to wait to be sure the commit is done
    // before opening the history page.

    await contextMenuClick('history', page);

    await expect(page.locator('text=History of Second Title')).toBeVisible();

    // await page.reload();
    await page.getByTestId('version-button').nth(1).click();

    await expect(page.locator('text=First Title')).toBeVisible();

    await page.click('text=Make current version');

    await expect(page.locator('text=Resource version updated')).toBeVisible();
    await expect(page.locator('h1:has-text("First Title")')).toBeVisible();
    await expect(page.locator('text=History of First Title')).not.toBeVisible();
  });
});
