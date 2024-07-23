// This file is copied from `atomic-data-browser` to `atomic-data-server` when `pnpm build-server` is run.
// This is why the `testConfig` is imported.

import { test, expect } from '@playwright/test';
import type { Browser, Page } from '@playwright/test';

const demoFileName = 'testimage.svg';

const demoFile = () => {
  const processPath = process.cwd();

  // In the CI, the tests dir is missing for some reason?
  if (processPath.endsWith('tests')) {
    return `${processPath}/${demoFileName}`;
  } else {
    return `${processPath}/tests/${demoFileName}`;
  }
};

const testConfig: TestConfig = {
  demoFileName,
  demoFile: demoFile(),
  demoInviteName: 'document demo',
  serverUrl: 'http://localhost:9883',
  frontEndUrl: process.env.FRONTEND_URL || 'http://localhost:5173',
  initialTest: true,
};

export interface TestConfig {
  demoFileName: string;
  demoFile: string;
  demoInviteName: string;
  serverUrl: string;
  frontEndUrl: string;
  /** If /setup is used to register */
  initialTest: boolean;
}

const {
  demoFileName,
  demoFile,
  demoInviteName,
  serverUrl,
  frontEndUrl,
  initialTest,
} = testConfig;

const timestamp = () => new Date().toLocaleTimeString();
const editableTitle = '[data-test="editable-title"]';
const sideBarDriveSwitcher = '[title="Open Drive Settings"]';
const sideBarNewResource = '[data-test="sidebar-new-resource"]';
const currentDriveTitle = '[data-test=current-drive-title]';
const publicReadRight =
  '[data-test="right-public"] input[type="checkbox"] >> nth=0';
const contextMenu = '[data-test="context-menu"]';
const addressBar = '[data-test="address-bar"]';
const defaultDevServer = 'http://localhost:9883';
const currentDialogOkButton = 'dialog[open] >> footer >> text=Ok';
// Depends on server index throttle time, `commit_monitor.rs`
const REBUILD_INDEX_TIME = 6000;

async function setTitle(page, title: string) {
  await page.locator(editableTitle).click();
  await page.fill(editableTitle, title);
  await page.waitForTimeout(300);
}

test.describe('data-browser', async () => {
  test.beforeEach(async ({ page }) => {
    if (!serverUrl) {
      throw new Error('serverUrl is not set');
    }

    // Open the server
    await page.goto(frontEndUrl);

    // Sometimes we run the test server on a different port, but we should
    // only change the drive if it is non-default.
    if (serverUrl !== defaultDevServer) {
      await changeDrive(serverUrl, page);
    }

    await expect(page.locator(currentDriveTitle)).toBeVisible();
  });

  test('sidebar mobile', async ({ page }) => {
    await page.setViewportSize({ width: 500, height: 800 });
    await page.reload();
    // TODO: this keeps hanging. How do I make sure something is _not_ visible?
    // await expect(page.locator('text=new resource')).not.toBeVisible();
    await page.click('[data-test="sidebar-toggle"]');
    await expect(await page.locator(currentDriveTitle)).toBeVisible();
  });

  test('switch Server URL', async ({ page }) => {
    await expect(page.locator(`text=${demoInviteName}`)).not.toBeVisible();
    await changeDrive('https://atomicdata.dev', page);
    await expect(page.locator(`text=${demoInviteName}`).first()).toBeVisible();
  });

  test('sign in with secret, edit prole, sign out', async ({ page }) => {
    await signIn(page);
    await editProfileAndCommit(page);

    page.on('dialog', d => {
      d.accept();
    });

    // Sign out
    await page.click('text=user settings');
    await page.click('[data-test="sign-out"]');
    await page.click('text=Sign in');
    await expect(page.locator('#current-password')).toBeVisible();
    await page.reload();
    await page.click('text=Sign in');
    await expect(page.locator('#current-password')).toBeVisible();
  });

  test('sign up and edit document atomicdata.dev', async ({ page }) => {
    await openAtomic(page);
    // Use invite
    await page.click(`text=${demoInviteName}`);
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

  test('text search', async ({ page }) => {
    await page.fill(addressBar, 'welcome');
    await expect(page.locator('text=Welcome to your')).toBeVisible();
    await page.keyboard.press('Enter');
    await expect(page.locator('text=resources:')).toBeVisible();
  });

  test('scoped search', async ({ page }) => {
    await signIn(page);
    await newDrive(page);

    // Create folder called 1
    await page.locator('[data-test="sidebar-new-resource"]').click();
    await page.locator('button:has-text("folder")').click();
    await setTitle(page, 'Salad folder');

    // Create document called 'Avocado Salad'
    await page.locator('button:has-text("New Resource")').click();
    await page.locator('button:has-text("document")').click();
    await page.waitForResponse(`${serverUrl}/commit`);
    // commit for initializing the first element (paragraph)
    await page.waitForResponse(`${serverUrl}/commit`);
    await editTitle('Avocado Salad', page);

    await page.locator('[data-test="sidebar-new-resource"]').click();

    // Create folder called 'Cake folder'
    await page.locator('button:has-text("folder")').click();
    await setTitle(page, 'Cake Folder');

    // Create document called 'Avocado Salad'
    await page.locator('button:has-text("New Resource")').click();
    await page.locator('button:has-text("document")').click();
    await page.waitForResponse(`${serverUrl}/commit`);
    // commit for initializing the first element (paragraph)
    await page.waitForResponse(`${serverUrl}/commit`);
    await editTitle('Avocado Cake', page);

    await clickSidebarItem('Cake Folder', page);

    // Set search scope to 'Cake folder'
    await page.waitForTimeout(REBUILD_INDEX_TIME);
    await page.locator('button[title="Search in Cake Folder"]').click();
    // Search for 'Avocado'
    await page.locator('[data-test="address-bar"]').type('Avocado');
    // I don't like the `.first` here, but for some reason there is one frame where
    // Multiple hits render, which fails the tests.
    await expect(page.locator('h2:text("Avocado Cake")').first()).toBeVisible();
    await expect(page.locator('h2:text("Avocado Salad")')).not.toBeVisible();

    // Remove scope
    await page.locator('button[title="Clear scope"]').click();

    await expect(page.locator('h2:text("Avocado Cake")').first()).toBeVisible();
    await expect(
      page.locator('h2:text("Avocado Salad")').first(),
    ).toBeVisible();
  });

  test('collections & data view', async ({ page }) => {
    await openAtomic(page);
    // collections, pagination, sorting
    await openSubject(page, 'https://atomicdata.dev/properties');
    await page.click(
      '[data-test="sort-https://atomicdata.dev/properties/description"]',
    );
    // These values can change as new Properties are added to atomicdata.dev
    const firstPageText = 'text=A base64 serialized JSON object';
    const secondPageText = 'text=include-nested';
    await expect(page.locator(firstPageText)).toBeVisible();
    await page.click('[data-test="next-page"]');
    await expect(page.locator(firstPageText)).not.toBeVisible();
    await expect(page.locator(secondPageText)).toBeVisible();

    // context menu, keyboard & data view
    await page.click(contextMenu);
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');
    await expect(page.locator('text=JSON-AD')).toBeVisible();
    await page.click('[data-test="fetch-json-ad"]');
    await expect(
      page.locator(
        'text="https://atomicdata.dev/properties/collection/members": [',
      ),
    ).toBeVisible();
    await page.click('[data-test="fetch-json"]');
    await expect(page.locator('text=  "members": [')).toBeVisible();
    await page.click('[data-test="fetch-json-ld"]');
    await expect(page.locator('text="current-page": {')).toBeVisible();
    await page.click('[data-test="fetch-turtle"]');
    await expect(page.locator('text=<http')).toBeVisible();
    await page.click('[data-test="copy-response"]');
    await expect(page.locator('text=Copied')).toBeVisible();
  });

  test('localhost /setup', async ({ page }) => {
    if (initialTest) {
      // Setup initial user (this test can only be run once per server)
      await page.click('[data-test="sidebar-drive-open"]');
      await expect(page.locator('text=/setup')).toBeVisible();
      // Don't click on setup - this will take you to a different domain, not to the dev build!
      // await page.click('text=/setup');
      await openSubject(page, `${serverUrl}/setup`);
      await expect(page.locator('text=Accept as')).toBeVisible();
      // await page.click('[data-test="accept-existing"]');
      await page.click('text=Accept as');
    } else {
      // eslint-disable-next-line no-console
      console.log('Skipping `/setup` test...');
    }
  });

  test('create document, edit, page title, websockets', async ({
    page,
    browser,
  }) => {
    await signIn(page);
    await newDrive(page);
    await makeDrivePublic(page);
    // Create a document
    await newResource('document', page);
    // commit for saving initial document
    await page.waitForResponse(`${serverUrl}/commit`);
    // commit for initializing the first element (paragraph)
    await page.waitForResponse(`${serverUrl}/commit`);
    await page.locator(editableTitle).click();
    const title = `Document ${timestamp()}`;
    // These keys make sure the onChange handler is properly called
    await page.keyboard.press('Space');
    await page.keyboard.press('Backspace');
    // await page.waitForTimeout(100);
    // await page.fill(documentTitle, title);
    await page.keyboard.type(title);

    // commit for editing title
    await page.waitForResponse(`${serverUrl}/commit`);
    // await page.click('[data-test="document-edit"]');
    // await expect(await page.title()).toEqual(title);
    await page.press(editableTitle, 'Enter');
    // await page.waitForTimeout(500);
    const teststring = `My test: ${timestamp()}`;
    await page.fill('textarea', teststring);
    // commit editing paragraph
    await expect(await page.locator(`text=${teststring}`)).toBeVisible();

    // multi-user
    const currentUrl = page.url();
    const page2 = await openNewSubjectWindow(browser, currentUrl);
    await expect(await page2.locator(`text=${teststring}`)).toBeVisible();
    await expect(await page2.title()).toEqual(title);

    // Add a new line on first page, check if it appears on the second
    await page.keyboard.press('Enter');
    await page.waitForResponse(`${serverUrl}/commit`);
    await page.waitForResponse(`${serverUrl}/commit`);
    const syncText = 'New paragraph';
    await page.keyboard.type(syncText);
    // If this fails to show up, websockets aren't working properly
    await expect(await page2.locator(`text=${syncText}`)).toBeVisible();
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
    await page.click(currentDriveTitle);
    await contextMenuClick('share', page);
    await expect(await page.isChecked(publicReadRight)).toBe(false);

    // Initialize unauthorized page for reader
    const context2 = await browser.newContext();
    const page2 = await context2.newPage();
    await page2.setViewportSize({ width: 1000, height: 400 });
    await page2.goto(frontEndUrl);
    await openSubject(page2, driveURL);
    // TODO set current drive by opening the URL
    await expect(await page2.locator('text=Unauthorized')).toBeVisible();

    // Create invite
    await page.click('button:has-text("Send invite")');
    context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.click('button:has-text("Create Invite")');
    await expect(
      await page.locator('text=Invite created and copied '),
    ).toBeVisible();
    const inviteUrl = await page.evaluate(() =>
      document
        ?.querySelector('[data-code-content]')
        ?.getAttribute('data-code-content'),
    );
    expect(inviteUrl).not.toBeFalsy();

    // Open invite
    const page3 = await openNewSubjectWindow(browser, inviteUrl as string);
    await page3.click('button:has-text("Accept")');
    await page3.waitForTimeout(200);
    await page3.reload();
    await expect(
      await page3.locator(`text=${driveTitle}`).first(),
    ).toBeVisible();
  });

  test('upload, download', async ({ page }) => {
    await signIn(page);
    await newDrive(page);
    // add attachment to drive
    await page.click(contextMenu);
    await page.locator('[data-test="menu-item-edit"]').click();
    const [fileChooser] = await Promise.all([
      page.waitForEvent('filechooser'),
      page.click('button:has-text("Upload file")'),
    ]);
    await fileChooser.setFiles(demoFile);
    await page.click(`[data-test="file-pill"]:has-text("${demoFileName}")`);
    const image = page.locator('[data-test="image-viewer"]');
    await expect(image).toBeVisible();
    await expect(image).toHaveScreenshot({ maxDiffPixelRatio: 0.1 });
  });

  test('chatroom', async ({ page, browser }) => {
    await signIn(page);
    await newDrive(page);
    await newResource('chatroom', page);
    await page.locator('text=New ChatRoom');
    const teststring = `My test: ${timestamp()}`;
    await page.fill('[data-test="message-input"]', teststring);
    const chatRoomUrl = page.url();
    await page.keyboard.press('Enter');
    await expect(await page.locator(`text=${teststring}`)).toBeVisible();

    const dropdownId = await page
      .locator(contextMenu)
      .getAttribute('aria-controls');

    await page.click(contextMenu);
    await page
      .locator(`[id="${dropdownId}"] >> [data-test="menu-item-share"]`)
      .click();
    await page.locator(publicReadRight).click();
    await page.click('text=save');

    const page2 = await openNewSubjectWindow(browser, chatRoomUrl);
    // Second user
    await signIn(page2);
    await expect(await page2.locator(`text=${teststring}`)).toBeVisible();
    const teststring2 = `My reply: ${timestamp()}`;
    await page2.fill('[data-test="message-input"]', teststring2);
    await page2.keyboard.press('Enter');
    // Both pages should see then new chat message
    await expect(await page.locator(`text=${teststring2}`)).toBeVisible();
    // TODO: get rid of this reload! It should not be necessary
    // For some reason the page does not see the new message
    await page2.reload();
    await expect(await page2.locator(`text=${teststring2}`)).toBeVisible();
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

    await expect(page.locator(':text-is("Full-service")')).toBeVisible();
  });

  test('folder', async ({ page }) => {
    await signIn(page);
    await newDrive(page);

    // Create a new folder
    await newResource('folder', page);
    // Createa sub-resource
    await page.click('[data-test="new-resource-folder"]');
    await page.click('button:has-text("Document")');
    await page.locator(editableTitle).click();
    await page.keyboard.type('RAM Downloading Strategies');
    await page.keyboard.press('Enter');
    await page.click('[data-test="sidebar"] >> text=Untitled folder');
    await expect(
      page.locator(
        '[data-test="folder-list"] >> text=RAM Downloading Strategies',
      ),
      'Created document not visible',
    ).toBeVisible();
  });

  test('drive switcher', async ({ page }) => {
    await signIn(page);
    await page.locator(`${currentDriveTitle} > text=localhost`);

    await page.click(sideBarDriveSwitcher);
    // temp disable for trailing slash
    await page.click(`[id="${dropdownId}"] >> text=Atomic Data`);
    await expect(page.locator(currentDriveTitle)).toHaveText('Atomic Data');
    //   .getAttribute('aria-controls');
    // await page.click(`[id="${dropdownId}"] >> text=Atomic Data`);
    // await expect(page.locator(currentDriveTitle)).toHaveText('Atomic Data');

    // Cleanup drives for signed in user
    await page.click('text=user settings');
    await page.click('text=Edit profile');
    await page.click('[data-test="input-drives-clear"]');
    await page.click('[data-test="save"]');
  });

  test('configure drive page', async ({ page }) => {
    await signIn(page);
    await openDriveMenu(page);
    await expect(page.locator(currentDriveTitle)).toHaveText('Main drive');

    // temp disable this, because of trailing slash in base URL
    // await page.click(':text("https://atomicdata.dev") + button:text("Select")');
    // await expect(page.locator(currentDriveTitle)).toHaveText('Atomic Data');

    await openDriveMenu(page);
    await page.fill('[data-test="server-url-input"]', 'https://example.com');
    await page.click('[data-test="server-url-save"]');

    await expect(page.locator(currentDriveTitle)).toHaveText('example.com');

    await openDriveMenu(page);
    await page.click(':text("https://atomicdata.dev") + button:text("Select")');
    await openDriveMenu(page);
    await page.click(
      ':text("https://example.com") ~ [title="Add to favorites"]',
    );

    await page.click(
      ':text("https://example.com") ~ [title="Remove from favorites"]',
    );
  });

  test('form validation', async ({ page }) => {
    await signIn(page);
    await newDrive(page);
    await newResource('class', page);
    const shortnameInput = '[data-test="input-shortname"]';
    // Try entering a wrong slug
    await page.click(shortnameInput);
    await page.keyboard.type('not valid');
    await expect(page.locator('text=Not a valid slug')).toBeVisible();
    await page.locator(shortnameInput).fill('');
    await page.keyboard.type('is-valid');
    await expect(page.locator('text=Not a valid slug')).not.toBeVisible();

    // Add a new property
    await page.click(
      '[placeholder="Select a property or enter a property URL..."]',
    );
    await page.keyboard.type(
      'https://atomicdata.dev/properties/invite/usagesLeft',
    );
    await page.keyboard.press('Enter');
    await page.click('[title="Add this property"]');
    await expect(page.locator('text=usages-left')).toBeVisible();
    // Integer validation
    await page.click('[data-test="input-usages-left"]');
    await page.keyboard.type('asdf' + '1');
    await expect(page.locator('text=asdf')).not.toBeVisible();
    // Dropdown select
    await page.click('[data-test="input-recommends-add-resource"]');
    await page.locator('text=append').click();
    await expect(
      page.locator(
        '[data-test="input-recommends"] >> text=https://atomicdata.dev',
      ),
    ).not.toBeVisible();

    // Try to save without a description
    page.locator('button:has-text("Save")').click();
    await expect(
      page.locator(
        'text=Property https://atomicdata.dev/properties/description missing',
      ),
    ).toBeVisible();

    // Add a description
    await page.click('textarea[name="yamdeContent"]');
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
    await expect(
      page.locator(`[data-test="sidebar"] >> text=${klass}`),
    ).toBeVisible();
    const d0 = 'depth0';
    await setTitle(page, d0);

    // Create a subresource, and later check it in the sidebar
    await page.locator(`[data-test="sidebar"] >> text=${d0}`).hover();
    await page.locator(`[title="Create new resource under ${d0}"]`).click();
    await page.click(`button:has-text("${klass}")`);
    const d1 = 'depth1';
    await setTitle(page, d1);

    await expect(
      page.locator(`[data-test="sidebar"] >> text=${d1}`),
    ).toBeVisible();
    await expect(
      page.locator(`[data-test="sidebar"] >> text=${d0}`),
    ).toBeVisible();
    await page.reload();
    await expect(
      page.locator(`[data-test="sidebar"] >> text=${d1}`),
    ).toBeVisible();
    await expect(
      page.locator(`[data-test="sidebar"] >> text=${d0}`),
    ).toBeVisible();
  });

  test('import', async ({ page }) => {
    await signIn(page);
    await newDrive(page);
    await newResource('folder', page);
    await contextMenuClick('import', page);

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
    const url = await page.url();
    await page.goto(url + '/' + localID);
    await expect(page.locator(`text=${name}`)).toBeVisible();
  });

  test('dialog', async ({ page }) => {
    await signIn(page);
    await newDrive(page);
    // Create new class from new resource menu
    await newResource('class', page);

    await fillInput('shortname', page);
    await fillInput('description', page);
    await page.click('[data-test="save"]');
    await page.waitForNavigation();
    await page.locator('text=Resource Saved');
    await page.goBack();

    await page
      .locator('[title="Add an item to this list"] >> nth=0')
      .first()
      .click();
    await page.locator('[data-test="input-recommends"]').click();
    await page.locator('[data-test="input-recommends"]').fill('test-prop');

    // Create new Property using dialog
    await page.locator('text=Create property: test-prop').click();
    await expect(page.locator('h1:has-text("new property")')).toBeVisible();
    await page.locator('[data-test="input-datatype"]').click();
    // click twice, first click is buggy, it closes the dropdown from earlier
    await page.locator('[data-test="input-datatype"]').click();
    await page
      .locator(
        'li:has-text("boolean - Either `true` or `false`. In JSON-AD, th...")',
      )
      .click();
    await page.locator('dialog textarea[name="yamdeContent"]').click();
    await page
      .locator('dialog textarea[name="yamdeContent"]')
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
    await page.waitForResponse(`${serverUrl}/commit`);
    // commit for initializing the first element (paragraph)
    await page.waitForResponse(`${serverUrl}/commit`);

    await editTitle('First Title', page);
    expect(page.locator('text=First Title')).toBeVisible();

    await editTitle('Second Title', page, true);
    expect(page.locator('text=Second Title')).toBeVisible();

    await contextMenuClick('history', page);
    expect(page.locator('text=History of Second Title')).toBeVisible();

    await page.getByTestId('version-button').nth(1).click();

    expect(page.locator('text=First Title')).toBeVisible();

    await page.click('text=Make current version');

    expect(page.locator('text=Resource version updated')).toBeVisible();
    await page.waitForNavigation();
    expect(page.locator('h1:has-text("First Title")')).toBeVisible();
    expect(page.locator('text=History of First Title')).not.toBeVisible();
  });
});

async function disableViewTransition(page: Page) {
  await page.click('text=Theme Settings');
  const checkbox = await page.getByLabel('Enable view transition');

  await expect(checkbox).toBeVisible();

  await checkbox.uncheck();
  await page.goBack();
}

/** Signs in using an AtomicData.dev test user */
async function signIn(page: Page) {
  await disableViewTransition(page);
  await page.click('text=user settings');
  await expect(
    await page.locator('text=edit data and sign Commits'),
  ).toBeVisible();
  // If there are any issues with this agent, try creating a new one https://atomicdata.dev/invites/1
  const test_agent =
    'eyJzdWJqZWN0IjoiaHR0cHM6Ly9hdG9taWNkYXRhLmRldi9hZ2VudHMvaElNWHFoR3VLSDRkM0QrV1BjYzAwUHVFbldFMEtlY21GWStWbWNVR2tEWT0iLCJwcml2YXRlS2V5IjoiZkx0SDAvY29VY1BleFluNC95NGxFemFKbUJmZTYxQ3lEekUwODJyMmdRQT0ifQ==';
  await page.click('text=Sign in');
  await page.click('#current-password');
  await page.fill('#current-password', test_agent);
  await expect(await page.locator('text=Edit profile')).toBeVisible();
  await page.goBack();
}

/**
 * Create a new drive, go to it, and set it as the current drive. Returns URL of
 * drive and its name
 */
async function newDrive(page: Page) {
  // Create new drive to prevent polluting the main drive
  await page.locator(sideBarDriveSwitcher).click();
  await page.locator('button:has-text("New Drive")').click();
  await page.waitForNavigation();
  await expect(await page.locator('text="Create new resource"')).toBeVisible();
  const driveURL = await getCurrentSubject(page);
  await expect(driveURL).toContain('localhost');
  const driveTitle = `testdrive-${timestamp()}`;
  await page.locator(editableTitle).click();
  await page.fill(editableTitle, driveTitle);
  await page.waitForTimeout(200);

  return { driveURL: driveURL as string, driveTitle };
}

async function makeDrivePublic(page: Page) {
  await page.click(currentDriveTitle);
  await page.click(contextMenu);
  await page.click('button:has-text("share")');
  await expect(await page.isChecked(publicReadRight)).toBe(false);
  await page.click(publicReadRight);
  await page.locator('text=Save').click();
  await expect(await page.locator('text="Share settings saved"')).toBeVisible();
}

async function openSubject(page: Page, subject: string) {
  await page.fill(addressBar, subject);
}

async function getCurrentSubject(page: Page) {
  return page.locator(addressBar).getAttribute('value');
}

/** Set atomicdata.dev as current server */
async function openAtomic(page: Page) {
  await changeDrive('https://atomicdata.dev', page);
  // Accept the invite, create an account if necessary
  await expect(await page.locator(currentDriveTitle)).toHaveText('Atomic Data');
}

/** Opens the users' profile, sets a username */
async function editProfileAndCommit(page: Page) {
  await page.click('text=user settings');
  await page.click('text=Edit profile');
  await expect(page.locator('text=add another property')).toBeVisible();
  const username = `Test user edited at ${new Date().toLocaleDateString()}`;
  await page.fill('[data-test="input-name"]', username);
  await page.click('[data-test="save"]');
  await expect(page.locator('text=Resource saved')).toBeVisible();
  await page.waitForURL(/\/app\/show/);
  await expect(page.locator(`text=${username}`).first()).toBeVisible();
}

/** Create a new Resource in the current Drive */
async function newResource(klass: string, page: Page) {
  await page.locator(sideBarNewResource).click();
  await expect(page).toHaveURL(`${frontEndUrl}/app/new`);
  await page.locator(`button:has-text("${klass}")`).click();
}

/** Opens a new browser page (for) */
async function openNewSubjectWindow(browser: Browser, url: string) {
  const context2 = await browser.newContext();
  const page = await context2.newPage();
  await page.goto(frontEndUrl);

  // Only when we run on `localhost` we don't need to change drive during tests
  if (serverUrl !== defaultDevServer) {
    await changeDrive(serverUrl, page);
  }

  await openSubject(page, url);
  await page.setViewportSize({ width: 1000, height: 400 });

  return page;
}

async function openDriveMenu(page: Page) {
  await page.click(sideBarDriveSwitcher);
  await page.click('[data-test="menu-item-configure-drives"]');
}

async function changeDrive(subject: string, page: Page) {
  await openDriveMenu(page);
  await expect(page.locator('text=Drive Configuration')).toBeVisible();
  await page.fill('[data-test="server-url-input"]', subject);
  await page.click('[data-test="server-url-save"]');
  await expect(page.locator('text=Create new resource')).toBeVisible();
}

async function editTitle(title: string, page: Page, clear = false) {
  await page.locator(editableTitle).click();

  if (clear) {
    await page.locator(editableTitle).clear();
  }

  // These keys make sure the onChange handler is properly called
  await page.keyboard.press('Space');
  await page.keyboard.press('Backspace');
  await page.keyboard.type(title);
  await page.waitForResponse(`${serverUrl}/commit`);
}

async function clickSidebarItem(text: string, page: Page) {
  await page.click(`[data-test="sidebar"] >> text="${text}"`);
}

async function fillInput(
  propertyShortname: string,
  page: Page,
  value?: string,
) {
  let locator = `[data-test="input-${propertyShortname}"]`;

  if (propertyShortname === 'description') {
    locator = 'textarea[name="yamdeContent"]';
  }

  await page.click(locator);
  await page.fill(locator, value || `test-${propertyShortname}`);
}

/** Click an item from the main, visible context menu */
async function contextMenuClick(text: string, page: Page) {
  await page.click(contextMenu);
  await page
    .locator(`[data-test="menu-item-${text}"] >> visible = true`)
    .click();
}
