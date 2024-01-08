import { Page, expect, Browser, Locator } from '@playwright/test';

export const DEMO_FILENAME = 'testimage.svg';
export const SERVER_URL = 'http://localhost:9883';
export const DELETE_PREVIOUS_TEST_DRIVES =
  process.env.DELETE_PREVIOUS_TEST_DRIVES === 'false' ? false : true;

export const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
// TODO: Should use an env var so the CI can test the setup test.
export const INITIAL_TEST = false;
export const DEMO_INVITE_NAME = 'document demo';

export const demoFile = () => {
  const processPath = process.cwd();

  // In the CI, the tests dir is missing for some reason?
  if (processPath.endsWith('tests')) {
    return `${processPath}/${DEMO_FILENAME}`;
  } else {
    return `${processPath}/tests/${DEMO_FILENAME}`;
  }
};

export const timestamp = () => new Date().toLocaleTimeString();
export const editableTitle = '[data-test="editable-title"]';
export const sideBarDriveSwitcher = '[title="Open Drive Settings"]';
export const sideBarNewResource = '[data-test="sidebar-new-resource"]';
export const currentDriveTitle = '[data-test=current-drive-title]';
export const publicReadRightLocator = (page: Page) =>
  page
    .locator(
      '[data-test="right-public"] input[type="checkbox"]:not([disabled])',
    )
    .first();
export const contextMenu = '[data-test="context-menu"]';
export const addressBar = '[data-test="address-bar"]';
export const newDriveMenuItem = '[data-test="menu-item-new-drive"]';

export const defaultDevServer = 'http://localhost:9883';
export const currentDialogOkButton = 'dialog[open] >> footer >> text=Ok';
// Depends on server index throttle time, `commit_monitor.rs`
export const REBUILD_INDEX_TIME = 5000;

/** Checks server URL and browser URL */
export const before = async ({ page }: { page: Page }) => {
  if (!SERVER_URL) {
    throw new Error('serverUrl is not set');
  }

  // Open the server
  await page.goto(FRONTEND_URL);

  // Sometimes we run the test server on a different port, but we should
  // only change the drive if it is non-default.
  if (SERVER_URL !== 'http://localhost:9883') {
    await changeDrive(SERVER_URL, page);
  }

  await expect(page.locator(currentDriveTitle)).toBeVisible();
};

export async function setTitle(page: Page, title: string) {
  const waiter = waitForCommitOnCurrentResource(page);
  await page.locator(editableTitle).click();
  await page.locator(`${editableTitle} > input`);
  await page.type(editableTitle, title);
  await page.keyboard.press('Escape');
  // await page.waitForTimeout(500);
  await waiter;
}

export async function disableViewTransition(page: Page) {
  await page.click('text=Settings');
  const checkbox = page.getByLabel('Enable view transition');

  await expect(checkbox).toBeVisible();

  await checkbox.uncheck();
  await page.goBack();
}

/** Signs in using an AtomicData.dev test user */
export async function signIn(page: Page) {
  await disableViewTransition(page);
  await page.click('text=Login');
  await expect(page.locator('text=edit data and sign Commits')).toBeVisible();
  // If there are any issues with this agent, try creating a new one https://atomicdata.dev/invites/1
  const test_agent =
    'eyJzdWJqZWN0IjoiaHR0cHM6Ly9hdG9taWNkYXRhLmRldi9hZ2VudHMvaElNWHFoR3VLSDRkM0QrV1BjYzAwUHVFbldFMEtlY21GWStWbWNVR2tEWT0iLCJwcml2YXRlS2V5IjoiZkx0SDAvY29VY1BleFluNC95NGxFemFKbUJmZTYxQ3lEekUwODJyMmdRQT0ifQ==';
  await page.click('#current-password');
  await page.fill('#current-password', test_agent);
  await expect(page.locator('text=Edit profile')).toBeVisible();
  await page.goBack();
}

/**
 * Create a new drive, go to it, and set it as the current drive. Returns URL of
 * drive and its name
 */
export async function newDrive(page: Page) {
  // Create new drive to prevent polluting the main drive
  await page.locator(sideBarDriveSwitcher).click();
  await page.locator('button:has-text("New Drive")').click();
  expect(page.locator(`${currentDriveTitle} > localhost`)).not.toBeVisible();
  await expect(page.locator('text="Create new resource"')).toBeVisible();
  const driveURL = await getCurrentSubject(page);
  expect(driveURL).toContain('localhost');
  const driveTitle = `testdrive-${timestamp()}`;
  await editTitle(driveTitle, page);

  return { driveURL: driveURL as string, driveTitle };
}

export async function makeDrivePublic(page: Page) {
  await page.click(currentDriveTitle);
  await page.click(contextMenu);
  await page.click('button:has-text("share")');
  await expect(
    publicReadRightLocator(page),
    'The drive was public from the start',
  ).not.toBeChecked();
  await publicReadRightLocator(page).click();
  await page.locator('text=Save').click();
  await expect(page.locator('text="Share settings saved"')).toBeVisible();
}

export async function openSubject(page: Page, subject: string) {
  await page.fill(addressBar, subject);
  await expect(page.locator(`main[about="${subject}"]`).first()).toBeVisible();
}

export async function getCurrentSubject(page: Page) {
  const selector = await page.waitForSelector('main[about]');

  return selector.getAttribute('about');
}

/** Waits until a commit for main resource is processed
 */
export async function waitForCommitOnCurrentResource(
  page: Page,
  match?: { set?: Record<string, unknown> },
) {
  const currentSubject = await getCurrentSubject(page);

  await page.waitForResponse(async response => {
    if (!response.url().endsWith('/commit')) {
      return false;
    }

    try {
      const result = await response.json();
      const isForCurrentResource =
        result['https://atomicdata.dev/properties/subject'] === currentSubject;

      if (!isForCurrentResource) {
        return false;
      }

      if (match) {
        const set = result['https://atomicdata.dev/properties/set'];

        for (const key in match.set) {
          if (set[key] !== match.set[key]) {
            return false;
          }
        }
      }

      // Wait for commit response to be processed by the store.
      await page.waitForTimeout(200);
    } catch (e) {
      return false;
    }

    return true;
  });
}

export async function openAgentPage(page: Page) {
  page.goto(`${FRONTEND_URL}/app/agent`);
}

/** Set atomicdata.dev as current server */
export async function openAtomic(page: Page) {
  await changeDrive('https://atomicdata.dev', page);
  // Accept the invite, create an account if necessary
  await expect(page.locator(currentDriveTitle)).toHaveText('Atomic Data');
}

/** Opens the users' profile, sets a username */
export async function editProfileAndCommit(page: Page) {
  await openAgentPage(page);
  await page.click('text=Edit profile');
  await expect(page.locator('text=add another property')).toBeVisible();
  const username = `Test user edited at ${new Date().toLocaleDateString()}`;
  await page.fill('[data-test="input-name"]', username);
  await page.click('[data-test="save"]');
  await expect(page.locator('text=Resource saved')).toBeVisible();
  await page.waitForURL(/\/app\/show/);
  await page.reload();
  await expect(page.locator(`text=${username}`).first()).toBeVisible();
}

export async function fillSearchBox(
  page: Page,
  placeholder: string,
  fillText: string,
  options: {
    nth?: number;
    container?: Locator;
  } = {},
) {
  const { nth, container } = options;
  const selector = container ?? page;

  if (nth !== undefined) {
    await selector.getByRole('button', { name: placeholder }).nth(nth).click();
  } else {
    await selector.getByRole('button', { name: placeholder }).click();
  }

  await selector.getByPlaceholder(placeholder).type(fillText);

  return async (name: string) => {
    await selector.getByTestId('searchbox-results').getByText(name).hover();
    await selector.getByTestId('searchbox-results').getByText(name).click();
  };
}

/** Create a new Resource in the current Drive.
 * Class can be an Class URL or a shortname available in the new page. */
export async function newResource(klass: string, page: Page) {
  await page.locator(sideBarNewResource).click();
  await expect(page).toHaveURL(`${FRONTEND_URL}/app/new`);

  if (klass.startsWith('https://')) {
    await fillSearchBox(page, 'Search for a class or enter a URL', klass);
    await page.keyboard.press('Enter');
  } else {
    await page.locator(`button:has-text("${klass}")`).click();
  }
}

/** Opens a new browser page (for) */
export async function openNewSubjectWindow(browser: Browser, url: string) {
  const context2 = await browser.newContext();
  const page = await context2.newPage();
  await page.goto(FRONTEND_URL);

  // Only when we run on `localhost` we don't need to change drive during tests
  if (SERVER_URL !== defaultDevServer) {
    await changeDrive(SERVER_URL, page);
  }

  await openSubject(page, url);
  await page.setViewportSize({ width: 1000, height: 400 });

  return page;
}

export async function openConfigureDrive(page: Page) {
  // Make sure the drive switched dropdown is not open
  if (await page.locator(newDriveMenuItem).isVisible()) {
    await page.click(sideBarDriveSwitcher);
    await page.waitForTimeout(100);
  }

  await page.click(sideBarDriveSwitcher);
  await page.click('text=Configure Drives');
  await expect(page.locator('text=Drive Configuration')).toBeVisible();
}

export async function changeDrive(subject: string, page: Page) {
  await openConfigureDrive(page);
  await expect(page.locator('text=Drive Configuration')).toBeVisible();
  await page.fill('[data-test="server-url-input"]', subject);
  await page.click('[data-test="server-url-save"]');
  await expect(page.locator('text=Create new resource')).toBeVisible();
}

export async function editTitle(title: string, page: Page) {
  await page.locator(`${editableTitle} > h1`);
  await page.locator(editableTitle).click();
  await page.locator(`${editableTitle} > input`);
  await page.fill(editableTitle, title);
  await page.keyboard.press('Escape');
  // Make sure the commit is processed
  // await page.waitForTimeout(300);
}

export async function clickSidebarItem(text: string, page: Page) {
  await page.click(`[data-test="sidebar"] >> text="${text}"`);
}

export async function fillInput(
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
export async function contextMenuClick(text: string, page: Page) {
  await page.click(contextMenu);
  await page.waitForTimeout(100);
  await page
    .locator(`[data-test="menu-item-${text}"] >> visible = true`)
    .click();
}

export const waitForCommit = async (page: Page) =>
  page.waitForResponse(`${SERVER_URL}/commit`);

export function currentDialog(page: Page) {
  return page.locator('dialog[open]');
}
