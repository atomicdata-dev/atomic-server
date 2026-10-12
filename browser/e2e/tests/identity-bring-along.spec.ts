import { test, expect, type Page } from './fixtures';
import type { DiagnosticCollector } from './diagnostic-collector';
import { devDrive, FRONTEND_URL, nodeReachableServerUrl } from './test-utils';

/**
 * A demo guest makes a workspace, then signs in with an email that already
 * has an identity. The account's identity wins, and the guest's workspace
 * comes along: still there, and editable, as the account.
 *
 * The control plane is mocked: `/api/me` answers as nobody while the guest
 * works and as the account once they sign in, and `/api/recovery-secret`
 * names the account's identity, which a devDrive in a second context made.
 */

const EMAIL = 'bring-along@example.com';

type Portal = { signedIn: boolean };

function allowTemplateSetupWarning(
  diagnostics: Pick<DiagnosticCollector, 'expect'>,
) {
  diagnostics.expect(
    'error',
    /Each child in a list should have a unique.*key.*DriveTemplateSetup/s,
    'Existing Wuchale React key warning in Vite template setup',
    1,
    undefined,
    { optional: true },
  );
}

async function mockPortal(page: Page, accountAgent: string): Promise<Portal> {
  const portal: Portal = { signedIn: false };
  await page.addInitScript(portalUrl => {
    (
      window as unknown as Window & {
        __ATOMIC_MANAGED__: { portalUrl: string };
      }
    ).__ATOMIC_MANAGED__ = { portalUrl };
  }, new URL(FRONTEND_URL).origin);
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;

    if (path === '/api/me')
      // 204 means "no session" to the app, like the real 401.
      return portal.signedIn
        ? route.fulfill({ json: { email: EMAIL } })
        : route.fulfill({ status: 204 });

    if (path === '/api/recovery-secret' && portal.signedIn)
      return route.fulfill({
        json: { agent_subject: accountAgent, wrappers: [] },
      });

    return route.fulfill({ json: [] });
  });
  await page.route('**/server', async route => {
    const response = await route.fetch({
      url: nodeReachableServerUrl(route.request().url()),
    });
    const body = await response.json();
    await route.fulfill({
      json: {
        ...body,
        'https://atomicdata.dev/properties/server/managed': true,
        'https://atomicdata.dev/properties/server/portalUrl': FRONTEND_URL,
      },
    });
  });

  return portal;
}

/** The existing account: an identity with a home, made in its own context. */
async function existingAccount(
  page: Page,
): Promise<{ secret: string; agent: string }> {
  const other = await page.context().browser()!.newContext();
  const otherPage = await other.newPage();
  const secret = await devDrive(otherPage);
  await other.close();

  return { secret, agent: JSON.parse(atob(secret)).subject };
}

/**
 * As the guest: a drive of its own, which the guest owns. Made directly: the
 * template gallery sends a guest to create an account first (see
 * template-recovery.spec.ts), and this is about a guest that already has work.
 */
async function guestWorkspace(page: Page): Promise<string> {
  await page.goto(`${FRONTEND_URL}/app/demo`);
  await expect(page).not.toHaveURL(/\/app\/demo/, { timeout: 90_000 });
  // Leave the demo document: its scripted teammates keep moving their
  // cursors, and under load the editor logs each cursor it cannot place yet.
  await page.goto(`${FRONTEND_URL}/app/settings`);
  await expect
    .poll(() => page.evaluate(() => !!window.store?.getAgent()), {
      timeout: 30_000,
    })
    .toBe(true);

  return page.evaluate(async () => {
    const store = window.store;
    // As `prepareTemplateDrive` does for a guest: its home lives here only.
    store.registerLocalOnlyDrive(await store.getAgent()!.privateDriveSubject());
    const drive = await store.createDrive('Guest drive', {
      personal: false,
      localOnly: true,
    });
    store.setDrive(drive.subject);

    return drive.subject;
  });
}

async function unlockAccount(page: Page, secret: string, agent: string) {
  await expect(page).toHaveURL(/\/app\/welcome/, { timeout: 30_000 });
  await expect(page.getByLabel('Agent secret')).toBeVisible({
    timeout: 20_000,
  });
  await page.getByLabel('Agent secret').fill(secret);
  await expect
    .poll(() => page.evaluate(() => window.store.getAgent()?.subject), {
      timeout: 30_000,
    })
    .toBe(agent);
}

/** The drive is back, listed for the account, and the account can edit it. */
async function expectBroughtAlong(page: Page, drive: string, agent: string) {
  await expect
    .poll(
      () =>
        page.evaluate(
          async ([subject, account]) => {
            const store = window.store;
            const resource = await store.getResource(subject);
            const home = await store.getAgent()!.privateDriveSubject();
            const listed = (await store.getResource(home)).getSubjects(
              'https://atomicdata.dev/properties/drives',
            );

            return {
              loads: !resource.error,
              writable: (await resource.canWrite(account))[0],
              listed: listed.includes(subject),
            };
          },
          [drive, agent] as const,
        ),
      { timeout: 60_000 },
    )
    .toEqual({ loads: true, writable: true, listed: true });

  // An edit as the account saves.
  const saved = await page.evaluate(async subject => {
    const resource = await window.store.getResource(subject);
    await resource.set(
      'https://atomicdata.dev/properties/name',
      'Brought along',
    );
    await resource.save();

    return (await window.store.getResource(subject)).get(
      'https://atomicdata.dev/properties/name',
    );
  }, drive);
  expect(saved).toBe('Brought along');
}

test('a guest workspace comes along when signing in to an existing account', async ({
  page,
  browserDiagnostics,
}) => {
  test.setTimeout(300_000);
  allowTemplateSetupWarning(browserDiagnostics);
  const account = await existingAccount(page);
  const portal = await mockPortal(page, account.agent);
  const drive = await guestWorkspace(page);

  portal.signedIn = true;
  await page.goto(
    `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(drive)}`,
  );
  // Nothing to choose: a guest's workspace goes with the account.
  await expect(page.getByTestId('identity-conflict')).toHaveCount(0);
  await unlockAccount(page, account.secret, account.agent);
  await expectBroughtAlong(page, drive, account.agent);
});

test('the conflict dialog brings the workspace along after a failed try', async ({
  page,
  browserDiagnostics,
}) => {
  test.setTimeout(300_000);
  allowTemplateSetupWarning(browserDiagnostics);
  const account = await existingAccount(page);
  const portal = await mockPortal(page, account.agent);
  const drive = await guestWorkspace(page);
  const home = await page.evaluate(() =>
    window.store.getAgent()!.privateDriveSubject(),
  );

  // The guest's home cannot be read on the first, automatic try.
  await page.evaluate(subject => {
    const store = window.store as typeof window.store & {
      __failHome?: boolean;
    };
    const original = store.getResource.bind(store);
    store.__failHome = true;
    store.getResource = (async (s: string, ...rest: unknown[]) => {
      if (store.__failHome && s === subject)
        throw new Error('home unavailable');

      return (original as (...a: unknown[]) => unknown)(s, ...rest);
    }) as typeof store.getResource;
  }, home);

  portal.signedIn = true;
  // Client-side navigation, so the patched store stays.
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  await page.evaluate(() => {
    window.history.pushState({}, '', '/app/agent');
    window.dispatchEvent(new PopStateEvent('popstate'));
  });
  const dialog = page.getByTestId('identity-conflict');
  await expect(dialog).toBeVisible({ timeout: 30_000 });
  await expect(dialog.getByTestId('identity-conflict-switch')).toBeVisible();
  await expect(dialog.getByTestId('identity-conflict-keep')).toBeVisible();

  await page.evaluate(() => {
    (
      window.store as typeof window.store & { __failHome?: boolean }
    ).__failHome = false;
  });
  await dialog
    .getByRole('button', { name: 'Bring this workspace into my account' })
    .click();
  await unlockAccount(page, account.secret, account.agent);
  await expectBroughtAlong(page, drive, account.agent);
});
