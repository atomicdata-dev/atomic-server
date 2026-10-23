import { test, expect } from './fixtures';
import { devDrive, FRONTEND_URL, getDevDriveSecret } from './test-utils';

/**
 * Signing in with a secret on a browser that already holds another identity
 * with work: the card asks to add that work to the account and names the
 * drive, and "Add to my account" hands the old identity's drive to the new
 * one (see planning/identity-bring-along.md).
 *
 * B is the account (made in its own context). A is what this browser held
 * before: a fresh identity with a drive of its own.
 */
test('signing in with a secret brings the previous identity’s drive along', async ({
  page,
  browser,
}) => {
  test.slow();

  // Context 1: the account, B.
  const accountContext = await browser.newContext();
  const accountPage = await accountContext.newPage();
  await devDrive(accountPage);
  const secret = await getDevDriveSecret(accountPage);
  await accountContext.close();
  const accountSubject: string = JSON.parse(atob(secret)).subject;

  // Context 2: A, with a drive that holds work.
  await devDrive(page);
  const guestSubject = await page.evaluate(
    () => window.store.getAgent()?.subject,
  );
  expect(guestSubject).toBeTruthy();
  expect(guestSubject).not.toBe(accountSubject);

  const driveSubject = await page.evaluate(async () => {
    const drive = await window.store.createDrive('Made before signing in', {
      personal: false,
    });

    return drive.subject;
  });

  // Sign in as B from the welcome flow, while A is still the signed-in agent.
  await page.goto(`${FRONTEND_URL}/app/welcome?step=signin`);
  await expect(page.getByLabel('Agent secret')).toBeVisible({
    timeout: 30_000,
  });
  await page.getByLabel('Agent secret').fill(secret);

  const card = page.getByTestId('bring-along');
  await expect(card).toBeVisible({ timeout: 60_000 });
  await expect(
    card.getByText('Add your work from this browser to your account?', {
      exact: true,
    }),
  ).toBeVisible();
  await expect(card.getByText('Made before signing in')).toBeVisible();
  await card.getByTestId('bring-along-yes').click();

  // The app is B now.
  await expect
    .poll(() => page.evaluate(() => window.store.getAgent()?.subject), {
      timeout: 60_000,
    })
    .toBe(accountSubject);

  // A's drive is listed on B's home and B can write it.
  await expect
    .poll(
      () =>
        page.evaluate(
          async ([drive, account]) => {
            const store = window.store;
            const resource = await store.getResource(drive);
            const home = await store.getAgent()!.privateDriveSubject();
            const listed = (await store.getResource(home)).getSubjects(
              'https://atomicdata.dev/properties/drives',
            );

            return {
              loads: !resource.error,
              writable: (await resource.canWrite(account))[0],
              listed: listed.includes(drive),
            };
          },
          [driveSubject, accountSubject] as const,
        ),
      { timeout: 60_000 },
    )
    .toEqual({ loads: true, writable: true, listed: true });
});
