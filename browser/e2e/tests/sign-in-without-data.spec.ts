import { test, expect, type Page } from './fixtures';
import { generateKeyPair } from '@tomic/lib';
import { FRONTEND_URL } from './test-utils';

/**
 * Signing in with a secret whose workspace this device has never held.
 *
 * A secret restores who you are, not what you have — so this is a normal
 * state, and it keeps producing the same complaint: "I made an account on my
 * phone, signed in on my desktop, and my drive wasn't there." The workspace
 * genuinely isn't there. What was wrong is the app carrying on as if it were.
 *
 * The failure has a shape. Nothing sets the active drive when the account's
 * own cannot be found, so it keeps whatever it had — and its default is the
 * server's own root. That is somebody else's workspace, on screen, under your
 * name, immediately after signing in.
 *
 * Deliberately no `before`: that signs in as the dev agent and opens the dev
 * drive, which is the exact state this test must not start from.
 */
test.describe('signing in on a device that holds none of the account’s data', () => {
  /**
   * A real, well-formed secret for an account this server has never seen.
   * Minted with the library's own keygen — hand-rolling one would test my
   * crypto rather than the flow.
   */
  async function strangerSecret(): Promise<string> {
    const { privateKey, publicKey } = await generateKeyPair();

    return btoa(
      JSON.stringify({
        privateKey,
        subject: `did:ad:agent:${publicKey}`,
      }),
    );
  }

  async function signInAsAStranger(page: Page) {
    await page.goto(FRONTEND_URL);

    await page
      .getByRole('button', { name: 'Sign in', exact: true })
      .click({ timeout: 20_000 });
    // No confirm button: the flow signs in as soon as the secret parses —
    // `onChange` runs the sign-in, and on success the dialog unmounts. So
    // don't touch the field after filling it: a `blur()` here races the
    // dialog teardown and fails on the success path itself. The callers'
    // assertions on what the sign-in produced are the completion signal.
    await page.getByLabel('Agent secret').fill(await strangerSecret());
  }

  async function expectRecoveryStep(page: Page) {
    // Managed installations offer account recovery first. Standalone nodes
    // offer device pairing first; both must stop before opening a workspace.
    await expect(
      page.getByRole('heading', {
        name: /^(Your data is on another device|Bring your data back)$/,
      }),
    ).toBeVisible({ timeout: 20_000 });
  }

  test('stops, and says so, instead of opening a workspace', async ({
    page,
  }) => {
    await signInAsAStranger(page);

    await expectRecoveryStep(page);

    const devices = page.getByText('…or bring it over from another device', {
      exact: true,
    });
    if (await devices.isVisible()) await devices.click();

    // And offers the way across, rather than only naming the problem.
    await expect(
      page.getByText(/Scan this from that device|Connect a device/),
    ).toBeVisible();
  });

  test('leaves no other workspace active', async ({ page }) => {
    await signInAsAStranger(page);

    await expectRecoveryStep(page);

    const drive = await page.evaluate(() =>
      JSON.parse(localStorage.getItem('drive') ?? '""'),
    );

    // The default is the server's origin. Anything of the server's own is not
    // this account's, and must not be sitting there waiting to be opened. The
    // account's own key-derived drive is fine — that one is empty, not
    // somebody else's, and it is where this identity writes.
    expect(
      drive,
      'signing in without data must not leave another workspace active',
    ).not.toMatch(/^https?:/);
  });

  test('names the account’s own drive as the place to write', async ({
    page,
  }) => {
    await signInAsAStranger(page);

    await expectRecoveryStep(page);

    const drive = await page.evaluate(() =>
      JSON.parse(localStorage.getItem('drive') ?? '""'),
    );

    expect(drive).toMatch(/^did:ad:/);
  });
});
