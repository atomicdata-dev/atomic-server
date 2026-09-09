import { test, expect } from './fixtures';
import { FRONTEND_URL } from './test-utils';

test.describe('onboarding', () => {
  // FLAKY (remote CI, observed twice): the auto-verify form flow
  // depends on a 150 ms timer (`GettingStartedFlow useEffect`) and the
  // cross-context profile-name propagation needs the second context to
  // pick up the agent + drive over WS within ~10 s. Either step can
  // miss its budget under contention. Investigate: drop the auto-submit
  // race by clicking the explicit Continue button + `waitForCommit`,
  // and gate the second-context assertion on `store.getAgent()` instead
  // of DOM text.
  test('create new identity with verifySecret flow - profile name persists', async ({
    page,
    browser,
  }) => {
    // Navigate to user settings
    await page.goto(`${FRONTEND_URL}/app/agent`);

    // Card → create account (then NewIdentitySection auto-starts)
    await page.getByRole('button', { name: 'Create account' }).click();

    // Wait for the profile step (after identity is created)
    await expect(
      page.getByRole('heading', { name: 'Set your profile name!' }),
    ).toBeVisible({ timeout: 10000 });

    // Set a profile name — a private home drive is created automatically
    await page.getByLabel('Profile Name').fill('Test User');

    await page.getByRole('button', { name: 'Save & continue' }).click();

    await expect(page.getByText('Creating your private drive')).toBeVisible({
      timeout: 5000,
    });

    // Secret step — the secret includes the drive URL. Headed "This is your
    // account" since the passkey-first rework: on a self-hosted server there
    // is no passkey-wrapped backup to fall back on, so the secret is still
    // shown here and this remains the step that hands it over.
    await expect(
      page.getByRole('heading', { name: 'This is your account' }),
    ).toBeVisible({ timeout: 10000 });

    // Get the secret from the code block BEFORE signing out
    const secret = await page
      .locator('[data-code-content]')
      .getAttribute('data-code-content');

    expect(secret).toBeTruthy();
    expect(secret).toContain('eyJ'); // Base64 encoded JSON

    // Verify the secret contains the drive URL and agent subject by decoding it
    const decodedSecret = JSON.parse(atob(secret!));
    expect(decodedSecret.initialDrive).toBeTruthy();
    expect(decodedSecret.initialDrive).toContain('did:ad:');
    expect(decodedSecret.subject).toBeTruthy();
    expect(decodedSecret.subject).toContain('did:ad:agent:');

    // Click confirm to sign out and go to verify
    await page.locator('button[title="Copy to clipboard"]').click();
    await expect(
      page.getByRole('button', { name: /Yes, I.*stored it.*sign me out/ }),
    ).toBeEnabled();
    await page
      .getByRole('button', { name: /Yes, I.*stored it.*sign me out/ })
      .click();

    // Should now be on the verify step
    await expect(
      page.getByRole('heading', { name: 'Verify your secret' }),
    ).toBeVisible();

    // Paste the secret we read earlier (clipboard may not work after signout)
    await page.getByLabel('Enter your Agent Secret').fill(secret!);

    // The form auto-submits ~150ms after fill (GettingStartedFlow useEffect).
    // The URL assertion below already polls — no separate sleep needed.
    await expect(page).toHaveURL(/did(?:%3A|:)ad(?:%3A|:)/, { timeout: 10000 });

    // Open a NEW BROWSER CONTEXT (fresh, as if on a completely different computer)
    const context2 = await browser.newContext();
    const page2 = await context2.newPage();

    // Sign in with the secret on the SettingsAgent page (card → Sign in → secret)
    await page2.goto(`${FRONTEND_URL}/app/agent`);
    await page2.getByRole('button', { name: 'Sign in', exact: true }).click();
    await page2.getByLabel('Agent secret').fill(secret!);

    // Signing in lands the user on their home drive (sign-in is unified through
    // /app/welcome now; /app/agent no longer hosts its own login form). Wait for
    // the signed-in drive URL, then open settings to confirm the account.
    await expect(page2).toHaveURL(/did(?:%3A|:)ad(?:%3A|:)/, {
      timeout: 10000,
    });
    await page2.goto(`${FRONTEND_URL}/app/agent`);
    await expect(
      page2.getByRole('heading', { name: 'User Settings' }),
    ).toBeVisible({ timeout: 10000 });

    // Navigate to the agent's profile edit page to verify the name was saved
    await page2.goto(
      `${FRONTEND_URL}/app/edit?subject=${encodeURIComponent(decodedSecret.subject)}`,
    );

    // The profile name should be loaded into the edit form from the server.
    await expect(page2.getByLabel('Name')).toHaveValue('Test User', {
      timeout: 5000,
    });

    await context2.close();
  });
});
