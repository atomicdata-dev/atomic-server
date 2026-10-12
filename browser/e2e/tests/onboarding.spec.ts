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
    // This test signs up, creates a drive, signs out, verifies the secret and
    // then repeats the sign-in in a second browser context. Timed step by step
    // under four-worker load it runs 41.9s, 43.5s and 23.7s, i.e. up to 72% of
    // the suite's 60s default with nothing wrong. That is the same marginal
    // shape mt940 had: a test winning a coin toss rather than passing.
    test.slow();

    // Start at the canonical signed-out onboarding surface.
    await page.goto(`${FRONTEND_URL}/app/welcome`);

    // Card → create account (then NewIdentitySection auto-starts)
    await page.getByRole('button', { name: 'Create account' }).click();

    // Wait for the profile step (after identity is created)
    await expect(
      page.getByRole('heading', { name: 'How your colleagues see you' }),
    ).toBeVisible({ timeout: 10000 });

    // Set a profile name — a private home drive is created automatically
    await page.getByLabel('Full name', { exact: true }).fill('Test User');

    await page
      .getByRole('button', { name: 'Save and continue', exact: true })
      .click();

    await expect(page.getByText('Creating your private drive')).toBeVisible({
      timeout: 5000,
    });

    // Secret step — the secret includes the drive URL. Headed "This is your
    // account" since the passkey-first rework: on a self-hosted server there
    // is no passkey-wrapped backup to fall back on, so the secret is still
    // shown here and this remains the step that hands it over.
    // Behind the drive creation above, which is several signed commits before
    // this step mounts. Measured under four-worker load at 4.7s, 6.3s and 8.2s
    // against the 10s it used to carry, so the worst sample was at 82% of its
    // budget. This is the assertion develop run 4326 failed on, all three
    // attempts. 30s is what the other write-then-read-back waits in this suite
    // carry; anything near it is a hang rather than slowness.
    await expect(
      page.getByRole('heading', { name: 'This is your account' }),
    ).toBeVisible({ timeout: 30000 });

    // Get the secret from the code block BEFORE signing out
    const secret = await page
      .locator('[data-code-content]')
      .getAttribute('data-code-content');

    expect(secret).toBeTruthy();
    expect(secret).toContain('eyJ'); // Base64 encoded JSON

    // Verify the secret contains the drive URL and agent subject by decoding it
    const decodedSecret = JSON.parse(atob(secret!));
    expect(decodedSecret.initialDrive).toBeTruthy();
    expect(decodedSecret.initialDrive).toMatch(/atomic:|did:ad:/);
    expect(decodedSecret.subject).toBeTruthy();
    expect(decodedSecret.subject).toMatch(/^(atomic|did:ad):agent:/);

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
    await expect(page).toHaveURL(/(?:did(?:%3A|:)ad|atomic)(?:%3A|:)/, {
      timeout: 10000,
    });

    // Open a NEW BROWSER CONTEXT (fresh, as if on a completely different computer)
    const context2 = await browser.newContext();
    const page2 = await context2.newPage();

    // The signed-out SettingsAgent route opens the canonical sign-in form.
    await page2.goto(`${FRONTEND_URL}/app/agent`);
    // Cold boot in a fresh context; 7018 to 7806ms at four workers, against
    // the 10s the bare `fill` would have allowed.
    await expect(page2.getByLabel('Agent secret')).toBeVisible({
      timeout: 20_000,
    });
    await page2.getByLabel('Agent secret').fill(secret!);

    // The agent route passes return_to=agent through the unified sign-in flow.
    await expect(page2).toHaveURL(/\/app\/agent$/, {
      timeout: 10000,
    });
    await expect(
      page2.getByRole('heading', { name: 'User', exact: true }),
    ).toBeVisible({ timeout: 10000 });

    // Navigate to the agent's profile edit page to verify the name was saved
    await page2.goto(
      `${FRONTEND_URL}/app/edit?subject=${encodeURIComponent(decodedSecret.subject)}`,
    );

    // The profile name should be loaded into the edit form from the server.
    // A second browser context navigating to /app/edit and waiting for the
    // profile resource to arrive from the server: the heaviest step in the
    // test, on what was its shortest budget. Measured at 0.6s, 2.1s and 3.3s,
    // and observed failing outright on a loaded box. The assertions either
    // side of it already carry 10s.
    await expect(page2.getByLabel('Name')).toHaveValue('Test User', {
      timeout: 30000,
    });

    await context2.close();
  });
});
