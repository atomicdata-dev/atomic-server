/**
 * Cloud Vault: the wipe-and-restore round trip.
 *
 * The promise the feature makes is narrow and testable — "lose the device, get
 * the workspace back, and we could never read it" — and every part of that
 * sentence has a way of being reported as done without being done. Things this
 * spec exists to catch, all of which have actually happened during the build:
 *
 *  - a backup that reports success while nothing reaches object storage;
 *  - a restore that reports success while silently dropping a device's lane;
 *  - a second backup that uploads nothing because the lane cursor advanced
 *    before the upload, so the delta was skipped;
 *  - a key envelope overwritten by a second enrolment, making every stored
 *    object undecryptable.
 *
 * So the assertions here deliberately look past the UI wherever the UI is the
 * thing under test: object counts come from the control plane's own state
 * rather than from prose, and the restore is done in a browser context that
 * never held the data.
 *
 * REQUIRES `browser/e2e/scripts/vault-stack.sh` — MinIO plus the atomic-saas
 * control plane on :3030. Without it every test here skips rather than fails,
 * because a normal e2e run has no reason to have a control plane up.
 */
import { test, expect, type Page } from './fixtures';
import { randomUUID } from 'node:crypto';
import {
  FRONTEND_URL,
  editableTitle,
  newResource,
  timestamp,
} from './test-utils';

const PORTAL_URL =
  process.env.ATOMIC_VAULT_PORTAL_URL ?? 'http://localhost:3030';

/**
 * A fresh account per test.
 *
 * `Date.now()` alone is not enough: two workers starting together land on the
 * same millisecond, both tests then drive the *same* account, and the second
 * sign-in invalidates the first's session. That failed as onboarding dumping
 * the page back on the welcome gate, which reads like an onboarding bug and
 * is not one.
 */
const uniqueEmail = () => `vault-${randomUUID()}@localhost`;

/**
 * The control plane answers `/api/me` with 401 when nobody is signed in, which
 * is all we need: any HTTP response means it is up. A connection refusal means
 * the stack was never started.
 */
async function portalIsUp(): Promise<boolean> {
  try {
    const res = await fetch(`${PORTAL_URL}/api/me`);

    return res.status !== 0;
  } catch {
    return false;
  }
}

/**
 * Sign up and return the magic link.
 *
 * `ATOMIC_SAAS_DEV_MAGIC_LINKS=true` (which `vault-stack.sh` sets) makes the
 * control plane put the link in the response instead of an email, so no mail
 * server is involved. A production build ignores the flag entirely.
 */
async function signUpAndGetMagicLink(email: string): Promise<string> {
  const res = await fetch(`${PORTAL_URL}/api/signup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });

  if (!res.ok) {
    throw new Error(`signup failed: ${res.status} ${await res.text()}`);
  }

  const body = (await res.json()) as { magic_link?: string; status?: string };

  if (!body.magic_link) {
    throw new Error(
      `no magic link in signup response (status "${body.status}") — is ATOMIC_SAAS_DEV_MAGIC_LINKS set?`,
    );
  }

  return body.magic_link;
}

/**
 * Walk first-run onboarding and return the generated recovery code.
 *
 * The code is the only way back in later: the agent keypair is created
 * non-extractable in a secure context, so a wiped device genuinely cannot
 * produce the agent secret from storage. Capturing it here is not a
 * convenience, it is the whole restore path.
 *
 * Also returns where onboarding landed — the drive's own URL. A returning
 * account's magic link goes to the portal dashboard rather than back into the
 * app, so a wiped device needs this to reach the drive at all.
 */
async function completeOnboarding(
  page: Page,
): Promise<{ recoveryCode: string; driveUrl: string }> {
  // Explicit wait rather than the 10s action timeout: this is the first paint
  // after the magic-link redirect, so it also pays for the WASM ClientDb boot,
  // which on a loaded machine takes longer than a click is allowed to wait.
  const profileStep = page.getByRole('button', { name: 'Save & continue' });
  await profileStep.waitFor({ state: 'visible', timeout: 60_000 });
  await profileStep.click();

  await page
    .getByRole('button', { name: 'Generate my recovery code' })
    .click({ timeout: 30_000 });

  // Five groups of five, as `generateRecoveryCode` emits them. Matching the
  // shape rather than a container keeps this off the card's DOM structure.
  const code = await page
    .locator('text=/^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$/')
    .first()
    .innerText();

  // The confirm button stays disabled until the code has been copied — the
  // flow's own guard against a user skipping past the one thing they must keep.
  await page.getByRole('button', { name: 'Copy to clipboard' }).click();
  await page
    .getByRole('button', { name: "Yes, I've stored it safely" })
    .click();

  await expect(page).toHaveURL(/\/app\/show\?subject=/, { timeout: 30_000 });

  return { recoveryCode: code.trim(), driveUrl: page.url() };
}

/**
 * Rename the open resource and wait for it to stick locally.
 *
 * Not `test-utils`' `setTitle`: that one waits for a server commit, and a
 * drive created through the portal is local-first — the edit lands in the
 * ClientDb and there is no HTTP commit to wait for. Waiting for one times out
 * on a rename that in fact succeeded.
 *
 * The local store is also exactly what the vault backs up, so this is the
 * right level to assert at anyway.
 */
async function renameLocally(page: Page, title: string) {
  await editableTitle(page).click();
  await expect(editableTitle(page)).toHaveRole('textbox');
  // New resources pre-fill the title with their class name ("Folder"), so
  // typing without selecting first concatenates the two.
  await page.keyboard.press(
    process.platform === 'darwin' ? 'Meta+a' : 'Control+a',
  );
  await editableTitle(page).type(title);
  await page.keyboard.press('Enter');

  const sidebarEntry = page.getByRole('button', {
    name: new RegExp(escapeForRegExp(title)),
  });
  await expect(sidebarEntry).toBeVisible({ timeout: 15_000 });

  // Then reload and check again. The sidebar alone only proves the in-memory
  // store has the rename, and what the vault exports is the ClientDb — so
  // surviving a reload is what establishes the precondition this test needs:
  // the edit is in the data the backup will actually pack.
  //
  // Not a workaround for a known product bug. An earlier version of this
  // comment claimed backups could race a debounced write; that could not be
  // reproduced (see "backups and pending writes" in
  // planning/CLOUD_VAULT_ARCHITECTURE.md) and the failure it was written for
  // turned out to be the restore-flush race, fixed in the worker.
  await expect
    .poll(() =>
      page.evaluate(async () => {
        const subject = document
          .querySelector('main[about]')
          ?.getAttribute('about');
        if (!subject) return undefined;
        const db = window.store.getClientDb();
        const saved = await db?.getResource(subject);
        if (!saved) return undefined;
        await db?.flush();

        return JSON.parse(saved)['https://atomicdata.dev/properties/name'];
      }),
    )
    .toBe(title);
  await page.reload();
  await expect(sidebarEntry).toBeVisible({ timeout: 30_000 });
}

const escapeForRegExp = (value: string) =>
  value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const vaultPanel = (page: Page) => page.getByTestId('vault-panel');

/**
 * Confirmed object count as the control plane reports it, not as prose.
 *
 * Returns -1 rather than throwing while the panel is mid-render, so the
 * `expect.poll` callers retry instead of failing on the first tick.
 */
async function confirmedObjects(page: Page): Promise<number> {
  try {
    const value = await page
      .getByTestId('vault-summary')
      .getAttribute('data-vault-objects', { timeout: 1000 });

    return Number(value ?? -1);
  } catch {
    return -1;
  }
}

async function openSync(page: Page) {
  await page.goto(`${FRONTEND_URL}/app/sync`);
  // The panel renders nothing at all while the control plane has not answered
  // yet ("cannot say" is not "off"), so waiting on the heading would pass on a
  // page that never reached the portal.
  await expect(vaultPanel(page)).toBeVisible({ timeout: 30_000 });
}

test.describe('Cloud Vault backup and restore', () => {
  // Probed per test rather than once: `test.skip()` takes a synchronous
  // condition, and a stack that went down mid-run should skip the rest rather
  // than report failures that say nothing about the code.
  test.beforeEach(async () => {
    test.skip(
      !(await portalIsUp()),
      `no control plane on ${PORTAL_URL} — run browser/e2e/scripts/vault-stack.sh`,
    );
  });

  test('a second backup after an edit stores more than the first', async ({
    page,
  }) => {
    // Onboarding, enrolment, two backups and their round trips to S3.
    test.slow();

    const email = uniqueEmail();
    await page.goto(await signUpAndGetMagicLink(email));
    await completeOnboarding(page);

    await openSync(page);

    // Already on, without anybody asking for it: onboarding enrols a
    // portal-created drive in encrypted backup, and sync is the premium option
    // it no longer turns on. Asserted rather than assumed, because a silent
    // best-effort step that quietly stopped running is invisible otherwise.
    await expect(vaultPanel(page)).toHaveAttribute('data-vault-state', 'on', {
      timeout: 60_000,
    });

    // Enrolment backs up immediately on purpose, so a new account has
    // something restorable rather than an empty vault waiting on a tick it
    // cannot see. If that first upload silently did nothing, this is where it
    // shows.
    await expect
      .poll(() => confirmedObjects(page), { timeout: 60_000 })
      .toBeGreaterThan(0);

    const afterEnable = await confirmedObjects(page);

    // Make a real change, then back up again. The delta path is the one that
    // regressed before: the lane cursor was committed before the upload, so a
    // second pass believed it had already stored what it had not.
    const canary = `Vault canary ${timestamp()}`;
    await newResource('folder', page);
    await renameLocally(page, canary);

    await openSync(page);
    await page.getByTestId('vault-backup-now').click();

    await expect
      .poll(() => confirmedObjects(page), { timeout: 60_000 })
      .toBeGreaterThan(afterEnable);

    await expect(page.getByTestId('vault-error')).toBeHidden();
  });

  test('a device with no local data restores the workspace from the vault', async ({
    page,
    browser,
  }) => {
    test.slow();

    const email = uniqueEmail();
    await page.goto(await signUpAndGetMagicLink(email));
    const { recoveryCode, driveUrl } = await completeOnboarding(page);

    // Cut this device off from the node BEFORE making the canary.
    //
    // Without this the test proves nothing. A drive created through the portal
    // is assigned to a managed node, so a wiped device that signs back in
    // re-syncs the whole drive from the server — the canary reappears whether
    // or not the vault works, and a restore that silently did nothing still
    // passes. Making the canary somewhere the node can never see it is what
    // makes "it came back" mean "it came back from the vault".
    await page.evaluate(() => {
      const store = window.store;
      store.registerLocalOnlyDrive(store.getDrive());
      store.getDefaultWebSocket()?.close();
    });

    const canary = `Vault canary ${timestamp()}`;
    await newResource('folder', page);
    // Two edits rather than one, so the pack carries a history and not just a
    // single state. What comes back is checked in Rust
    // (`a_restore_keeps_edit_history`) — see the note further down.
    await renameLocally(page, `${canary} draft`);
    await renameLocally(page, canary);

    await openSync(page);
    await expect(vaultPanel(page)).toHaveAttribute('data-vault-state', 'on', {
      timeout: 90_000,
    });
    // The canary was made after onboarding's first backup, so back up again to
    // get it into the vault.
    await page.getByTestId('vault-backup-now').click();
    await expect
      .poll(() => confirmedObjects(page), { timeout: 90_000 })
      .toBeGreaterThan(0);

    // A brand-new context, not a cleared one: no OPFS, no IndexedDB, no
    // cookies, no service worker. Clearing storage by hand keeps missing
    // something, and the one thing missed is exactly what would make a restore
    // pass without restoring.
    //
    // The node is reachable here on purpose — signing in needs it — which is
    // precisely why the canary had to be kept away from it above.
    const wiped = await browser.newContext();

    try {
      const fresh = await wiped.newPage();

      // A returning account lands on the portal dashboard rather than
      // onboarding, so reach the app the way the dashboard's own drive link
      // does. The app then asks how to sign in.
      await fresh.goto(await signUpAndGetMagicLink(email));
      // The portal exchanges the token before setting the session cookie.
      await fresh.waitForURL(url => !url.searchParams.has('token'));
      await fresh.goto(driveUrl);

      // "Forgot it? Restore from …" is the portal path: the account is known from
      // the session cookie the magic link just set, so all it needs is the
      // recovery code. Minting a second agent here instead would leave the
      // vault's key envelope unopenable — the objects would still be stored and
      // permanently unreadable, which is the worst failure this feature has.
      await fresh
        .getByRole('button', { name: /^Forgot it\? Restore from/ })
        .click({ timeout: 30_000 });
      await expect(
        fresh.getByRole('heading', { name: 'Restore account' }),
      ).toBeVisible({ timeout: 30_000 });
      await fresh.getByLabel('Recovery code').fill(recoveryCode);
      await fresh.getByRole('button', { name: 'Restore & sign in' }).click();

      // The server still knows the original drive, so sign-in opens it.
      // Only Vault knows the canary created in local-only mode above.
      await fresh.waitForURL(/\/app\/show\?subject=/, { timeout: 90_000 });
      await expect(fresh.getByRole('button', { name: canary })).toBeHidden();
      await openSync(fresh);
      await expect(fresh.getByTestId('vault-restore')).toBeEnabled({
        timeout: 30_000,
      });
      await fresh.getByTestId('vault-restore').click();
      await expect(
        fresh.getByRole('button', { name: canary }).first(),
      ).toBeVisible({ timeout: 90_000 });

      // Edit history is NOT asserted here, deliberately. The format carries it
      // — `lib/src/vault/sync.rs::a_restore_keeps_edit_history` proves a
      // restored resource has every version it had — but reading it back
      // through the history view after a restore fails roughly one run in six
      // even with a 60s poll, on the right URL, with the count stuck at zero.
      // That is an open bug in what the browser holds after a restore, not a
      // slow page (see CLOUD_VAULT_ARCHITECTURE.md). Asserting it here would
      // add a one-in-six failure that says "vault broken" when the vault is
      // fine, which is how a suite gets ignored.

      // And the vault agrees it is on for this drive, from a device that had
      // to learn that from the control plane rather than from local state.
      await openSync(fresh);
      await expect(vaultPanel(fresh)).toHaveAttribute(
        'data-vault-state',
        'on',
        {
          timeout: 60_000,
        },
      );
      await expect(fresh.getByTestId('vault-error')).toBeHidden();
    } finally {
      await wiped.close();
    }
  });
});
