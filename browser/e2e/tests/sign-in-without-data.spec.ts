import { test, expect, type Page } from './fixtures';
import { Agent, generateKeyPair, toLegacyScheme } from '@tomic/lib';
import {
  FRONTEND_URL,
  getCurrentSubject,
  installCommitWatcher,
  newResource,
  expectPkarrLookupMiss,
  setTitle,
  smoke,
} from './test-utils';

test.beforeEach(async ({ page }) => {
  await installCommitWatcher(page);
});

// No dev-drive setup: neither this browser nor the server has this identity's
// home. A stored DID alone is not a usable workspace.
async function unknownAccount(
  legacyHome = false,
): Promise<{ secret: string; home: string }> {
  const { privateKey, publicKey } = await generateKeyPair();
  const initialDrive = legacyHome ? (await unknownAccount()).home : undefined;
  const secret = btoa(
    JSON.stringify({
      privateKey,
      subject: `did:ad:agent:${publicKey}`,
      initialDrive,
    }),
  );

  return { secret, home: await Agent.privateDriveSubjectFromSecret(secret) };
}

async function signIn(page: Page, secret: string) {
  const home = await Agent.privateDriveSubjectFromSecret(secret);
  await page.goto(
    `${FRONTEND_URL}/app/welcome?next=${encodeURIComponent(home)}`,
  );
  // Cold boot again, and the widest of these: 6050 to 8586ms at four workers,
  // so the bare `fill` was running at 86% of the 10s actionTimeout.
  await expect(page.getByLabel('Agent secret')).toBeVisible({
    timeout: 20_000,
  });
  await page.getByLabel('Agent secret').fill(secret);
  // Wait for identity persistence independently of navigation so the direct
  // link test can exercise a restored session even when onboarding is broken.
  await expect
    .poll(() => page.evaluate(() => window.store.getAgent()?.subject))
    .toBe(JSON.parse(atob(secret)).subject);
}

async function expectWritableHome(page: Page, home: string) {
  await expect(page).toHaveURL(
    url =>
      url.pathname === '/app/show' && url.searchParams.get('subject') === home,
    { timeout: 30_000 },
  );
  await expect(page.locator(`main[about="${home}"]`)).toBeVisible();
  expect(await page.evaluate(() => window.store.getDrive())).toBe(home);
  // The error screen also has main[about]. Require a readable Drive before
  // clicking New, which could otherwise initialize the home as a side effect.
  //
  // This carries the same 30 s as the URL wait above, and for the same reason.
  // Callers whose home already exists reach this in a few ms, but the
  // missing-home caller has to initialize the drive on the server and read it
  // back first, and that is the case this helper exists for. Measured over five
  // four-worker rounds on this container, the poll splits into two populations
  // with nothing between them:
  //
  //     home already present      4 to  105 ms
  //     home being initialized  5202 to 8829 ms
  //
  // 8829 ms is 88% of the 10 s `expect.timeout` default, which is what develop
  // run 4671 failed on, three attempts out of three. The `toHaveURL` above
  // splits the same way (11.2 to 12.8 s for the same caller) and already had an
  // explicit 30 s, so this is the wait that was left behind rather than a new
  // allowance.
  await expect
    .poll(
      () =>
        page.evaluate(subject => {
          const resource = window.store.resources.get(subject);

          return (
            !!resource &&
            !resource.error &&
            resource.hasClasses('https://atomicdata.dev/classes/Drive')
          );
        }, home),
      { timeout: 30_000 },
    )
    .toBe(true);

  await newResource('document-v2', page);
  const title = `Private home canary ${Date.now()}`;
  await setTitle(page, title);
  const subject = await getCurrentSubject(page);
  // Let the rename finish landing before reloading it away. `setTitle` returns
  // once a commit for this subject has been posted, and `useValue`'s save is
  // debounced, so under load the commit it returns on can be one the debounce
  // fired part-way through the typing. Reloading then persists the prefix, and
  // the assertion below reports the truncation several lines from its cause:
  // seen at four workers on 24 September 2026 storing "Private home can" and
  // "Private home canary 17902" for titles ending 1790211504841 and
  // 1790210871258, each stable across 23 locator resolutions, so what was
  // saved was short and not merely what was drawn.
  //
  // Waiting for the whole title ON SCREEN is not enough, and that is the
  // useful half of this: with only that wait the reload still restored
  // "Private home cana", 3 runs of 6, so the editor was ahead of the outbox
  // rather than the store being ahead of the screen. What the reload must wait
  // for is the write, so wait for the outbox to drain as well. Matching the
  // commit body cannot substitute for either, because a rename travels as a
  // binary `loroUpdate` and the title is never in it.
  await expect(page.getByTestId('editable-title')).toHaveText(title);
  await expect
    .poll(
      () => page.evaluate(() => window.store.getSyncStatus().pendingDirtyCount),
      { timeout: 30_000 },
    )
    .toBe(0);
  await page.reload();
  await expect(page.locator(`main[about="${subject}"]`)).toBeVisible();
  await expect(page.getByTestId('editable-title')).toHaveText(title);
}

test(
  'a secret with no recoverable data opens its writable private home',
  smoke,
  async ({ page, browserDiagnostics }) => {
    expectPkarrLookupMiss(browserDiagnostics);
    const { secret, home } = await unknownAccount();
    await signIn(page, secret);
    // The nudge is a toast, raised from `ShowRoute`'s effect once
    // `openPrivateHome` reports `created`, so this waits on a home drive being
    // built on the server and not on a render. `signIn` returns as soon as the
    // agent is in the store, which is what STARTS that effect, so the whole
    // creation falls inside this budget. The 10s default cannot cover it:
    // measured at four workers on 24 September 2026, the step cost 12.9s, 13.9s
    // and 14.6s, and the test failed 3 of 3 with the link never found. It is
    // green 5 of 5 unloaded, which is why this reads as a flake rather than as
    // the fixed shortfall it is. CI saw the same test on run 4485.
    await expect(
      page.getByRole('link', {
        name: 'Connect another device or restore a backup',
      }),
    ).toBeVisible({ timeout: 30_000 });
    await expectWritableHome(page, home);
  },
);

test('an unavailable legacy home does not prevent a writable derived home', async ({
  page,
  browserDiagnostics,
}) => {
  expectPkarrLookupMiss(browserDiagnostics);
  const { secret, home } = await unknownAccount(true);
  const legacy = JSON.parse(atob(secret)).initialDrive as string;
  browserDiagnostics.expect(
    'error',
    /^Failed to load resource: the server responded with a status of 404 \(Not Found\)$/,
    'The deliberately unavailable legacy drive returns 404.',
    1,
    new RegExp(`/(?:did|resource)\\?subject=${encodeURIComponent(legacy)}$`),
    { optional: true },
  );
  browserDiagnostics.expect(
    'error',
    new RegExp(`^${legacy} .*Resource not found`),
    'Legacy drive migration reports the unavailable source; the derived home must still work.',
    1,
    undefined,
    { optional: true },
  );
  await signIn(page, secret);
  await expectWritableHome(page, home);
});

test('a restored session can initialize its missing private home from a direct link', async ({
  page,
  browserDiagnostics,
}) => {
  expectPkarrLookupMiss(browserDiagnostics);
  const { secret, home } = await unknownAccount();
  browserDiagnostics.expect(
    'warning',
    new RegExp(
      `^\\[WS\\] refused: (SUB|SYNC) refused for (?:${home}|${toLegacyScheme(home)}): not readable$`,
    ),
    'The persisted identity has no drive on the node while recovery and initialization run; bounded sync retries may be refused.',
    16,
    undefined,
    { optional: true },
  );
  // Seed only a supported persisted identity record, never run sign-in or
  // create the home. This remains a missing-home test after sign-in is fixed.
  await page.goto(
    `${FRONTEND_URL}/app/welcome?next=${encodeURIComponent(home)}`,
  );
  await page.evaluate(
    async ({ secret: storedSecret, home: storedHome }) => {
      await new Promise<void>((resolve, reject) => {
        const request = indexedDB.open('keyval-store');
        request.onupgradeneeded = () =>
          request.result.createObjectStore('keyval');
        request.onerror = () => reject(request.error);

        request.onsuccess = () => {
          const db = request.result;
          const tx = db.transaction('keyval', 'readwrite');
          // The fallback record is a supported format for installations without
          // WebCrypto. Only this disposable, generated test identity is stored.
          tx.objectStore('keyval').put(
            {
              ...JSON.parse(atob(storedSecret)),
              privateDrive: storedHome,
            },
            'atomic.agent.fallback',
          );

          tx.oncomplete = () => {
            db.close();
            resolve();
          };

          tx.onerror = () => {
            db.close();
            reject(tx.error);
          };
        };
      });
      localStorage.setItem('drive', JSON.stringify(storedHome));
    },
    { secret, home },
  );
  await page.goto(
    `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(home)}`,
  );
  await expectWritableHome(page, home);
});

test('Sync does not claim an unreadable drive is cached or on another device', async ({
  page,
  browserDiagnostics,
}) => {
  expectPkarrLookupMiss(browserDiagnostics);
  const { secret, home } = await unknownAccount();
  await signIn(page, secret);
  await expect
    .poll(() => page.evaluate(() => window.store.getDrive()))
    .toBe(home);
  // Select an unrelated, genuinely absent drive, even after private-home
  // initialization is fixed. Merely knowing a DID must not synthesize it.
  const missing = (await unknownAccount()).home;
  browserDiagnostics.expect(
    'warning',
    new RegExp(
      `^\\[WS\\] refused: (SUB|SYNC) refused for ${missing}: not readable$`,
    ),
    'Selecting and reloading this deliberately nonexistent foreign drive can be refused by the node, including bounded sync retries.',
    16,
    undefined,
    { optional: true },
  );
  browserDiagnostics.expect(
    'error',
    /^Failed to load resource: the server responded with a status of 404 \(Not Found\)$/,
    'Drive usage for the deliberately nonexistent drive can return 404 on initial mount and refresh.',
    4,
    new RegExp(`/drive-usage\\?subject=${encodeURIComponent(missing)}$`),
    { optional: true },
  );
  await page.evaluate(drive => window.store.setDrive(drive), missing);
  await page.goto(`${FRONTEND_URL}/app/sync`);
  await expect(
    page.getByRole('heading', { name: 'Sync', exact: true }),
  ).toBeVisible();
  await expect
    .poll(() =>
      page.evaluate(async drive => {
        const resource = await window.store.getResource(drive);

        return !!resource.error;
      }, missing),
    )
    .toBe(true);
  await expect
    .soft(page.getByText('Cached locally · works offline', { exact: true }))
    .toBeHidden();
  await expect
    .soft(page.getByText('Your data is on another device', { exact: true }))
    .toBeHidden();
});
