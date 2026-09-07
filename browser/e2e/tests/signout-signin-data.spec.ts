/**
 * Signing out and back in must not lose data.
 *
 * The reported symptom is "create an account, create some content, sign out,
 * sign in again — the content is gone". Nothing covered that round trip: the
 * suite signs out (`e2e.spec.ts`) and separately signs in (`signIn`), but no
 * test had ever signed back in *as the same agent* and looked for what it made.
 *
 * Two levels, because the symptom has two candidate causes and they need
 * telling apart:
 *
 *  1. the resource itself — is the content still readable by the re-signed-in
 *     agent at all;
 *  2. the local ClientDb encryption key — sign-out deletes the session copy of
 *     the DbKey and keeps a wrapped copy that only the agent's private key can
 *     unwrap (see `helpers/localDbKey.ts`). If sign-in fails to unwrap it, the
 *     worker generates a fresh key, the old encrypted OPFS file can no longer
 *     be opened, and the cache silently empties even though the server still
 *     has everything. That is exactly what "the content is gone" looks like.
 */
import { test, expect, type Page } from './fixtures';
import {
  before,
  getCurrentSubject,
  getDevDriveSecret,
  newResource,
  openAgentPage,
  openSubject,
  setTitle,
  timestamp,
} from './test-utils';

const SESSION_KEY_PREFIX = 'atomic.clientdb.session-key.';
const WRAPPED_KEY_PREFIX = 'atomic.clientdb.wrapped-key.';

/**
 * Read raw `idb-keyval` records straight out of IndexedDB.
 *
 * Deliberately not through the app: the point is to assert on what sign-out
 * actually left on disk, so going via a helper that could itself be the thing
 * that broke would prove nothing. `keyval-store`/`keyval` are idb-keyval's
 * defaults, which `helpers/localDbKey.ts` uses unmodified.
 */
async function readKeyvalEntries(page: Page): Promise<Record<string, unknown>> {
  return page.evaluate(
    () =>
      new Promise<Record<string, unknown>>((resolve, reject) => {
        const open = indexedDB.open('keyval-store');
        open.onerror = () => reject(open.error);

        open.onsuccess = () => {
          const db = open.result;

          if (!db.objectStoreNames.contains('keyval')) {
            resolve({});

            return;
          }

          const store = db
            .transaction('keyval', 'readonly')
            .objectStore('keyval');
          const keysReq = store.getAllKeys();
          const valuesReq = store.getAll();

          keysReq.onerror = () => reject(keysReq.error);
          valuesReq.onerror = () => reject(valuesReq.error);

          valuesReq.onsuccess = () => {
            const entries: Record<string, unknown> = {};
            keysReq.result.forEach((key, i) => {
              if (typeof key !== 'string') return;

              const value = valuesReq.result[i];

              // Uint8Array doesn't survive Playwright's serialisation as
              // anything comparable; a hex string does, and identity is all
              // these assertions need.
              entries[key] =
                value instanceof Uint8Array
                  ? [...value]
                      .map(b => b.toString(16).padStart(2, '0'))
                      .join('')
                  : value;
            });

            resolve(entries);
          };
        };
      }),
  );
}

const keysWithPrefix = (entries: Record<string, unknown>, prefix: string) =>
  Object.keys(entries).filter(key => key.startsWith(prefix));

/**
 * Sign out through the UI, exactly as a user does — `handleSignOut` in
 * `SettingsAgent.tsx` does the key cleanup as a side effect, so calling any
 * lower-level helper would skip the code under test.
 */
async function signOut(page: Page) {
  page.on('dialog', dialog => {
    dialog.accept();
  });

  await openAgentPage(page);
  await page.click('[data-test="sign-out"]');
  await expect(
    page.getByRole('button', { name: 'Create account' }),
  ).toBeVisible();
}

/**
 * Sign back in on a device that just signed out.
 *
 * Not `test-utils`' `signIn`: that one waits for the signed-in sidebar, and
 * here the app may land on the "Your data is on another device" screen
 * instead. Waiting for a sidebar that will never come reports a locator
 * timeout, which says nothing about what actually went wrong — this asserts on
 * the screen it landed on instead.
 *
 * There is no button to confirm the secret: the flow signs in as soon as the
 * value parses (on change, and again on blur).
 */
async function signInAgain(page: Page, secret: string) {
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();

  const field = page.getByLabel('Agent secret');
  await field.fill(secret);
  await field.blur();

  // The whole point of this spec. This device made the workspace moments ago
  // and is still talking to the same server, so "your data is elsewhere" is
  // never a correct answer here — it is what the reported data loss looks
  // like from the user's side.
  await expect(
    page.getByRole('heading', { name: 'Your data is on another device' }),
  ).toBeHidden({ timeout: 15000 });
}

test.describe('sign-out / sign-in round trip', () => {
  test.beforeEach(before);

  test('content made before signing out is still readable after signing back in', async ({
    page,
  }) => {
    // Signing out, signing in and re-resolving a resource is three server
    // round trips on top of the dev-drive setup.
    test.slow();

    const secret = await getDevDriveSecret(page);
    const folderTitle = `Survives sign-out ${timestamp()}`;

    await newResource('folder', page);
    await setTitle(page, folderTitle);

    // Capture the subject rather than relying on the sidebar after sign-in:
    // sign-out clears the active drive on purpose, so the sidebar legitimately
    // starts empty. What must survive is the resource.
    const folderSubject = await getCurrentSubject(page);

    await signOut(page);
    await signInAgain(page, secret);

    await openSubject(page, folderSubject);
    await expect(page.locator(`text=${folderTitle}`).first()).toBeVisible({
      timeout: 15000,
    });
  });

  test('the local database key survives sign-out and is restored on sign-in', async ({
    page,
  }) => {
    test.slow();

    const secret = await getDevDriveSecret(page);

    const beforeSignOut = await readKeyvalEntries(page);
    const sessionKeys = keysWithPrefix(beforeSignOut, SESSION_KEY_PREFIX);
    const wrappedKeys = keysWithPrefix(beforeSignOut, WRAPPED_KEY_PREFIX);

    // Sign-in must have produced both records; without the wrapped one there
    // is nothing for the next sign-in to restore from, and the rest of this
    // test would pass vacuously.
    expect(sessionKeys).toHaveLength(1);
    expect(wrappedKeys).toHaveLength(1);

    const dbKeyBefore = beforeSignOut[sessionKeys[0]];
    expect(typeof dbKeyBefore).toBe('string');

    await signOut(page);

    const afterSignOut = await readKeyvalEntries(page);
    // The signed-out session must not be able to open the encrypted cache...
    expect(keysWithPrefix(afterSignOut, SESSION_KEY_PREFIX)).toHaveLength(0);
    // ...while the durable copy stays, or the cache is lost for good.
    expect(keysWithPrefix(afterSignOut, WRAPPED_KEY_PREFIX)).toEqual(
      wrappedKeys,
    );

    await signInAgain(page, secret);

    // The restored key must be the SAME bytes. A fresh key would also leave a
    // session record here, and the encrypted OPFS file it can't open is
    // precisely the "my content vanished" bug.
    await expect
      .poll(
        async () => {
          const entries = await readKeyvalEntries(page);

          return entries[sessionKeys[0]];
        },
        { timeout: 15000 },
      )
      .toBe(dbKeyBefore);
  });
});
