import {
  Page,
  expect,
  Browser,
  ConsoleMessage,
  Locator,
  TestInfo,
  test,
} from '@playwright/test';
import {
  applyCpuThrottle,
  envCpuThrottle,
  registerPerfPage,
} from './perf-attach';
import { installEmptyDiscoveryRoom } from './fixtures';
import type { DiagnosticCollector } from './diagnostic-collector';

/** Playwright tag for the light CI gate (`pnpm test-e2e:light` / `--grep @smoke`). */
export const smoke = { tag: '@smoke' } as const;

/**
 * A secret signed in on a server that has none of its data makes the app ask
 * the pkarr relay which server hosts the drive. The relay answers 404 when no
 * record exists, which is the normal case for a throwaway identity, and the
 * browser logs every 404 as a console error. Optional: offline or sandboxed
 * runs never get that far. Two calls at most: the home and a derived retry.
 */
export function expectPkarrLookupMiss(
  browserDiagnostics: Pick<DiagnosticCollector, 'expect'>,
): void {
  browserDiagnostics.expect(
    'error',
    /^Failed to load resource: the server responded with a status of 404 \(Not Found\)$/,
    'The pkarr relay has no record for a drive nobody announced.',
    2,
    /^https:\/\/dns\.iroh\.link\/pkarr\/[a-z0-9]+$/,
    { optional: true },
  );
}

export const PROPERTIES = {
  isA: 'https://atomicdata.dev/properties/isA',
  set: 'https://atomicdata.dev/properties/set',
  delete: 'https://atomicdata.dev/properties/delete',
  push: 'https://atomicdata.dev/properties/push',
  loroUpdate: 'https://atomicdata.dev/properties/loroUpdate',
} as const;

/**
 * Click "Page edit" on a website resource, waiting as long as the draft build
 * behind it can take.
 *
 * That button is `disabled={!draft || busy || refreshing || !!problem}`
 * (`WebsitePage.tsx`), and `refreshing` stays true until the page's effect has
 * read the website config and run `buildWebsiteArtifact`. So the click is not a
 * click, it is a wait on that build, and it was sitting on Playwright's 10 s
 * ACTION default rather than on any assertion budget.
 *
 * Measured on this container (4 cores, so a four-worker round is oversubscribed),
 * over the website specs at four workers:
 *
 *     website-inline-content.spec.ts   3708 to 9170 ms   (n=8)
 *     website-inline-fixture.ts        1235 to 7629 ms   (n=11)
 *
 * 9170 ms is 91% of the old budget, and a further round blew past it outright:
 * `locator.click: Timeout 10000ms exceeded`, the element `disabled` for all
 * fifteen retries. A CI shard runs ~71 tests against one server with three other
 * shards alongside, so 91% locally is not a budget at all.
 *
 * 30 s is ~3x the worst sample, matching the wait in `waitForSynced` below.
 * `website.spec.ts`'s own "Page edit" click needs none of this and is left alone:
 * it happens after a release round-trip, by which time the draft is long settled,
 * and it measures 109 to 203 ms (2%) over the same eight rounds.
 */
export const clickPageEdit = (page: Page) =>
  page
    .getByRole('button', { name: 'Page edit', exact: true })
    .click({ timeout: 30_000 });

export const SERVER_URL = process.env.SERVER_URL || 'http://localhost:9883';
export const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:6747';

/**
 * Rewrite a server-origin URL onto the SPA origin Playwright drives.
 *
 * Invite links and `/app/…` URLs are minted on the atomic-server origin.
 * Locally that origin may serve a stub bundle while Vite is on
 * `FRONTEND_URL`. Opening the server URL then loads an empty page and
 * every "Create account and accept" wait times out. CI sets both to the
 * same origin, so this is a no-op there.
 */
export function spaUrl(url: string): string {
  try {
    const parsed = new URL(url, FRONTEND_URL);
    const frontend = new URL(FRONTEND_URL);
    parsed.protocol = frontend.protocol;
    parsed.host = frontend.host;

    return parsed.toString();
  } catch {
    return url;
  }
}

/**
 * Internal transport URL for intercepted requests forwarded with `route.fetch`.
 * Keep public URLs in generated configuration and authentication signatures:
 * `server-dns.cjs` maps those to the CI service without changing their identity.
 */
export function nodeReachableServerUrl(browserFacingUrl: string): string {
  const service = process.env.ATOMIC_SERVICE_URL?.replace(/\/$/, '');

  if (!service) {
    return browserFacingUrl.replace(/\/$/, '');
  }

  try {
    const from = new URL(browserFacingUrl);
    const to = new URL(service);
    from.hostname = to.hostname;
    from.port = to.port;
    from.protocol = to.protocol;

    return from.toString().replace(/\/$/, '');
  } catch {
    return browserFacingUrl.replace(/\/$/, '');
  }
}

export const DEMO_INVITE_NAME = 'document demo invite';

export const testFilePath = (filename: string) => {
  const fixturesFolder = __dirname + '/fixtures';

  return `${fixturesFolder}/${filename}`;
};

export const timestamp = () => new Date().toLocaleTimeString();
export const sideBarDriveSwitcher = (page: Page) =>
  page.getByTitle('Switch Drive');
export const sideBarNewResourceTestId = 'sidebar-new-resource';

/** Sidebar "New" → `/app/new` (scoped so drive/folder QuickCreateRow duplicates do not match). */
export const sidebarNewResourceButton = (page: Page) =>
  page.getByTestId('sidebar').getByTestId(sideBarNewResourceTestId);

/**
 * Top bar Share control. `getByRole('button', { name: 'Share' })` matches twice because
 * ShareDialog wraps the trigger in a `div[role="button"]` around the real `<button>`.
 */
export const topBarShareButton = (page: Page) =>
  page.locator('[aria-label="navigation"] button').filter({ hasText: 'Share' });
export const editableTitle = (page: Page) => page.getByTestId('editable-title');
export const currentDriveTitle = (page: Page) =>
  page.getByTestId('current-drive-title');
export const contextMenu = '[data-test="context-menu"]';
/**
 * The search input inside the search overlay (modal). Only visible after the
 * overlay is opened via the Search button or cmd/ctrl+K. Replaces the old
 * inline contentEditable that had data-testid="adress-bar".
 */
export const searchInput = (page: Page) =>
  page.getByPlaceholder('Search for resources...');

/**
 * Opens the search overlay if not already open. Idempotent — returns the
 * focused input locator.
 */
export async function openSearchOverlay(page: Page) {
  const input = searchInput(page);

  if (!(await input.isVisible().catch(() => false))) {
    await page.locator('nav button[title^="Search ("]').first().click();
    await input.waitFor({ state: 'visible', timeout: 3000 });
  }

  return input;
}

/**
 * Type a search query into the overlay. Opens the overlay first if needed.
 * Clears any existing query, which is important since the input persists
 * across re-opens in the same page session.
 */
export async function typeInSearch(page: Page, text: string) {
  // The search overlay re-renders as results stream in — its input node can
  // be detached and replaced mid-`fill` ("element was detached from the
  // DOM"). Retry against a freshly-resolved locator until the value sticks.
  for (let attempt = 0; attempt < 4; attempt++) {
    const input = await openSearchOverlay(page);
    const ok = await input
      .fill(text)
      .then(() => input.inputValue())
      .then(value => value === text)
      .catch(() => false);

    if (ok) {
      return;
    }
  }

  // Final attempt — surface the error if the input is still unstable.
  const input = await openSearchOverlay(page);
  await input.fill(text);
}

/**
 * Search-and-navigate: open overlay, type query, wait for a result matching
 * `resultText` to appear in the overlay, click it, and wait for navigation
 * to the result's show page. Returns after the overlay closes.
 *
 * Use this instead of the old pattern of typing and pressing Enter — the new
 * overlay requires an explicit result click (or ArrowDown → Enter) and only
 * navigates when a real result is selected, not on raw Enter.
 *
 * Result rows carry a `data-index` attribute
 * (see OverlayContainer.tsx → ResultRowWrapper).
 */
export async function searchAndOpen(
  page: Page,
  query: string,
  resultText: string,
) {
  await typeInSearch(page, query);
  const result = page
    .locator('[data-index]')
    .filter({ hasText: resultText })
    .first();
  await expect(result).toBeVisible({ timeout: 15000 });
  // The overlay streams results in waves (local index first, then the
  // server-merge), re-rendering the list and detaching row nodes. A plain
  // `click()` can fire mid-wave and fail with "element was detached from the
  // DOM" — and under suite-wide load the server wave lands later, widening that
  // window. Retry the click (re-resolving the locator each attempt) until it
  // lands on a stable node, rather than racing a single re-render.
  await expect(async () => {
    // A click can close the overlay before Playwright finishes its action.
    // On a retry, that closed overlay is success, not a missing result to
    // click again. Otherwise the helper times out after successful navigation.
    if (await searchInput(page).isVisible()) {
      await result.click({ timeout: 2000 });
    }

    await expect(searchInput(page)).toBeHidden();
  }).toPass({ timeout: 15000 });
}

/**
 * Deprecated alias — old tests called this. Forwards to the new `typeInSearch`
 * which opens the overlay. Kept so we can migrate tests incrementally.
 * @deprecated use `typeInSearch` or `searchAndOpen`
 */
export async function typeInAddressBar(page: Page, text: string) {
  await typeInSearch(page, text);
}

/**
 * Deprecated alias — old tests used `addressBar(page).fill(...)`. Returns the
 * new search input after opening the overlay. Prefer `typeInSearch`.
 * @deprecated use `searchInput` (and open the overlay first)
 */
export const addressBar = (page: Page) => searchInput(page);
export const newDriveMenuItem = '[data-test="menu-item-new-drive"]';
export const sidebarDriveButtonId = 'sidebar-drive-open';
export const defaultDevServer = 'http://localhost:9883';
export const currentDialogOkButton = 'dialog[open] >> footer >> text=Ok';
// Fallback wait for the search index to catch up, for callers that can't
// supply a probe to `waitForSearchIndex`. Prefer the probe form, which
// polls real readiness. Kept as a named budget for comments that still
// refer to the server's flush interval (`commit_monitor.rs`).
export const REBUILD_INDEX_TIME = 1500;

/**
 * Default test setup: `/app/dev-drive` creates a fresh agent + drive on the dev
 * server and switches to it. Most specs use `test.beforeEach(before)` so every
 * test starts isolated without extra navigation.
 */
export const before = async (
  // Accept the second positional `testInfo` argument so we can stash
  // the page for `attachPerfOnFailure`. `beforeEach` callbacks in
  // Playwright receive `(fixtures, testInfo)` — most callers don't
  // need it, but optional second-arg ergonomics keeps the signature
  // backwards-compatible for the dozens of specs that already call
  // `test.beforeEach(before)`.
  { page }: { page: Page },
  testInfo?: TestInfo,
): Promise<void> => {
  if (!SERVER_URL) {
    throw new Error('serverUrl is not set');
  }

  // Optional CPU throttle: simulates dagger's single-core slowdown
  // locally so flaky tests reproduce on a dev box. No-op when the
  // env var is unset.
  const throttle = envCpuThrottle();
  if (throttle) await applyCpuThrottle(page, throttle);

  if (testInfo) registerPerfPage(testInfo, page);

  // Peer discovery never reaches a real signalling service from a test,
  // whichever `test` the spec imported. `fixtures.ts` installs this for the
  // specs that take their `test` from there; twenty-two spec files import it
  // straight from `@playwright/test`, and nineteen of those call this function,
  // which is why it goes here. The app contacts no service unless one is
  // configured, so this is a guard for the day a build or a stored setting
  // names one; registering it a second time is harmless.
  await installEmptyDiscoveryRoom(page.context());

  await installCommitWatcher(page);
  await test.step('Initialize fresh agent and drive', () => devDrive(page));
};

/**
 * Mirror outgoing v2 WebSocket COMMIT frames (tag `0x13`) into a
 * `window.__atomicCommitLog` so {@link waitForCommit} can observe
 * commits regardless of transport. Must be installed BEFORE
 * `page.goto(...)` — `addInitScript` runs before any page script,
 * including the SPA bundle that opens the WebSocket.
 *
 * The Store now prefers WS for persisted commits (HTTP `/commit`
 * remains a fallback), so the previous `page.waitForResponse(/commit)`
 * helper alone misses the happy path and tests time out.
 */
export async function installCommitWatcher(page: Page) {
  await page.addInitScript(() => {
    // Idempotent — `before()` may run multiple times against the same
    // browser context if a spec opens additional pages.
    if (
      (window as unknown as { __atomicCommitWatcherInstalled?: boolean })
        .__atomicCommitWatcherInstalled
    ) {
      return;
    }

    (
      window as unknown as { __atomicCommitWatcherInstalled: boolean }
    ).__atomicCommitWatcherInstalled = true;
    (window as unknown as { __atomicCommitLog: unknown[] }).__atomicCommitLog =
      [];

    const COMMIT_TAG = 0x13;
    const ISA = 'https://atomicdata.dev/properties/isA';
    const SUBJECT = 'https://atomicdata.dev/properties/subject';
    const COMMIT_CLASS = 'https://atomicdata.dev/classes/Commit';

    type ObservedCommit = {
      sentAt: number;
      subject: string;
      commit: Record<string, unknown>;
    };
    const pending = new WeakMap<WebSocket, Map<number, ObservedCommit>>();
    const origSend = WebSocket.prototype.send;

    WebSocket.prototype.send = function (
      data: string | ArrayBufferLike | Blob | ArrayBufferView,
    ) {
      try {
        if (!pending.has(this)) {
          const requests = new Map<number, ObservedCommit>();
          pending.set(this, requests);
          this.addEventListener('message', async event => {
            const bytes =
              event.data instanceof Blob
                ? new Uint8Array(await event.data.arrayBuffer())
                : event.data instanceof ArrayBuffer
                  ? new Uint8Array(event.data)
                  : undefined;
            if (!bytes || bytes.length < 3 || bytes[0] !== 0x14) return;
            const id = new DataView(bytes.buffer, bytes.byteOffset).getUint16(
              1,
              false,
            );
            const entry = requests.get(id);

            if (entry) {
              (
                window as unknown as { __atomicCommitLog: ObservedCommit[] }
              ).__atomicCommitLog.push(entry);
              requests.delete(id);
            }
          });
        }

        if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
          const buf =
            data instanceof ArrayBuffer
              ? new Uint8Array(data)
              : new Uint8Array(
                  (data as ArrayBufferView).buffer,
                  (data as ArrayBufferView).byteOffset,
                  (data as ArrayBufferView).byteLength,
                );

          if (buf[0] === COMMIT_TAG && buf.length >= 3) {
            const json = new TextDecoder().decode(buf.subarray(3));
            const commit = JSON.parse(json) as Record<string, unknown>;
            const isA = commit[ISA] as string[] | undefined;

            if (Array.isArray(isA) && isA.includes(COMMIT_CLASS)) {
              pending
                .get(this)!
                .set(
                  new DataView(buf.buffer, buf.byteOffset).getUint16(1, false),
                  {
                    sentAt: Date.now(),
                    subject: (commit[SUBJECT] as string | undefined) ?? '',
                    commit,
                  },
                );
            }
          }
        }
      } catch {
        // Best-effort — never break the real send.
      }

      // eslint-disable-next-line prefer-rest-params
      return origSend.apply(this, arguments as unknown as [data: never]);
    };
  });
}

/**
 * Agent secret from the last `devDrive()` / `before()` (stored in localStorage).
 * Use for second browser contexts that must sign in as the same user.
 */
export async function getDevDriveSecret(page: Page): Promise<string> {
  const secret = await page.evaluate(() =>
    localStorage.getItem('atomic-test.dev-drive-secret'),
  );

  if (!secret) {
    throw new Error(
      'getDevDriveSecret: missing atomic-test.dev-drive-secret — run devDrive or before() first',
    );
  }

  return secret;
}

export async function setTitle(page: Page, title: string) {
  await editableTitle(page).click();
  await expect(editableTitle(page)).toHaveRole('textbox');
  // New resources pre-fill the title input with the class name (e.g. "Folder"),
  // so typing would concatenate ("FolderTestFolder-…"). Select-all + type
  // replaces the existing value.
  await page.keyboard.press(
    process.platform === 'darwin' ? 'Meta+a' : 'Control+a',
  );
  // Read the resource subject BEFORE we close the editor — used to
  // match the commit that carries this rename across either transport.
  const subject = await page.evaluate(() => {
    const main = document.querySelector('main[about]');

    return main?.getAttribute('about') ?? '';
  });
  const renameStartedAt = Date.now();
  // Arm the commit waiter BEFORE pressing Enter — Playwright's
  // `waitForResponse` / `waitForFunction` only see signals that
  // happen AFTER the call is awaited, so installing it first
  // guarantees we don't miss a fast post.
  const commitPosted = waitForCommitForSubject(page, subject, renameStartedAt);
  await editableTitle(page).type(title);
  await page.keyboard.press('Enter');

  // Wait for the commit carrying this resource to complete server-side.
  // This is the definitive signal that the rename has landed — far more
  // reliable than polling `pendingDirtyCount === 0`, which is trivially
  // true before `useValue`'s debounced save fires (the outbox doesn't
  // even know about the change yet).
  //
  // We deliberately DON'T also poll the local store for `name === title`.
  // Plugins / class-extender `after_commit` hooks can transform the
  // commit's value before it's reflected back (e.g. test-plugin
  // prefixes folder names with "My "), so the local store may end up
  // with a derived value. The contract of `setTitle` is "the user's
  // rename has been committed to the server"; what the server (or its
  // plugins) does next is not setTitle's concern.
  await commitPosted;

  // The waiter above matches ANY commit for this subject, and `useValue`'s
  // save is debounced, so under load the debounce can fire part-way through
  // the typing and that first commit satisfies it. `setTitle` then returned
  // with the rename half done, and a caller that reloaded straight after
  // persisted the prefix: a title ending `1790210871258` was stored as
  // `Private home canary 17902`, stable across 23 reads, so it was saved
  // truncated rather than rendered late.
  //
  // Waiting for quiescence here closes that. The objection recorded above —
  // that `pendingDirtyCount === 0` is trivially true before the debounce
  // fires — is a statement about checking it BEFORE any commit; by this point
  // one has posted. Any characters still unsaved are either in the outbox, in
  // an in-flight `save()`, or in an armed debounce timer, and
  // `pendingDirtyCount` counts all three (`_scheduledSaves` is incremented by
  // `startScheduledSave`), so a partial rename cannot read as settled.
  //
  // Matching the commit BODY against the title instead cannot work: a rename
  // travels as a base64 `loroUpdate`, never as a literal substring.
  await waitForSynced(page);
}

/** Wait for either an HTTP `/commit` POST or an acknowledged WS COMMIT frame whose
 *  body references `subject` and was sent at or after `since`. */
function waitForCommitForSubject(page: Page, subject: string, since: number) {
  const http = page.waitForResponse(
    r => {
      const request = r.request();

      return (
        r.url().endsWith('/commit') &&
        request.method() === 'POST' &&
        request.timing().startTime >= since &&
        request.postData()?.includes(subject) === true &&
        r.status() < 400
      );
    },
    { timeout: 15000 },
  );
  const ws = page.waitForFunction(
    ({ targetSubject, sinceMs }) => {
      const log =
        (
          window as unknown as {
            __atomicCommitLog?: Array<{
              sentAt: number;
              subject: string;
              commit: Record<string, unknown>;
            }>;
          }
        ).__atomicCommitLog ?? [];

      return log.some(
        entry => entry.sentAt >= sinceMs && entry.subject === targetSubject,
      );
    },
    { targetSubject: subject, sinceMs: since },
    { polling: 100, timeout: 15000 },
  );

  return Promise.race([http, ws]);
}

/**
 * Signs in with the explicit or current test agent secret if not already signed in.
 *
 * Handles three entry states:
 *   1. Already signed in (e.g. post-`before()`/`devDrive()`): no-op.
 *   2. Welcome gate visible: click its "Sign in" button → paste secret.
 *   3. On a drive page with a "Login / New User" sidebar row: go to the
 *      welcome gate and follow its flow.
 *
 * There is no button to confirm the secret, by design: a secret either parses
 * or it doesn't, so GettingStartedFlow signs in the moment the value is valid
 * (on change, and again on blur). This helper used to click a "Continue"
 * button that the passkey-first onboarding rework removed, which timed out and
 * took down every spec that signs in — most of the suite.
 *
 * Note this is deliberately the FOSS path. The neighbouring "Restore account"
 * button is the managed/recovery route (passkey or recovery code); sending
 * self-hosted tests through it would exercise the wrong flow entirely.
 *
 * Idempotence is important because `before()` already signs in with a
 * fresh dev-drive agent; tests that also call `signIn(page)` used to pre-empt
 * that by looking for a "Sign in" button that wasn't there.
 */
/**
 * Types the agent secret and lets the flow sign itself in.
 *
 * Filling a valid secret starts sign-in immediately. Do not blur or submit
 * afterward: the input may already have unmounted. Callers await the resulting
 * signed-in state before continuing.
 */
async function enterSecret(page: Page, secret: string) {
  await page.getByLabel('Agent secret').fill(secret);
}

export async function signIn(page: Page, secret?: string) {
  const input = page.getByLabel('Agent secret');
  const signInButton = page.getByRole('button', {
    name: 'Sign in',
    exact: true,
  });
  // The sidebar's user row, which opens the account menu. It carries
  // `data-signed-in` once there is an agent, and reads "Login / New User"
  // before that.
  const settings = page.locator(
    '[data-testid="account-menu-trigger"][data-signed-in="true"]',
  );
  const login = page
    .getByTestId('account-menu-trigger')
    .filter({ hasText: 'Login / New User' });
  // The first thing this helper waits for is a cold app boot in whatever
  // context it was handed: wasm, store init and the route all have to land
  // before any of these four appear. It was on the 10s default while the two
  // waits below it already had 20s, which is the tell that nobody chose it.
  // Measured at four workers on 24 September 2026: 751ms to 6118ms, so on this
  // box it was already at 61% of its budget. On a Mancave running four runners
  // at once, where a shard took 44 to 50 minutes against the usual 19 to 25,
  // that doubles and goes past 10s. `meetings.spec.ts:237` failed exactly there
  // on run 4537, waiting for the `Sign in` button. 20s was not enough either
  // for a second browser context whose local database opened late (batch
  // #1915, runs 1 and 7). This only waits longer when boot is slow.
  await expect(
    input.or(signInButton).or(settings).or(login).first(),
  ).toBeVisible({ timeout: 45_000 });
  // Not "is the settings link visible": the signed-in layout renders from
  // stored state and can be up before the agent is in the store, so that
  // check returned for sessions that had no agent at all. Ask the store.
  if (await page.evaluate(() => !!window.store?.getAgent())) return;

  if (!(await input.isVisible())) {
    // Navigate directly: the sidebar login link opens a new tab and may
    // unmount while onboarding takes over the initial route.
    if (!(await signInButton.isVisible()))
      await page.goto(`${FRONTEND_URL}/app/welcome`);
    // Same story: an action's own 10s default, guarding a button that only
    // renders once onboarding has settled. 52ms to 5947ms at four workers.
    await signInButton.click({ timeout: 20_000 });
  }

  await enterSecret(page, secret ?? (await getDevDriveSecret(page)));
  await expect(settings).toBeVisible({ timeout: 20000 });
  // The settings link appears from the signed-in layout, which can render
  // before the agent is actually in the store. Callers navigate straight
  // afterwards, and a page that loads without an agent reads its drive
  // unauthenticated, never adopts one, and so never gets a presence manager
  // — the facepile assertions in `presence-follow` and `meetings` then fail
  // with no sign of why. Wait for the agent itself.
  await page.waitForFunction(() => !!window.store?.getAgent(), undefined, {
    timeout: 20000,
  });
}

/**
 * Quick dev setup: navigates to /app/dev-drive which creates a fresh agent +
 * drive on localhost:9883 and switches to it automatically.
 * Returns the agent secret so other pages/contexts can sign in as the same user.
 */
export async function devDrive(page: Page): Promise<string> {
  // The route sits on a splash until the drive exists; when it never does, the
  // timeout alone says nothing, so keep what the page printed to say why.
  const printed: string[] = [];

  const remember = (m: ConsoleMessage) => {
    if (['error', 'warning'].includes(m.type()))
      printed.push(`${m.type()}: ${m.text()}`.slice(0, 300));
  };

  page.on('console', remember);
  page.on('pageerror', e => printed.push(`pageerror: ${e}`.slice(0, 300)));

  await page.goto(`${FRONTEND_URL}/app/dev-drive`);

  try {
    await page.waitForURL(/(?:did(?:%3A|:)ad|atomic)(?:%3A|:)/, {
      timeout: 30000,
    });
  } catch (e) {
    const shown = await page
      .evaluate(() => document.body.innerText.slice(0, 300))
      .catch(() => '(page unreadable)');

    throw new Error(
      `devDrive never reached the drive: ${page.url()} shows ${JSON.stringify(shown)}; page printed ${JSON.stringify(printed.slice(-10))}`,
      { cause: e },
    );
  } finally {
    page.off('console', remember);
  }

  await expect(currentDriveTitle(page)).toBeVisible({ timeout: 15000 });

  const secret = await page.evaluate(() =>
    localStorage.getItem('atomic-test.dev-drive-secret'),
  );

  if (!secret) {
    throw new Error('devDrive: agent secret not found in localStorage');
  }

  return secret;
}

/**
 * Create a new drive, go to it, and set it as the current drive. Returns URL of
 * drive and its name
 */
export async function newDrive(page: Page) {
  // Create new drive to prevent polluting the main drive
  const driveTitle = `testdrive-${timestamp()}`;

  await expect(sideBarDriveSwitcher(page)).toBeVisible({ timeout: 15000 });

  await sideBarDriveSwitcher(page).click();
  const newDriveButton = page.getByTestId('menu-item-new-drive');
  await expect(newDriveButton).toBeVisible({ timeout: 10000 });
  await newDriveButton.click();
  await waitForCurrentDialog(page);

  const dialog = currentDialog(page);
  await dialog
    .getByRole('button', { name: 'Create a blank drive', exact: true })
    .click();
  await dialog.getByLabel('Drive name').fill(driveTitle);

  const createButton = dialog.locator('button', { hasText: 'Create' });
  await createButton.waitFor({ state: 'attached' });
  await expect(createButton).toBeEnabled();
  await createButton.click();

  // Wait for the URL to change to did:ad: (newly created drive)
  await page.waitForURL(/(?:did(?:%3A|:)ad|atomic)(?:%3A|:)/, {
    timeout: 30000,
  });
  // The URL changes when the route does, but the header still shows the drive
  // you came FROM until the new one's resource has loaded and its name has
  // arrived, so this waits on a fetch and not on a render. The 10s default does
  // not cover it: measured at four workers on 24 September 2026, the slowest
  // few per run were 9.3s, 11.1s and 8.5s, so the budget was already being
  // blown. Being marginal rather than short is why it presents as a flake,
  // `saved-drives.spec.ts:81` red 4 of 10, reporting the title of the previous
  // drive rather than a missing one. 30s, matching the `waitForURL` above it.
  await expect(currentDriveTitle(page)).toHaveText(driveTitle, {
    timeout: 30_000,
  });
  const driveURL = await getCurrentSubject(page);
  expect(driveURL).toBeTruthy();

  return { driveURL: driveURL as string, driveTitle };
}

export async function makeDrivePublic(page: Page) {
  await currentDriveTitle(page).click();
  await page.click(contextMenu);
  await page.getByRole('menuitem', { name: 'Share', exact: true }).click();

  const dialog = page.locator('dialog[open]');
  const publicAccess = dialog.locator('[data-test="share-public"]');
  const profileStep = dialog.getByRole('button', {
    name: 'Save and continue',
    exact: true,
  });

  // A first Share starts with the optional profile step.
  await expect(publicAccess.or(profileStep)).toBeVisible({ timeout: 15000 });

  if (await profileStep.isVisible()) {
    await dialog.getByLabel('Full name', { exact: true }).fill('Drive Owner');
    await profileStep.click();
  }

  const read = publicAccess.getByRole('radio', { name: 'Read', exact: true });
  await expect(
    publicAccess.getByRole('radio', { name: 'Off', exact: true }),
    'The drive was public from the start',
  ).toBeChecked();
  // The dialog saves each change at once: no Save button.
  await read.check();
  await expect(read).toBeChecked({ timeout: 15000 });
  await dialog.getByRole('button', { name: 'Done', exact: true }).click();
  await expect(dialog).toHaveCount(0);
}

export async function openSubject(page: Page, subject: string) {
  // Navigate via the SPA's /app/show route instead of typing into the old
  // address bar (which no longer exists — replaced by the search overlay,
  // and the overlay only resolves indexed resources, not arbitrary URLs).
  await page.goto(
    `${FRONTEND_URL}/app/show?subject=${encodeURIComponent(subject)}`,
  );
  // Default 5s actionTimeout is too tight under dagger CI: a second-context
  // openSubject has to bootstrap WASM, open a WS, authenticate, and fetch
  // the resource before `main[about=...]` lands. Multi-context tests
  // (authorization invite, multi-user documents) saw routine 10s+ waits.
  await expect(page.locator(`main[about="${subject}"]`).first()).toBeVisible({
    timeout: 20000,
  });
}

export async function getCurrentSubject(page: Page): Promise<string> {
  const selector = await page.waitForSelector('main[about]');

  const about = await selector.getAttribute('about');

  if (!about) {
    throw new Error('No subject found (no `main[about]` found)');
  }

  return about;
}

/** Waits until a commit for main resource is processed */
export async function waitForCommitOnCurrentResource(
  page: Page,
  match?: { set?: Record<string, unknown> },
) {
  const currentSubject = await getCurrentSubject(page);
  const startedAt = Date.now();

  const httpMatch = page.waitForResponse(async response => {
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
        // Same caveat as waitForCommit: modern Loro-based commits don't
        // populate `set` on the wire. If a loroUpdate is present we accept
        // the commit instead of trying to decode individual props.
        const hasLoroUpdate =
          'https://atomicdata.dev/properties/loroUpdate' in result;

        if (!hasLoroUpdate) {
          const set = result['https://atomicdata.dev/properties/set'];

          for (const key in match.set) {
            if (set[key] !== match.set[key]) {
              return false;
            }
          }
        }
      }
    } catch (e) {
      return false;
    }

    return true;
  });

  const wsMatch = page.waitForFunction(
    ({ targetSubject, sinceMs, matchSet, setProp, subjectProp, loroProp }) => {
      const log =
        (
          window as unknown as {
            __atomicCommitLog?: Array<{
              sentAt: number;
              subject: string;
              commit: Record<string, unknown>;
            }>;
          }
        ).__atomicCommitLog ?? [];

      return log.some(entry => {
        if (entry.sentAt < sinceMs) return false;
        const commit = entry.commit;
        if (commit[subjectProp] !== targetSubject) return false;
        if (!matchSet) return true;
        const hasLoroUpdate = loroProp in commit;
        if (hasLoroUpdate) return true;
        const setMap = commit[setProp] as Record<string, unknown> | undefined;
        if (!setMap) return false;

        return Object.keys(matchSet).every(
          key => setMap[key] === matchSet[key],
        );
      });
    },
    {
      targetSubject: currentSubject,
      sinceMs: startedAt,
      matchSet: (match?.set ?? null) as Record<string, unknown> | null,
      setProp: PROPERTIES.set,
      subjectProp: 'https://atomicdata.dev/properties/subject',
      loroProp: PROPERTIES.loroUpdate,
    },
    { polling: 100, timeout: 15000 },
  );

  await Promise.race([httpMatch, wsMatch]);
  // The commit is on the wire; wait until this resource is no longer saving
  // so callers that read the store or UI are not racing the apply.
  await page.waitForFunction(
    subject => {
      const r = window.store?.resources.get(subject);

      return !!r && !r.loading && !r.isSaving;
    },
    currentSubject,
    { timeout: 15_000 },
  );
}

/**
 * Waits until the server's search index can answer for `query`.
 *
 * Polls `store.search` until it returns at least `expected` hits. A fixed
 * sleep (the old `REBUILD_INDEX_TIME` fallback) is not a signal: on a loaded
 * server Tantivy may still be behind, and the search then returns fewer hits
 * than the test is about to select.
 *
 * `expected` matters when a test indexes into the results. For a filtered
 * picker (`filters: {isA: <class>}`), use {@link waitForClassInstanceSearchable}
 * instead — those searches skip the local index.
 */
export async function waitForSearchIndex(
  page: Page,
  query: string,
  expected = 1,
): Promise<void> {
  await expect
    .poll(
      () =>
        page.evaluate(
          async args => {
            try {
              const hits = await window.store.search(args.query, {
                parents: window.store.getDrive(),
                include: false,
                limit: 30,
              });

              return Array.isArray(hits) ? hits.length : 0;
            } catch {
              return 0;
            }
          },
          { query },
        ),
      { timeout: 30_000, intervals: [500] },
    )
    .toBeGreaterThanOrEqual(expected);
}

/**
 * Wait until `/app/new` will actually offer `shortname` as a class button.
 *
 * A plain text search for the class is the wrong signal, even though it is the
 * obvious one: `OntologySections` searches for ONTOLOGIES
 * (`filters: {isA: ontology}`, empty query, scoped to the drive) and renders
 * each one's `classes`. So the Class resource can be indexed and findable while
 * the page still shows nothing, because the ontology carrying it has not come
 * back from that filtered query yet. Filtered searches skip the local index and
 * go to Tantivy, so this polls the same server path the page depends on.
 *
 * (`allowEmptyQuery` is a `useServerSearch` gate on whether to call the store
 * at all for an empty query — calling `store.search('')` here is the same
 * thing, so it has no counterpart in `SearchOpts`.)
 */
export async function waitForOntologyClass(
  page: Page,
  shortname: string,
): Promise<void> {
  await expect
    .poll(
      () =>
        page.evaluate(
          async args => {
            try {
              const ontologies = await window.store.search('', {
                filters: { [args.isA]: args.ontologyClass },
                parents: window.store.getDrive(),
                limit: 100,
              });

              for (const subject of ontologies) {
                const ontology = await window.store.getResource(subject);
                const classes = (ontology.get(args.classesProp) ??
                  []) as string[];

                for (const classSubject of classes) {
                  const klass = await window.store.getResource(classSubject);

                  if (klass.get(args.shortnameProp) === args.shortname) {
                    return true;
                  }
                }
              }

              return false;
            } catch {
              return false;
            }
          },
          {
            shortname,
            isA: 'https://atomicdata.dev/properties/isA',
            ontologyClass: 'https://atomicdata.dev/class/ontology',
            classesProp: 'https://atomicdata.dev/properties/classes',
            shortnameProp: 'https://atomicdata.dev/properties/shortname',
          },
        ),
      { timeout: 30_000, intervals: [500] },
    )
    .toBe(true);
}

/**
 * Wait until a SearchBox filtered to `classShortname` will actually return
 * `title` for `query`.
 *
 * `waitForSearchIndex` is not this signal. It polls an UNFILTERED
 * `store.search`, which merges in local-index hits; the SearchBox passes
 * `filters: {isA: <class>}` (SearchBoxWindow's ServerSearchUnit), and a
 * filtered search skips the local index entirely and waits on Tantivy. So the
 * unfiltered call goes green while the picker still shows only its "Create"
 * row — which is what times out, on a loaded runner, inside `pickOption`.
 *
 * The class subject is resolved by shortname rather than threaded through the
 * test, because these specs build their ontology through the UI and never hold
 * the subject.
 */
export async function waitForClassInstanceSearchable(
  page: Page,
  classShortname: string,
  query: string,
  title: string,
): Promise<void> {
  await expect
    .poll(
      () =>
        page.evaluate(
          async args => {
            try {
              const drive = window.store.getDrive();
              const ontologies = await window.store.search('', {
                filters: { [args.isA]: args.ontologyClass },
                parents: drive,
                limit: 100,
              });

              let classSubject: string | undefined;

              for (const subject of ontologies) {
                const ontology = await window.store.getResource(subject);
                const classes = (ontology.get(args.classesProp) ??
                  []) as string[];

                for (const candidate of classes) {
                  const klass = await window.store.getResource(candidate);

                  if (klass.get(args.shortnameProp) === args.classShortname) {
                    classSubject = candidate;
                    break;
                  }
                }

                if (classSubject) break;
              }

              if (!classSubject) return false;

              const hits = await window.store.search(args.query, {
                filters: { [args.isA]: classSubject },
                parents: drive,
                limit: 30,
              });

              for (const hit of hits) {
                const resource = await window.store.getResource(hit);

                if (resource.get(args.nameProp) === args.title) return true;
              }

              return false;
            } catch {
              return false;
            }
          },
          {
            classShortname,
            query,
            title,
            isA: 'https://atomicdata.dev/properties/isA',
            ontologyClass: 'https://atomicdata.dev/class/ontology',
            classesProp: 'https://atomicdata.dev/properties/classes',
            shortnameProp: 'https://atomicdata.dev/properties/shortname',
            nameProp: 'https://atomicdata.dev/properties/name',
          },
        ),
      { timeout: 30_000, intervals: [500] },
    )
    .toBe(true);
}

export async function openAgentPage(page: Page) {
  await page.goto(`${FRONTEND_URL}/app/agent`);
}

/** Opens the users' profile, sets a username, saves, reloads and verifies the change persisted. */
export async function editProfileAndCommit(page: Page) {
  await openAgentPage(page);
  // Was "Edit profile". AgentProfileHeader now renders name and avatar inline
  // on the settings page, so the button that leaves for the full edit form
  // says what is actually behind it. Same destination (`editURL`).
  const editButton = page.getByRole('button', { name: 'More profile fields' });
  await expect(editButton).toBeVisible();

  await editButton.click();
  await page.waitForURL(/\/app\/edit/);

  const nameInput = page.locator('[data-test="input-name"]');
  await expect(nameInput).toBeVisible({ timeout: 10000 });
  const username = `Test user edited at ${new Date().toLocaleDateString()}`;
  await nameInput.fill(username);
  await page.getByRole('button', { name: 'Save' }).click();
  await page.waitForURL(/\/app\/show/);
  await page.reload();
  await expect(page.locator(`text=${username}`).first()).toBeVisible({
    timeout: 10000,
  });
}

export async function fillSearchBox(
  page: Page | Locator,
  placeholder: string | RegExp,
  fillText: string,
  options: {
    nth?: number;
    container?: Locator;
    label?: string | RegExp;
  } = {},
) {
  const { nth, container, label } = options;
  const selector = container ?? page;

  // Many search inputs are directly visible; others are hidden behind a
  // button that must be clicked first (legacy pattern). Only click the
  // button if the input isn't already in view.
  const inputLocator = selector.getByPlaceholder(placeholder);
  const inputVisible = await inputLocator
    .first()
    .isVisible({ timeout: 500 })
    .catch(() => false);

  if (!inputVisible) {
    if (nth !== undefined) {
      await selector
        .getByRole('button', { name: label ?? placeholder })
        .nth(nth)
        .click();
    } else {
      await selector
        .getByRole('button', { name: label ?? placeholder })
        .click();
    }
  }

  await inputLocator.fill(fillText);

  return async (name: string) => {
    await selector.getByTestId('searchbox-results').getByText(name).click();
  };
}

/**
 * SearchBox placeholder is templated as `Search for a ${typeResource.title} or
 * enter a URL...`. The title can resolve to "property", but also to other
 * resource titles depending on store state — match the stable prefix/suffix
 * instead of pinning a specific title.
 */
export const SEARCHBOX_PROPERTY_PLACEHOLDER = /Search for a .+ or enter a URL/;

/** Create a new Resource in the current Drive.
 * Class can be an Class URL or a shortname available in the new page. */
/**
 * Click the sidebar's "New" and land on `/app/new`.
 *
 * Sidebar "New" navigates to /app/new?parentSubject=<parent> to preserve the
 * container context (see QuickCreateRow). Match pathname only.
 *
 * Retry the click AND the navigation as a unit: the button can be clicked
 * before its handler is attached, and the click is then simply swallowed — the
 * app stays where it was, and no amount of waiting on a navigation that was
 * never started will produce one. Seen in CI as an assertion timing out with
 * the URL still on `/app/show`, or as the next click waiting out its budget on
 * a class button that was never going to render.
 *
 * Exported because every caller needs the retry, not just `newResource`.
 * Clicking and then asserting the URL separately looks equivalent and is not:
 * it waits for a navigation that the swallowed click never began.
 */
export async function openNewResourcePage(page: Page) {
  await expect(async () => {
    await sidebarNewResourceButton(page).click();
    await expect(page).toHaveURL(/\/app\/new(\?|$)/, { timeout: 3_000 });
  }).toPass({ timeout: 20_000 });
}

/** Create a complete starter from the catalog, preserving the current parent. */
export async function createFromCatalog(page: Page, title: string) {
  const parent = new URL(page.url()).searchParams.get('subject');
  await waitForSynced(page);
  const url = new URL('/app/new', page.url());
  if (parent) url.searchParams.set('parentSubject', parent);
  await page.goto(url.href);
  await page
    .getByRole('searchbox', { name: 'Search templates and resource types' })
    .fill(title);

  // `openCreation` (NewRoute.tsx:205) navigates only after the template has
  // been built, and its catch calls `store.notifyError` and navigates nowhere.
  // So a creation that failed and a creation still running leave the page on
  // exactly the same URL, and the wait below reports them identically: a wall
  // of identical polls and a timeout naming itself. `apps:93` and `apps:182`
  // both flaked here on develop run 4334 with 90 unchanged polls over the full
  // 45s and nothing in the log to say which of the two had happened.
  //
  // `errorHandler` calls `console.error` before it raises the toast, and an
  // unhandled rejection reaches it too, so the page's own console is the one
  // place that can tell them apart. Collect it for the length of this step and
  // report it only if the wait fails, leaving Playwright's call log intact.
  const complaints: string[] = [];

  const onConsole = (message: ConsoleMessage) => {
    if (message.type() === 'error') complaints.push(message.text());
  };

  const onPageError = (error: Error) => complaints.push(error.message);
  page.on('console', onConsole);
  page.on('pageerror', onPageError);

  try {
    await page
      .getByRole('region', { name: 'Start blank' })
      .getByRole('button', { name: title, exact: true })
      .click();
    // 90s, not the 45s this used to be. Develop run 4547 failed `apps:180`
    // here on all three attempts with the page still on `/app/new` and the
    // console silent, which is the branch below saying the creation had not
    // finished rather than that it threw — the distinction `62871ba` added
    // this diagnostic for, answering the question it was left open on.
    //
    // Measured since, click to leaving `/app/new`, at four workers over 108
    // samples across two mixes: 9.6s min, 16.6s median, 25.2s max, and 29.7s
    // in the 22 September run of the same measurement. So 45s was already
    // two thirds spent on this box, and Mancave now runs four CI runners at
    // once: 4547's shards took 31 to 38 minutes against 19.1 on 4512.
    //
    // App is what this budget is really for. The other catalog titles are far
    // cheaper — Plugin 9.9s and Website 4.8s worst — so they pay nothing for
    // the headroom. An App builds its drive's plugin schema first, nineteen
    // properties and classes as separate signed commits, which is the same
    // cost `newPlugin` documents and is a product finding of its own rather
    // than something a test can shorten.
    await expect(page).not.toHaveURL(/\/app\/new(\?|$)/, { timeout: 90_000 });
  } catch (waitFailed) {
    console.error(
      complaints.length > 0
        ? `Creating a ${title} from the catalog left the page on /app/new, and the page reported: ${complaints.join(' | ')}`
        : `Creating a ${title} from the catalog left the page on /app/new, and the page reported no error, so the creation had not finished within the budget.`,
    );
    throw waitFailed;
  } finally {
    page.off('console', onConsole);
    page.off('pageerror', onPageError);
  }
}

export async function newResource(klass: string, page: Page) {
  await openNewResourcePage(page);

  const waitForResourceForm = async () => {
    await Promise.any([
      page.waitForURL(url => !url.pathname.endsWith('/app/new'), {
        timeout: 20000,
      }),
      page
        .locator('[data-test="input-shortname"]')
        .first()
        .waitFor({ state: 'visible', timeout: 20000 }),
      page.getByLabel('Shortname').first().waitFor({
        state: 'visible',
        timeout: 20000,
      }),
      page
        .getByRole('button', { name: 'Save' })
        .first()
        .waitFor({ state: 'visible', timeout: 20000 }),
    ]);
  };

  if (klass.startsWith('https://')) {
    await page.getByText('Choose a class by URL', { exact: true }).click();
    await fillSearchBox(page, 'Search for a class or enter a URL', klass);
    await page.keyboard.press('Enter');
    await waitForResourceForm();
  } else {
    // The class button for a non-built-in class only renders once that class
    // is in the search index (the new-resource page lists classes via the
    // search API). For a freshly-created custom class under suite-wide load the
    // index flush + render can exceed the default 10s click auto-wait, so the
    // click times out. Gate on the button's visibility explicitly — its
    // appearance IS the "class is searchable" readiness signal — with a budget
    // that tolerates a slow index flush instead of a blind pre-sleep.
    const label =
      (
        {
          'document-v2': 'Document',
          chatroom: 'Chat room',
          'ai-chat': 'AI chat',
        } as Record<string, string>
      )[klass] ?? klass;
    const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    // Scoped to the page's `section`s, which is where the class buttons live:
    // "Start blank" and "Your resource types". The assistant's suggestion row
    // above them is not a section, and #1577 gave it buttons that carry the
    // same words, since "Dashboard" and "Custom table" are each both a
    // suggestion and a class. Unscoped, the name then matches two buttons and
    // Playwright refuses to touch either.
    const classButton = page
      .getByRole('main')
      .locator('section')
      .getByRole('button', {
        name: new RegExp(`^${escaped}$`, 'i'),
      });
    await classButton.waitFor({ state: 'visible', timeout: 30000 });
    await classButton.click();
    // Wait for any of: URL leaves /app/new (basic-instance handlers), a
    // dialog opens (bookmark/table), or the in-place NewFormFullPage shows
    // up (custom user classes — `/app/new?classSubject=...` keeps the path
    // but renders the resource form).
    await Promise.any([
      page.waitForURL(url => !url.pathname.endsWith('/app/new'), {
        timeout: 10000,
      }),
      page
        .locator('dialog[open]')
        .waitFor({ state: 'visible', timeout: 10000 }),
      page
        .getByRole('button', { name: 'Save' })
        .first()
        .waitFor({ state: 'visible', timeout: 10000 }),
    ]);
  }
}

/**
 * Waits out a table build started from the New Table dialog.
 *
 * A template is a few dozen commits, and the dialog carries that wait: the
 * Create button sits in its "Creating table…" state until the build resolves,
 * and only then does the dialog close and the app navigate to the new table.
 * Asserting on the view the table opens in — a grid, a board, a timer — right
 * after clicking Create therefore races the build, not the render. Under load
 * the build is the long leg, so the assertion fails with the view "not found"
 * while the dialog is still visibly building, which reads like a broken view.
 *
 * The dialog closing IS the build's completion signal, so wait for that first
 * and let the view assertions keep their ordinary budget.
 */
export async function waitForTableBuild(page: Page, timeoutMs = 60_000) {
  const dialog = currentDialog(page);

  try {
    await dialog.waitFor({ state: 'hidden', timeout: timeoutMs });
  } catch (cause) {
    // A build that throws leaves the dialog up with the reason inline. Say
    // what it said, rather than "timed out waiting for hidden".
    const footer = await dialog
      .locator('footer')
      .textContent({ timeout: 1_000 })
      .catch(() => '');
    throw new Error(
      `The New Table dialog was still building after ${timeoutMs}ms: ${footer?.trim()}`,
      { cause },
    );
  }
}

/**
 * Creates a table through the New Table dialog and returns once it exists.
 *
 * `template` names the card to start from — omit it for a blank table. Omit
 * `name` to keep the one the dialog pre-fills, which is the template's own
 * title. The caller is left on the new table's page, on whichever view the
 * template defaults to, and still has to wait for that view: a board, a grid,
 * a timer.
 */
export async function createTableFromDialog(
  page: Page,
  { template, name }: { template?: RegExp; name?: string },
) {
  await newResource('table', page);

  if (template) {
    await currentDialog(page).getByRole('button', { name: template }).click();
  }

  if (name !== undefined) {
    await page.getByPlaceholder('New Table').fill(name);
  }

  await currentDialog(page)
    .getByRole('button', { name: 'Create', exact: true })
    .click();
  await waitForTableBuild(page);
}

/**
 * Opens a totals footer cell's menu and picks one of its options — an
 * aggregate, a second totals row, a breakdown.
 *
 * Two things move under the pointer here: the menu plays an entrance
 * transition (opacity + scale), and the totals footer re-renders whenever an
 * aggregate recomputes — which takes the menu with it. A single click races
 * both and fails as "element is not stable" or "element was detached".
 *
 * Picking an option closes the menu, so retry while it is gone: a click that
 * took effect ends the loop, one that lost the race gets a fresh menu.
 */
/**
 * Reloads, and waits until the app is talking to the server again.
 *
 * Which view a table opens in is configuration on its View resource, fetched
 * after the page boots. Until that lands `normalizeViewKind(undefined)` falls
 * back to `table`, so the marker for a board / calendar / timer is simply
 * absent, and any filter the view carries has not been applied yet. Asserting
 * on either straight after `reload()` races that fetch rather than testing the
 * view — on a contended CI server, well past the default 10s budget.
 *
 * Callers still need a budget of their own on the view marker: being
 * reconnected is when the fetch can start, not when it has finished.
 *
 * Before reloading, wait until the outbox is empty and OPFS has flushed.
 * Kanban/calendar persist tests previously reloaded off a UI preview while
 * `save()` was still in flight, so the post-reload assertion saw the old
 * grouping. `waitForSynced` is a no-op when nothing is dirty.
 */
export async function reloadReconnected(page: Page) {
  await waitForSynced(page);
  await waitForClientDbFlush(page);
  await page.reload({ waitUntil: 'domcontentloaded' });
  await waitForServerConnected(page);
}

/**
 * Wait until the WebSocket is up.
 */
export async function waitForServerConnected(page: Page, timeoutMs = 30_000) {
  await page.waitForFunction(
    () => window.store?.getSyncStatus().serverConnected === true,
    undefined,
    { timeout: timeoutMs },
  );
}

/**
 * Wait until the WASM ClientDb has finished init + seed.
 */
export async function waitForClientDbReady(page: Page, timeoutMs = 30_000) {
  await page.waitForFunction(
    () => window.store?.getClientDb()?.isReady === true,
    undefined,
    { timeout: timeoutMs },
  );
}

/**
 * Persist OPFS writes that commit with `Durability::None`.
 *
 * Reloading, going offline, or turning ClientDb off before this tick rolls
 * those writes back. `flush()` is the durable signal; a sleep is not.
 * No-op (and not an error) when ClientDb is disabled — there is nothing to
 * flush.
 */
export async function waitForClientDbFlush(
  page: Page,
  opts: { required?: boolean } = {},
) {
  await page.evaluate(async required => {
    const db = window.store?.getClientDb();

    if (!db) {
      if (required) {
        throw new Error('ClientDb missing when asking for a flush');
      }

      return;
    }

    await db.flush();
  }, opts.required === true);
}

/**
 * Wait until nothing local is still waiting to reach the server, and what
 * reached it is also on disk here.
 *
 * Covers the outbox, in-flight `save()`s, and UI debounce timers
 * (`startScheduledSave`), then the ClientDb flush. `pendingDirtyCount === 0`
 * alone means the server has the edit; the OPFS write that mirrors it is
 * queued on a worker that a navigation destroys ("ClientDb worker
 * destroyed" in CI logs), and a folder page loaded from OPFS then lacks the
 * child that was just made. On a loaded runner the gap between ack and
 * write is what made `folder @smoke` flap.
 */
export async function waitForSynced(page: Page, timeoutMs = 30_000) {
  try {
    await page.waitForFunction(
      () => {
        const status = window.store?.getSyncStatus();

        return !!status && status.pendingDirtyCount === 0;
      },
      undefined,
      { timeout: timeoutMs },
    );
    await waitForClientDbFlush(page);
  } catch (cause) {
    const diag = await page
      .evaluate(() => {
        const store = window.store;
        const status = store?.getSyncStatus();
        const entries =
          store?.outbox
            ?.pending?.()
            .map(
              (entry: {
                subject: string;
                enqueuedAt: number;
                signedGenesis?: unknown;
                lastAttemptError?: unknown;
                baseVersion?: string;
              }) => ({
                subject: entry.subject,
                enqueuedAt: entry.enqueuedAt,
                hasSignedGenesis: !!entry.signedGenesis,
                lastAttemptError: entry.lastAttemptError,
                baseVersion: entry.baseVersion,
                saveCursor: store?.resources
                  .get(entry.subject)
                  ?.getEncodedSaveCursor(),
                hasUnsavedChanges: store?.resources
                  .get(entry.subject)
                  ?.hasUnsavedChanges(),
              }),
            ) ?? [];

        // `pendingDirtyCount` is a sum:
        //
        //     outbox.size - blockedCount + inFlightSaves + _scheduledSaves
        //
        // so a timeout with an empty outbox says only that one of the other
        // two terms is stuck, and the sum cannot say which. Develop run 4596
        // (25 September) timed out here with `entries: []`, `blockedCount: 0`
        // and `pendingDirtyCount: 1`, and there was nothing in the message to
        // tell a save that never settled from a debounce slot that was never
        // balanced. Split it, so the next one names its own cause.
        const savingSubjects = [...(store?.resources.values() ?? [])]
          .filter(resource => resource.isSaving)
          .map(resource => resource.subject);
        const outboxSize = store?.outbox?.size ?? 0;
        const blocked = status?.blockedCount ?? 0;
        const breakdown = {
          outboxSize,
          blocked,
          savingSubjects,
          // The store does not expose the debounce counter, so take it as what
          // the other terms cannot account for.
          scheduledSaves:
            (status?.pendingDirtyCount ?? 0) -
            outboxSize +
            blocked -
            savingSubjects.length,
        };

        return { status, breakdown, entries };
      })
      .catch(() => undefined);
    throw new Error(
      `waitForSynced timed out. Outbox diagnostics: ${JSON.stringify(diag)}`,
      { cause },
    );
  }
}

/**
 * Wait until the current drive has finished its post-load handshake.
 *
 * Collection queries that fire during bootstrap have either already gone
 * out or will go out as part of rendering the settled UI — so this is the
 * point at which "no more /query traffic" assertions become meaningful.
 * When ClientDb is disabled, readiness is just the WS + a finished drive
 * sync (`clientDbAttached` is false).
 */
export async function waitForDriveSettled(page: Page, timeoutMs = 30_000) {
  await page.waitForFunction(
    () => {
      const s = window.store?.getSyncStatus();

      if (!s) {
        return false;
      }

      const dbOk = s.clientDbAttached ? s.clientDbReady : true;

      return (
        s.serverConnected &&
        !s.syncInProgress &&
        s.pendingDirtyCount === 0 &&
        dbOk &&
        !!s.lastDriveSync
      );
    },
    undefined,
    { timeout: timeoutMs },
  );
}

/**
 * Wait until the table grid has mounted a data row.
 *
 * The grid element can paint before the collection's first page lands, and
 * a timer / quick-add that creates a row in that window persists it without
 * rendering it. The trailing placeholder (`aria-rowindex="2"`) is the
 * collection's "I have rows to show" signal — including the empty table.
 */
export async function waitForGridMounted(page: Page, timeoutMs = 30_000) {
  await expect(page.getByRole('grid')).toBeVisible({ timeout: timeoutMs });
  // The empty entry row renders before the collection has answered, so a
  // visible row no longer means the data (and the ClientDb queue in front of
  // it) has settled. The grid says so itself: `aria-busy` while loading.
  // Treat anything other than `true` as settled — React/omitted `false` both
  // mean not busy, and `[aria-busy="false"]` misses the omitted case.
  await expect(page.locator('[role="grid"][aria-busy="true"]')).toHaveCount(0, {
    timeout: timeoutMs,
  });
  await expect(page.locator('[aria-rowindex="2"]')).toBeVisible({
    timeout: timeoutMs,
  });
}

/**
 * Wait until the grid will accept keyboard input.
 *
 * TableEditor binds cell handlers after the first render. A click in that
 * window leaves focus on the title, and keystrokes never create a row.
 * {@link focusCell} is the observable precondition.
 */
export async function waitForGridInteractive(page: Page) {
  await waitForGridMounted(page);
  await focusCell(
    page,
    page.locator('[aria-rowindex="2"] > [aria-colindex="2"]'),
  );
}

/**
 * Press Enter in the grid and wait until a cell editor is focused.
 *
 * In Visual mode this enters edit; in Edit mode it moves to the next row
 * and stays in edit. Either way the signal is the same: an `<input>`
 * inside the grid has focus.
 */
export async function enterGridEdit(page: Page) {
  await page.keyboard.press('Enter');
  await expect(page.locator('[role="grid"] input').first()).toBeFocused({
    timeout: 15_000,
  });
}

/**
 * Type into the focused grid cell editor and wait until the value stuck.
 *
 * Keystrokes that land before the editor mounts are dropped, and Enter
 * on the next row then commits an empty cell. The input's value is the
 * signal that React has the text.
 */
export async function typeInActiveGridCell(page: Page, value: string) {
  const input = page.locator('[role="grid"] input').first();
  await expect(input).toBeFocused({ timeout: 15_000 });
  await input.fill(value);
  await expect(input).toHaveValue(value);
}

/**
 * Tab out of the current grid cell and wait until focus moved.
 *
 * The next cell's editor mounts asynchronously; typing before that
 * writes into the previous cell or into the title.
 */
export async function tabToNextGridCell(page: Page) {
  const from = await page.evaluate(
    () =>
      document.activeElement
        ?.closest('[aria-colindex]')
        ?.getAttribute('aria-colindex') ?? null,
  );

  await page.keyboard.press('Tab');
  await expect
    .poll(
      () =>
        page.evaluate(
          () =>
            document.activeElement
              ?.closest('[aria-colindex]')
              ?.getAttribute('aria-colindex') ?? null,
        ),
      { timeout: 15_000 },
    )
    .not.toBe(from);
}

/**
 * Put `value` in one grid cell, addressed by row and column index.
 *
 * Clicks until the grid takes focus, opens the editor if needed, fills,
 * Tabs to commit (Escape would revert), and waits until the cell shows
 * `match` (defaults to `value`). Retries the whole sequence when the
 * grid remounts the cell under the pointer.
 */
export async function setGridCell(
  page: Page,
  rowIndex: number,
  columnIndex: number,
  value: string,
  opts: { match?: string | RegExp } = {},
) {
  const cell = page.locator(
    `[aria-rowindex="${rowIndex}"] > [aria-colindex="${columnIndex}"]`,
  );

  await expect(async () => {
    await cell.click();
    const input = cell.locator('input');

    if ((await input.count()) === 0) {
      await expect(cell).toBeFocused({ timeout: 2_000 });
      await page.keyboard.press('Enter');
    }

    await expect(input).toBeVisible({ timeout: 2_000 });
    await fillGridInput(input, value);
    await page.keyboard.press('Tab');
    await page.keyboard.press('Escape');

    if (opts.match instanceof RegExp) {
      await expect(cell).toContainText(opts.match, { timeout: 3_000 });
    } else {
      await expect(cell).toHaveText(opts.match ?? value, { timeout: 3_000 });
    }
  }).toPass({ timeout: 30_000 });
}

/**
 * Fill a grid editor. Native `type="date"` inputs reject `fill("15012026")`
 * (`Malformed value`); they want ISO. The suite types ddMMyyyy because it
 * runs in `en-GB` — convert that, then `fill` the ISO form.
 */
async function fillGridInput(input: Locator, value: string) {
  const type = await input.getAttribute('type');

  if (type === 'date') {
    const iso = ddmmyyyyToIso(value);
    await input.fill(iso);

    return;
  }

  await input.fill(value);
}

/** `15012026` / `2026-01-15` → `2026-01-15`. Other strings pass through. */
function ddmmyyyyToIso(value: string): string {
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return value;
  }

  const digits = value.replace(/\D/g, '');

  if (digits.length === 8) {
    return `${digits.slice(4)}-${digits.slice(2, 4)}-${digits.slice(0, 2)}`;
  }

  return value;
}

/**
 * Waits until every row typed into a grid is a real member of its table.
 *
 * A new row is a draft held purely locally (its genesis is unsigned) until
 * its materialize timer fires — no commit, no collection membership. Anything
 * computed OVER that collection therefore cannot see it yet: a total renders
 * an em-dash, a filter does not match it, a chart omits it. Asserting on such
 * a value before this point is asserting about a table that does not contain
 * the row yet, and it fails as a wrong number rather than as a missing row.
 *
 * Also waits for the outbox, since a materialized row still has to reach the
 * server before anything server-side (search, a reload) will agree.
 */
export async function waitForRowsMaterialized(page: Page, timeoutMs = 15_000) {
  await page.waitForFunction(
    () => {
      const resources = Array.from(window.store.resources?.values?.() ?? []);
      // What creating a draft row writes; anything more is a row someone
      // typed into.
      const seeded = new Set([
        'https://atomicdata.dev/properties/isA',
        'https://atomicdata.dev/properties/parent',
        'https://atomicdata.dev/properties/drive',
        'https://atomicdata.dev/properties/genesis',
      ]);
      const stillVirtual = resources.some(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (r: any) =>
          r.new &&
          /^(did:ad|atomic):/.test(String(r.subject)) &&
          (r.getEntries?.() ?? []).some(
            ([property]: [string]) => !seeded.has(property),
          ),
      );

      return (
        !stillVirtual && window.store.getSyncStatus().pendingDirtyCount === 0
      );
    },
    undefined,
    { timeout: timeoutMs },
  );

  // Acked is not queryable. The ClientDb writes each row — and rebuilds the
  // index inside that write — on a flush tick, so a query issued in between
  // answers from an index that is missing rows the grid already shows. The
  // worker handles its messages in order, so awaiting a flush means everything
  // queued ahead of it has landed. Without this a filter drops a matching row,
  // and a total reads an em-dash because the value it sums is not there yet.
  await waitForClientDbFlush(page);
}

/**
 * Reloads a table page once everything typed into it would survive the reload.
 *
 * Waiting on the outbox alone is not enough: a row typed into the grid stays
 * virtual until it is deselected or edit mode is left, so `pendingDirtyCount`
 * can legitimately read zero while a row exists only in this tab — and the
 * reload then drops it. {@link waitForRowsMaterialized} covers both halves.
 */
export async function reloadGrid(page: Page) {
  // Includes the OPFS flush: those writes commit with `Durability::None`, so
  // reloading inside the worker's 1s tick rolls them back and the local db
  // answers post-reload queries with the pre-edit copy.
  await waitForRowsMaterialized(page);
  await page.reload();
  await waitForGridMounted(page);
}

/**
 * Clicks a grid cell and confirms the grid actually took input focus.
 *
 * Typing goes wherever focus is, and after a table is created focus is on the
 * title input — not the grid. A click that lands before the grid is listening
 * leaves it there, so the keystrokes go into the title and the row is never
 * created. Nothing about the page looks wrong afterwards: the cells are
 * present and empty, and the failure surfaces later as a total with nothing
 * to add or a row missing after a reload.
 *
 * Wait for this cell to own focus. Focus elsewhere in the grid is insufficient
 * and a forced click can hit its old position while layout is still moving.
 */
export async function focusCell(page: Page, cell: Locator) {
  await cell.click();
  await expect
    .poll(
      () =>
        cell.evaluate(element => {
          const target = element.closest('[aria-colindex]');

          return !!target && target.contains(document.activeElement);
        }),
      { message: 'click did not focus the requested cell', timeout: 15_000 },
    )
    .toBe(true);
}

/**
 * Opens the menu behind `trigger` and clicks `item` in it.
 *
 * Two things go wrong with a plain click-then-click. The dropdown mounts
 * `visibility: hidden` and reveals itself a frame after it has been
 * positioned, and a dismissed menu can linger in the DOM — so an unscoped
 * locator can resolve to a hidden item and wait out its whole budget on
 * something that will never appear. And the trigger TOGGLES its menu, so a
 * click landing while a previous menu is still closing closes this one
 * instead of opening it.
 *
 * Hence: scope to a visible instance, and retry the open as well as the pick.
 */
export async function pickFromMenu(trigger: Locator, item: Locator) {
  const visible = item.filter({ visible: true }).first();

  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      if (!(await visible.isVisible())) {
        await trigger.click();
        await visible.waitFor({ state: 'visible', timeout: 5_000 });
      }

      await visible.click({ timeout: 5_000 });

      return;
    } catch {
      // Fall through and try the whole open-and-pick again.
    }
  }

  // Bounded, so a menu that is genuinely dead still fails loudly.
  await trigger.click();
  await visible.click({ timeout: 5_000 });
}

/** {@link pickFromMenu} for a totals footer cell's aggregate menu. */
export async function pickTotal(page: Page, cell: Locator, option: string) {
  await pickFromMenu(cell, page.getByTestId(`menu-item-${option}`));
}

/** Opens a new browser page for multi-user testing */
export async function openNewSubjectWindow(
  browser: Browser,
  url: string,
  /** If set, sign in as this user */
  secret: string | undefined = undefined,
) {
  const context2 = await browser.newContext();
  const page = await context2.newPage();

  await page.goto(secret ? `${FRONTEND_URL}/app/welcome` : FRONTEND_URL);

  if (secret) {
    if (secret.length < 1) throw new Error('Secret must be provided');
    await signIn(page, secret);
  }

  // Frontend route URLs (e.g. invite links pointing at /app/invite) need to
  // be visited directly — wrapping them in /app/show?subject=... would treat
  // them as resources to fetch and the server has no such resource.
  if (url.includes('/app/')) {
    await page.goto(spaUrl(url));
  } else {
    await openSubject(page, url);
  }

  return page;
}

export async function openConfigureDrive(page: Page) {
  // Drive management lives on the User Settings page (/app/server redirects
  // there too, but go direct).
  await page.goto(`${FRONTEND_URL}/app/agent`);
  await expect(
    page.getByRole('heading', { name: 'User', exact: true }),
  ).toBeVisible({
    timeout: 10000,
  });
}

export async function changeDrive(
  subject: string,
  page: Page,
  validate: boolean = true,
) {
  try {
    const driveLink = page.getByTestId(sidebarDriveButtonId);
    await expect(driveLink).toBeVisible();
    await openConfigureDrive(page);
    // The input lives behind an "Open" disclosure now — the drives
    // section leads with the drive list and "New drive", and only reveals the
    // URL/DID field when asked. Without this click the field is not in the DOM
    // at all, which reads as a locator timeout rather than a hidden element.
    const openByUrlToggle = page.locator('[data-test="open-drive-by-url"]');

    if (await openByUrlToggle.isVisible({ timeout: 2000 }).catch(() => false)) {
      if ((await openByUrlToggle.getAttribute('aria-expanded')) !== 'true') {
        await openByUrlToggle.click();
      }
    }

    // The open-by-URL input starts empty on the User Settings page; the Open
    // button is disabled when the target equals the current drive.
    const currentDriveInput = page.getByTestId('drive-url-input');
    await currentDriveInput.fill(subject);

    const openButton = page.locator('[data-test="drive-url-save"]');

    if (await openButton.isDisabled()) {
      // Already on this drive.
      await page.keyboard.press('Escape');

      if (validate) {
        await expect(currentDriveTitle(page)).toBeVisible();
      }

      return;
    }

    await openButton.click();
  } catch (e) {
    console.error('Error in changeDrive:', e);
    throw e;
  }
}

export async function editTitle(title: string, page: Page) {
  const titleEl = editableTitle(page);

  // After resource creation, EditableTitle auto-enters edit mode (textbox).
  // Wait for that to appear. Don't short-circuit on H1 — the previous page's
  // title (e.g. "Cake Folder") can still be rendered as <h1> for a brief
  // window after a Click 'New Document' triggers SPA navigation. Eagerly
  // clicking it would activate the OLD page's title and rename the wrong
  // resource. Only fall back to the click-H1 path after waiting long enough
  // that the new page's textbox would have appeared if it was going to.
  try {
    await expect(titleEl).toHaveRole('textbox', { timeout: 5000 });
  } catch {
    // Pre-existing resource: title renders as <h1>. Click to enter edit mode.
    await titleEl.click();
    await expect(titleEl).toHaveRole('textbox');
  }

  // Watch for the commit BEFORE typing so we don't miss the response that
  // fires during the debounced save.
  const waiter = waitForCommitOnCurrentResource(page);
  // Select-all + type rather than fill: fill replaces the input value via
  // direct DOM mutation, but React's controlled input + useValue debounce
  // sometimes drops the change. Per-character type events keep onChange firing
  // on every keystroke and let the debounce settle naturally.
  await titleEl.focus();
  await page.keyboard.press(
    process.platform === 'darwin' ? 'Meta+a' : 'Control+a',
  );
  await titleEl.type(title);
  await page.keyboard.press('Enter');
  await waiter;
}

/**
 * Opens the account menu behind the user row at the bottom of the sidebar
 * (Profile, Notifications, Integrations, Sync, Feedback, About) and returns
 * it. Settings is not in it: that is the gear button beside the user row,
 * `sidebar-settings-button`.
 */
export async function openAccountMenu(page: Page): Promise<Locator> {
  const sidebar = page.getByTestId('sidebar');
  await sidebar.hover();
  await sidebar.getByTestId('account-menu-trigger').click();
  const menu = page.getByRole('menu');
  await expect(menu).toBeVisible();

  return menu;
}

/** Picks an item from the sidebar's account menu. */
export async function clickAccountMenuItem(page: Page, name: string) {
  const menu = await openAccountMenu(page);
  // Not `exact`: an item's trailing badge (Notifications' unread count) is
  // part of its accessible name.
  await menu.getByRole('menuitem', { name: new RegExp(`^${name}\\b`) }).click();
}

export async function clickSidebarItem(text: string, page: Page) {
  await page.getByTestId('sidebar').getByRole('link', { name: text }).click();
}

/** Click an item from the main, visible context menu */
export async function contextMenuClick(text: string, page: Page) {
  await page.click(contextMenu);
  // Wait for the menu item to actually render in the opened menu rather than
  // sleeping for the open animation. `.click()` auto-waits for actionability,
  // but an explicit visibility wait makes the readiness signal clear and
  // avoids racing the menu's mount.
  const item = page.getByTestId(`menu-item-${text}`);
  await item.waitFor({ state: 'visible' });
  await item.click();
}

/**
 * Open the Connections or Automations dialog of the table page on screen.
 * Both live in the table's context menu, which only lists them once the table
 * page has mounted. `timeout` covers opening the menu too, since whatever is
 * still in front of the page (a setup dialog, say) blocks that click.
 */
export async function openWorkspaceDialog(
  page: Page,
  section: 'connections' | 'automations',
  timeout?: number,
) {
  // A top-level dialog left over from an earlier step covers the table and
  // swallows this click: the GitHub setup dialog stays up, its button reading
  // "Connecting…", until the install settles. A bigger budget does work,
  // because Playwright retries until the dialog goes, but it makes the budget
  // the thing under test. Measured on develop at `2c581ff`, running this file
  // at four workers, the click cost 41.1s against the 45s it had, and 9.8s
  // unloaded against the 10s it had before that.
  //
  // So wait for the dialog to go, the way `waitForTableBuild` above does, and
  // let the clicks keep their ordinary budgets. A dialog that never closes now
  // says so, instead of arriving as a click that could not reach its target.
  await currentDialog(page).waitFor({ state: 'hidden', timeout });
  await page.click(contextMenu, { timeout });
  await page.getByTestId(`menu-item-${section}`).click({ timeout });
}

export const anyValue = Symbol('any');
type CommitFilter = {
  set?: Record<string, unknown | typeof anyValue>;
};

/**
 * Resolve when a commit matching `filter` lands on the server. Watches
 * BOTH transports so the helper survives the WS-first commit path:
 *
 * - HTTP `POST /commit` responses (fallback path, anonymous flows, multi-server)
 * - WS `COMMIT` frames captured by {@link installCommitWatcher} into
 *   `window.__atomicCommitLog`
 *
 * Whichever signal fires first wins. The promise resolves once a match
 * is found; rejecting is left to the surrounding `expect`/test timeout.
 */
export const waitForCommit = async (page: Page, filter?: CommitFilter) => {
  // Capture wall-clock at call-time so the WS matcher only resolves
  // on commits sent AFTER this point — matches `waitForResponse`'s
  // future-only semantics. Without this, pre-existing entries in
  // `__atomicCommitLog` would resolve the helper immediately.
  const since = Date.now();

  return Promise.any([
    waitForHttpCommit(page, filter),
    waitForWsCommit(page, filter, since),
  ]);
};

const waitForWsCommit = (
  page: Page,
  filter: CommitFilter | undefined,
  since: number,
) =>
  page.waitForFunction(
    ({ filterSet, isAProp, setProp, loroProp, commitClass, sinceMs }) => {
      const log =
        (
          window as unknown as {
            __atomicCommitLog?: Array<{
              sentAt: number;
              subject: string;
              commit: Record<string, unknown>;
            }>;
          }
        ).__atomicCommitLog ?? [];

      return log.some(entry => {
        if (entry.sentAt < sinceMs) return false;
        const commit = entry.commit;
        const isA = commit[isAProp] as string[] | undefined;
        if (!Array.isArray(isA) || !isA.includes(commitClass)) return false;

        if (!filterSet) return true;

        const hasLoroUpdate = loroProp in commit;
        // Mirrors the HTTP filter below: a Loro-bearing commit can't be
        // inspected per-property here, so a `set` filter degrades to a
        // match on any Commit carrying a loroUpdate.
        if (hasLoroUpdate) return true;

        const setMap = commit[setProp] as Record<string, unknown> | undefined;
        if (!setMap) return false;

        return Object.keys(filterSet).every(key => key in setMap);
      });
    },
    {
      filterSet: (filter?.set ?? null) as Record<string, unknown> | null,
      isAProp: PROPERTIES.isA,
      setProp: PROPERTIES.set,
      loroProp: PROPERTIES.loroUpdate,
      commitClass: 'https://atomicdata.dev/classes/Commit',
      sinceMs: since,
    },
    { polling: 100, timeout: 15000 },
  );

const waitForHttpCommit = (page: Page, filter?: CommitFilter) =>
  page.waitForResponse(async response => {
    if (
      !response.url().endsWith('/commit') ||
      response.request().method() !== 'POST'
    ) {
      return false;
    }

    const commit = response.request().postDataJSON() as Record<string, unknown>;

    const isA = commit[PROPERTIES.isA] as string[];

    if (!isA.includes('https://atomicdata.dev/classes/Commit')) {
      return false;
    }

    // Modern commits carry all property changes inside `loroUpdate` — the
    // `set` map on the wire is empty. `filter.set` used to match by property
    // URL; with Loro we can't decode those bytes here, so if the commit has a
    // `loroUpdate` we accept it. Callers that care about exact property
    // values should assert on the rendered UI instead.
    if (!filter) {
      return true;
    }

    const hasLoroUpdate = PROPERTIES.loroUpdate in commit;

    if (filter.set) {
      if (hasLoroUpdate) {
        // Can't read individual props from the binary update — treat any
        // Loro-bearing commit as a match when a `set` filter was requested.
        return true;
      }

      if (!(PROPERTIES.set in commit)) {
        return false;
      }

      const set = commit[PROPERTIES.set] as Record<string, unknown>;

      for (const [key, value] of Object.entries(filter.set)) {
        if (!(key in set)) {
          return false;
        }

        if (value === anyValue) {
          continue;
        }

        if (JSON.stringify(set[key]) !== JSON.stringify(value)) {
          return false;
        }
      }
    }

    return true;
  });

export function currentDialog(page: Page) {
  return page.locator('dialog[open][data-top-level="true"]');
}

export async function waitForCurrentDialog(page: Page, timeoutMs = 20000) {
  // Default waitFor uses the 5s `actionTimeout`. Several dialogs only open
  // after a server round-trip (plugin upload parses the zip server-side, file
  // chooser uploads the file, etc.). 20s covers the slow path without
  // hiding genuine hangs. Callers with a heavier round-trip chain behind the
  // click (e.g. `acceptInvite`'s agent-creation flow) can pass a larger
  // value — see that call site for why.
  await currentDialog(page).waitFor({ state: 'visible', timeout: timeoutMs });
}

export const DIALOG_CLOSE_BUTTON = 'dialog-close-button';

/** Click history version buttons until the preview panel shows `text`. */
export async function selectHistoryVersionShowing(
  page: Page,
  text: string,
): Promise<void> {
  const buttons = page.getByTestId('version-button');
  const count = await buttons.count();

  for (let i = 0; i < count; i++) {
    await buttons.nth(i).click();

    // Judge the version by its *resource*, not by whatever text the page
    // happens to contain.
    //
    // The default tab is the diff, and a diff names both sides of the change:
    // the version that introduced "First Title" and the one that replaced it
    // with "Second Title" both render "First Title". Scanning the page for
    // that string therefore matched two different versions, and which one the
    // loop settled on came down to how quickly a preview rendered. Landing on
    // the newest version leaves "Restore this version" correctly disabled,
    // because it is already the current one — a failure that looks like a
    // broken button and is really a test picking the wrong row.
    //
    // The Resource tab shows only the selected version, so it can only match
    // the version actually meant. Radix unmounts the inactive panel, so this
    // has to be selected rather than read through.
    await page.getByRole('tab', { name: 'Resource' }).click();

    const shown = await page
      .getByRole('tabpanel')
      .getByText(text, { exact: true })
      .first()
      .waitFor({ state: 'visible', timeout: 5_000 })
      .then(() => true)
      .catch(() => false);

    if (shown) {
      return;
    }
  }

  throw new Error(`No history version preview shows "${text}"`);
}

export async function inDialog(
  page: Page,
  fn: (
    dialog: Locator,
    closeDialogWith: (buttonText: string) => Promise<void>,
  ) => Promise<void>,
  timeoutMs = 20000,
): Promise<void> {
  await waitForCurrentDialog(page, timeoutMs);

  const closeDialogWith = async (buttonText: string) => {
    const button =
      buttonText === DIALOG_CLOSE_BUTTON
        ? currentDialog(page).getByRole('button', { name: 'Close' })
        : currentDialog(page).locator('footer button', { hasText: buttonText });

    // Locator.click already waits for actionability and resolves replacement
    // nodes before dispatch. Submit once, then observe the dialog closing;
    // replaying a save after a short timeout can create duplicate mutations.
    await button.click();
    await expect(currentDialog(page)).toBeHidden({ timeout: timeoutMs });
  };

  await fn(currentDialog(page), closeDialogWith);

  await currentDialog(page).waitFor({ state: 'hidden' });
  await expect(page.locator('dialog[open]')).toHaveCount(0);
}

export async function acceptInvite(page: Page) {
  // InvitePage CTA now reads "Create account and accept" (it generates a new
  // DID agent on the fly); the old "Accept as new user" button is gone. The
  // invite resource is loaded over WS, so under suite-wide load wait longer
  // than the default 5s for the button to appear.
  const acceptBtn = page.getByRole('button', {
    name: 'Create account and accept',
  });
  await expect(acceptBtn).toBeVisible({ timeout: 15000 });
  // Record even a transient duplicate acceptance CTA during agent creation.
  await page.evaluate(() => {
    const observer = new MutationObserver(() => {
      if (document.querySelector('[data-test="accept-existing"]')) {
        document.documentElement.dataset.duplicateInviteAcceptance = 'true';
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  });
  await acceptBtn.click();

  await page
    .getByLabel('Full name', { exact: true })
    .fill(`Test User ${timestamp()}`);
  await page
    .getByRole('button', { name: 'Save and continue', exact: true })
    .click();

  // Unlike most dialogs (one round trip), the click above kicks off TWO
  // sequential server round trips before the dialog opens: InvitePage's
  // handleNew() saves the new agent's genesis commit, then handleAccept()
  // POSTs to accept the invite — see InvitePage.tsx. Give it a wider budget
  // than the 20s default so it isn't tight under load, same rationale as
  // plugin.spec.ts's install flow.
  await inDialog(
    page,
    async dialog => {
      await expect(
        dialog.getByRole('heading', { name: 'This is your account' }),
      ).toBeVisible();
      await expect(dialog.getByLabel('Agent Name')).toHaveCount(0);
      await dialog
        .getByRole('button', { name: 'Feedback', exact: true })
        .click();
      await expect(
        page.getByRole('heading', { name: 'Send feedback' }),
      ).toBeVisible();
      await page.getByRole('button', { name: 'Close', exact: true }).click();
      await expect(
        dialog.getByRole('heading', { name: 'This is your account' }),
      ).toBeVisible();
      await expect(page.locator('html')).not.toHaveAttribute(
        'data-duplicate-invite-acceptance',
        'true',
      );
      await dialog.getByRole('button', { name: 'Copy to clipboard' }).click();
      // The shared secret step carries its own confirm button, not a footer.
      await dialog
        .getByRole('button', { name: "Yes, I've stored it safely" })
        .click();
      await expect(dialog).toBeHidden({ timeout: 40000 });
    },
    40000,
  );
}
