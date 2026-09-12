import type { PlaywrightTestConfig } from '@playwright/test';
import { devices } from '@playwright/test';
import { workerBudget } from './scripts/concurrency.mjs';

const config: PlaywrightTestConfig = {
  // Default `expect` timeout. Playwright's built-in is 5s; bump to 10s
  // so retrying assertions match the action timeout below. Tests that
  // need a longer specific budget still pass `{ timeout: ... }` directly.
  expect: { timeout: 10000 },
  use: {
    screenshot: 'only-on-failure',
    viewport: { width: 1200, height: 800 },
    locale: 'en-GB',
    timezoneId: 'Europe/Amsterdam',
    // 10s actionTimeout. The atomic-server runs as a single process behind
    // every test (dev-drives, commits, search index, WS handshake all on
    // one box). On CI the server is in a smaller container and runs
    // noticeably slower than a dev laptop — the default 5s budget started
    // catching real round-trips, not bugs. 10s covers the slow path
    // without hiding genuine hangs.
    actionTimeout: 10000,
    trace: 'retain-on-failure',
    storageState: {
      cookies: [],
      origins: [
        // `FRONTEND_URL` / `SERVER_URL` are overridable, but this list was not,
        // so running the suite on any other port silently lost
        // `viewTransitionsDisabled` — the flake-reducer below — for the origin
        // actually under test. Derive those two first; the fixed entries stay
        // for the default and dagger setups.
        ...[process.env.FRONTEND_URL, process.env.SERVER_URL]
          .filter((url): url is string => !!url)
          .map(url => new URL(url).origin)
          .map(origin => ({
            origin,
            localStorage: [{ name: 'viewTransitionsDisabled', value: 'true' }],
          })),
        {
          origin: 'http://localhost:6747',
          localStorage: [{ name: 'viewTransitionsDisabled', value: 'true' }],
        },
        {
          origin: 'http://localhost:9883',
          localStorage: [{ name: 'viewTransitionsDisabled', value: 'true' }],
        },
        {
          origin: 'http://atomic:9883',
          localStorage: [{ name: 'viewTransitionsDisabled', value: 'true' }],
        },
        {
          // Dagger e2e FRONTEND_URL — chromium treats `*.localhost` as a
          // secure context (needed for WASM ClientDb / crypto.subtle).
          origin: 'http://atomic.localhost:9883',
          localStorage: [{ name: 'viewTransitionsDisabled', value: 'true' }],
        },
      ],
    },
  },
  reporter: [
    [
      'html',
      {
        // attachmentsBaseURL: '://external-storage.com/',
        // outputFolder: '/artifact/test-report',
        open: 'never',
      },
    ],
  ],
  // CI retries: default 1 (was 2 — triple runtime on flakes dominated the
  // ~50 min e2e budget). Override with PLAYWRIGHT_RETRIES. Dagger Main sets
  // it explicitly; hosted/local CI without the env still get 1.
  retries:
    process.env.PLAYWRIGHT_RETRIES !== undefined
      ? Number(process.env.PLAYWRIGHT_RETRIES)
      : process.env.CI
        ? 1
        : 0,
  // Per-test budget — not a race-prevention timeout. Playwright's
  // default is 30s; some tests (chatroom invite flow, share menu,
  // tables) legitimately run 25–35s when the shared atomic-server is
  // under suite-wide load. Bumping to 60s gives them headroom without
  // masking real hangs. Specific assertions inside tests still have
  // their own targeted timeouts.
  timeout: 60_000,
  projects: [
    {
      name: 'chromium',
      // No `testMatch` — chromium runs the whole suite (incl. the locks spec).
      use: {
        ...devices['Desktop Chrome'],
        // CI sets ATOMIC_TEST_INSECURE_ORIGIN to the http:// origin of the
        // atomic-server (e.g. `http://atomic:9883` in the dagger pipeline).
        // The SPA's WASM ClientDb uses `crypto.subtle`, which only works in
        // "secure contexts" — `localhost`/`*.localhost` qualify, but a
        // dagger service-binding alias like `atomic` does not. We tell
        // chromium to treat that origin as secure so the WASM init can
        // complete; otherwise every test times out at `beforeEach`.
        launchOptions: process.env.ATOMIC_TEST_HOST_MAP
          ? {
              // CI sets ATOMIC_TEST_HOST_MAP to a chromium host-resolver-rules
              // string like `MAP atomic.localhost atomic` so the browser
              // resolves a `*.localhost` hostname (which it treats as a
              // secure context, exposing `crypto.subtle`) to the actual
              // dagger service. Without a secure origin the SPA's WASM
              // ClientDb fails to init and every test hangs.
              args: [
                `--host-resolver-rules=${process.env.ATOMIC_TEST_HOST_MAP}`,
              ],
            }
          : undefined,
      },
    },
    // Firefox runs ONLY the ClientDb locks spec — it guards the hardened
    // Firefox leadership path (no Chromium lock-steal). The rest of the suite
    // stays chromium-only (the SPA targets Chromium-class browsers). Skipped
    // when ATOMIC_TEST_HOST_MAP is set: that's the dagger CI's non-localhost
    // origin, where the secure-context (`crypto.subtle`) workaround is a
    // chromium-only `--host-resolver-rules` flag, so the WASM ClientDb can't
    // init on Firefox there. Locally (localhost is a secure context) it runs.
    ...(process.env.ATOMIC_TEST_HOST_MAP
      ? []
      : [
          {
            name: 'firefox',
            testMatch: /client-db-locks\.spec\.ts/,
            use: { ...devices['Desktop Firefox'] },
          },
        ]),
    // WebKit is the engine the Tauri desktop app actually runs on (WKWebView on
    // macOS, WebKitGTK on Linux) — the whole suite otherwise proves things only
    // about Chromium, so every WebKit-specific storage difference (OPFS sync
    // access handles, IndexedDB eviction, CryptoKey serialisation) reaches
    // users unmeasured. Scoped to the storage round-trip spec, same pattern as
    // the firefox project above; running the full suite here is a separate,
    // much larger job.
    //
    // Opt-in via ATOMIC_TEST_WEBKIT=1 because it needs `pnpm playwright-install
    // --webkit`, which the default `playwright-install` script does not fetch.
    // This is NOT a substitute for driving the real Tauri binary — same engine,
    // but an http:// origin instead of tauri://, and no embedded node.
    ...(process.env.ATOMIC_TEST_WEBKIT
      ? [
          {
            name: 'webkit',
            testMatch: /signout-signin-data\.spec\.ts/,
            use: { ...devices['Desktop Safari'] },
          },
        ]
      : []),
  ],
  fullyParallel: true,
  // Light vs full: tag `@smoke` (see `smoke` in tests/test-utils.ts).
  // `pnpm test-e2e:light` / CI feature branches pass `--grep @smoke`.
  // `pnpm test-e2e` and develop/tag CI run the unfiltered suite.
  // The local runner and direct Playwright share one conservative budget.
  // Dagger sets a per-shard override; aggregate concurrency includes all shards.
  workers: workerBudget().workers,
};

export default config;
