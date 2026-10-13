import type { PlaywrightTestConfig } from '@playwright/test';
import { devices } from '@playwright/test';
import { workerBudget } from './scripts/concurrency.mjs';
import './scripts/server-dns.cjs';
import path from 'node:path';

// Workers and generated Next/Svelte sites must use the same DNS mapping as the
// test process, without baking the internal service hostname into their URLs.
const serverDns = path.resolve(__dirname, 'scripts/server-dns.cjs');

if (
  process.env.ATOMIC_SERVICE_URL &&
  !process.env.NODE_OPTIONS?.includes(serverDns)
) {
  process.env.NODE_OPTIONS = [
    process.env.NODE_OPTIONS,
    `--require=${JSON.stringify(serverDns)}`,
  ]
    .filter(Boolean)
    .join(' ');
}

// Both the plugin catalog and the integration proxy are read from
// localStorage at runtime, with the `VITE_*` build-time values as mere
// defaults. Seeding those keys here is what lets one unmodified binary serve
// a lane whose catalog and proxy sit on arbitrary ports: `storageState` is
// applied when the browser context is created, so the first script on the
// page already sees them, and nothing has to be rebuilt.
//
// The `VITE_*` spellings are accepted too, so an invocation that used to bake
// the value keeps working by seeding it instead.
//
// Unless a catalog is given, the suite serves its own: a static copy of the
// atomic-plugins layout (testdata/atomic-plugins-mock), started below as a
// `webServer`, so no spec depends on what is published upstream.
const configuredCatalogUrl =
  process.env.PLUGIN_CATALOG_URL || process.env.VITE_PLUGIN_CATALOG_URL;
const pluginsMockPort = process.env.ATOMIC_PLUGINS_MOCK_PORT || '9893';
const pluginsMockUrl = `http://127.0.0.1:${pluginsMockPort}/integrations/catalog.json`;
const catalogUrl = configuredCatalogUrl || pluginsMockUrl;
const integrationProxy =
  process.env.INTEGRATION_PROXY_URL || process.env.VITE_INTEGRATION_PROXY_URL;

// RFC 6761 gives the whole `.localhost` TLD to loopback; this mirrors
// `isLoopbackHost` in data-browser/src/helpers/runtimeSetting.ts, which both of the
// runtime validators use.
const isLoopbackHost = (host: string) =>
  host === 'localhost' ||
  host.endsWith('.localhost') ||
  host === '127.0.0.1' ||
  host === '[::1]';

// A seeded value the app rejects is dropped silently and the default is used
// instead — the suite would then run against the public catalog, or against a
// proxy that isn't there, and report the product broken. Fail here instead,
// naming the value, while the cause is still in front of whoever set it.
function checkSeed(name: string, value: string, originOnly: boolean) {
  let url: URL;

  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} is not a URL: ${value}`);
  }

  if (
    url.protocol !== 'https:' &&
    !(url.protocol === 'http:' && isLoopbackHost(url.hostname))
  ) {
    throw new Error(
      `${name} must be an HTTPS URL or a loopback HTTP URL: ${value}`,
    );
  }

  if (originOnly && url.origin !== value) {
    throw new Error(`${name} must be a bare origin, without a path: ${value}`);
  }

  return value;
}

const seededStorage = [
  // Transitions are off by default now, and `isAutomated()` disables them
  // under webdriver anyway, so this is belt and braces: it keeps the suite
  // deterministic if either of those ever changes.
  { name: 'viewTransitionsEnabled', value: 'false' },
  {
    name: 'plugin-catalog-url',
    value: checkSeed('PLUGIN_CATALOG_URL', catalogUrl, false),
  },
  ...(integrationProxy
    ? [
        {
          name: 'integration-proxy-url',
          value: checkSeed(
            'INTEGRATION_PROXY_URL',
            integrationProxy.replace(/\/$/, ''),
            true,
          ),
        },
      ]
    : []),
];

// Persistent WebKit profiles on macOS access the login Keychain to persist
// CryptoKeys. They repeatedly prompt for the user's password during these
// storage tests. Run this optional project on Linux, never on a user's Mac.
if (process.env.ATOMIC_TEST_WEBKIT && process.platform === 'darwin') {
  throw new Error(
    'WebKit storage tests are disabled on macOS because they trigger login Keychain password prompts. Run ATOMIC_TEST_WEBKIT=1 on Linux instead.',
  );
}

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
        // so running the suite on any other port silently lost the seeds above
        // — `viewTransitionsEnabled`, and now the catalog and proxy URLs — for
        // the origin actually under test. Derive those two first; the fixed
        // entries stay for the default and dagger setups.
        ...[process.env.FRONTEND_URL, process.env.SERVER_URL]
          .filter((url): url is string => !!url)
          .map(url => new URL(url).origin),
        'http://localhost:6747',
        'http://localhost:9883',
        'http://atomic:9883',
        // Dagger e2e FRONTEND_URL — chromium treats `*.localhost` as a
        // secure context (needed for WASM ClientDb / crypto.subtle).
        'http://atomic.localhost:9883',
      ]
        .filter((origin, index, all) => all.indexOf(origin) === index)
        .map(origin => ({ origin, localStorage: seededStorage })),
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
    // Set by the Dagger shard script, which prints a per-file timing table
    // from it at the end of the shard so the shard sizes can be set from
    // measurements.
    ...(process.env.PLAYWRIGHT_JSON_OUTPUT_NAME
      ? [
          [
            'json',
            { outputFile: process.env.PLAYWRIGHT_JSON_OUTPUT_NAME },
          ] as const,
        ]
      : []),
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
    // Opt-in on Linux via ATOMIC_TEST_WEBKIT=1 because it needs `pnpm playwright-install
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
  webServer: configuredCatalogUrl
    ? undefined
    : {
        command: `node ${JSON.stringify(
          path.resolve(
            __dirname,
            '../../testdata/atomic-plugins-mock/serve.mjs',
          ),
        )} ${pluginsMockPort}`,
        url: pluginsMockUrl,
        // The mock is stateless and identical across checkouts, so another
        // run's instance on the same port serves this one just as well.
        reuseExistingServer: true,
      },
};

export default config;
