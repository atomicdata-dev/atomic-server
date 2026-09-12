## Local production E2E

From `browser/`, run `pnpm test-e2e:local`. The launcher installs locked packages,
builds the app/WASM and optimized server, starts a fresh isolated stack, invokes
Playwright, and stops its owned processes. Cargo and pnpm keep their standard
caches; container CI uses Dagger caching. There is no custom build-hash cache.

```sh
pnpm test-e2e:local --workers=4
# Explicitly reuse artifacts for test-only edits:
pnpm test-e2e:local --skip-build dashboard.spec.ts --workers=2
```

`--skip-build` skips builds and dependency installation. Rebuild after product,
lockfile, toolchain or build-environment changes. It makes no freshness guarantee.
Browser installation still uses `--no-remove` to preserve other jobs' versions.

The embedded app/API share an `atomic.localhost` origin on a free port.
`--preview` uses Vite on another free port. Preview builds embed the API port,
so preview must rebuild; it cannot use --skip-build. `ATOMIC_E2E_CARGO_PROFILE`
accepts `dev`, `e2e` (default) or `release`. Prerequisites: the repository Rust
toolchain, wasm32-unknown-unknown, cargo-run-bin, Node and pnpm.

Each invocation retains separate data/config/cache, a private server binary and
logs in `.e2e-runs/`. A checkout lock prevents overlapping local runs; use separate
worktrees for concurrent builds. Generated Next/Svelte projects retain unique
paths, ephemeral ports and owned process groups. Their builds default to two
workers (`ATOMIC_TEMPLATE_BUILD_WORKERS` overrides). No global process killing.

Playwright owns worker counts, filters, repetitions, sharding and reports. The
launcher defaults to Chromium, zero retries, failure traces and line/HTML/JSON
reporters; normal Playwright arguments can override these. `run.json` retains
build/startup/test phase durations, and `report.json` contains test outcomes,
skips and step timings. Cloud Vault tests need an explicit
`ATOMIC_VAULT_PORTAL_URL`; unrelated local portals are never discovered.

### Comparing concurrency

Use ordinary shell loops for independent runs:

```sh
pnpm test-e2e:local --workers=1 --retries=0
for workers in 2 4 8 12; do
  for repetition in 1 2 3 4 5; do
    pnpm test-e2e:local --skip-build --workers="$workers" --retries=0 || exit
  done
done
```

Keep source and artifacts unchanged. Each invocation starts a fresh server.
Playwright's `--repeat-each=5` repeats within one server lifetime instead, useful
for reproducing flakes. Review expected test counts, failures and skips in native
reports. No custom script declares acceptance. Record host load with standard
tools such as vmstat/pidstat; #1461 still requires repeated clean full-suite runs.

Dagger owns isolated server shards and shared container builds. Its `ci` and
`end-to-end` commands accept `--playwright-workers`, `--playwright-shards`,
`--playwright-retries=0` and optional `--playwright-clone-sessions`. Mancave's CI
budget remains 4 shards × 2 workers; hosted uses 2 × 1. Other CI jobs share the
host. Check Pick runner: repository overrides may force hosted even when Mancave
is online. High-worker reliability remains unvalidated. See
[`planning/e2e-concurrency.md`](../../planning/e2e-concurrency.md).

### Cloned-session experiment

`ATOMIC_E2E_CLONE_SESSION=1 PLAYWRIGHT_WORKERS=4 pnpm test-e2e:local dashboard.spec.ts`
compares the dashboard specs using a closed browser profile as a seed.
Without the environment flag they retain the normal fresh-agent setup.
Only specs importing `tests/session-fixtures.ts` opt into this experiment:
dashboards, table tools/filtering/refresh/templates, row actions, aggregates,
derived columns, calendar, kanban, timer and quick-add.

Each worker initializes its own agent once and closes Chromium. Each test gets
an independent copy of that immutable profile, including its encrypted OPFS
database and IndexedDB signing keys, a distinct device ID, and a fresh project
drive. Copy-on-write is requested where the filesystem supports it; hard links
are never used. Profiles are removed during teardown and live under the run's
output directory so interrupted runs do not scatter state into global temp paths.
Do not use this fixture for account settings, personal-drive lists, authorization,
backup/discovery identity, or cold-start/storage tests: those contracts need a
fresh identity or fresh disk. Global account searches can also see prior drives.

Playwright and the CI image are pinned to 1.63.0. Its OPFS JSON snapshot option
works, but its IndexedDB serialization does not restore non-extractable
`CryptoKey` objects, so a JSON snapshot alone cannot restore this signed-in app.
The closed profile preserves those keys without changing application security.

The version-specific `playwright-core` patch adds a temporary Chromium launch
flag for `PreventCrossWorldServiceWorkerResourceReuse`, preserving Playwright's
other default flags. Chromium 153's preload check confuses null and MainWorld()
and produces warnings even in fresh-session reload tests. Remove the patch when
the bundled browser includes [Chromium's fix](https://github.com/chromium/chromium/commit/4df9ee2790a40a55a6ac0a08e4ded457d1460723).
Service workers and strict diagnostic assertions remain active. These runs do
not validate that browser's cross-world service-worker resource isolation check.
Browser installation uses `--no-remove` to preserve other jobs' browser versions.

### Deployment fixtures

Import `standaloneTest as test` or `managedTest as test` from
`tests/deployment-fixtures.ts` when a spec depends on deployment behavior.
Managed mode sets the runtime portal URL and mocks the account API before
navigation; register endpoint-specific routes afterward. Standalone mode does
not inject hosted configuration. Use `managedDriveTest` for a fresh dev-drive
identity followed by hosted mode; the standalone dev-drive route cannot run
under hosted onboarding. The other fixtures do not create an identity.
For mocked portal navigation, disable service workers in the spec so routes
can intercept the dashboard instead of the app's navigation fallback.

# Atomic Data Browser E2E tests

We use `playwright` to run end-to-end tests in the browser.

## Running the server

The suite needs the data-browser dev server on **6747** and an `atomic-server` on
whatever port **`VITE_ATOMIC_SERVER_URL`** names in
`browser/data-browser/.env.development` (currently 9885).

That indirection is the single easiest thing to get wrong here. The suite's own
`SERVER_URL` variable only points the test _helpers_; the app the tests drive
reads the vite env. Start a server on 9883 while the SPA is pointed at 9885 and
every test fails on a connection refused that mentions neither port.

Start the server with **its own store**, not your dev one:

```sh
# build a server binary once — plain build, so the embedded frontend bundle
# is built too (see "Keep the binary in step with the branch" below).
# ATOMICSERVER_SKIP_JS_BUILD=true is for backend-only iteration; it reuses
# whatever bundle was embedded last, which breaks the invite/dev-drive specs.
cargo build -p atomic-server
# then, from browser/e2e:
pnpm test-server         # serves the configured port from <repo>/.e2e-store
pnpm test-server-fresh   # same, but wipes that store first
```

### Keep the binary in step with the branch

`build.rs` embeds the data-browser bundle into the server, and the **invite and
dev-drive pages are served from that copy** rather than from vite. A binary built
on another branch therefore serves one frontend on those pages and vite serves
another everywhere else. Specs that cross the boundary — invite, share, anything
going through a server-side plugin hook — then fail for a reason that appears
nowhere in their output, while CI (which builds from source) stays green.

`test-server` refuses to start when the binary is older than `server/src`,
`lib/src`, `browser/data-browser/src` or `browser/lib/src`, and names the file
that outranks it. Rebuild with `cargo build -p atomic-server` — note the plain
build, since `ATOMICSERVER_SKIP_JS_BUILD=true` leaves the embedded bundle stale,
which is the very thing being guarded. `--stale-ok` starts anyway, which is fine
when the specs you are running only touch vite-served pages.

It prints the URL it chose and the matching `SERVER_URL=… pnpm test-e2e` to run.

Sharing your own store costs more than it looks like it saves, and the store goes
stale faster than you would expect. Measured on this repo: `aggregates.spec.ts`
passes in 10s against a fresh store and fails outright against a 324MB one — which
is roughly two full suite runs' worth of accumulated drives, tables and rows. The
failure looks like a bug in the totals footer and is not one.

So: keep the store separate from your dev one. The script now **wipes** the store
itself once it passes ~150MB rather than printing a note nobody reads — the usual
way to start it is in the background with output going to a log. Pass
`--keep-store` if you really want to keep an oversized one; it warns instead.

If a spec does fail, **reproduce it alone before believing it**:

```sh
pnpm playwright test some.spec.ts --project=chromium --workers=1
```

Comparing failure _sets_ against a known baseline beats expecting all-green.

## Light vs full

Feature-branch CI runs **light**: `--grep @smoke`, about twenty first-hour
journeys. `develop` and `v*` tags run the **full** suite. Tag a test with
`smoke` from `./tests/test-utils.ts` only if a failure means the demo is
dead. See [`planning/e2e-light-heavy.md`](../../planning/e2e-light-heavy.md).

```sh
# install deps
pnpm i
# install chromium
pnpm playwright-install
# light suite (matches feature-branch CI)
pnpm test-e2e:light
# run all tests, creates a `playwright-report` folder with HTML files + images
pnpm test-e2e
# run all tests and updates snapshots
pnpm test-update
# run all tests in debug mode
pnpm test-debug
# run a single test (e.g. 'table')
pnpm test-query table
# create a new test
pnpm test-new
# deploy report to netlify
netlify deploy --dir playwright-report --prod --site atomic-tests
```

### Editor binding compatibility

The scoped `loro-prosemirror@0.4.3` patch restores the selection in the same
transaction as an imported document update. The upstream deferred cursor timer
can run after a subsequent keystroke and reorder typed text. Its regression is
`data-browser/src/chunks/RTE/loro-selection.test.ts`; remove the patch when the
upstream binding includes an equivalent atomic selection fix.
