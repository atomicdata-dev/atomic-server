## Reproducible local production run

From `browser/`, run `pnpm test-e2e:local`. It installs locked dependencies,
builds every JS package and WASM, then builds the native server from this
checkout. A private binary copy lives in each run directory, avoiding shared
`target/debug` process-name cleanup from other jobs. It serves the embedded production app and API from the same
`atomic.localhost` origin on a free port, matching CI, with a fresh database.
Use `--preview` to exercise the separate-origin Vite preview instead. It runs Chromium with
a conservative hardware-aware budget (at most two workers by default) and zero retries. It stops only its own process groups. Build logs,
test data, failure traces and the HTML report remain in the git-ignored `.e2e-runs/` directory.

Prerequisites: the repository's Rust toolchain, `wasm32-unknown-unknown`,
`cargo-run-bin` (for the pinned wasm-pack), Node and pnpm. The first build may
be slow. Later runs check a build cache keyed by product file contents (including
untracked files), Node/pnpm/Rust versions and build environment.
Reusing a build also requires matching checksums for the server binary, package
outputs, frontend and WASM. Spec-only edits can reuse those artifacts; changed
or missing artifacts require a rebuild. WASM has a narrower Rust-input cache,
so frontend-only changes rebuild JS without rerunning wasm-pack/wasm-opt.
The runner only sets `SKIP_WASM_BUILD=1` after building or verifying that WASM.
Dependency installation still validates
the workspace lockfile. Generated sites use pnpm's package cache with
`--prefer-offline` and retain separate install/build directories. Generated build
processes default to at most two workers (`ATOMIC_TEMPLATE_BUILD_WORKERS` overrides).
The editor disconnects after its saves settle while the generated site builds.
Generated Next.js/Svelte sites use unique temporary directories and OS-assigned
ports. Teardown terminates their owned process groups; worker IPC disconnect
also shuts them down after an interrupted test. No port-owner lookup is used.

Pass Playwright filters directly, e.g. `pnpm test-e2e:local --grep @smoke`.
`PLAYWRIGHT_WORKERS` can override concurrency. Cloud Vault integration needs a
real portal explicitly selected with `ATOMIC_VAULT_PORTAL_URL`; this isolated
runner skips those tests when it is unset or unavailable, and never discovers
a portal from an unrelated local task. Mocked managed-account tests do not
require that portal.

### Worker/shard experiments

```sh
# One build, fresh server/data per setting and repetition; no test filters.
pnpm test-e2e:local --matrix=1,2,4,8,12,2x4 --repeat=5
node e2e/scripts/summarize-matrix.mjs ../.e2e-runs/<run-directory>
```

Entries are `workers` or `workers x shards`: `8` shares one server among eight
workers, while `2x4` runs two workers against each of four isolated servers.
Separate-origin preview supports one server per run. Counts are positive integers;
`PLAYWRIGHT_WORKERS` overrides the conservative automatic default for ordinary
runs. Matrix mode rejects test filters and overrides, and always disables retries.
This matrix covers the complete **Chromium project**, like the local runner;
it does not establish Firefox/WebKit support. Opt-in tests remain listed with
their skip annotations, including real portal and profiling requirements.

`run.json` separates install/build, service startup, test time and total elapsed
time. Each shard retains HTML/JSON reports, complete expected/executed test IDs,
per-test initialization durations and the slowest tests. Host samples include
CPU use, free/available memory, Linux pressure stalls, process CPU/RSS snapshots,
reporter event-loop delay and `/server` latency. Failure attachments also include
recent host samples and bounded renderer long-task/timer-delay observations.
In containers, process snapshots describe that container's visible processes;
server latency measures the service but is not a server CPU profile.

The summary requires five complete zero-retry passes with matching test accounting
and the same clean source commit at the start, after each run and at the end
before marking a setting accepted. Inspect all skip
reasons; a green summary alone does not excuse lost coverage or unexplained skips.
Record concurrent builds/CI work when interpreting saturation and speedup.
A checkout lease prevents one local runner from rebuilding package outputs while
another run uses them; use separate worktrees for concurrent local runs.

High-worker defaults remain **unvalidated** pending issue #1461's repeated matrix.
CI keeps its explicit aggregate budget: Mancave full uses 4 shards × 2 workers,
hosted uses 2 × 1; other build/unit jobs run concurrently. Dagger `ci` and `end-to-end` accept
`--playwright-workers`, `--playwright-shards` and `--playwright-retries` for
controlled experiments; 0 workers/shards retain the profile and -1 retries
retains its retry policy. Use `--playwright-retries=0` for acceptance and include
all simultaneous build/unit jobs when interpreting the printed aggregate budget. Do not interpret the
ability to request 8 or 12 workers as evidence those settings are reliable.
The active experiments and caching decisions live in
[`planning/e2e-concurrency.md`](../../planning/e2e-concurrency.md).

The isolated local runner builds with Cargo's optimized `e2e` profile, matching
CI while preserving debug assertions and overflow checks. Its first native build
costs more than a debug build; subsequent runs reuse verified artifacts.
`ATOMIC_E2E_CARGO_PROFILE=dev` explicitly selects the slower debug server for
iteration, and `release` selects the production profile. Profile changes
invalidate the native build cache without invalidating the WASM cache.

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
Seed timings are retained separately from per-test restore/drive setup timings.
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
