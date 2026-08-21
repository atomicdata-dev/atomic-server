# Atomic Data Browser E2E tests

We use `playwright` to run end-to-end tests in the browser.

## Running the server

The suite needs the data-browser dev server on **6747** and an `atomic-server` on
whatever port **`VITE_ATOMIC_SERVER_URL`** resolves to. Vite reads
`.env.development.local` first, then the committed `.env.development` (9885
today), and falls back to the default in `browser/data-browser/vite.config.ts`
(9883), which points the app and the dev proxy at the same server.
`pnpm test-server` reads the same two files in the same order, so it follows
the app; a shell export it cannot see, which is what `ATOMIC_E2E_SERVER_URL`
is for.

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
