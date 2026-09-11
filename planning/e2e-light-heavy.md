# Light vs heavy E2E, and where unit tests should grow

**Status: partial, updated 2026-09-11.** Tags, `test-e2e:light`, Dagger `--playwright-mode`, and
`main.yml` gating are in. Remaining: grow `jsTestIntegration`, stop adding
heavy-only variants as Playwright, then drop redundant heavy specs.

Yes: split Playwright into a **light** suite that gates feature-branch CI,
and a **heavy** suite that gates `develop` / tags / releases. Lint, Rust,
vitest, JS integration, and Flutter stay on **every** run — “partial” means
fewer browsers, not a thinner backend net. The split only works if the
cases we drop from the feature-branch gate already have a cheaper test at
the right layer. Do not shrink E2E first and hope unit tests appear later.

Companion: [`TESTING_COVERAGE.md`](../TESTING_COVERAGE.md) — protocol vs glue
vs flow. This plan is about *which flow tests run when*, not about abandoning
the flow layer.

---

## Verdict

The suite is doing two jobs in one job:

1. **Can a person still use the app?** Sign in, make a document, share it,
   edit a table, survive reload. A few dozen browser tests.
2. **Did this operator / template / offline path / regression still work?**
   Combinatorics, serial specs, two-browser sessions, website scaffolding,
   perf probes. Another ~140 tests, most of the wall time.

Job 1 belongs on every PR. Job 2 belongs on `develop`, on `v*` tags, and
whenever someone is about to ship. The missing piece is not more Playwright:
it is using the layers we already have so job 2 does not have to live in a
browser.

---

## Earlier timing baseline (re-measure before tuning)

Playwright is the slow lane. Counts from this tree (2026-08-20):

| Layer | Size | CI job |
|---|---|---|
| Playwright | 68 spec files, ~172 `test()`s, ~13.5k lines | `endToEnd` |
| Browser unit (vitest) | ~100 files (`@tomic/lib` + data-browser helpers) | `jsTest` |
| Browser integration (vitest + real `atomic-server`, no UI) | 5 files under `browser/lib/tests/` | `jsTestIntegration` |
| Rust | ~580 `#[test]` / `#[tokio::test]` | `rustTest` |

There is **no React Testing Library**. UI is only asserted through Playwright.

CI already shards E2E (Mancave: 4 shards × 2 workers, `retries=2`; hosted: 2
shards × 1 worker). `ci()` runs those browsers **in parallel with** clippy,
nextest, Flutter, and two vitest jobs. Dagger comments record the cost: at 3
workers Chromium was killed outright ("Target page, context or browser has
been closed") — starvation, not a race. Retries were dropped to 1 to save
wall time, then raised back to 2 because remaining failures rotated run to
run. The retries are buying headroom the host does not have.

Wall-clock of a Main run is not the same as E2E runtime. Recent Mancave
successes (2026-08-20):

- Docs-only / cache hit: **~2–12 min** end to end.
- Code changes: **~15–45 min** of actual `Main (Mancave) / CI` once the
  runner starts. Queue time on a busy box can add another hour before that.
- Playwright config still talks about a **~50 min e2e budget** as the reason
  retries were cut.

Every test that uses `before` (`test-utils.ts`) pays a full `/app/dev-drive`
bootstrap: WASM ClientDb + OPFS + genesis agent + drive. ~50 specs do this
per test. Setup tax scales with test count, not with assertion count.

Other known drags, already documented in-tree:

- `template.spec.ts` is serial and spawns Next.js / SvelteKit applies.
- `table-refresh.spec.ts` is serial.
- Two-browser specs (`e2e.spec.ts` invite/chatroom, `meetings`, `presence-follow`,
  `second-device-load`, `drive-deeplink`, `vault-backup-restore`, `onboarding`,
  `sync.spec.ts`) hold extra contexts.
- Perf / profile specs (`first-paint-*`, `dev-drive-timing/profile`,
  `opfs-init-perf`, `perf-budgets`, `perf-sidebar-reload`,
  `table-create-perf`) are probes. Several already `test.skip` unless an env
  var is set, but they still occupy the suite.
- Staging deploys from `develop` only after Main is green
  (`deploy_staging.yml`). Production follows a `v*` tag. The full suite is
  load-bearing for those two gates; PRs do not have to share that cost.

`e2e.spec.ts` already says this out loud: *these tests are relatively slow,
try to utilize unit tests to catch bugs earlier.*

---

## The trap

[`TESTING_COVERAGE.md`](../TESTING_COVERAGE.md) exists because **protocol is
well tested and glue/flow is not**, and every production device-sync bug so
far lived in an uncovered glue/flow row. A light suite that is just "delete
half the specs" would recreate that imbalance in the browser.

So:

- Keep **one** Playwright test per user journey that can only fail in the
  UI (click, dialog, drag, two tabs, reload with OPFS).
- Move **combinatorics** (operators, templates, filter keys, row actions,
  pairing envelope validation) down to vitest / Rust, where many already
  live.
- Prefer `jsTestIntegration` (real server, `Store` + `NodeClientDb`, no
  browser) for "does the client actually persist / sync / upload" before
  adding another Playwright file. That job exists and is underused: five
  tests covering upload, genesis, wasm smoke.

Do **not** introduce React Testing Library as the escape hatch. The cost of
a third UI-test stack is higher than tagging Playwright and growing helper /
integration tests.

---

## Implemented model

Three layers. **Only Playwright splits.** Lint, Rust, vitest, JS integration,
and Flutter stay on every run.

```
always (any branch / tag / dispatch)
  jsLint, rustFmt, rustClippy, rustTest, jsTest, jsTestIntegration, flutterTest

e2e light  (@smoke)     feature-branch pushes (today's `on: push` to anything but develop)
e2e heavy  (full suite) develop, v* tags, and opt-in
```

Mechanism: Playwright **tags**, not two folders. A test can be `@smoke` and
still run in heavy (heavy = unfiltered). Light is `--grep @smoke`. Optional
later: `@perf` excluded from both default jobs and run on a schedule.

### CI policy: when full?

**Partial by default. Full when we are about to ship, or when someone asks.**

Feature-branch pushes now run the light suite; develop and release validation
use the full suite according to the policy below. Superseded feature-branch
runs cancel within their ref; develop and tag runs finish because deployment
consumes their results. `jsLint` uses installed sources without JS or WASM builds.
Full Dagger execution and queue timing must still be measured in CI.

| Trigger | Unit / integration / lint | Playwright |
|---|---|---|
| Push to a feature branch | always, required | **light**, required |
| Push to `develop` | always, required | **full**, required (staging deploys from this green) |
| Push of a stable `v*` tag | always, required | **full**, required (production deploys from this green) |
| `workflow_dispatch` | always | **full** unless the input says light |
| PR label / dispatch input `full-e2e` on a feature branch | always | **full** (opt-in, still required for that run) |
| Local `pnpm test-e2e` | — | full (today) |
| Local `pnpm test-e2e:light` | — | light |

Never skip the non-Playwright jobs on a “partial” run. Those are the cheap
net, already parallel with E2E, and they are where protocol bugs belong.
“Partial CI” means **fewer browsers**, not “skip Rust.”

Do **not**:

- Run light on `develop`. Staging (`deploy_staging.yml`) follows a green
  Main on `develop`. A subset gate would ship untested offline / table /
  two-browser paths.
- Run full E2E as a non-blocking extra job on every feature branch. That
  keeps Mancave contended and undoes the split.
- Infer the suite from changed paths (`tables.spec.ts` if `TablePage`
  changed). Brittle, and agents will get it wrong. Opt-in full on the
  branch if you touched a heavy-only flow and want the answer before merge.
- Skip E2E entirely on docs-only commits as a first step. Dagger cache
  already makes those ~2–12 min. A GHA path filter is an optional later
  save, not the policy.

**Merge tax.** A light-green feature branch can still turn `develop` red.
That is the point of the `develop` gate: staging waits, the author (or
whoever lands) pays the full suite once, not on every push. Use the
`full-e2e` opt-in when the change is in a heavy-only area (offline tables,
canvas, vault, website templates) so you find that before merge.

Retries: light `retries=1` (0 locally). Heavy keeps `retries=2` on Mancave
until the host is less contended. A smaller default job *is* the contention
fix.

Shards: light **1–2 shards**, not 4. Full keeps current 4 / 2.

Nightly full-on-`develop` is optional later (retries=0, flake hunting). It
is not required if every `develop` push already runs full.

---

## What belongs in light (~25–35 tests)

One happy path per product surface a user hits in the first hour. Draft
list — tag these, do not copy them into a new file:

| Journey | Source spec | Keep in light |
|---|---|---|
| Create identity / sign in / sign out | `e2e.spec.ts`, `onboarding.spec.ts` | 1–2 tests |
| Invite + share + second context accepts | `e2e.spec.ts` authorization | 1 (this *is* a flow test; protocol coverage is not a substitute) |
| Chatroom | `e2e.spec.ts` | 1 |
| Folder | `e2e.spec.ts` | 1 |
| Document CRDT (create + websockets) | `documents.spec.ts` | 0 — already marked FLAKY; folder covers create |
| Table create + type a row | `tables.spec.ts` `create and fill` | 1 |
| Search | `search.spec.ts` text search | 1 |
| Offline edit survives reload + reconnect | `sync.spec.ts` | 1 |
| Second device cold-loads a drive | `second-device-load.spec.ts` | 1 |
| Drive deep link adopts the right drive | `drive-deeplink.spec.ts` | 1 |
| Kanban: create board + drag persists | `kanban.spec.ts` | 1 |
| Dashboard: one block with a real total | `dashboard.spec.ts` | 1 |
| Meeting prepare → start | `meetings.spec.ts` | 1 |
| File upload round-trip | `filePicker.spec.ts` or `file-upload-offline` online case | 1 |
| Pairing: paste code success (Tauri-gated form) | `pairing-dialog.spec.ts` | 1 |
| Ontology create/edit | `ontology.spec.ts` | 1 |
| History page | `e2e.spec.ts` | 1 |
| Delete resource | `e2e.spec.ts` | 1 |

That is roughly 20 tests plus a small buffer. Everything else in those files
stays in the repo and runs in heavy.

Rule of thumb for adding a new `@smoke` tag: **would a broken test here
mean we cannot demo the app?** If it is an operator, a template, a
Firefox-only lock, or a perf budget, it is heavy.

---

## What belongs only in heavy

Group by why they are expensive or redundant as a PR gate.

**Combinatorics already unit-tested** — keep one smoke, run the rest in
heavy until (or after) the unit tests are trusted as the regression net:

- Table filters / views, derived columns, aggregates, row actions, quick
  add, templates (`table-*.spec.ts`, `derived-columns`, `aggregates`,
  `quick-add`, `row-actions`) — twins exist:
  `tableFiltering.test.ts`, `derivedColumns.test.ts`,
  `tableAggregates.test.ts`, `rowActions.test.ts`, `quickAdd.test.ts`,
  `tableTemplates.test.ts`.
- Forks (`forks.spec.ts` vs `browser/lib/src/forks.test.ts`).
- Pairing malformed / remembered-peer cards (`pairing.test.ts`,
  `knownPeers.test.ts`).
- Dashboard block math (`dashboardBlocks.test.ts`).
- Meeting lifecycle helpers (`meetingLifecycle.test.ts`).
- Vault helpers (`helpers/managed/*.test.ts`).
- AI compact / tool XML (`chunks/AI/*.test.ts`). The E2E file is fully
  mock-routed; it tests chrome, not a model.

**Multi-session / OPFS / server-only fallbacks** — these *are* flow tests
and should stay Playwright, just not on every PR:

- `offline-*`, `local-db-off-*`, `server-only-fallback`,
  `clientdb-edit-persistence`, `signout-signin-data`,
  `sign-in-without-data`, `client-db-locks` (incl. Firefox project),
  `canvas-*`, `presence-follow`, `vault-backup-restore`.

**Product surfaces that are not the first-hour path:**

- `timer`, `calendar`, `plugin`, `template.spec.ts` (Next/Svelte apply),
  `ai.spec.ts`, `localized-text`, `JSONProp`, `tags`, `discussion`,
  `shortcuts`, `settings`, `default-ontology`, `query-drive-filter`,
  `resource-context-menu`, `rename-regression`, `table-refresh` (serial),
  `sync-devices` (QR copy / form gate — pairing success is the smoke).

**Perf probes** — never a PR gate. Exclude with `@perf` (or keep today's
`test.skip` + env). Run on a schedule or locally with
`ATOMIC_TEST_CPU_THROTTLE`.

---

## Unit / integration gaps to fill *before* shrinking heavy

Do not move a spec to heavy-only and then delete it later unless the row
below exists.

| Gap | Better layer than more E2E |
|---|---|
| Offline create → reconnect → server has the commit | `jsTestIntegration` (extend upload-offline-reconnect pattern) |
| Collection query + AND filters without a grid | already Rust + `multi-property-filter`; UI stays one E2E |
| Kanban group-by precedence (explicit > existing select > auto-create) | data-browser helper unit test; DnD stays E2E |
| Table view config persist (filters/sort/columns) | helper unit + one E2E reload |
| Search overlay parsing (`tag:`, scoped) | small parser unit; overlay E2E stays one test |
| Document CRDT / cursor | keep E2E; no RTL |
| Chatroom invite across contexts | keep E2E; this is the flow |
| `/app/dev-drive` bootstrap timing | perf job, not unit |

`@tomic/lib` is in good shape. data-browser unit tests cluster on **tables
and managed-node helpers**. Thin spots are RTE/documents, search overlay,
ontology editor, plugin loader, settings — those should keep Playwright
until a helper is extracted, not a mock React tree.

Policy for new tests (put this in `TESTING_COVERAGE.md` and
`browser/e2e/README.md` when building):

1. If the logic is a pure function or a Store method, write vitest / Rust
   first.
2. If it is "client talks to a real server, no UI", add
   `*.integration.test.ts`.
3. If it is a user journey, add **one** Playwright test. Tag `@smoke` only
   if a failure means the demo is dead.
4. Extra operators, templates, and "also works offline" variants go to
   heavy, or to (1)/(2) instead.

Debugging process in `AGENTS.md` currently pushes agents toward E2E
("reproduce the bug in a test"). Amend it: reproduce at the cheapest layer
that can fail.

---

## CI / Dagger shape

Today `ci()` takes `--playwright-mode light|full` and passes it to `endToEnd`.
The workflow decides the mode; Dagger does not guess the branch.

- `endToEnd` / `ci` take `--playwright-mode light|full` (not `--e2e-mode`:
  Dagger camelCases that to `e2EMode` and the call fails).
- `main.yml` defaults to `full` on `refs/heads/develop` and all `v*` tags.
  Feature branches use `light` unless `[full-e2e]` in the commit message or a
  `full-e2e` PR label requests full. An explicit workflow-dispatch `e2e_mode`
  overrides the default; release validation still needs the full suite.
- Light: `--grep @smoke`, two Mancave shards or one hosted shard,
  `PLAYWRIGHT_RETRIES=1`; workers follow the selected Dagger host profile.
- Full: current command, current shards/retries.
- `pnpm` scripts: `test-e2e:light` / keep `test-e2e` = full.
- Do not grep-exclude by filename forever; tags survive file splits.

Optional later, not required for the split to pay off:

- Nightly full on `develop` with `retries=0` (flake hunting).
- `@perf` job, one shard, `workers=1`, no retries, fail on budget miss.
- Firefox/WebKit projects stay heavy-only (locks + sign-out round-trip).
- Docs-only path filter that skips Playwright entirely (Dagger cache
  already makes these cheap).

---

## What not to do

- Two copies of each spec in `tests/light/` and `tests/heavy/`.
- Light-only on `develop`. Staging would then ship on a subset.
- Deleting heavy tests whose only coverage is Playwright, "to save CI",
  before a unit/integration twin exists.
- Treating mocked `ai.spec.ts` as a substitute for tool-unit tests, or
  vice versa.
- Raising Mancave workers again to make the full suite faster. The box is
  already oversubscribed; a smaller default job is the fix.
- A new component-test framework.

---

## Build order

1. [x] Tag the draft smoke list; add `test-e2e:light`.
2. [x] Wire Dagger + `main.yml` so feature branches run light, `develop`/tags run full.
3. [x] Document the policy in `TESTING_COVERAGE.md`, `browser/e2e/README.md`,
   `AGENTS.md` (cheapest layer first).
4. For each heavy spec that duplicates a unit file, leave the E2E in heavy
   and stop adding variants there. New variants go to vitest.
5. Grow `jsTestIntegration` for offline/sync/upload paths that currently
   exist only as Playwright.
6. Only then drop individual heavy tests that have become redundant.

Step 1–3 is the split (landed). Step 4–6 is how the heavy suite stops growing
faster than the product.

## Local reproduction and diagnostics

`pnpm test-e2e:local` builds JS, WASM and the native backend from the checkout,
uses fresh data on matching free ports, and retains failure traces. It runs
with zero retries by default. External Cloud Vault tests require an explicit
`ATOMIC_VAULT_PORTAL_URL`; managed mocks do not depend on a portal.

Failures also attach bounded resource/save and WebSocket frame metadata before
page teardown. Extracting the collectors into explicit lifecycles is planned in
[js-maintainability.md](./js-maintainability.md); retaining payload-free metadata
and existing diagnostic strictness is part of its acceptance criteria.
