# E2E concurrency (#1461)

Status: active. Acceptance requires five complete zero-retry passes at each
chosen high-worker setting on one commit; infrastructure checks alone do not
establish supported concurrency.

- [x] Inspect runner, template process ownership, fresh-agent setup and hardware.
- [x] Isolate generated sites, ephemeral listening ports and process teardown (Node lifecycle checks and both generated sites pass).
- [x] Implement phase timing, host pressure, server latency, renderer stalls and slow-test evidence (retained in focused and full runs).
- [ ] Benchmark 1, 2, 4, 8 and higher workers; compare shared vs isolated servers.
- [ ] Reproduce and fix failures with observable readiness.
- [ ] Repeat acceptance settings five times on the final commit; account for skips.
- [ ] Select measured local/CI budgets and document saturation/limitations.

Initial audit: before() creates fresh agents/drives, normal browser contexts have
separate storage, and the common fixture closes extra contexts. Template tests
instead share /tmp/atomic-data-template-tests and kill owners of fixed ports.
The local runner builds once per invocation but forces one worker. CI already
isolates one server per shard; its aggregate browser budget is eight on Mancave.

Measurement host: Mancave WSL2 reports 24 logical CPUs and 31 GiB RAM (not the
64 GiB described by older comments). The Mac has about 20 GiB used swap and
12 GiB disk free; do not use it for high-concurrency acceptance. Record competing
CI processes when measuring Mancave; do not stop unrelated jobs.

## Initialization and caching experiments

- [x] Reuse one frontend/WASM/native build across a matrix; retain build time
  separately. Each entry starts fresh server/data/config/cache directories.
- [x] Keep generated sites separate; use pnpm's content-addressed package store
  with prefer-offline resolution. Do not share mutable node_modules or compiled
  Next/Svelte outputs: those include the test drive and server URL.
- [x] Measure the shared before() dev-drive bootstrap as a named Playwright step.
- [ ] Rank bootstrap, template installation/build and test-body timings at each
  worker count; optimize the dominant repeated cost before choosing a cache.
- [ ] Compare a closed, initialized server snapshot cloned per shard with normal
  fresh startup. Never copy an open redb database; server identity, endpoint URLs
  and first-run configuration need explicit handling.
- [ ] Evaluate pre-created unique agent/drive fixtures for tests whose contract
  begins after login. Preserve dedicated onboarding/dev-drive/sign-in/OPFS tests
  on their real UI path. Browser storageState includes neither OPFS snapshots nor
  all CryptoKey persistence, so it cannot stand in for a signed-in disk image.

Avoid worker-scoped mutable agent/drive reuse: authorization tests and agent
settings mutate agent resources, so a fresh drive alone does not isolate them.
Browser contexts remain per-test; immutable downloads/build products are safe
sharing candidates. Two screenshot paths and the optional CDP trace path were
also global; they now use testInfo.outputPath.

Host limitation: Playwright 1.60 rejects Ubuntu 26.04 when selecting a browser.
Exploratory native WSL runs use PLAYWRIGHT_HOST_PLATFORM_OVERRIDE=ubuntu24.04-x64.
This is recorded separately from supported-container CI acceptance. The host's default Docker CLI is a stale Desktop symlink; a private CLI reaches
the healthy daemon. No runner services changed.

Pending spec comparison: AI, table tools, JSON, ontology, tags, file
picker and plugin tests now reuse the unique agent/drive already made by before().
Template tests do the same. Tests explicitly exercising login, onboarding,
additional drives or account switching keep those interactions. Table-refresh
cases no longer serialize or retry failed page loads internally; their existing
observable title/row expectations now expose failures. These changes remain
out of the first exploratory baseline so the comparison is interpretable.

Build reuse is content-based across spec-only commits, with artifact checksum
verification and a checkout lease. Ten standalone harness checks pass locally;
the E2E package type-checks against the freshly built library declarations.
The shared process supervisor now covers the local runner as well as generated
site fixtures, so interruption closes only live owned process groups.

First exploratory baseline was invalidated by another job: at 04:20:43 UTC
Atomic SaaS CI's Stop the stack step used `pkill -f target/debug/atomic-server`,
and our server logged SIGTERM at that instant. It had reached 156 passes;
the resulting connection-refused cascade produced 54 failures and two serial
cases did not run. This is not a concurrency or correctness baseline. The
runner now executes a private copied binary under the run artifact directory,
independent of other checkouts' target/debug paths. The matrix was stopped
before continuing comparison; reports remain retained.

Focused four-worker run: 20/24 passed in 3.3 minutes. Quick-add's deterministic
COMMIT gate and all three independently running table-refresh cases passed.
Both generated sites built and served on ephemeral ports; the Next test failed
its strict diagnostics on a background editor search 408. Generated build
workers are now capped and the editor disconnects after its saves settle.
Rename tests retain project-drive creation: the private dev-drive title is locked.

The ontology failure is a real delayed-completion race: CreateInstanceButton's
old save callback cleared classSubject after a new form opened. The existing
ontology test now gates that completion, failing deterministically with one
worker on the old product; state cleanup now happens before the async save.

Bootstrap profiling: 131 successful setups in the interrupted baseline had a
5.993s median, 8.322s p95, 831.74s accumulated. A focused profile attributed
4.676s to two client-db initializations (anonymous, then fresh agent). Dev-drive
now defers its anonymous worker; the lifecycle unit reproducer failed before
and both handoff tests pass after the fix. Browser timing comparison pending.
A cache-hit run skipped browser/native rebuilds; fresh server startup was 5.6–7.1s.
Given that startup occurs once per shard, prioritize per-test worker initialization
over copying mutable initialized server databases.

Latest focused validation: all 25 selected cases passed at four workers in
3.3 minutes, including gated ontology completion, quick-add/reload, all table
refresh cases, and both generated sites. The deferred startup preserves the
anonymous-to-agent boundary; otherwise its transient seed fingerprint forces
a full reseed on reload. The unit test now checks that no signed-out seed is
copied. Ten standalone runner checks pass, and the app/E2E typechecks pass.
Dagger functions and end-to-end help load with the new CLI overrides. A private
Docker CLI bypasses the stale Docker Desktop symlink; the daemon is healthy.

Verified WASM reuse reduced the browser build phase from 129.0s (including WASM)
to 25.0s (frontend only); native rebuild was 17.0s and startup 5.6s. Generated
site install times were 2.5s Next / 3.2s Svelte; builds 27.6s / 16.5s. Keep
separate install/build directories; immutable package downloads already cache well.
The latest dialog helper submits once and waits for closure, removing its
previous replay loop; the upcoming full run validates that change broadly.

Clean fefe4f223 full eight-worker run completed all 220 selected tests in 14.6m:
198 passed, 14 unexpected failures, 8 explained skips, zero retries. CPU was
near saturation during the busy section; failures include setup/static HTTP
408s and UI/persistence races. The remaining matrix was paused after this sample
(the next four-worker run was interrupted) to evaluate session snapshots at the
user's request. Artifacts: Mancave .e2e-runs/2026-09-12T04-55-38.256Z-saOPxH.

Session experiments: a closed persistent Chromium profile preserves Atomic's
IndexedDB CryptoKeys and encrypted OPFS database. On an unloaded host, one fresh
setup took 2.819s; two copied profiles restored in 0.921s and 0.904s including
~0.20s filesystem copies. Four concurrent clones on Playwright 1.60 restored in
1.650–1.833s and created separate drives/children, preserving the same agent,
distinct device IDs and independent local markers across navigation, with no
console diagnostics. This is a feasibility probe, not full-suite acceptance.

The user requested new Playwright: upgraded the package, lockfile and matching
Dagger image to 1.63.0. Its new `storageState({indexedDB:true,opfs:true})` exported
5.7MB in 0.619s but restored signing keys as non-CryptoKey objects, so it could
not restore authentication. Closed-profile copies work without that lossy JSON
serialization. Drive-scoped dashboard and table/view specs now opt into a worker seed / per-test clone and
fresh project drive through ATOMIC_E2E_CLONE_SESSION=1; default remains fresh.

Playwright 1.63 bundles Chromium 153.0.8010.12, whose new service-worker preload
world check emits false warnings. Reproduced both with clones (6/7 diagnostic
failures) and fresh sessions (2/7 diagnostic failures). The bundled code uses
pointer inequality; upstream 4df9ee2790a4 treats null and MainWorld() as equivalent.
Chrome stable 153.0.8010.36 does not contain that fix yet. A version-specific
pnpm patch adds the narrow compatibility flag to Playwright's existing disabled
feature list, preserving its other flags. Strict diagnostics and service workers
stay enabled; this browser-level isolation check is explicitly outside validation.
The patch must be removed when bundled Chromium includes the upstream fix.

Playwright 1.63 cloned-profile selection: 55/57 passed at four workers in 4.0m,
zero retries. The two failures were a ResizeObserver diagnostic in date filtering
and positional row insertion. The same fresh-session selection is being run
before drawing a performance/reliability conclusion. Artifacts: Mancave
.e2e-runs/2026-09-12T05-35-30.958Z-Pk1Lrs. Cloning remains opt-in.

Durable-write investigation: putResourceWithSnapshot already flushed internally
but swallowed flush errors; Resource then sent another flush RPC. That second
RPC can race identity teardown after a successful write. A failing unit
reproducer returned ok for a disk error. The worker now propagates errors and
keeps failed flushes retryable, while the caller relies on this single durable
response. Focused worker/store unit tests pass locally; real-browser validation
is pending.

Matched 57-test selection on Playwright 1.63: fresh sessions passed 57/57 in
6.5m, while the preceding cloned run passed 55/57 in 4.0m (38% shorter sample,
not accepted concurrency). Successful setup medians were 9.696s fresh versus
5.654s cloned; p95 11.150s versus 6.766s. Cloned worker seeds consumed 51.016s
combined, including replacement workers after failures. Host CPU medians were
71.5% fresh versus 67.6% cloned; server probe medians 12.7ms versus 12.8ms.
Artifacts for fresh: .e2e-runs/2026-09-12T05-43-40.130Z-bXBloz.

The resize hook wrote layout within ResizeObserver delivery. A unit test fails
on the old synchronous write and passes with one deferred/coalesced animation
frame and teardown cancellation. App typecheck and the hook test pass on Linux;
all 458 library unit tests pass locally. Cell focus now uses a normal click and
asserts focus in the requested cell rather than forced clicks and any grid focus.
Focused browser validation combines these fixes with persistence, heading-command
readiness and waiting for table creation before testing context menus.

Focused combined browser validation passed 21/22 selected cases in 1.4m at
four workers, zero retries; the sole existing skip is the Linux cmd+m context
menu shortcut (explicit fixme). Both previously failing table cases passed,
along with offline persistence, second-device load, sign-out/sign-in, documents
and context menus. Artifacts: .e2e-runs/2026-09-12T05-52-24.721Z-qruJy6.
The matching Playwright 1.63 noble CI image manifest is available for amd64
and arm64. Freeze this source for the next complete matrix.
