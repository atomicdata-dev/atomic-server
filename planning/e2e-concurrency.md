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
The local runner builds once per invocation but forces one worker. CI intends one server per shard; its aggregate browser budget is eight on Mancave.
The follow-up Dagger probe below found that identical definitions were deduplicated.

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

Frozen 815bae28d DEBUG-server eight-worker run: 206 passed, six unexpected
failures, eight existing skips, zero retries, 12.7m. The four-worker entry was
interrupted after discovering a major local/CI mismatch: local-e2e still built
target/debug, while CI atomicService already uses the optimized e2e profile.
Do not treat these debug-server timings as CI concurrency evidence. Retained
artifacts: .e2e-runs/2026-09-12T05-55-45.108Z-v7F7OE.

Local default now matches Cargo profile e2e; dev/release remain explicit
ATOMIC_E2E_CARGO_PROFILE overrides. Cache regression failed before profile-aware
keys and passes afterwards, preserving WASM reuse across native profiles.
Profile e2e retains debug assertions and overflow checks. Optimized browser
validation is pending; the first profile build is a separate one-time cost.

Menu focus now follows visibility in the same reveal callback, but this alone
did not fix the failure. A focus-call trace reproduced it in all eight parallel
copies: focusing the menu blurs EditableTitle, whose onCommit callback then
focuses the first table cell synchronously. Blur now saves without invoking the
Enter-only focus handoff. Validate the same eight-copy reproduction again. The user
drives case completed all assertions but used its 60s budget before teardown;
its own-drive and public-drive journeys now run as independent tests. Date
filtering still produced a ResizeObserver diagnostic under eight workers; trace
places it while the open popover anchor text changes, so inspect Radix/Floating
UI observation next. The website import took 25.142s before root lookup/render.
Offline-table and late second-user bootstrap failures included transport-level
408s. Re-evaluate those costs on the optimized server before tuning timeouts.

Optimized e2e-profile focused run: 28 passed, one context-menu focus failure,
one existing Linux shortcut skip, zero retries, 1.8m. Artifacts:
.e2e-runs/2026-09-12T06-14-08.241Z-8bEPim. Both split drive journeys and the
previously failing website/offline-table/second-device selections passed.
Playwright 1.63 officially supports Ubuntu 26.04; subsequent probes remove the
old Ubuntu 24 override inherited from the earlier Playwright version.

The first optimized native build took 8m21s, including 89.437s precompression.
A content-addressed Brotli cache in OUT_DIR now survives replacement of staged
frontend assets; each hit is decompressed and compared before reuse. Cache
publication is atomic, and compression honors Cargo NUM_JOBS. Corruption and
concurrent publication tests passed (2/2) under the optimized e2e profile.
The initial cache population compressed 67 files in 84.050s with zero hits;
warm-build timing remains pending.

Observer instrumentation reproduced the remaining date-filter warning in 1/8
runs and captured Floating UI anchor-size updates during operator changes.
The filter popover now requests frame-based position tracking; repeated browser
validation is pending. This is a hypothesis until that reproduction passes.

Post-fix validation: both targeted cases passed (11.6s). The exact menu probe
changed from 8/8 failures to 8/8 passes at eight workers (26.4s), proving the
blur focus handoff fix. Filter probe passed 8/8 at two workers (43.6s), including
strict diagnostics; full eight-worker suite remains the next check.
Artifacts: .e2e-runs/2026-09-12T06-42-59.446Z-2VqUuC,
/tmp/e2e-1461-focus-run-wLS7c7 and /tmp/e2e-1461-observer-run-cAKRsg.
App typecheck, focused lint (existing warnings, zero errors), formatting and
E2E typecheck passed. Freeze before complete optimized matrix.

Complete optimized 16ef6e015 eight-worker run: 211 passed, two failures,
eight existing skips, zero retries, 11.6m. Remaining failures were fork body
text (characters reordered) and website import completion. Other matrix entries
were stopped after the full eight-worker result to address these first.
Artifacts: .e2e-runs/2026-09-12T06-52-46.554Z-5b8bcN.

A DOM-free Loro/ProseMirror regression reproduces remote metadata moving the
selection from 3 to 5 before its deferred cursor timer fires. A narrow 0.4.3
patch restores selection in the same transaction, passing the regression.
The app's test resolver aliases Loro to web WASM, so this DOM-free test explicitly
mocks that import to Node WASM; app typecheck validation is being repeated.

Website timing probe: import HTTP completed in 1.5-1.8s, then local index search
consumed 22.0-22.6s before the server lookup. Store.search now has an explicit
serverOnly option for authoritative HTTP results after server-side writes;
template completion uses it. Its regression fails on the old local-index wait
and passes now, along with all 459 library tests. General/offline search remains
unchanged. Probe: /tmp/e2e-1461-import-run-YiKKkR (4/4 passed in 34.9s,
showing the delay rather than an absolute failure at this load).

Warm compression after these UI fixes: 40 verified hits among 67 assets,
15.321s versus 84.050s cold. WASM build was independently reused.

The fork/import/document selection passed 9/9 at eight workers in 33.9s,
zero retries, with both fixes. Artifacts:
.e2e-runs/2026-09-12T07-09-38.725Z-1MNyif.
The cursor regression passes on Linux with Node WASM, and app typecheck passes.
User asked for maximum parallel throughput on Mancave: prioritize full runs at
12, 16 and 24 workers, then compare eight, while retaining failures alongside
timings. No fastest reliable setting has been established yet.


## Follow-up after merging #1463

- [x] Merge the first improvements into develop (#1463, 3ac7aefe5).
- [x] Correct the library test formatting that stopped merged CI (#1464).
  Actual library, data-browser and E2E package format-check commands all pass.
- [x] Reproduce Dagger service deduplication with live containers on Mancave.
- [x] Give each shard a distinct runtime graph and hostname while sharing the
  binary build; expose cloned profiles through an explicit Dagger CLI argument.
- [ ] Validate the changed Dagger path with the actual E2E suite.
- [ ] Complete the maximum-worker matrix and repeated acceptance above.

The live Dagger probe bound the same service definition twice and a third with
an instance environment variable. The first two endpoints returned the same
process-start UUID; the third returned a different UUID. This confirms the old
shard setup shared writable server state. The fix varies the runtime only, using
the existing run nonce plus shard index. Browser-facing service aliases remain
`atomic`. Evidence: Mancave /tmp/e2e-1461-service-proof.log.

`ci` and `end-to-end` now expose `--playwright-clone-sessions`; schema/help loading
passes. The default stays false until full-suite acceptance. Worker and retry
defaults also stay unchanged. Mancave's runner service is active. The earlier
12-worker run was interrupted for the requested merge before completing and is
not a valid performance result. No maximum reliable worker count is established.


## Harness simplification

User requested less permanent harness complexity. Earlier measurements remain
historical evidence; retained artifacts are not deleted.

- [x] Replace local matrix scheduling with one stack and Playwright arguments.
- [x] Remove custom build hashes, host reporter and acceptance summarizer.
- [x] Keep process ownership, checkout locking, fresh data and private binaries.
- [x] Document explicit --skip-build and native reports/shell-loop comparisons.
- [x] Verify the simplified launcher with a real server/browser and Node checks.

Local builds use normal Cargo/pnpm behavior. --skip-build explicitly reuses
artifacts without claiming freshness. Dagger owns container caching and isolated
server shards. Deleted benchmark helpers remain available in Git history.

Refactor validation: all eight remaining Node harness checks pass; E2E typecheck,
lint and formatting pass (existing lint warnings remain). The simplified launcher
ran all seven dashboard tests with two workers and zero retries in 1.3 minutes,
using the existing optimized binary through explicit --skip-build. This validates
launcher/reporting/teardown, not a rebuilt full-suite acceptance result.
Artifacts: Mancave .e2e-runs/2026-09-12T08-40-34.904Z-VO9ZNy.
Both rebuilt launcher paths were subsequently validated as recorded below.


Merge validation: both rebuilt launcher paths pass their dashboard smoke case:
preview 6.4s (.e2e-runs/2026-09-12T08-47-06.245Z-Vq0M0u), embedded 8.6s
(.e2e-runs/2026-09-12T08-54-28.885Z-VDTlpU). Builds ran without --skip-build;
dependency/compiler caches were retained. The full Dagger run exposed a startup
failure: custom nonce hostnames plus Dagger DNS suffix exceeded the runtime's
hostname limit. Shards now use Dagger-generated names and retain the stable
consumer alias. Runtime identity still prevents service deduplication.


Full Dagger validation on adb66378b failed three tests: both generated templates
blocked on the unbundled i18n language property, and the discussion test asserted
its badge while the post-reload app was still on the startup splash. A bootstrap
unit reproducer fails before bundling i18n.json and passes after (3/3 tests);
app typecheck passes. Discussion alone passed five times (39.4s, two workers),
then was updated to the existing reloadReconnected helper so the badge's unchanged
15-second assertion starts after reconnect. Full Dagger rerun is required.


The ec38a1d37 full Dagger run (four isolated servers, two workers each, cloned
sessions enabled, zero retries) completed with 212 passed, six failed and eight
skipped. Failures: canvas and deep-link total test timeouts, a saved-drive reload
leader-election warning, server-only initial SUB/SYNC refusals, and both template
sync waits. The canvas and deep-link specs redundantly created another agent and
drive after their shared before hook; those extra calls are removed. Failure
snapshots now include scheduled saves as well as dirty/in-flight resources.

A rebuilt native run at two workers passed all 20 selected canvas, deep-link,
saved-drive, server-only, website and table-template tests in 3.6m, zero retries.
Canvas also passed eight focused repetitions before this run. The other failures
did not reproduce at this load; they are not claimed fixed. Artifacts: Mancave
.e2e-runs/2026-09-12T09-44-09.837Z-PqfUko. Eight Node harness checks and E2E
typecheck pass. Another complete Dagger run remains necessary before merge.
