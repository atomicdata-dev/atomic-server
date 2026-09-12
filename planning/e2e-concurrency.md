# E2E concurrency (#1461)

Status: active. Acceptance requires five complete zero-retry passes at each
chosen high-worker setting on one commit; infrastructure checks alone do not
establish supported concurrency.

- [x] Inspect runner, template process ownership, fresh-agent setup and hardware.
- [x] Isolate generated sites, ephemeral listening ports and process teardown (Node lifecycle checks pass; generated sites pending).
- [x] Implement phase timing, host pressure, server latency, renderer stalls and slow-test evidence (browser validation pending).
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
This is recorded separately from supported-container CI acceptance. The host's
Docker executable currently fails with an I/O error; no runner services changed.

Pending spec comparison: AI, table tools, rename, JSON, ontology, tags, file
picker and plugin tests now reuse the unique agent/drive already made by before().
Template tests do the same. Tests explicitly exercising login, onboarding,
additional drives or account switching keep those interactions. Table-refresh
cases no longer serialize or retry failed page loads internally; their existing
observable title/row expectations now expose failures. These changes remain
out of the first exploratory baseline so the comparison is interpretable.

Build reuse is content-based across spec-only commits, with artifact checksum
verification and a checkout lease. Nine standalone harness checks pass locally;
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
