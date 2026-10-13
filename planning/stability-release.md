# Stability release and data safety

> **Status: active, 2026-09-14.** Save acknowledgement, failure injection, and Chromium crash
> checks landed. Restore checks use Vault metadata plus retained external files;
> broader implementation and release acceptance remain open.

## Objective

Make Atomic Server safe to recommend for real data. Intermittent failures must
leave enough evidence to investigate, acknowledged edits must survive the failures
we claim to tolerate, and recovery must work when prevention fails.

This milestone covers the complete user data path: browser/native client,
persistence, sync, server, indexes, attachments, and backup/restore. Feature
completion and a green unit/E2E suite do not establish these guarantees.

Prioritize data safety, recoverability, and misleading success states over new
features. Do not turn this into a broad architecture rewrite. Extend existing
ingress, outbox, save-state, diagnostics, and test infrastructure.

## Starting evidence and ownership

- [Testing coverage](../TESTING_COVERAGE.md) records strong protocol coverage,
  glue-layer regressions, and platform acceptance gaps.
- [Silent failures](./silent-failures.md) records missing rows caused by stale
  views or incomplete indexes, and a desktop local-save claim requiring review.
  Entries are investigation leads, not proof that the current build still fails.
- [Unified data layer](./unified-data-layer.md) owns browser persistence and outbox
  architecture; [save signals](./unify-resource-dirty-signals.md) owns save status.
- [Unified sync](./unified-sync.md) owns transport and reconciliation work.
- [Sentry readiness](./sentry-feedback-readiness.md) owns reporting deployment gates.
- [Vault format](./encrypted-vault-format.md) and the sibling repository's
  `atomic-saas/planning/BACKUP_SECURITY.md` own backup and account recovery design.

This plan owns stability acceptance and prioritization. Keep implementation details
in those domain plans and update the coverage map as tests or gaps are identified.
Verify existing implementation before adding duplicate work.

## 1. Define and audit the guarantees

- [ ] Agree on the supported release matrix: hosted/standalone, browser/native,
  storage backends, browsers/devices, and supported upgrade paths.
- [ ] Trace each user-visible save state to its actual persistence acknowledgement
  on every supported runtime. Record gaps and assign owners.
- [ ] Audit attachment persistence alongside resource metadata: a saved reference
  must not imply that its file is durable when it is not.
- [ ] Turn the following proposed guarantees into executable acceptance checks.

| Promise | Required evidence |
| --- | --- |
| Saved locally | Acknowledged edits survive abrupt process termination and reopening on the same intact storage. |
| Synced to a node | The named receiving node durably accepted the edit; a socket send or broadcast is insufficient. |
| Save failed or was refused | Pending content remains recoverable, the failure is visible, and retry does not silently discard newer edits. |
| Reconnected | Replicas converge after successful reconciliation without losing acknowledged operations outside the defined conflict/deletion semantics. |
| Data is visible | Production query shapes and derived indexes agree with authoritative stored state after a defined settling bound, or report a detectable failure. |
| Backup available | A completed backup restores usable content, attachments, and required identity/access material in an empty environment. |

Distinguish local durability, replication, and backup in product copy. Local
persistence does not promise survival of browser storage eviction, disk loss, or
lost keys. Document recovery for those cases separately. A process-kill test does
not establish power-loss durability.

## 2. Make intermittent incidents diagnosable

- [ ] Add a bounded flight recorder to existing diagnostics. Retain recent semantic
  actions, resource lifecycle transitions, save/persistence acknowledgements,
  retries, connection changes, and storage errors.
- [ ] Include build/runtime identity and correlation IDs across client and server;
  use random session-scoped aliases for resources/drives, not their URLs or stable
  hashes. Scope correlation IDs to the diagnostic session or operation.
- [ ] Connect “Something went wrong” feedback to the preceding diagnostic window,
  even when there was no exception and the tester cannot describe the trigger.
- [ ] Define retention across reload/crash, storage limits, and export behavior.
  Diagnostics must not block saves or worsen a storage failure.
- [ ] Implement the collection levels and privacy acceptance checks below before
  expanding production incident reporting.
- [ ] Detect stuck saves, blocked queues, failed recovery, and index disagreement;
  error-free execution alone must not count as healthy operation.
- [ ] Finish applicable deployed Sentry/source-map/backend acceptance checks from
  the existing readiness plan.

Acceptance: a deliberately injected save/reconnect failure produces a useful,
bounded report linking the user action to the failed boundary without requiring
the tester to reconstruct events from memory.

### Privacy boundaries

Record what the system did, not what the user wrote. Production diagnostics should
explain whether an edit reached durable storage without collecting the edit.
Minimal metadata can still reveal activity patterns; do not describe it as
anonymous or risk-free.

| Level | Data | Activation and delivery |
| --- | --- | --- |
| Production baseline | Build/platform, predefined error codes, durations, queue counts, save-state transitions, temporary correlation IDs | Minimal collection during normal operation; external reporting follows the installation's explicit reporting configuration. |
| Temporary diagnostics | More detailed event ordering and lifecycle transitions, still excluding content | User explicitly enables a bounded local recording; automatically expires. Upload only with the user's report submission. |
| Test diagnostics | Detailed traces, payloads, or screenshots when needed | Isolated environments with synthetic data. A testing flag alone does not authorize capturing real user data. |

- [ ] Define an allowlisted, structured event schema. Do not capture arbitrary
  objects and rely on redaction afterward.
- [ ] Exclude titles, document text, filenames, resource URLs, query strings,
  credentials, signed payloads, request/response bodies, and raw console logs from
  production diagnostics. Prefer predefined failure codes over arbitrary error
  messages, which can embed sensitive values.
- [ ] Keep detailed recent events on-device in a bounded buffer. Provide a
  readable report preview and let users omit diagnostics before submission.
  Enabling local recording must not silently enable automatic uploads.
- [ ] Keep production session replay, DOM snapshots, and screenshots disabled by
  default; any exceptional capture needs a separate informed choice.
- [ ] Set concrete buffer limits, local/server retention periods, access controls,
  and deletion procedures before rollout. Temporary recording must expire
  automatically, including across restarts.
- [ ] Let self-hosted installations disable all external reporting. Apply the same
  collection policy to third-party telemetry SDKs and server-side reporting.
- [ ] Test the complete export/telemetry path with distinctive fake secrets,
  resource identifiers, and document text. Assert they never appear in production
  reports; also test field allowlists, bounds, expiration, and upload controls.

Start with save-state transitions, persistence acknowledgements, connection
lifecycle, and sanitized failure codes. Expand only when a concrete investigation
shows that additional metadata is necessary and its privacy boundary is tested.

## 3. Build a durability and recovery harness

Start with one workload: create a document, edit text, add table rows, and attach a
file. Track intended operations and observed acknowledgements in an independent
test ledger. Do not derive expected results solely from the store under test.

- [ ] Establish a baseline that restarts and verifies content, query membership,
  pending edits, and attachment hashes.
- [ ] Add controlled failpoints before/after local persistence, queue updates,
  remote durable acceptance, and acknowledgement delivery.
- [ ] Kill actual client/server processes without graceful cleanup. Verify the
  harness cannot accidentally flush state through normal object destruction.
- [ ] Exercise lost acknowledgements, duplicate delivery, reconnect during save,
  and edits made while an earlier save is in flight.
- [ ] Exercise storage write failures/quota exhaustion and refused remote writes;
  verify visible failure and retained content where intact storage permits it.
- [ ] Exercise concurrent edits during a network partition, then reconnect and
  verify convergence according to explicit conflict and deletion semantics.
- [ ] Expand deterministic cases into seeded operation/failure schedules. Retain
  the seed, schedule, build IDs, acknowledgement ledger, and diagnostic artifacts.
  Minimize failing sequences into focused regressions.

Start disjoint edits with simple expected outcomes. For conflicting edits, define
an independent semantic oracle; comparing replicas alone can miss identical loss.
An unacknowledged operation may have persisted, so allow that outcome while
requiring every acknowledged operation to be accounted for. Do not equate LWW
resolution or an authorized later deletion with accidental loss.

Place checks at the cheapest effective layer: Rust/JS units, real-server
integration, then production-build browser tests for actual OPFS, lifecycle,
rendering, and UI save claims. Keep broader fault campaigns outside the smoke suite.

## 4. Exercise lived-in workspaces and supported devices

- [ ] Maintain versioned representative fixtures with rich history, tables,
  attachments, deletions, permissions, and pending offline work.
- [ ] Upgrade fixtures from each supported prior release and verify content,
  identity/access, indexes, attachments, and subsequent edits.
- [ ] Run sustained workloads against persistent workspaces, including reload,
  multiple tabs, account switching, sleep/wake, and network changes.
- [ ] Check that late asynchronous work cannot cross account/drive boundaries.
- [ ] Run physical browser/native acceptance where automated environments do not
  establish storage, lifecycle, or credential-provider behavior.
- [ ] Capture the actual application query when investigating missing rows;
  compare UI, exact query results, indexes, and authoritative resource state.

Keep fresh-agent E2Es for isolation. These longer-lived checks supplement them.

## 5. Prove recovery independently of replication

- [ ] Inventory what each backup contains and excludes, including blobs, history,
  identity material, and dependencies on account services.
- [ ] Define acceptable backup age and recovery time for supported deployments.
- [ ] Restore into an empty environment and compare resource contents and file
  hashes; verify users can open and edit the restored workspace.
- [ ] Test interrupted/incomplete backups and ensure they cannot be advertised as
  successful replacements for the last usable backup.
- [ ] Test recovery with lost device state and the supported recovery credentials;
  document what is unrecoverable without keys.
- [ ] Verify retained historical copies can recover accidental deletion or
  corruption propagated through sync.
- [ ] Schedule recurring restore drills and retain their evidence.

## 6. Triage and release gates

Every intermittent failure gets an incident record with build/platform, impact,
evidence, owner, and status. Separate actual persistence loss, rejected/unsent
writes, convergence failures, stale views/indexes, and identity/routing mistakes.
All can make data appear gone; classification must follow evidence.

- [ ] Record first-attempt failures even when retries pass. Classify product,
  harness, and infrastructure faults; do not treat retry success as resolution.
- [ ] Require a regression at the cheapest failing layer for each confirmed bug.
- [ ] Give quarantined tests an owner, reason, and review date. Quarantine cannot
  waive a data-safety gate.
- [ ] Set explicit reconciliation/save time bounds, campaign sizes, soak duration,
  supported platforms, and evidence retention before release acceptance starts.
- [ ] Track acknowledged-write loss, false success claims, stuck saves, convergence
  failures, restore success/time, and first-attempt failures with workload counts.

Release only when:

- [ ] No known unresolved acknowledged-write loss or false saved/synced claims
  remain in the supported matrix; unexplained possible-loss incidents are resolved.
- [ ] Deterministic crash/reconnect/storage-failure checks pass.
- [ ] The agreed seeded campaigns and soak period complete without unresolved
  safety failures on the actual release candidate.
- [ ] Supported upgrade checks and full empty-environment restore drills pass.
- [ ] Diagnostic delivery works from deployed builds and reports can be acted on.
- [ ] Evidence records exact builds, platforms, workloads, failures, and limitations.

Passing these gates provides bounded evidence, not proof of zero possible bugs.
Publish the supported guarantees and recovery procedure with the release.

## First implementation slice

1. Audit local/remote save acknowledgement boundaries and existing regression
   coverage; confirm whether historical desktop save warnings still apply.
2. Capture one complete save lifecycle through the existing diagnostics and
   feedback path, including a deliberately failed save.
3. Implement one real abrupt-termination/restart scenario with a document, row,
   and attachment, checked against an independent acknowledgement ledger.
4. Perform one empty-environment restore drill and record concrete gaps.

Use these results to order subsequent work by demonstrated risk. Each completed
slice must include reproducible evidence, not only a new test count.

### Save acknowledgement audit — 2026-09-14

Branch: `codex/save-durability-audit`. Scope is the shared save boundary; this
does not establish complete document/table UI or native-platform acceptance.

| Path | Inspected boundary | Finding |
| --- | --- | --- |
| Browser explicit online save | `Resource.save()` drains the outbox, checks acknowledgement/version, then awaits `persistToClientDb()` | Local snapshot RPC is awaited before returning `persisted`; remote durability depends on server acknowledgement semantics. |
| Browser local snapshot | `persistToClientDb()` awaits `putResourceWithSnapshot` | Worker durability tests cover the flush barrier and errors. Chromium crash checks exercise real OPFS with remote recovery blocked. |
| Browser offline/local-only | `saveOffline()` / `saveLocalOnly()` require local persistence | Missing/unsupported storage now rejects. Failed local-only saves retain signed work for retry and remain unsaved. Children waiting on a new parent return `queued` rather than claiming local durability. |
| HTTP and WebSocket commits | Both use `handlers::commit::apply_commit_json` | Reproduced loss: acknowledged name reverted after unclean exit before the periodic flush. Handler now awaits a blocking-pool durable flush before returning success; crash regression and server checks pass. |
| Desktop | Embedded server; no browser ClientDb (`desktop/src/lib.rs`) | Server acknowledgement is the local durability boundary when connected. Disconnected saves without ClientDb now reject; actual native acceptance remains open. |
| Connection-loss messaging | `NetworkIndicator.tsx` | Original connection-loss toast wording retained following review. Save failures are errors rather than queued/idle; the inspector offers Retry save. Save-state kinds use the exported `ResourceSaveStateKind` enum. |

- [x] Run existing save acknowledgement, worker durable-put, and scheduled-save
  suites: 17 tests passed across three files.
- [x] Reproduce and fix early server acknowledgement with a subprocess test
  using real redb, no graceful shutdown, and no periodic flush to hide the gap.
- [x] Verify the fix and relevant server HTTP/WS regressions: server library suite
  76 passed, 2 intentionally ignored (S3 environment test and subprocess entry);
  WebSocket commit and drive-isolation integration tests both passed.
- [x] Fix unsupported/offline local-save claims with focused regression coverage.
  Client library: 498 tests pass. Compiled browser retry/reload scenario passes.
- [x] Add Chromium document/table crash acceptance: three consecutive passes,
  each with two SIGKILL/reopen cycles and remote data access blocked.
- [ ] Add attachment recovery and native/other-browser crash acceptance.

The first server test uses an existing drive resource's name edit and the shared
HTTP/WS handler directly. It records the acknowledged subject outside the database,
exits without destructors, and reopens the same store. It deliberately excludes
the periodic flush thread, modeling a crash before the next tick. It does not
exercise network delivery, browser UI, attachment durability, or power loss.

The fix adds a durable flush per successful HTTP/WS handler call. Flush errors
propagate instead of returning success; the periodic flush remains for other
writers. This prioritizes the acknowledgement contract but may increase write
latency and disk I/O. Throughput benchmarking and a possible shared group-commit
barrier are follow-ups; any batching must retain the same durability guarantee.

Validation commands:

```sh
ATOMICSERVER_SKIP_JS_BUILD=true cargo test -p atomic-server --lib --no-default-features --features light
ATOMICSERVER_SKIP_JS_BUILD=true cargo test -p atomic-server --test it ws_commit --no-default-features --features light
cd browser/lib
pnpm exec vitest run src/save-acknowledgement.test.ts src/client-db-durable-put.test.ts src/scheduled-save.test.ts
```

The Rust checks used the light feature set. Existing frontend assets were reused;
these checks establish server behavior, not a rebuilt frontend or default-feature
release acceptance. `git diff --check` passed.

### Browser acceptance and runner findings

The next browser checks build the frontend/WASM and default-feature server. The
first attempts exposed runner issues before reaching the new scenarios:

- Installed Playwright rejects `install --no-remove`; use
  `PLAYWRIGHT_SKIP_BROWSER_GC=1` to preserve other installed browser versions.
- Cargo built beta.7 into its configured shared target directory, while the runner
  copied a stale beta.2 binary from the repository's `target/debug`. The runner
  now obtains `target_directory` from `cargo metadata` instead of guessing it.

Those failed runs do not establish product failure or durability acceptance. The
crash test owns a dedicated Chromium persistent profile and obtains that browser's
PID through CDP before sending SIGKILL. On restart, HTTP data access and WebSocket
sync are blocked so remote copies cannot rescue missing local edits.

Accepted local evidence:

- `.e2e-runs/2026-09-14T13-55-58.954Z-Svh0AH`: rebuilt frontend/WASM and
  default-feature beta.7 server; both inspector save tests passed. The crash
  content checks passed, but the harness incorrectly required a warning for each
  deliberately closed socket, including closes preempted by process termination.
- `.e2e-runs/2026-09-14T13-58-19.747Z-2anKCD`: reused that build, corrected the
  diagnostic expectation to permit at most one specifically identified warning
  per injected close, and passed the crash test three consecutive times (56.8 s).
  No unexpected diagnostics are permitted. Earlier first-failure artifacts remain.
- All 498 client-library tests, seven process-runner tests, UI and E2E typechecks,
  changed-source lint/format, and `git diff --check` pass.

The retry button needed its new message in the locale catalogs; the compiled UI
test caught the missing label. Its click handler now handles the save rejection
while the subscribed resource state keeps the failure visible and retryable.

**Historical toolchain limitation (resolved in the failure-boundary slice):** the earlier installed environment used pnpm 8.15.0 and
Playwright 1.60.0, while the repository pins pnpm 10.15.1 and Playwright 1.63.0.
The runner's install subprocess printed replacement prompts and exited without
bringing them into alignment. Corepack resolves the pinned pnpm, but nested bare
`pnpm` commands still resolve to 8.15.0 on this machine. These results are valid
local source-level checks under the installed toolchain, not frozen-lockfile
release acceptance. Do not count the reported install phase as verification.

- [x] Make runner installation noninteractive and pin nested package-manager
  calls; verify installed Playwright and record both versions in `toolchain.json`.
  Rebuilt browser checks now use pnpm 10.15.1 and Playwright 1.63.0. Full release
  acceptance across the supported platform matrix remains open.

Public API note: `SaveResult` now includes `queued` for an unsaved parent. It
explicitly carries no durability promise; consumers that exhaustively switch on
the result must handle it. `offline` is reserved for successful local persistence.

### Durable acknowledgement throughput probe

Manual probe, local macOS, Rust debug/light build, real redb, synthetic folder
renames. Each writer performs 16 sequential edits; writers run concurrently on
independent resources in one database. Timing includes signing, validation and
persistence, not HTTP or browser latency. Both modes retain the 100 ms periodic
flush. The baseline intentionally reproduces the unsafe early acknowledgement;
it is a comparison, not an acceptable implementation.

Repeat measurement after builds/browser tests finished:

| Concurrent writers | Operations | Periodic-only ops/s | Durable-ack ops/s | Periodic-only p95 ms | Durable-ack p95 ms |
| --- | --- | --- | --- | --- | --- |
| 1 | 16 | 28.6 | 17.0 | 42.19 | 124.01 |
| 4 | 64 | 82.7 | 66.1 | 100.89 | 69.68 |
| 16 | 256 | 93.6 | 72.7 | 53.59 | 386.06 |

The earlier run overlapped other build activity, so it is not the primary
measurement; at 16 writers it also showed a roughly 380 ms durable-ack p95.
Small sample sizes and inconsistent low-concurrency tails preclude a production
capacity claim. The high-concurrency cost merits a group-commit experiment, not
removing the durability barrier. The probe checks final values for all writers.

Reproduce with:

```sh
ATOMICSERVER_SKIP_JS_BUILD=true cargo test -p atomic-server --lib compare_acknowledgement_throughput --no-default-features --features light -- --ignored --nocapture
```

- [x] Measure per-commit flush cost under concurrent writes.
- [ ] Benchmark an optimized build on representative deployment storage and agree
  on latency/throughput targets.
- [ ] If needed, prototype one shared flush barrier that acknowledges a batch only
  after its durable commit point; preserve crash and flush-failure guarantees.

### Commit gate repair — 2026-09-14

The first stability commit bypassed a failing pre-commit hook. That was not an
acceptable release signal. Follow-up work keeps the existing strict hook and
fixes its failures, including those outside the original save changes.

- [x] Remove redundant clones and deprecated test macros, simplify optional
  values, name shared callback/map types, and gate image helpers with `img`.
- [x] Replace the deprecated async WASM constructor with `ClientDb.open()` and
  update the worker opener and its recovery tests together.
- [x] Pass the complete workspace Clippy command with `-D warnings`.
- [x] Pass 498 client library tests, frontend typecheck, and three rebuilt-WASM
  save/crash browser tests (`2026-09-14T14-52-22.823Z-phgG97`).
- [x] Pass 76 server unit tests (three intentionally ignored).
- [x] Verify core sync tests in their documented serial mode: 183 passed, one
  intentionally ignored. Both Iroh failures from the broad parallel run passed
  serially; that earlier run passed 603 core tests and ignored eight. Keep the
  shared-global Iroh suite serial as documented in `lib/src/sync/iroh_e2e.rs`.
- [x] Commit with the unmodified pre-commit hook enabled: staged browser lint
  and formatting, complete workspace Clippy with `-D warnings`, and its nested
  JS/WASM asset build all passed. No hook or lint suppressions were added.

### Failure boundaries and recovery — 2026-09-14

- [x] Pin nested runner commands to Corepack pnpm and fail on a mismatched
  Playwright installation; frozen noninteractive install resolves pnpm 10.15.1
  and Playwright 1.63.0. Regression checks exercise an older pnpm on PATH.
- [x] Default Cargo libtest to serial execution; nextest remains process-isolated.
- [x] Inject server flush failure and retry the exact signed commit, then replay
  a lost acknowledgement. No successful acknowledgement on failure and no
  duplicate history after retries.
- [x] Reproduce missing worker blob flush with a failing test, then require
  durability before acknowledging `putBlob`; flush errors remain retryable.
- [x] Verify the client outbox against a real server that loses an acknowledgement
  after accepting a genesis, with a second edit made before retry. The same signed
  genesis is replayed and an independent server read sees the final edit.
- [x] Extend the Chromium crash ledger with attachment bytes and SHA-256 checks.
  Corrected-harness run `2026-09-14T15-23-42.129Z-LXAlAO` passed using the freshly
  rebuilt pinned-toolchain artifacts from `2026-09-14T15-19-32.375Z-PbLWDT`.
- [x] Correct the restore drill to match hosted storage: Vault restores resource
  metadata; file bytes remain in the independently configured S3 backend.
  The drill replaces the graph database and reconnects the configured S3 backend, checks four resources and parent links, edits a restored document, and
  verifies the restored file reference and 65,537 bytes by BLAKE3.

**Correction:** the initial drill incorrectly required file bytes inside the
restored local database. Its failure did not demonstrate missing hosted backups.
Vault does not store files. Hosted recovery requires both Vault metadata and access
to the existing S3 bucket/prefix. Losing that bucket is a separate recovery
scenario; an independent S3 protection/recovery policy must cover it.

- [x] Verify metadata restore, attachment retrieval through the production S3
  adapter, and a subsequent edit against scratch MinIO (2026-09-15).
  SaaS Vault API and HTTP download authorization remain separate checks.
- [ ] Document and exercise recovery for deleted/corrupt S3 objects and bucket loss,
  with retention aligned to the supported Vault restore window.

Reproduce the independent restore check with:

```sh
cargo run -p atomic-server --no-default-features --features light --example vault_restore_drill
```

This is a standalone acceptance probe, not an ignored test or a successful backup
claim. It uses only synthetic data, drops the source store before restoring into
an empty one, compares against an independent ledger, and retains its encrypted
filesystem vault and separate file fixture for inspection. It fails on missing or
corrupt externally stored bytes. See the September 15 acceptance below for S3
validation. Full rich-text history and schema/column fidelity still
need a richer fixture; this first drill checks resource fields and parent links.

First pinned Chromium attempt (`2026-09-14T15-19-32.375Z-PbLWDT`) passed both save
UI tests but exposed a harness race: the row ledger captured its `_new:` ID before
awaiting save, although the row itself restored and was visible. The ledger now
captures the final DID after save and asserts it is stable. First-failure artifacts
are retained; that failed run is not counted as complete crash acceptance.

Validation for this slice: 500 client-library unit tests, the real-server lost-ack
integration test, both runner toolchain tests, and E2E typecheck pass. Both save UI
cases passed in the fresh pinned build; the corrected attachment crash case passed
against those same artifacts. Strict workspace Clippy passes. The original vault
probe failed because of an incorrect local-blob expectation; the corrected probe
checks retained external storage through the BlobBackend API instead. The corrected
run passed: four resources, a subsequent edit, and all 65,537 attachment bytes
matched (`complete: true`, zero unreadable objects). The backend was a filesystem
test double; live S3 recovery remains a separate acceptance check.
No real user data or telemetry was involved.

Final isolated crash acceptance: `2026-09-14T15-28-42.714Z-QSVPbU` passed after
also blocking `/blob` requests and service workers. The preceding isolation run
recovered every value/byte but failed diagnostics on Playwright's own deliberate
service-worker-blocking warnings; those now have an exact-message, four-navigation
allowance. Product warnings/errors remain failures. Both server durability tests
pass together (one subprocess entry point is intentionally ignored by the parent).

## Hosted restore acceptance and retention — 2026-09-15

The executable now lives in `server/examples/vault_restore_drill.rs` so it can use
`atomic_server_lib::blob_storage::from_config`, the production S3 adapter. It
requires a scratch bucket and overrides the object prefix with a unique
`restore-drills/atomic-vault-restore-drill-*` namespace. It never deletes existing
objects. Vault metadata remains a local encrypted fixture; this checks graph
restore plus S3 file retrieval, not the SaaS Vault API or browser download route.

Run with the documented `ATOMIC_BLOB_BACKEND=s3` and `ATOMIC_S3_*` configuration:

```sh
python3 scripts/verify-vault-s3-restore.py
```

The runner retains JSON evidence and stderr in a temporary evidence directory.
Healthy recovery must pass. Missing-object and corrupt-object controls must fail
recovery while still restoring all four resources and allowing a subsequent edit.
The missing control reconnects an empty prefix; the corruption control overwrites
only its newly created synthetic object. Remove only the reported fixture prefixes
from the scratch bucket after inspection. Never point this drill at production.

### File retention contract

- Vault metadata recovery requires the same S3 bucket/prefix (or a restored copy)
  and working credentials. Credentials are recovery configuration, not Vault data.
- Every attachment referenced by any supported Vault restore point must remain
  recoverable. Current-state references alone are insufficient for file GC.
- Until a historical-reference-aware GC exists, do not expire hosted file objects
  by age. Keep the hosted file namespace outside Vault object cleanup.
- Protect deletion/overwrite using provider-supported object versioning or an
  independent recoverable copy. Retain those versions/copies for at least the
  advertised Vault recovery window plus the incident detection/recovery margin.
- A separate copy must cover bucket/account loss if that failure is promised;
  keeping versions only in the same bucket does not establish that guarantee.

Repository inspection found no deployed hosted-file lifecycle/versioning policy
in the available configuration. This is an **unverified operational guarantee**,
not evidence that the provider currently has no protection. Do not advertise a
specific recovery window until the deployment policy and a recovery drill agree.

- [ ] Record the actual hosted bucket/prefix, policy owner, supported recovery
  window, version/copy retention, credential recovery procedure and last drill.
- [ ] In a disposable bucket configured like production, write a file, capture
  its hash/version, then delete and overwrite it. Restore the earlier bytes using
  the configured provider mechanism and verify the original hash and Vault link.
- [ ] Restore an independent copy into a new bucket, reconnect restored metadata,
  verify downloads and edits, and record elapsed time and latest recoverable point.
- [ ] Confirm lifecycle/GC preserves files referenced by the oldest supported
  Vault restore point, including files deleted from the current graph.

These operational checks remain open; this task does not change deployed bucket
policies or assert production recovery coverage from a local MinIO result.

### Recorded acceptance

2026-09-15: all three cases passed against local MinIO
`RELEASE.2025-09-07T16-13-09Z` (Quay image digest
`sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e`).
Healthy recovery returned `complete: true`; missing and corrupt controls returned
`complete: false` and nonzero exit codes. Each restored four resources, preserved
parent links, accepted an edit, and reported zero unreadable Vault objects. The
healthy file was 65,537 bytes with the expected BLAKE3 hash. Neither database held
local blob bytes. Strict Clippy for the example passed.

Evidence directory from this run:
`/var/folders/n1/1f33j70s5vs1ytzpshgpk11h0000gn/T/atomic-s3-restore-evidence-1_2zyl4u`.
Only a disposable local bucket and synthetic data were used. The test container
was removed after validation; the JSON reports and local Vault fixtures remain.


## Initial local diagnostic recorder — 2026-09-15

Historical implementation below. Default persistent recording now supersedes the
opt-in/memory-only policy and 30-minute app recording limit; see schema 3 below.

- [x] Add an opt-in recorder per Store, with fixed event codes and explicit numeric
  fields. Resource aliases use weak object identity within one recording; no URLs,
  titles, filenames, raw errors, request bodies, or signed data enter the buffer.
- [x] Record save start/outcome, outbox drain attempts/results, connection changes,
  pending and blocked counts. A save running for 30 seconds produces `save-slow`;
  an online pending queue with unchanged counts for 60 seconds produces
  `queue-stalled`. These are investigation hints, not proof of data loss.
- [x] Bound events and unfinished-save tracking to 500 entries each. Keep a rolling
  10-minute event window, stop and erase after 30 minutes, and clear on account
  changes. Recording is memory-only; reload/crash loses it and does not re-enable it.
- [x] Add controls in Feedback to start/clear recording, preview a frozen report,
  download JSON, and explicitly include that exact preview with feedback. Inclusion
  defaults off; refreshing the preview resets inclusion. A cleared/expired session
  cannot submit an older preview. Recording does not enable Sentry or networking.
- [x] Include build identity and a fixed browser runtime label. Feedback events use
  an allowlist that excludes inherited Sentry breadcrumbs, URLs, user context,
  arbitrary tags and extra fields. User-entered message/email remain intentional.
- [x] Cover bounds, expiry, late completion, actual save rejection, listener failures,
  account changes, frozen preview selection, explicit inclusion, and privacy filters
  in unit tests. Browser acceptance intercepts Sentry; it never sends a real report.
- [ ] Add separate local storage/server acknowledgement stage codes, cross-process
  correlation, and resource lifecycle/index diagnostics as needed by real incidents.
- [ ] Decide a production report retention/access/deletion policy before expanding
  collection. This slice inherits the installation's existing Sentry opt-in setting.

Operational limits: recording must be enabled before reproducing an issue. It is
not a crash-persistent recorder and captures no payloads or replay. Downloaded or
explicitly submitted reports outlive the local recording according to the user's
file handling or the installation's existing reporting policy. Background browser
suspension can delay timer-based warnings and clearing until execution resumes;
export checks expiry synchronously as well. Local storage failures cannot break
recording because the recorder performs no storage writes.

Validation: 508 client-library tests and 894 app unit tests passed; all 11 focused
report/privacy tests also passed after the expiry changes. Fresh pinned browser
run `2026-09-15T09-22-55.392Z-VIsqtQ` passed all five selected feedback/Ollama tests
(19.4 seconds), including exact preview-to-envelope equality, JSON download,
private content/URL exclusion, and recording off after reload. The preview
screenshot was visually checked. Earlier first attempts exposed missing generated
locale entries (`2026-09-15T09-16-36.692Z-rqhO0h`) and a React Compiler cached
recording flag (`2026-09-15T09-19-48.442Z-Vq2ACo`); both were corrected, and their
failure artifacts remain. No real reports were submitted.

Compiler follow-up: removed the unsupported `finally` in `FeedbackMenuItem`;
Oxc now reports zero diagnostics and emits memoization. A targeted regression
requires both feedback components to compile without bailouts. All 12 focused
compiler/feedback tests and app typecheck pass. Browser run
`2026-09-15T09-58-43.250Z-3g0p9m` passed all five feedback/Ollama tests against
freshly rebuilt assets (17.7 seconds). The preceding build attempt ran out of
Cargo cache space; removing stale Atomic Server incremental caches allowed the
same server build to complete. No tests or hooks were bypassed.

## Agent-readable diagnostics (schema 2)

- [x] Add separate local persistence, server submission, outbox and reconciliation boundaries.
- [x] Include ordered evidence IDs, operation IDs and anonymous resource aliases; document that alias correlation is not causality and call ordinals are not proven retries.
- [x] Embed event meanings, missing capabilities, collection limits and dropped/unfinished evidence counts in the frozen report.
- [x] Preserve opt-in preview/export and content-free recording.
- [x] Add an investigation guide and deterministic fault-injection evidence tests (see `browser/DIAGNOSTICS.md`).
- [x] Run an initial blind cheaper-model triage pilot: GPT-5.6 Luna correctly interpreted four synthetic reports (19/20 qualitative rubric points). See `browser/diagnostic-evaluations/2026-09-15/README.md`.
- [ ] Broaden to independent runs and real transport faults; the pilot does not establish production accuracy or repair ability.

Validation: the full library suite passed (511 tests), followed by the added
reconciliation test (12 diagnostic tests total). Nine report/privacy tests,
library/app/E2E type checks, workspace lint, and both Feedback React Compiler
checks passed. A fresh frontend build and recovered server build passed;
all five feedback browser tests passed in
`.e2e-runs/2026-09-15T11-20-27.582Z-q9g1ag` (17.8s), including schema-2 export,
privacy, download and explicit inclusion. Initial server compilation exhausted
the shared cache; deleting older rebuildable incremental entries resolved it.
The frontend build also refreshed locale metadata in already-modified catalogs.


## Default persistent diagnostics (schema 3)

- [x] Enable app recording by default; standalone library Stores remain opt-in.
- [x] Use independent IndexedDB storage with two-second batched transactions, a
  shared 500-event / 20-session cap and ten-minute retention on reads/writes.
- [x] Restore prior recording sessions without merging their aliases, operation
  IDs, elapsed times or build identities. Export no persistent IDs/timestamps.
- [x] Freeze history when Feedback opens; keep explicit inclusion unchecked.
- [x] Persist disable-and-clear; reset on account changes and fence stale tabs.
- [x] Expose memory fallback, pending writes and failed preference/clear operations.
- [x] Test retention, reload, stale writer and account-reset races, failure handling
  and privacy allowlists at the helper layer.
- [x] Verify the real IndexedDB reload/disable/multi-tab journey in Chromium.

Limits: batches can be lost in a crash. Background timers can be delayed. Expired
records remain on disk until the app next accesses storage. If IndexedDB cannot
open, its stored preference cannot be read and this session records in memory.
Clearing failures stop recording and require an explicit retry or site-data clear.


Validation for schema 3: all 512 library tests and 916 app tests passed; workspace
lint, app/E2E TypeScript checks and the three edited React modules' compiler checks
passed. Six Chromium feedback tests passed (24.7s) in
`.e2e-runs/2026-09-15T11-57-28.100Z-v5b0qw`, including real IndexedDB reload,
persisted disable/clear and cross-tab pausing. The preview screenshot was inspected.
The embedded and built frontend index hashes matched for that run.

An initial browser attempt was invalidated by a standalone frontend rebuild
without the runner's E2E environment; the final run used the normal runner end to
end. Broad app tests also exposed a compiler-hook fixture timeout: its CLI changed
TMPDIR only after fixture Git setup. A fresh-TMPDIR Git probe measured 2.9 seconds
versus roughly 25ms for subsequent calls, exceeding the hook's five-second budget
under load. Fixture setup now uses the same TMPDIR as its CLI; the normal parallel
suite passed without changing the production hook's timeout or checks.

Existing locale edits were preserved; only five new diagnostic UI messages were
added to each catalog. No real feedback was sent; browser tests intercepted it.

- [x] Simplify feedback diagnostics: keep the explicit “Include diagnostic data” checkbox between feedback and email, and place recording controls and preview inside a collapsed Diagnostics disclosure. Existing browser scenarios now expand the disclosure before using those controls.

## Interrupted two-client reconciliation — 2026-09-15

- [x] Add a deterministic real-server integration scenario with separate accounts
  and independent WASM client databases. Both clients edit different fields of
  the same resource and create child rows while HTTP and WebSocket access are
  unavailable. Expected field values and row names are defined before writes.
- [x] Forward a real SYNC probe and immediately disconnect its client before
  response delivery. Record and assert the fault boundary was reached.
- [x] Acknowledge a further offline edit, assert it remains queued, discard the
  Store/resource/outbox instances, and rehydrate from the retained database and
  persisted outbox. Reconnect both clients and require convergence.
- [x] Check both local databases directly, plus an independent server reader,
  against the expected values and row identities. Require empty, unblocked queues.
  On failure emit the ledger, acknowledgement results, sync status and diagnostics.
- [x] Extend the combined scenario to actual Chromium process termination with
  persistent storage; see the crash acceptance and resulting fix below.
- [ ] Expand into seeded failure schedules and conflicting-edit semantics after
  the deterministic baseline.

Run from the repository root:

```sh
corepack pnpm --dir browser/lib test:integration interrupted-sync.integration.test.ts lost-ack.integration.test.ts
```

This checks resource-level disjoint field edits and child rows, not rich-text
editing, table UI/query membership, attachments, server restart or power loss.
The deterministic scenario passed without a production code change.

Validation: the new scenario and existing lost-ack integration test passed together
(2 tests, 15.02 seconds). Library typecheck and a separate TypeScript check that
includes the new integration file passed, as did focused lint/format checks and
`git diff --check`. The ordinary library tsconfig excludes `tests/`, so its
typecheck alone would not validate this new file.


## Two-client browser crash acceptance — 2026-09-15

- [x] Add a full-suite Chromium test with two dedicated processes/profiles and
  real OPFS. Both clients edit different fields and create child resources offline.
- [x] Interrupt a forwarded SYNC probe, acknowledge a further offline edit and
  SIGKILL only the owned browser process without an explicit flush or unload.
- [x] Reopen the same profile with HTTP data access and WebSocket recovery blocked;
  read OPFS directly before allowing either client to reconcile.
- [x] Reconnect both clients and compare their local databases and forced HTTP
  server reads with an independent expected-value/acknowledgement ledger.
- [x] Retain the ledger, recovered outbox, browser diagnostics and per-client
  diagnostic windows as test artifacts.

The new test exposed acknowledged-edit loss after recovery: OPFS retained the
final edit, but the outbox's localStorage entry was absent after SIGKILL.
Subsequent incoming state could build a Resource from only the older server
snapshot and overwrite OPFS when the local resource was not mounted.

The first run stopped on an overly strict assertion that an outbox entry must
survive. The second checked the actual user-data contract and failed: the final
name became the earlier name after reconciliation. The smaller
`cold-ingress-recovery.test.ts` reproduced the overwrite without a browser.
The Node integration scenario alone did not reproduce the browser's ingress
ordering, even with localStorage queue metadata removed.

Remote HTTP and WebSocket ingestion now reads the local snapshot before applying
remote state, merges complete local causal history instead of replacing it,
serializes updates per subject, and rejects late work after a database/connection
change. Storage read failures fail ingestion rather than overwrite unread data.
Local synchronous ingestion remains unchanged. This adds a local read to remote
ingestion; it does not make localStorage crash-durable or introduce a new outbox.

The test-storage double now returns the real ClientDb cache-miss shape
(`{jsonAd: null, snapshot: null}`) rather than undefined. Two existing tests
revealed that mismatch when HTTP ingestion began consulting local storage.

An initial rebuilt-browser acceptance passed (19.3 seconds) in
`.e2e-runs/2026-09-15T14-21-42.191Z-Sw0ygt`.
A later combined run (`2026-09-15T14-29-03.451Z-vPYRWE`) failed again, so that
initial pass was insufficient. Tracing in `2026-09-15T14-34-02.811Z-TzjaiF`
showed collection JSON hydration rebuilding a fresh LoroDoc and replacing the
original persisted history. The visible local value survived, but the other
client and server did not converge. A unit regression compared original and
hydrated version vectors and failed before the fix. Query results now carry
the stored snapshots through hydration in the same worker operation. The browser
check also compares recovered causal history and uses an independent HTTP reader.

The prior failing runs are retained:
`2026-09-15T14-14-31.537Z-sWYDut` and
`2026-09-15T14-15-30.572Z-PmICjH`.

Limits: POSIX Chromium, one deterministic disjoint-edit schedule, graph fields and
child resources. This does not establish power-loss, other browsers/native apps,
conflicting edits, or table UI/query membership. No real user data or external
feedback is involved.

Validation before the query-snapshot fix: all 519 library unit tests passed, including seven focused recovery
cases.
All 916 app tests and three real-server integration cases passed. The existing
Chromium document/table/attachment SIGKILL check also passed (21.8 seconds), using
those freshly rebuilt artifacts in `2026-09-15T14-24-13.203Z-JEvssk`.
Generated locale churn was restored to its pre-build contents.

A final regression reproduced a deletion race introduced by asynchronous ingress:
a read begun before deletion could recreate the resource on completion. Deletion
now cancels that subject's pending ingress queue; its regression passes alongside
database and connection invalidation checks.

A second rebuilt browser run (`2026-09-15T14-41-34.611Z-5nnfN8`) still failed
convergence while preserving the recovered version vector. The outbound SYNC_DIFF
path preferred any non-empty in-memory export over OPFS, even when memory lagged
behind durable state during reload. A frame-level regression reproduced the
omitted acknowledged edit. Reconciliation now exports the union of memory and
durable snapshots, checking the connection and outbox again after the read.
A retained-outbox Node integration run also failed intermittently during this
investigation; a rerun alone passed and was not treated as proof of a fix.

Latest validation after the outbound export fix: 522 library tests, 916 app tests,
three real-server integration cases, library/E2E/integration TypeScript checks and
scoped lint/format checks pass. The rebuilt two-client browser SIGKILL acceptance
passed in 14.7 seconds (`2026-09-15T14-46-10.561Z-nfgtmu`), including identical
recovered causal history and independent HTTP server reads. Repeated browser
acceptance was required because earlier single passes hid intermittent loss.

Repetition exposed an additional harness sequencing error: `waitForSynced` only
waits for the outbox (plus a database flush), and a drive-sync status can be emitted
before server processing of an outbound push. B sometimes reconnected too early.
The new tests now independently poll the server for A's acknowledged edit before
B's final reconciliation, rather than treating an empty queue as proof of remote
persistence. Browser repetition before this correction had two convergence
failures and four passes (`2026-09-15T14-48-35.151Z-ljvOqF`); all three existing
single-browser document/table/attachment crash runs passed.

- [x] Tighten drive-sync completion to wait for each outbound chunk acknowledgement
  and queued incoming persistence. Frame regressions cover reordered async work,
  rejection, invalid updates, disconnect and overlapping probes.
- [ ] Consider semantic per-entry receipts or verification probes: the existing
  protocol's SYNC_OK admits a chunk but does not certify every entry was imported.

With the server-persistence barrier, all three browser runs passed the data,
causal-history and independent server checks (`2026-09-15T14-51-49.339Z-t56Aia`).
One run failed only the diagnostic collector: blocked service-worker registration
retried, exceeding the four-warning allowance. The exact Playwright warning now
has a bounded allowance of eight across four navigations; unrelated warnings and
errors remain failures. Both Node recovery variants passed three consecutive
runs (six cases total) with the barrier.

Final acceptance: all three repeated two-client Chromium SIGKILL tests passed
(45.6 seconds total, `2026-09-15T14-53-37.650Z-joiOVc`). No product changes were
made after the 522 library / 916 app test runs. Final test-file typechecks,
scoped lint/format and `git diff --check` are clean. Locale files retain their
pre-build contents. The acceptance test and recovery fixes were subsequently
committed as `6d87c0fee`; the earlier Node test is `c41ded112`.

## Acknowledged sync completion — 2026-09-16

Recovery fixes committed as `6d87c0fee` with hooks enabled. The next change waits
for every outbound chunk's SYNC_OK and serializes SYNC_DIFF / SYNC_PUSH / SYNC_OK
processing. Final incoming chunks cannot overtake earlier asynchronous imports.
Remote ingestion awaits its queued canonical database write and propagates write
failure; failed or invalid incoming state and rejected pushes cannot complete.
Overlapping same-drive probes are coalesced because the wire has no request ID.
Queued work is fenced to its connection and identity. Blob fetching and future
local edits are separate work; completion concerns this reconciliation round.

A rejection regression also found that drive parsing stopped at the first colon
of a DID. The parser now uses the colon-space separator before the reason, so a
late acknowledgement cannot clear a rejection recorded for the wrong drive.

The Node and browser crash tests now wait for a fresh completion status, then
perform a single independent server read, instead of polling the server until
it happens to catch up. The wire contract remains important: SYNC_OK confirms
chunk admission, not per-entry semantic success (see docs/src/websockets.md).

Repeated Node acceptance exposed a separate adapter race: NodeClientDb's composed
JSON/snapshot operation awaited the JSON write before writing the snapshot, while
other reads could run between them. WASM's temporary JSON-derived snapshot could
therefore enter reconciliation as competing history. Captured frames showed the
actual chunk acknowledgement followed by a stale field winning that invented
history; it was not an acknowledgement-order failure. A cheap Node adapter test
failed while the JSON write was paused. Public adapter operations now share a
serialized queue, matching the browser worker. The test passes without exposing
the intermediate snapshot. Temporary wire tracing was removed.

A final frame regression covers a hash-match response after the reduced/full-vector
fallback: that path has consumed the cached probe state, but the round remains
active and must still accept its SYNC_OK. The regression failed before checking
active rounds instead of only cached probe state.

Validation: 916 app tests pass. Both real-server recovery variants pass three
consecutive runs after the Node queue fix (six cases); the lost-ack case also
passed during this change. The rebuilt two-client Chromium crash test passes
three consecutive runs with a single server read after completion
(`2026-09-16T09-28-46.098Z-YR4lkq`, 41.6 seconds); the existing document/table/file
crash test also passed in the earlier combined run. The subsequent Node-only
queue change and fallback-ack fix have focused unit coverage. Locale files were
restored to their pre-build contents. These sync-completion changes were committed as `3a5ca6f1e`.

Final gate: all 534 library tests pass; library, E2E and integration TypeScript
checks, scoped lint/format and `git diff --check` pass.


### Verify reconciliation with existing version vectors — 2026-09-16

- [x] Reproduce false completion when an acknowledged chunk omits an update.
- [x] After outbound ACKs, query existing RBSR_ITEMS once for the sent subject
  range. Require server vectors to dominate the frozen exported vectors.
- [x] Retry only missing original updates, at most twice. Exhaustion or query
  failure leaves a recoverable failed sync and retains local data.
- [x] Fence asynchronous verification against disconnects and later local edits.
- [x] Cover skipped-entry recovery against a real server with a valid modified
  chunk and an independent HTTP read immediately after sync completion.

No new receipt protocol is introduced. Hash-match and receive-only rounds need
no additional query. Outbound rounds add a metadata range query; the server
currently enumerates drive items for it, so large-drive cost remains a performance
measurement to make. Version coverage establishes delivery of exported resource
operations, not attachment availability or preservation of a particular LWW value.

Validation: all 538 library tests pass; four real-server integration cases pass
(interrupted recovery with retained/lost queue, acknowledged missing entry, and
lost commit acknowledgement). Library plus integration TypeScript checks and
scoped lint/format checks pass. The unit regression failed before the change
because the first ACK completed the round without retrying the missing update.

### Iroh reconciliation completion — 2026-09-16

- [x] Reproduce a real QUIC peer rejecting an outgoing push while the caller
  still returned success and stamped the peer as synced.
- [x] Wait for every outgoing chunk ACK, then verify the stored snapshot version
  covers the frozen snapshot sent. Use existing GET/UPDATE frames: Iroh does not
  expose the browser's metadata-only RBSR_ITEMS request.
- [x] Retry only missing snapshots, at most twice; query failures, rejection,
  disconnect, invalid frames and bounded verification timeouts fail the call.
  Local resources remain available for a later reconciliation.
- [x] Preserve interleaved live frames for the normal authenticated dispatcher,
  with a bounded buffer. Retry traffic does not inflate sent-resource counts.
- [x] Stop treating the accepting side's switch to live mode as verified sync.
  Its timestamp advances on a matching SYNC probe or its own verified dial.
- [x] Validate focused peer tests, real QUIC regressions, and two-process offline
  edit recovery with a single receiver read after reported completion.

Version coverage checks resource-operation delivery, not attachment availability
or a remote fsync guarantee. GET adds a full snapshot response per sent resource;
a metadata-only Iroh query can be considered if measurements justify it. Each
verification round has a 30-second deadline. Large-drive throughput and physical
device/network acceptance remain separate work.


Validation: 32 focused peer/verification tests, 15 existing real-QUIC tests,
the new accepting-side timestamp test, and the two-process recovery test all
pass (49 total; the subprocess entry point is intentionally ignored when not
launched by its parent). Scoped rustfmt and `git diff --check` pass.


### Crash immediately after verified sync — 2026-09-16

- [x] Reproduce acknowledged-write loss in the shared WebSocket engine: import,
  confirm ACK and GET version coverage, exit without destructors, reopen redb.
- [x] Reproduce the same loss over real Iroh: two processes, verified outgoing
  edit, SIGKILL receiver immediately after completion, reopen its redb.
- [x] Flush shared sync imports before returning success, including incoming
  Iroh imports. Flush matching-hash acknowledgements too: an earlier failed
  flush can leave equal but volatile vectors.
- [x] Inject a flush failure and require ERROR instead of ACK for pushes and
  both hash-probe forms; replay the identical update without duplicate history.
- [x] Run targeted regression gates: four server durability cases, the two-process
  kill/reopen case, and twelve shared engine cases pass.

Both failing crash tests recovered the previous name despite successful sync.
This is process-crash evidence, not physical power-loss testing. The durability
barrier applies to upgraded responders; existing wire version vectors do not
prove that an older responder flushed its writes.

### Seeded sync failure schedules — 2026-09-16

- [x] Add a shared-engine campaign over two real redb replicas: four fixed seeds,
  eight shuffled blocks per seed, nine operation types per block (288 scheduled
  operations plus resource creation and final reconciliation).
- [x] Mix independent field edits on partitioned replicas, delayed/dropped/
  duplicated snapshots, reopen with restored identity, injected disk-flush
  failures, signed deletions and stale-update replay.
- [x] Compare both replicas and parent-query membership with an independent
  field/deletion ledger after two fixed final exchanges; do not poll until equal.
- [x] Keep the seed, schedule, expected ledger and synthetic databases on failure.
  Replay with ATOMIC_SYNC_SEED=<decimal seed> and the command below.
- [x] Final four-seed campaign passes (24.9 seconds); scoped rustfmt and diff checks pass.

```sh
ATOMICSERVER_SKIP_JS_BUILD=true cargo test -p atomic-server --lib --no-default-features --features light seeded_sync_failure_schedules
ATOMIC_SYNC_SEED=42 ATOMICSERVER_SKIP_JS_BUILD=true cargo test -p atomic-server --lib --no-default-features --features light seeded_sync_failure_schedules
```

The schedule and operation choices are deterministic; generated keys and wall
clock timestamps are not. Transport scheduling is simulated at the shared engine,
and reopen is a persisted-state reload, not an OS crash (covered by item 1).
This campaign checks disjoint field edits and deletion dominance, not every LWW
conflict policy, browser quota behavior, physical devices or a long-running soak.
The first run exposed a harness omission: resource storage reload does not restore
the default agent; the harness now restores that separate identity explicitly.

### Deployed diagnostics readiness — 2026-09-16

- [x] Sixteen local tests pass for diagnostic exports, persistent recording and
  Sentry helpers.
- [x] Identify the public staging release as
  `atomic-data-browser@0.41.0-beta.7+9c9cff0`.
- [x] Check available access: the pinned official Sentry CLI is unauthenticated.
  Neither repository's Actions secret list contains a SENTRY_AUTH_TOKEN; broader
  deployment/organization configuration remains unverified.
- [ ] Complete received-event, attachment, symbolication and backend acceptance
  with Sentry authentication and the intended deployed build.

Details and evidence limits are in `planning/sentry-feedback-readiness.md`.
No synthetic feedback or notifications were sent. Item 1 is committed as
`a5f1a2269`; item 2 is committed as `63937702f`.

## Develop integration — 2026-09-16

- [x] Rebase onto `develop` (`3b9f7e417`) without merge commits.
- [x] Retain the library-owned periodic flush from develop. Crash harnesses use
  the shared file-store initializer with the background tick disabled, so only
  explicit acknowledgement barriers can make their writes durable.
- [x] Preserve signed history envelopes in browser and Iroh selective retries;
  extend the existing retry tests to check the envelope payload.
- [x] Serialize the new Node database envelope methods with resource writes;
  extend the persistence race test to cover both envelope reads and imports.
- [x] Run client and app unit tests, TypeScript checks, server durability and
  seeded failure schedules, and the receiver-kill cross-process test.
- [x] Finish the native sync suite (204 passed, one ignored), Chromium crash
  regressions (two passed), and real-server interrupted-sync / lost-ACK tests
  (four passed). Browser lint and staged-snapshot Clippy hooks pass.
