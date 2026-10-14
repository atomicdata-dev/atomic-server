# Sync contracts

Status: durability follow-up in full-suite validation, 2026-10-14. Based on the latest recovery
work in #2242; CI maintenance remains separate. Preserve peer multiplayer and
independent Vault / hosted capabilities.

## First implementation

- [x] Reproduce save, recovery and ingress contract counterexamples in unit tests.
- [x] Separate queued work, required local durability and accepted remote saves;
  expose revision/destination receipts through the existing save pipeline.
  Reuse the relevant #1531 durability fixes rather than introduce another outbox.
- [x] Distinguish unavailable/cancelled recovery from confirmed backup absence,
  and require callers to carry the outcome instead of a recovery-attempted boolean.
- [x] Make ingress payloads exclusive and preserve existing causal history; preserve
  optimistic rendering separately from durable completion.
- [x] Verify targeted regressions, package tests, type checks and full browser lint.
- [x] Update the coverage map and public contract documentation.

## Full browser validation

- [x] Run the unfiltered standalone E2E suite on the current PR build.
- [x] Run both portal app profiles and the Vault / Cloud Server acceptance matrix.
- [x] Run browser peer sync between explicit drive members and through an invitation.
- [x] Diagnose failures, fix regressions and record exact results and exclusions.

## Second implementation

- [x] Reuse #2238 live private-drive subscriptions and the scoped query/pagination
  changes from #2130 (`8b54bd0c0`), preserving current recovery changes.
- [x] Make subscription releases idempotent and invalidate old account owners;
  fence late hosted-route discovery with identity and routing generations.
- [x] Expose query completeness and require it for operations claiming all members;
  include drive and query options in React query identity and read every Inbox page.
- [x] Share the Rust restore result between WASM and desktop. Detect provable lane
  gaps, keep imported coverage contiguous, and discard old unverified import cursors.
- [x] Pair this with ordered admission snapshots and installation receipts in the
  private managed adapter. Reject stale policy and refuse bootstrap before policy loads.
- [x] Verify package suites, changed browser journeys, formats, types and full lint.

## Second-slice validation

- Library: 1,699 passed / 1 skipped; real-server integrations: 4 passed.
- Full data-browser after the final fix: 2,132 passed plus 2 stdio checks.
- Rust Vault core: 41 passed. WASM built; desktop compiled (no native runtime claim).
- Notifications: 2 browser journeys passed; Inbox screenshot reviewed.
- Vault-only / Cloud Server acceptance: 9 passed, no retries/skips, including a
  real managed-node restart. First run: 8 passed / 1 failed. It caught a partial
  restore whose translated warning was empty, letting the UI reload as success.
  Reproduced in three panel tests, then fixed using structured status, fallback
  copy and settled catalogs. Manual and onboarding recovery now share the guard.
- Full browser lint/types, Rust format/Clippy and paired portal lint/types passed.
- Paired API: 611 passed / 3 ignored, then the final receipt-reset handler regression
  passed. Managed policy: 15 passed.

The earlier unfiltered browser/portal runs were not repeated in full for this
slice. The PR descriptions retain their initial failure counts and focused reruns.
Current acceptance evidence is in
`/tmp/sync-contracts-contracts-20261013/acceptance-contracts-final-report/summary.md`.

## Remaining architecture work

### Durability follow-up (2026-10-14)

Work on `codex/sync-durability-20261014`, stacked on the reviewed sync-contract
pair. TrekMeester retains ownership of that pair's integration. Preserve live
peer multiplayer and keep attachment ciphertext in separate object storage.

- [x] Add encrypted blob dependencies to the Vault format; upload dependencies
  before confirming graph backup; verify cold recovery and missing/corrupt bytes.
- [x] Carry key/epoch handles through adapters and validate expected recovery
  inventory, including omitted lane tails and incomplete checkpoints.
- [x] Pull Vault changes on reconnect/resume without replacing pending edits or
  accepting stale account/session completions.
- [x] Define stable notification identity and read-state convergence; test
  offline catch-up and distinguish closed-app delivery capabilities.
- [x] Add deterministic upload interruption coverage, rendered multiplayer
  journeys and native IPC adapter contract checks.
- [ ] Complete full-suite validation and publish the stacked PR pair.
- [ ] Validate packaged native lifecycle and seeded process/network schedules;
  native compilation and shared-core tests do not establish these guarantees.

Open adjacent work inspected: #2205 changes encrypted conversation attachments;
#2226 changes notification presentation. These changes stay below those views.

### Complexity Critic follow-up (merge remains on hold)

- [x] Reproduce accepted-genesis receipt failure and anonymous login subscription loss; fix both.
- [x] Trace invitation server selection through app bootstrap; require exact-origin confirmation before invite effects.
- [x] Check authoritative backup absence before requiring local storage; retain recovery failure guards.
- [x] Test partial SUB followed by full GET and a later local edit; current causal merge passes.
- [x] Restore explicit hosting consent for paid plans, matching checkout copy.
- [x] Validate notification offline loading, computed queries, Vault object-kind handling and callers.
- [x] Finish per-drive routing validation and regression checks; update coverage and PR evidence.
- [x] Paired review: policy generations, snapshot coherence, restart behavior and consent journey.

The working tree includes the third slice below. Existing CI and reviewer comments
cover the previously pushed revision. Do not retarget or merge here; TrekMeester
owns integration with the Vault pair. Keep follow-up fixes in separate commits
so the save/ingress, recovery, routing and managed-policy changes remain reviewable.

### Third slice: per-drive server routes

- [x] Reproduce cross-drive save/fetch routing and late response failures.
- [x] Give each drive an account-scoped route; preserve exact origins for
  subdomains, explicit migrations, HTTP aliases and cold outbox replay.
- [x] Use that route for reads, commits, queries, blobs, subscriptions and
  reconciliation; isolate connection state and stale work by destination.
- [x] Register routes in onboarding, discovery and cloud migration adapters.
- [x] Verify two live servers and vanity hosts, reconnect/account switches,
  relevant suites and full lint; update coverage and PR evidence.

- [x] Carry a drive key and its epoch as one handle through every adapter; add a
  manifest proving expected lane tails and resource/blob dependencies. Readable
  metadata and contiguous listed segments alone do not prove complete recovery.
- [x] Vault-only encrypted blob upload and fresh-device recovery through separate
  blob storage, with an explicit format and key lifecycle.
- [x] Logical notification event IDs, convergent read/unread receipts, and
  catch-up after a closed browser returns. Push delivery while all apps stay
  closed remains separate work.
- [ ] Native runtime parity and seeded network/process fault campaigns across
  capability combinations. Sharing a result type and compiling adapters is narrower.

The private cross-repository review is maintained in
`atomic-saas/planning/SYNC_CONTRACT_REVIEW.md`. This plan and public documentation
describe generic runtime guarantees and avoid managed-service implementation details.

## Critic follow-up evidence

- Unknown emailed invite origins are confirmed before any invite reader mounts or
  bootstrap changes the signing server. Exact origins include scheme, host and
  port; sibling subdomains do not inherit trust. The compiled warning is visible.
- Recovery asks whether a backup exists before requiring local storage. Unknown
  recovery still cannot justify creating a replacement home. The paired default
  browser suite now includes `identity-recovery.spec.ts`: a fresh profile with an
  existing identity and no account session offers recovery and a working skip path.
- Full GET snapshots merge real Loro state after a class-less partial SUB; stale
  snapshots preserve later local edits. Computed query rows replace projections.
  Incoming import errors notify the error channel and reject their caller.
- Accepted genesis cleanup precedes fallible receipt bookkeeping. Anonymous live
  subscriptions survive login, verified with actual WebSocket delivery.
- Offline partial Inbox loading settles. Local-copy reconciliation uses event
  completion and bounded parallel reads. Vault auxiliary objects do not taint
  graph completeness; whole-inventory import and conservative legacy pruning
  remain explicit contracts. E2E saves that require persistence check the result.
- Two real nodes verify independent drive destinations, reconnection and login;
  a forwarded tenant hostname resolves its canonical drive. Cold query members,
  new outbox entries and locally recoverable older queued edits keep ownership.
  An old queue with no surviving ownership metadata cannot reconstruct a lost
  historical destination; this is not a general historical-route migration.

The same PR pair is retained as requested. No base retarget, rebase, merge or
intervention in the previously queued run was performed. Updated paired CI and
Vault-base integration remain prerequisites for removing the hold.

### Third-slice local checks

- Library: 1,720 passed / 1 skipped; all real-server integrations: 26 passed /
  1 skipped. The anonymous-login case verifies real delivery after login.
- App: 2,146 passed plus 2 stdio checks. Notification browser journeys: 2 passed;
  compiled invite guard and storage journeys: 3 passed. Paired identity recovery
  and paid-hosting consent: 1 each, with visible warning screenshots inspected.
- Rust server: 392 passed / 4 ignored; Vault core: 42 passed. WASM rebuilt.
- Full browser build, recursive lint, types, Rust format and all-target Clippy
  pass. Commits run the repository hooks. Paired API: 611 passed / 3 ignored,
  managed-node: 27 passed.
- Two initial Rust build attempts exhausted disk space; the full server suite
  subsequently passed. A unit integration initially reached an unrelated local
  node; the full suite passed with the isolated server URL explicitly selected.
- Billing reruns exposed a stopped ephemeral object store and its missing bucket
  after restart; after restoring that fixture the full consent journey passed.
  The first acceptance attempt watched the direct API URL while the browser used
  the portal proxy; this configuration was corrected before the final matrix.

These are scoped local results. The unfiltered app E2Es and broad portal profiles
were not repeated for this follow-up, and old CI does not validate the new heads.

The final acceptance run initially exposed two test-fixture problems: G1 required
an extra pack even when automatic backup already held the uploaded File; D1's
base-36 marker could trigger rich-text multiplication typography before sync.
G1 now verifies confirmed encrypted storage and exact cold File recovery, retaining
missing/corrupt blob and access checks. Typed markers use hexadecimal IDs. The
pre-correction complete matrix was 8 passed / 1 failed; the marker issue was found
in a subsequent run and fixed before the final matrix.

Final matrix: **9 passed, zero failures, retries or skips**, including the real
managed-node restart. Evidence: `/tmp/critic-acceptance-final4.log` and
`/tmp/critic-acceptance-final4-html/`. The local Critic follow-up is complete;
remote paired CI and Vault-base integration still own the merge hold.


### Durability follow-up browser validation (2026-10-14)

- [x] Reproduce cross-origin cookie reuse in a library test; sign requests for
  their selected agent and destination, including same-origin requests.
- [x] Reproduce the profile history crash from captured public test-agent bytes;
  retain the document and local edits while warming its history tail cache.
- [x] Reproduce queue overflow ending the deletion listener; keep listening and
  reconnect subscribers to reconcile the missed interval.
- [x] Repeat invitation, public-drive and cascade-delete flows three times:
  nine passed with console diagnostics enforced.
- [x] Recover profile edits missed during a disconnect; verify actual materialized
  content after re-subscription instead of only counting SUB frames.
- [x] Prevent ordinary cached listeners from opening foreign WebSockets. The
  plugin failure also appears in the older remote CI run.
- [x] Keep a brief reconnect from flashing an offline toast over editing controls.
- [x] Complete the server-initiated restart close handshake; reject late data
  frames, wait for the peer acknowledgement and bound unresponsive peers.
- [x] Keep draft/signing/in-flight genesis resources ready and defer speculative
  fetches and subscriptions until the server has accepted their creation.
- [x] Fence a cancelled save's error continuation by identity so it cannot write
  the old account's resource into a newly attached database.
- [x] Preserve queued rows across tab storage handoff and require durable storage
  when a disconnect interrupts outbox drain.
- [x] Isolate the server's replica-change listener from commit/query traffic;
  verify genuine overflow still reconciles. Eight browser repetitions passed,
  including onboarding without local storage, without new overflow warnings.
- [x] Reproduce the cold file's clickable-but-unready Download action at the
  component layer on both layouts; enable it only when the local URL is ready.
- [x] Inspect the old paired CI failures: signup reached its target route but
  waited for Vite's load event; H1 clicked Download before local bytes were ready.
  Scope the signup handoff to navigation commit and bound the download wait.
- [x] Reproduce the open dropdown's stale direction after nested scrolling;
  track scroll and viewport changes while the menu is open.
- [x] Replace the history E2E's invalid server-only retention assumption with
  deterministic component checks for verified, unverified and absent proofs.
- [x] Complete final10 paired acceptance: 10/10 without retries or skips,
  including managed restart and cold byte-verified attachment recovery. Portal:
  119 passed / 4 skipped, then all 3 hosting/billing opt-ins passed. Vault opt-ins:
  2/2. The actual exported website: 1/1 with off-origin requests blocked.
- [x] Record the unfiltered final10 run: 358 passed / 4 failed / 9 skipped.
  All failures passed alone. Keep the traces; repeat with the dropdown fix,
  corrected history contract and CI's optimized server profile. Slow debug
  imports coincided with a template timeout and a WebSocket handshake timeout;
  that correlation does not by itself prove an event-loop defect.
- [x] Complete the unfiltered browser suites and paired acceptance on the final
  builds; retain first failures and state the exact remaining limits.
- [x] Complete final11: portal 122 passed / 1 staging-mail skip; paired journeys
  10/10, no retries or skips. The app finished 361 passed / 1 failed / 9 skipped.
  Its chat reload failure retained the actual message and author on the server.
- [x] Reproduce the remaining query transport discrepancy at the library layer:
  binary WebSocket GET merged independent computed snapshots, so an old empty
  result could defeat the current answer. Classify query projections before
  branching on payload format; retain causal merges for editable resources.
- [x] Repeat the app suite and shared recovery journeys with the binary-query
  fix, then publish updated validation evidence.
- [x] Reproduce the same stale-result merge in ordinary and semantic search;
  replace only known computed endpoint results. Both new tests fail before
  the fix and pass afterward; the complete library suite passes 1,750 tests
  with one skip against the isolated server.
- [x] Preserve final13 evidence: 359 passed / 3 failed / 9 skipped. The mobile
  UI passed its assertions but console diagnostics caught a WebSocket HTTP 408;
  it did not recur in 20 focused runs with connection diagnostics. Both website
  template commands stalled because query metadata decoding ran before Loro
  was ready. A fresh-module unit regression now verifies buffering at startup.
- [x] Make rejected single/batch GET snapshots settle as errors. The single
  request had already cleared its timeout and could hang; a batch could return
  old cached data as success. Both defects have failing-first regressions.
  The complete library suite now passes 1,753 tests / one skip; the previously
  stalled real template command completes with the rebuilt library.
- [x] Publish the follow-up source commits to #2249 / paired #220.
- [ ] Observe green paired CI and integrate the held base stack. TrekMeester owns
  retargeting and merging; these remain stacked on #2244 / #219.

Final local validation used source commits `e9b2a557e` / `8d28232` and the
`final14` frozen frontend builds, against the optimized native `e2e` profile:

- App browser suite: **362 passed / 9 skipped**, zero retries, 15.2 minutes.
  Includes Firefox lock handoff and WebKit sign-out/storage checks. The nine
  skips are four opt-in profilers, two already-disabled scenarios, two Vault
  journeys and the exported-site journey. The latter three passed separately
  on the same build: Vault **2/2**, actual downloaded website **1/1** with all
  off-origin requests blocked.
- Paired acceptance: **10/10**, no retries or skips, including node restart,
  cold byte-verified attachment recovery and automatic reconnect catch-up.
- Portal suite on unchanged SaaS source: **122 passed / one staging-mail skip**
  with hosting/billing opt-ins enabled. This is one complete run, not a count
  assembled from focused retries.
- Library: **1,753 passed / one skip**; app: **2,182 plus two stdio checks**.
  Full recursive browser lint, app types and both frontend builds pass. Native
  code was unchanged after the passing Rust core **827 / 11 ignored**, server
  **394 / 4 ignored**, SaaS **614 / 3 ignored**, WASM and adapter checks.
- Both generated website clients now pass their real scaffold/build/serve flows.
  The HTTP 408 did not recur in the complete final run or 20 focused probes;
  its root cause is still unproven and earlier evidence remains retained.

Evidence: `/tmp/sync-durability-20261014/live-results/`, specifically
`server-final14.log`, `acceptance-final14.log`, `portal-final11.log`,
`vault-final14.log`, `export-final14.log` and their HTML reports. Earlier failed
runs and failing-first unit logs remain available. Paired CI was still waiting
on its runner when these local results were recorded. Packaged native lifecycle,
closed-app push, large restores and broader fault schedules remain unproven.
