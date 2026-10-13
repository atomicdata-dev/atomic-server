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
