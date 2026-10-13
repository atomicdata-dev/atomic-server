# Sync contracts

Status: second slice implemented and locally verified, 2026-10-13. Based on the latest recovery
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

- [ ] Replace the global server route with per-drive ownership throughout fetch,
  commit, subscriptions, reconciliation and migration. Generations fence races;
  they do not implement simultaneous multi-origin routing.
- [ ] Carry a drive key and its epoch as one handle through every adapter; add a
  manifest proving expected lane tails and resource/blob dependencies. Readable
  metadata and contiguous listed segments alone do not prove complete recovery.
- [ ] Vault-only encrypted blob upload and fresh-device recovery through separate
  blob storage, with an explicit format and key lifecycle.
- [ ] Stable notification event IDs, read/unread conflict semantics, and closed-app
  delivery. Pagination/scope fix live inbox gaps without establishing those contracts.
- [ ] Native runtime parity and seeded network/process fault campaigns across
  capability combinations. Sharing a result type and compiling adapters is narrower.

The private cross-repository review is maintained in
`atomic-saas/planning/SYNC_CONTRACT_REVIEW.md`. This plan and public documentation
describe generic runtime guarantees and avoid managed-service implementation details.
