# Sync contracts

Status: consolidation locally validated, 2026-10-14. Server #2249 / SaaS #220 are
stacked on #2244 / #219, behind the Vault pair. TrekMeester owns base integration
and merging. Preserve browser multiplayer, independent Vault/hosting capabilities,
and separate object storage for encrypted attachments.

## Owners and contracts

The public reference is [Completion and recovery contracts](../docs/src/sync-contracts.md).
[Test coverage](../TESTING_COVERAGE.md) maps regressions and remaining gaps. The
private control-plane review is `atomic-saas/planning/SYNC_CONTRACT_REVIEW.md`.

| Owner | Responsibility |
| --- | --- |
| Store/outbox | Revision-specific save receipts, per-drive routes, retained retries, causal ingress |
| Collection | Pagination and scoped completeness; cached partial rows remain readable |
| Vault core | Authenticated graph/blob dependencies, import coverage and safe pruning |
| Vault operations | Signing/account/document lifetime and selected database for backup and restore |
| Standard locations | Concurrent folder creation per store, identity session, drive and pointer |
| Inbox | Stable event identity and one read/unread persistence path |
| Managed policy adapter | Epoch-scoped policy installation and acknowledgements |

## Current consolidation

- [x] Read #2244/#219 feedback and the new #220 complexity review. #2249 has
  no additional review comments as of this pass.
- [x] Reproduce stale backup continuation after database/signing-session changes.
  Backup and restore now share operation cancellation and cleanup.
- [x] Reproduce duplicate concurrent standard-location creation. Share it in the
  location owner; remove separate Inbox and AI-folder request maps. Failed calls
  remain retryable and new identity sessions cannot reuse old work.
- [x] Combine notification read/unread writes while retaining causal receipts,
  the read cutoff, legacy fields and cancellation checks.
- [x] Reuse captured routes for collection completeness instead of keeping
  another identity/server/route comparison protocol.
- [x] Replace fixed 20 ms ingress-test waits with observable completion.
- [x] Remove repeated recovery-head folding and inventory allocation in SaaS
  status polling; share head serialization and backfill only on table creation.
- [x] Finish full browser lint, types and client unit suites; compiled
  notification/onboarding journeys 10/10 and paired recovery acceptance 10/10.
- [x] Prepare the follow-up commits and current evidence for the existing PRs.

## Review disposition

The base review findings were addressed by the existing follow-up commits:

- Invitations cannot select the signing server at startup. Unrecognized exact
  origins, including sibling subdomains, require confirmation before invite reads.
- Backup absence is checked before requiring local storage. A configured account
  outage stays unavailable; the UI offers recovery/device/skip paths instead of
  overwriting a missing home. Standalone operation remains independent.
- Partial SUB/full GET preserves causal history. Computed query/search snapshots
  replace independent results. Cold Loro startup buffers bytes; rejected GET
  ingress settles both single and batch callers with errors.
- Accepted genesis commits cannot be retried because receipt decoding failed.
  Anonymous subscriptions survive first login; old account holders cannot remove
  the new account's subscriptions.
- Offline Inbox rows settle. Local-copy verification uses events and bounded
  reads. Auxiliary Vault objects do not count as corrupt graph history; import
  takes the complete inventory. Unproven legacy history remains unprunable.
- Paid hosting still requires explicit consent; unpaid enrollment returns 402.

The completeness API is retained: fetching every cached page does not prove a
remote index was available. Its ownership bookkeeping is reduced in this pass.
The emergency recovery warning retains an untranslated fallback so an incomplete
restore cannot appear successful when a translation is missing.

## Validation and remaining work

Before this consolidation, the complete app suite passed 362 / 9 skipped; the
portal passed 122 / 1 staging-email skip; paired acceptance passed 10/10 with no
retries. Vault and exported-site opt-ins passed separately (2/2 and 1/1).
These are previous-source results, not validation of subsequent edits. Exact
revisions and logs: `/tmp/sync-durability-20261014/validation-final14.json`.
Current results belong in the PR descriptions and coverage map, not a running log.

- [ ] Green paired CI and integration with the held base stack.
- [ ] Packaged native suspend/resume, kill/relaunch and notification activation.
- [ ] Push/background delivery while every app stays closed.
- [ ] Large-Vault memory budgets and replayable network/process failure schedules.
- [ ] Browser compaction/pruning races and cross-device invitation revocation.
- [ ] Multi-process control-plane leadership and rollback of all recovery witnesses.
- [ ] Explain the intermittent WebSocket HTTP 408 seen in an earlier run; the
  final full run and 20 focused probes passed, but the cause is still unproven.
