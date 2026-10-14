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

### Critic and CI follow-up (2026-10-14)

- [x] Reject an empty Vault export inventory when the recovery manifest records history.
- [x] Confirm computed-query replacement. Close placement-check gaps for unknown
  unsolicited updates, nested HTTP resources and batched WebSocket reads.
- [x] Reproduce the app duplicate-row race and plugin uninstall/navigation failure.
- [x] Measure pack/envelope duplication and retained checkpoint costs; encode byte
  payloads as binary while retaining compatibility with existing readers.
- [ ] Attribute the production account's exact 91 MB to its private inventory.
  The 411 KB server map already includes Loro history. A controlled 40-resource,
  128-edit run retained 126 packs and 3 checkpoints: about 1.22 MB versus 113 KB
  of server snapshots, with 905 KB of signed envelopes across those objects.
  The byte encoding fix reduces a 64 KiB uniform byte fixture from 98,384 to
  65,616 bytes, but saves only about 1% in that workload. It does not explain or
  resolve the full production ratio. The default 30-day retention preserves
  superseded copies, and restore still downloads the full object inventory.
  Investigate authenticated checkpoint selection and duplicate envelope storage
  before changing retention or deleting history. Probe source/logs are under
  `/tmp/sync-durability-20261014/production-restore/storage-probe*`.
- [x] Complete local review checks and prepare the follow-up for #2249.
  Base integration and merging remain with TrekMeester; current paired CI is pending.

### Production restore follow-up (2026-10-14)

The public app bundle reports `e7ccc6e`; #2249/#220 are still unmerged. The
reported 411 KB map reads current server resource snapshots and file bytes;
the 91 MB Vault total counts retained encrypted backup objects (59 MB change
packs and 32 MB checkpoints in the screenshot). The exact private inventory
has not been inspected. Production already downloads four objects concurrently,
but first waits for every batch of signed URLs. Before this follow-up, #2249
at `4374d5335` retained that barrier and the restore import-identity bug.

- [x] Reproduce ambiguous import identities in a Vault restore, then use the
  existing replica persistence boundary while keeping authoring checks intact.
- [x] Start bounded downloads as URL batches become available; test order,
  concurrency and partial failures across batches, and measure request latency.
- [x] Make Vault usage and its distinction from the server storage map clear
  on Sync; keep usage readable during restore and include object counts.
- [x] Validate the changed UI in the compiled app, update coverage and prepare
  the follow-up for the existing PR.

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
- [ ] Explain the intermittent WebSocket HTTP 408. It recurred in the latest
  full run: 357 passed, 11 skipped, one notification test failed its strict
  console check after all delivery/read-state assertions passed. Both notification
  journeys then passed three repetitions each, including console checks. The
  cause remains unproven; do not classify the full run as green.
