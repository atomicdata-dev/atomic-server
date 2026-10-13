# Sync contracts

Status: first slice implemented and locally verified, 2026-10-13. Based on the latest recovery
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

## Following slices

- [ ] Per-drive route/subscription ownership and versioned managed policy changes.
- [ ] Shared complete/partial restore outcomes, key handles and dependency coverage.
- [ ] Vault-only blob upload and fresh-device recovery through separate blob storage.
- [ ] Query completeness and notification event/read-state contracts.
- [ ] Native adapter parity and seeded fault campaigns across capability combinations.

The private cross-repository review is maintained in
`atomic-saas/planning/SYNC_CONTRACT_REVIEW.md`. This plan and public documentation
describe generic runtime guarantees and avoid managed-service implementation details.
