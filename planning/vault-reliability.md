# Vault reliability and recovery coverage

Branch: `codex/vault-reliability` in atomic-server and atomic-saas.

## First regression slice

- [x] Restore more than 64 objects without exceeding SaaS URL-batch limits.
- [x] Request URLs just before downloading each batch; preserve replay order.
- [x] Reject a failed durable flush rather than report successful restoration.
- [x] Cover interrupted downloads and import failure.
- [ ] Audit checkpoint coverage when an export cannot read a resource.

- [x] Preserve the recovered key epoch during automatic restore.
- [x] Report unreadable-object recovery as incomplete, retaining salvaged data.

Local validation: 416 client-library tests and 96 focused managed Vault tests
pass. Library build and browser typecheck pass; changed files pass lint. A
fresh deployed/MinIO browser restore is still pending. The former implementation
failed the new 65/130-object, flush-error, key-epoch and incomplete-outcome tests.

## Recovery acceptance backlog

- [ ] Browser restore: assert historical versions and diagnose intermittent empty history.
- [ ] Restore attachment bytes on a fresh device with Cloud Server unreachable.
- [ ] Bound restore memory and skip superseded packs using authenticated coverage.
- [ ] Surface stale/skipped backups, with account/key/network recovery tests.
- [ ] Exercise undelete through the user flow and retained/pruned boundaries.
- [ ] Whole-service restore with matching metadata, keys and Vault objects.
- [ ] Independent retention, recurring capture, key escrow and missing-run alerts.

Use unit/worker regressions first, then browser/MinIO drills. Local tests, CI,
deployed restore and operational guarantees are distinct. No live retention or
production restore changes are included in the initial slice. SaaS
`planning/BETA_AND_BACKUP_READINESS.md` owns infrastructure readiness gates.
