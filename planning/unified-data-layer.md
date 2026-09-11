# Unified browser data layer

> **Status: partial, reconciled 2026-09-11.** Atomic snapshot writes, the durable
> outbox, unified ingress entry points, React subscription hooks, immutable read/save
> snapshots and scheduled-save ownership have shipped. Remaining work is incremental
> boundary extraction and consumer migration; broader worker/sync proposals are below.

This is the browser cache/reactivity layer. The binding runtime is owned by
[atomic-lib-runtime.md](./atomic-lib-runtime.md); transport and multi-device sync by
[unified-sync.md](./unified-sync.md). Consumer migration is tracked in
[react-compiler-resource-proxy.md](./react-compiler-resource-proxy.md).

## Current implementation

### Ingress and causal state

`Store.applyIncoming` is the source-aware ingress for resource objects and Loro
bytes. `addResource` remains a public compatibility/merge path; its callers and
notification/persistence behavior still need an audit before claiming that every
producer uses exactly one path.

Local hydration restores JSON and its Loro snapshot before publishing through
`hydrateOfflineReplay`. It protects existing unsaved edits. Preserve that ordering
and snapshot causality when extracting modules; JSON must not seed a competing
fresh document before an authoritative snapshot is restored.

### Persistence and the outbound queue

`ClientDb.putResourceWithSnapshot` atomically writes JSON-AD plus the Loro snapshot
through the worker. There is no separate `OpfsPersistor` class. Low-level index-only
and snapshot operations remain available; a facade is optional cleanup, not an
unimplemented atomicity fix.

`LocalOutbox` holds dirty subjects and signs at drain time, with pre-signed genesis
and destroy exceptions. It does **not** hold an ordered list of signed commits per
resource. See [sign-at-drain.md](./sign-at-drain.md) for that decision. Do not restore
the superseded signed-at-every-save queue design.

Only user-origin local edits enqueue work. Imports, history checkouts and runtime
housekeeping must retain their provenance; `SYSTEM_COMMIT_ORIGIN` prevents hydration
or datatype maintenance from becoming unintended writes. Signed transport envelopes
remain the authorization boundary. Retry and Loro export cursors must preserve edits
that arrive during signing or an in-flight drain.

The Resource-owned pending-commit queue and `pushCommits` machinery have been removed.
`hasPendingCommits` delegates to the outbox; `saveOffline` still exists for local
persistence. `CommitBuilder` remains in genesis/signing paths. Any further reduction
must audit real callers and retry invariants rather than deleting methods from an
old checklist. Browser commit history must not require every accepted envelope to
remain fetchable as a resource; retention is node policy.

### React and save ownership

`Resource` stays a stable mutation handle. `Store.getResourceSnapshot` publishes an
immutable outer snapshot; `useResourceSnapshot` reads status, while `useValue`,
`useString`, `useArray` and other property hooks observe values. The property hooks
combine store notifications with property-level local-change events. Replacing every
Resource instance or deleting those listeners is not the accepted design.

`Store.getSaveState(resource)` and `useSaveState(resource)` expose idle, dirty,
scheduled, saving, queued and error states independently of loading/read errors.
`ScheduledSave` owns debounce slots and in-flight completion; hooks and virtual table
rows use `Store.createSaveScheduler`. Unmount flushes pending edits rather than
silently discarding them. Legacy start/finish accounting also covers non-save writes.
The internal `SaveStatusCoordinator` owns scheduler integration, cached immutable
save snapshots and subscription cleanup. Store delegates through its existing API;
the coordinator reads current outbox entries and never signs or drains commits.
See [unify-resource-dirty-signals.md](./unify-resource-dirty-signals.md).

## Remaining work

- [ ] Migrate additional rendered getters and bespoke save indicators with a failing
  regression before each flow change. Keep read and persistence state separate.
- [ ] Audit direct `addResource` producers before further ingress consolidation.
  Preserve normalization, alias handling, echo imports/dedup, unsaved local state,
  atomic persistence and notification ordering.
- [ ] Review remaining Resource signing/retry responsibilities and `CommitBuilder`
  consumers as a separate change. Preserve immutable signed envelopes and export
  baselines; do not conflate queued writes with persisted local durability.
- [ ] Evaluate whether a persistence facade removes meaningful duplication. Existing
  atomic writes must remain intact; index-only seeding needs an explicit path.

## Deferred proposals requiring separate decisions

**One drive-sync orchestrator.** Authentication, outbox drain and reconciliation
could share an explicit lifecycle. Connection-scoped cancellation already guards
late work after reconnect; that does not mean a `DriveSync` class has shipped.
Any orchestrator must handle offline/blocked outbox entries without preventing reads
or reconciliation forever. The authoritative sync checklist stays in
[unified-sync.md](./unified-sync.md).

**SharedWorker ownership of OPFS.** A SharedWorker could reduce per-tab leader
coordination, but it is not the current architecture. Validate browser, Tauri and
sandbox support, worker shutdown, account isolation and lock ownership before
choosing it. A per-context fallback must still coordinate exclusive OPFS access;
file locks alone are not a demonstrated replacement for leader election. Retain
existing cross-browser storage and multi-context tests during any migration.

## Guardrails and evidence

Keep stable public APIs and extract one responsibility at a time. No parallel
property store, durable queue or sync engine should be introduced by a cleanup.
Start regressions in Rust/JS units or real-server integration where possible, then
use production Playwright for compiled subscriptions, multiple tabs, reload/offline
persistence and rapid table entry. Coverage is tracked in
[TESTING_COVERAGE.md](../TESTING_COVERAGE.md).
