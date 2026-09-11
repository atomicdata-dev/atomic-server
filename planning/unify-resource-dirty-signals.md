# Resource save state

> **Status: partial, 2026-09-11.** Public API, scheduler, internal coordinator and initial consumers shipped;
> additional consumer migration remains.

The browser exposes `Store.getSaveState(resource)` and `useSaveState(resource)` as
immutable persistence snapshots. Read readiness stays in `useResourceSnapshot`;
a queued offline edit can remain readable. Save kinds are idle, dirty, scheduled,
saving, queued, and error.

`Store.createSaveScheduler` owns a debounce slot and counts each started save
until it settles. React value/debounced-save hooks and virtual table rows use it.
Rescheduling coalesces queued work, cancellation cannot uncount an in-flight save,
and unmount flushes edits that would otherwise only exist in memory.

Remaining migration: other screens with bespoke saving UI can adopt the hook
incrementally. Legacy global start/finish methods remain for compatibility and
non-save pending writes such as deletion. The outbox remains the durable queue;
this API derives state rather than keeping a second persistence engine.

The data inspector and legacy WASM PluginPage subscribe to this state. Their
production regressions cover offline edits, save completion and reconnect;
PluginPage also permits a later draft after an earlier save is queued. New-model
plugin UI lives on `feat/plugin-model` and needs its own consumer audit.

`SaveStatusCoordinator` now owns scheduler integration, per-resource counts,
immutable snapshot caching and subscription cleanup. Store retains its public
methods as delegates. The coordinator receives narrow callbacks for outbox entry
lookup, connection status, pending-count changes, sync notifications and errors.
It does not fetch, sign or drain, and has no Store import. `ScheduledSave` remains
the single scheduler implementation.

Unit coverage verifies overlapping owners, observer disposal without cancelling
another owner's save, temporary-to-DID renaming, immutable snapshots and failure
accounting. Shared production E2E covers inspector/table/offline behavior.
