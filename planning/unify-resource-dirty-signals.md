# Resource save state

> **Status: partial, 2026-09-11.** Public API, scheduler and initial consumers shipped;
> additional consumer migration and internal coordinator extraction remain.

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

The data inspector now subscribes to this state; its production regression covers
an offline edit and clearing the warning after reconnection. Next: PluginPage and
extracting Store coordination behind the same public methods, as specified in
[js-maintainability.md](./js-maintainability.md). `ScheduledSave` itself already
exists; the extraction must not implement a second scheduler.
