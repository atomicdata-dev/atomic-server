# Resource save state

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
