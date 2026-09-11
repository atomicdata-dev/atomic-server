# React Compiler and mutable Resources

> **Status: partial, 2026-09-11.** Read/save status boundaries and initial consumers
> shipped; rendered-property migration continues incrementally.

## Current boundary

`Resource` remains a stable mutation handle. `Store.getResourceSnapshot` captures
immutable `ready`, `loading`, `readState`, and `error` fields on each notification.
`useResourceSnapshot` exposes these to React; property values still flow through
`useString`, `useArray`, `useTitle`, and the other property hooks. An old snapshot's
status does not change when its resource changes.

Profile, invitation, sharing, tag and message-preview readiness consumers use
the snapshot fields. AgentProfileHeader no longer needs `use no memo`; production
E2E verifies profile editing, invitations, and live username updates. Library
tests check stable mutation identity and immutable status across notifications.

The data inspector also uses `useSaveState`: a production regression verifies
its warning appears for an offline edit and clears after synchronization without
replacing the Resource. Save status remains independent of read readiness.

## Remaining audit

A direct `resource.get(...)`, `resource.props.foo`, or `resource.isReady()` read
inside a component can still be memoized by Resource identity. Use property hooks
for rendered values and `useResourceSnapshot` for status. Live reads in event
handlers and asynchronous operations remain appropriate.

Do not change the identity of every Resource to invalidate compiler caches:
that would change effect dependencies throughout the app. Audit remaining
render-time property getters incrementally, with a reproduced stale-UI test
before migrating each flow. Saving/outbox state is separate from read readiness;
see `unify-resource-dirty-signals.md`.

Next bounded slice: PluginPage metadata and Save-button subscriptions, with a
reproduction before migration. Its checklist and delivery order live in
[js-maintainability.md](./js-maintainability.md).
