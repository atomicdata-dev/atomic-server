# Structural problems audit

> **Status: live index, reconciled 2026-09-11.** Original audit: 2026-05-28.
> Read/save subscription boundaries and scheduled-save ownership have shipped.
> Consumer migration, metadata representation cleanup and subject-brand adoption remain.

This index tracks structural work rather than individual failures. The next bounded
JS slices and acceptance checks are in [js-maintainability.md](./js-maintainability.md):
PluginPage subscriptions and E2E diagnostic collectors are implemented; Store save-status coordination is next.

| # | Plan | Current state | Next step |
| --- | --- | --- | --- |
| 1 | [React Compiler / Resources](./react-compiler-resource-proxy.md) | Partial: stable Resource handles, immutable read/save snapshots and initial UI migrations shipped. | PluginPage migrated; investigate derived plugin manifest metadata refresh, then continue one flow at a time. |
| 2 | [Subscription primitives](./unify-subscription-primitives.md) | Server work completed in reduced form; the original filter-scope design was not implemented. | Browser subscription changes belong in the data-layer plan, not a repeat of the server migration. |
| 3 | Subscription actors | Done: `LoroSyncBroadcaster` folded into `CommitMonitor`; original plan removed. | None in this slice. |
| 5 | [Resource save state](./unify-resource-dirty-signals.md) | API, scheduler and initial consumers shipped. | Migrate remaining save UIs and extract internal coordination without changing the public API. |
| 6 | [Resource representations](./unify-resource-representations.md) | Mostly shipped: browser `Resource#cache` derives from Loro. | Review `_auxValues` and preserved server-managed metadata; preserve causal hydration. |
| 7 | [Actor payloads](./arc-actor-message-payloads.md) | Encode-once and zero-copy WS frames shipped; `CommitMessage` Arc wrapping deferred. | Measure a remaining high-fanout cost before further work. |
| 8 | [Subject types](./subject-types-end-to-end.md) | Rust `DidKind` and browser branding helpers shipped. | Browser consumer migration remains. |

Items #4 (double hydration), #9 (connection-close cleanup) and #10 (Cargo lock
contention) were closed and their original plan documents removed. Recent lifecycle
work additionally restores snapshot-backed hydration before publication and cancels
asynchronous socket work across reconnects; that does not imply all sync work is done.

## Ownership and order

- #2, #5 and #6 share constraints with [unified-data-layer.md](./unified-data-layer.md).
  #6 also shares the Rust/Flutter direction in [loro-source-of-truth.md](./loro-source-of-truth.md).
- Start with the regression-driven UI slice, then diagnostics, then the narrow Store
  extraction. Do not replace every Resource identity or rewrite Store wholesale.
- Treat representation changes and subject-brand migration as separate work with
  explicit compatibility and persistence tests. Completed server subscription work
  is not a prerequisite to redo before starting these browser slices.
