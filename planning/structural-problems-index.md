# Structural problems audit (2026-05-28)

> **Status:** Live index (audit 2026-05-28). #4, #9 and #10 done and their docs deleted; #7 largely landed; #6 (browser `Resource` cache dual) largely shipped, see `unify-resource-representations.md`. Still open: #1 React Compiler / Resource proxy (audit not started while the compiler is on), #2 / #3 subscription unification (server side done 2026-09-04, actors not folded), #5 dirty signals, #8 subject types.

Working list of structural issues surfaced during the QUERY_UPDATE /
canvas-genesis-save / outbox / live-Loro debugging arc of late May 2026.
Ranked by load-bearing impact (1 = most bugs traced back to it).

Items #4 (opfs-double-rehydrate), #9 (connection-close-cleanup), and
#10 (dev-cargo-lock-contention) have been fully implemented and their
plan docs removed.

Several open items overlap with broader existing plans:

- **#2, #5, #6** are slices of [`unified-data-layer.md`](./unified-data-layer.md)
  — the browser data-layer redesign. Doing those three in isolation
  risks landing partial layouts that the bigger plan then has to undo.
- **#6** has a Rust/Flutter dual in [`loro-source-of-truth.md`](./loro-source-of-truth.md).
  The sparse `datatypes` map and `Tree::Resources` derived cache shipped on
  the Rust side. The browser `Resource._cache` dual
  ([unify-resource-representations.md](./unify-resource-representations.md))
  is still open.

The remaining standalone items (#1 react-compiler, #3 subscription
actors, #7 arc-wrap, #8 subject types) don't overlap with the broader
plans and can be tackled independently.

| # | Plan | Class | Risk | First step |
|---|---|---|---|---|
| 1 | [react-compiler-resource-proxy.md](./react-compiler-resource-proxy.md) | Correctness | High | 🔴 **Still open as of 2026-08.** The compiler is now *on* in data-browser (`224bd4816`, 2026-08-19, via `oxc-transform-react` in `vite.config.ts`), and a live instance of the class was hit in the field on 2026-08-16 — [`pairing-ux-field-test.md`](./completed/pairing-ux-field-test.md) M15a, a table not re-rendering after a peer row arrived. The audit of `.props.X` / `.isReady()` / `.loading` reads in render has not started. |
| 2 | [unify-subscription-primitives.md](./unify-subscription-primitives.md) | Cleanup | Medium | Single `Subscription` shape with `Match::{Subject, Drive, Filter}` |
| 3 | Unify subscription actors | Cleanup | Done 2026-09-05 | Folded `LoroSyncBroadcaster` into `CommitMonitor`; planning doc removed |
| 5 | [unify-resource-dirty-signals.md](./unify-resource-dirty-signals.md) | Correctness | Medium | Single `getSaveState(subject)` enum |
| 6 | [unify-resource-representations.md](./unify-resource-representations.md) | Correctness | High | 🟡 Rust `datatypes` map + derived `Tree::Resources` cache shipped. Browser `_cache` dual still open. |
| 7 | [arc-actor-message-payloads.md](./arc-actor-message-payloads.md) | Performance | Low | ✅ Stretch landed — `SendFrame` + encode-once + `Bytes::from_owner` zero-copy at WS write. `MembershipNotification` already Arc-wrapped. `CommitMessage` Arc-wrap (`atomic_lib` change) deferred. |
| 8 | [subject-types-end-to-end.md](./subject-types-end-to-end.md) | Correctness | High | 🟡 Started — `Subject` brand + `asSubject`/`tryAsSubject`/`isValidSubject` in `browser/lib/src/subject.ts`. Rust `DidKind` classifier shipped. Consumer migration not started. |

## Suggested execution order

**Highest leverage** — 1 (React Compiler) is the highest bug density
in the codebase (~280 suspect sites) and won't get easier as the
codebase ages.

**Opportunistic cleanups** — 2 and 3 reduce mental overhead but are
not blocking anything. 7 remaining (CommitMessage Arc-wrap) is a
small perf win for high-fanout drives.

**Defer the invasive ones** — 5, 6, 8 need design alignment before
implementation. Each warrants its own RFC-style discussion.
