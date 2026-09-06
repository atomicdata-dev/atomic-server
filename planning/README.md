# Planning

This folder is for internal design notes and larger technical direction. It is
not public-facing product/spec documentation; that belongs in `docs/`.

Use this folder to stay aligned on active architectural plans before making
broad changes. Prefer updating an existing plan over adding a new root-level
scratch document. When a plan becomes obsolete, delete it. Fully-shipped
checklists that are still useful as as-built notes stay here, listed under
**Landed**.

The status in this index should match the document's own status line. The
document wins if they disagree.

Protocol reference lives in the public docs:
[`docs/src/websockets.md`](../docs/src/websockets.md). Planning documents may
discuss how that protocol is used internally, but should not duplicate the
wire reference.

## Decisions

Decision documents: one question each, written as an RFC with a recommendation.
All five were **accepted on 2026-09-01**, folded into their owning plans, and
now live in [`completed/`](./completed/):

- [`runtime-boundary-decision.md`](./completed/runtime-boundary-decision.md) — `AtomicNode` in `lib/src/runtime/` is the binding runtime; no parallel `simple.rs` / `ffi/`.
- [`authority-unit-decision.md`](./completed/authority-unit-decision.md) — the drive stays the unit of authority; the zone chain is hybrid/additive.
- [`commit-retention-floor-decision.md`](./completed/commit-retention-floor-decision.md) — envelope-on-resource; amended 2026-09-05, `Tree::Envelopes` ships in #1313.
- [`trust-model-decision.md`](./completed/trust-model-decision.md) — the node that owns the URL is trusted with plaintext; anything that only stores is blind.
- [`schema-routes-decision.md`](./completed/schema-routes-decision.md) — `did:ad:frozen` is the on-ramp, optional schema is the write-path policy.

## Active

Remaining work, not "this file exists."

| Document | Status |
| --- | --- |
| [`unified-sync.md`](./unified-sync.md) | **Active.** One sync API over WS or Iroh. Carries the single **Remaining work (2026-09-03)** checklist for every open sync item across these plans. The 2026-07 audit history is in [`completed/unified-sync-audit-2026-07.md`](./completed/unified-sync-audit-2026-07.md). |
| [`serverless-p2p.md`](./serverless-p2p.md) | **Planned.** Device sync without a hub (written same-agent-first; admission is rights-based since 2026-07-17). AUTH-before-SYNC and the `AUTH.requestedSubject`↔drive binding landed 2026-09-01 (Iroh). Live-link destroys travel as signed `COMMIT` frames since 2026-09-03. P0 remaining: require envelopes on every `remove[]` once `Tree::Envelopes` exists. `AtomicTransport` / `SyncSession::serve` first slice landed 2026-09-05; outbox port and the remaining `sync_drive_with_peer*` collapse are open. |
| [`foss-public-host-mode.md`](./foss-public-host-mode.md) | **Partial.** Phase 1–2 built; OQ5 library path closed 2026-09-05 (`admit_unknown_drive`: Public never creates, Owner enrolls only the owner). Phase 3 (rate limits, Iroh stream refusal) is untouched. |
| [`authorization-sync.md`](./authorization-sync.md) | **Draft.** Signed commit authorization, grant-chain evidence, peer-sync trust boundaries. |
| [`unified-data-layer.md`](./unified-data-layer.md) | **Partial.** Browser/JS: one ingress, one outbox, one subscription model. Atomic writes and the single outbox shipped; the ingress/subscription half and `SaveState` are open. |
| [`loro-source-of-truth.md`](./loro-source-of-truth.md) | **Partial.** Sparse `datatypes` map + Phase 2a–2c shipped (`Tree::Resources` is a derived cache). Remaining: drop the untagged heuristic, Phase 1.6 `Value` reshape, Flutter undo. |
| [`atomic-lib-runtime.md`](./atomic-lib-runtime.md) | **Partial.** `AtomicNode` is the binding runtime; the WASM `ClientDb` is its only adapter and the unused surface was cut back 2026-09-04. Open: the other bindings. Local KV FTS landed in [`local-search.md`](./local-search.md). |
| [`genesis-self-verifying.md`](./genesis-self-verifying.md) | **Partial.** Server and browser mint and verify inline genesis certs. Remaining: DataRoute verify UI, `genesis` propval immutability. |
| [`drive-reconciliation.md`](./drive-reconciliation.md) | **Partial.** Core in `lib/src/sync/rbsr.rs` + TS mirror; **on the WS wire** as the stateless text frames `RBSR_FP`/`RBSR_ITEMS` (full-VV fallback). Not on Iroh; fingerprints still O(range); canonical cross-impl hash unspecified. |
| [`zones.md`](./zones.md) | **Proposal.** Nothing built. Structural fix for the permission-check half of [`index-performance.md`](./index-performance.md). |
| [`partial-sync.md`](./partial-sync.md) | **Proposal.** Replicate part of a drive per device. |
| [`drafts-and-suggestions.md`](./drafts-and-suggestions.md) | **Mechanism shipped** (`Fork` class, `diffFork`/`mergeFork`, document body CRDT merge). Review/diff UI, suggest-for-non-writers, Canvas fork still open. |
| [`device-pairing.md`](./device-pairing.md) | **Proposal.** One-scan pairing; QR is routing only (no secret). C0 and M6 closed. Remaining: extra-workspace inventory, M4 (carried over from the field test). |
| [`json-ad-compact.md`](./json-ad-compact.md) | **Phase 1–2 shipped** (resolver, tool I/O, context providers). Remaining: rebase `create_table.rows` on `fromCompact`; server `format=compact`. |
| [`table-view-filters.md`](./table-view-filters.md) | **Views shipped** — Default View (filters, sort, columns, operators) and the multi-view switcher (`TableViewTabs`, `?view=`). Remaining: index-accelerated range scans. |
| [`table-templates-and-mini-apps.md`](./table-templates-and-mini-apps.md) | **Partial.** Steps 3–6 shipped (computed columns, aggregates, assistant tools, catalogue). Remaining: derived columns in filters/aggregates. |
| [`dashboards.md`](./dashboards.md) | **First slice shipped.** Remaining: the sixth action verb, parameters, reaching a dashboard from its table. |
| [`content-i18n.md`](./content-i18n.md) | **LocalizedText + template locales shipped.** Remaining: TranslationsBar, `useTranslation`, `/query` `lang`, search language filter. |
| [`website-templates.md`](./website-templates.md) | Template repair complete (DID). Remaining CMS product: drafts-from-site, i18n tooling, canonical paths. |
| [`structural-problems-index.md`](./structural-problems-index.md) | **Live index.** Highest remaining: React Compiler / Resource proxy (#1), audit not started while the compiler is on. #6 mostly shipped; #2/#3 server side done 2026-09-04. |
| [`react-compiler-resource-proxy.md`](./react-compiler-resource-proxy.md) | **Planned, audit not started.** Stale UI from Compiler memoizing Resource proxy reads; compiler on since 2026-08-19, field instance M15a. |
| [`canvas-undo-consolidation.md`](./canvas-undo-consolidation.md) | Phase A + C landed (browser). Phase B (Flutter action-stack removal) open. |
| [`index-performance.md`](./index-performance.md) | First tranche shipped. Structural permission-check fix is `zones.md`, not built. |
| [`disk-storage-and-persistence-optimization.md`](./disk-storage-and-persistence-optimization.md) | **Proposal.** Full-snapshot writes, no auto-compaction, O(file) open fsync. |
| [`virtual-drive.md`](./virtual-drive.md) | **Shipped** as a local NFS mount in the Tauri desktop app (`desktop/src/vfs.rs`). Still proposal: headless-server mount, FUSE/WinFSP, native cloud-sync APIs, mobile providers. |
| [`commit-retention-and-state-certificates.md`](./commit-retention-and-state-certificates.md) | **Mostly shipped.** Commits are signed envelopes; content rows dropped; `Tree::Envelopes` keeps the latest (or all) per resource. Remaining: envelope carriage in bulk sync and the vault. |
| [`p2p-presence.md`](./p2p-presence.md) | **Mostly built.** `EPHEMERAL 0x40` codec, peer send/receive and the server bridge are in (`lib/src/sync/iroh_e2e.rs` `e2e_presence_crosses_the_link_without_being_stored`). Remaining: two-device verification (M12), bandwidth measurement (OQ1). Scoped to your own devices by product choice. |
| [`reticulum-sync.md`](./reticulum-sync.md) | **Proposal.** Atomic sync protocol over Reticulum. |
| [`json-schema-code-first.md`](./json-schema-code-first.md) | **Proposal**; `defineSchema` + frozen `did:ad:` schemas in flight in PR #1262 (not on `develop`). Code-first JSON Schema → local DID-backed Class/Property resources. |
| [`SDK-API-design.md`](./SDK-API-design.md) | SDK / agent DX direction. |
| [`plugins.md`](./plugins.md) | **Partial, off `develop`** — one plugin model (`run` end to end, per-app agents, unattended runs). The code lives on `feat/plugin-model` (PR #1307), not `develop`. Absorbed `llm-wasm-gui-plugins.md`, `importers.md`, `habits-app.md` (2026-09-01); the habits RPC-`query` blocker is a line in it. |
| [`personal-information-suite.md`](./personal-information-suite.md) | **Exploration.** Contacts, calendar, email. Nothing built. |
| [`social-apps.md`](./social-apps.md) | Requirements for social-network-shaped apps. Companion to `zones.md`. |
| [`android-data-reuse.md`](./android-data-reuse.md) | **Draft.** One store/agent/Iroh node per Android device. Supersedes `on-device-atomic-daemon.md` (deleted 2026-09-01; desktop remainder is a note in `virtual-drive.md`). |
| [`nextgraph-interop.md`](./nextgraph-interop.md) | **Proposal.** `did:ng:` via a scheme-routed Store backend. |
| [`s3-blob-storage.md`](./s3-blob-storage.md) | Pluggable blob backend (redb/S3/hybrid). |
| [`atomic-assistant-browser-extension.md`](./atomic-assistant-browser-extension.md) | **Proposal.** Local-first Chromium extension. |
| [`tours.md`](./tours.md) | Design, not built. |
| [`local-search.md`](./local-search.md) | **Landed.** KV inverted index in `atomic_lib` (redb/OPFS/sled): BM25 + prefix + 1-edit prefix-fuzzy + PropValSub filters. Hosted `/search` is the same engine; Tantivy is gone. |

## Slices and companions

Not top-level plans. Indexed so they do not go missing.

| Document | Status |
| --- | --- |
| [`unify-subscription-primitives.md`](./unify-subscription-primitives.md) | **Done in reduced form (2026-09-04).** One `SUB <subject>` frame; `SUBSCRIBE` and `SUBSCRIBE_QUERY` removed. Design text kept as the record. |
| [`unify-resource-representations.md`](./unify-resource-representations.md) | **Mostly shipped.** `Resource#cache` is derived from the Loro doc. Remaining: the `_auxValues` overlay. |
| [`unify-resource-dirty-signals.md`](./unify-resource-dirty-signals.md) | Planned, not started. Single `getSaveState(subject)` enum. |
| [`subject-types-end-to-end.md`](./subject-types-end-to-end.md) | Partial. Rust `DidKind` shipped; the browser brand still has no consumer. |
| [`arc-actor-message-payloads.md`](./arc-actor-message-payloads.md) | Partial. WS encode-once shipped; `CommitMessage` Arc-wrap deferred. |
| [`sync-onboarding-ux.md`](./sync-onboarding-ux.md) | Reference. Cross-client copy for what can reach what. Companion to [`device-pairing.md`](./device-pairing.md). |
| [`main-drive-and-paths.md`](./main-drive-and-paths.md) | Strategy. DID-branch deployment: root drive, legacy URLs, human-readable paths. |
| [`actions.md`](./actions.md) | **Steps 1–4 shipped.** Registry drives ⌘M, ⌘K (capped prefix match), hotkeys, the shortcuts overlay/page, and simple AI tools. Remaining: MCP projection when a server exists. |
| [`silent-failures.md`](./silent-failures.md) | Living log of error-handling failures that reported success (2026-08-21). Carries M8 from the pairing field test. |
| [`auditability-loro-history.md`](./auditability-loro-history.md) | **Building.** `Tree::Envelopes` + `attribute_history` + `/history-attribution` + History Verified badge shipped 2026-09-05. Next: envelopes travel in bulk sync and the vault. |

Closed decisions, as-built records, closed explorations and fixed notes live
in [`completed/`](./completed/): the five decisions above, the 2026-07 sync
audit, the outbox data-loss race, `encryption.md` (closed 2026-09-01: at-rest
plus vault), the pairing field test (2026-08, open items carried into
`device-pairing.md`, `silent-failures.md` and `p2p-presence.md`), the
table-creation observation log and the kanban test spec.

## Landed

As-built notes. Remaining follow-ups, if any, live in the Active table or in
the document itself.

| Document | What shipped |
| --- | --- |
| [`deterministic-personal-drive.md`](./deterministic-personal-drive.md) | Personal-drive DID derived from the Agent key. Repeat genesis merges. Pointer is not identity. `Db::create_drive` lists on the personal drive. |
| [`multi-property-filter.md`](./multi-property-filter.md) | AND filters, full-stack (Rust → server → lib → WASM → React → e2e). UI lives in `table-view-filters.md`. |
| [`commit-fanout-drive-isolation.md`](./commit-fanout-drive-isolation.md) | Drive-scoped WS commit fan-out + server-side drive safety net. |
| [`cleanup-update-encoding.md`](./cleanup-update-encoding.md) | Unified `decode_update`; TS client exports compact Loro deltas. |
| [`sign-at-drain.md`](./sign-at-drain.md) | One signed commit per dirty subject per drain pass. |
| [`sync.md`](./sync.md) | WS `COMMIT`, echo suppression, unified `UPDATE`/`DESTROY`; Flutter WS session shipped. The last test gaps (`ws_errors.rs`, `ws_unsub.rs`, browser `postCommit`) closed 2026-09-04. |
| [`encrypted-vault-format.md`](./encrypted-vault-format.md) | Vault backup v1 in `lib/src/vault/` (2026-08-04). |
| [`opfs-per-agent-encryption.md`](./opfs-per-agent-encryption.md) | One encrypted OPFS database per agent. Session isolation on sign-out. |
| [`meetings.md`](./meetings.md) | Meeting resource, page, prepare-then-start flow. |
| [`node-did-canonicalization.md`](./node-did-canonicalization.md) | `did:ad:node:<hex>` is the only user-facing node ID form. |
| [`migrate-jsonarray-to-json.md`](./migrate-jsonarray-to-json.md) | Canvas `strokeData` datatype is `json`. |
| [`emoji-cover-images.md`](./emoji-cover-images.md) | Emoji + cover images on resources. |
| [`presence-views.md`](./presence-views.md) | Presence on canvas, tables, navbar, sidebar. |
| [`demo-experience.md`](./demo-experience.md) | v1 demo workspace. |
| [`cloud-sync-managed-node.md`](./cloud-sync-managed-node.md) | Onboarding, managed-node detection, enrollment, heartbeat and replication pull. Verified against the SaaS `LocalProcessNodeProvider` only; the sync-path admission gate is not built. |

## Agent Workflow

Before architectural work, read:

1. [`atomic-lib-runtime.md`](./atomic-lib-runtime.md) for the long-term boundary.
2. [`unified-sync.md`](./unified-sync.md) for sync/transport work (Flutter, WS, Iroh).
3. Any other domain-specific plan that matches the task.
4. Relevant code and tests; treat plans as direction, not proof that code already matches.

Keep `planning/` concise. Avoid session transcripts, stale estimates, and
postmortems that duplicate current plans.
