# Planning

This folder is for internal design notes and larger technical direction. It is
not public-facing product/spec documentation; that belongs in `docs/`.

Use this folder to stay aligned on active architectural plans before making
broad changes. Prefer updating an existing plan over adding a new root-level
scratch document. When a plan becomes obsolete, delete it. Session logs,
release checklists and validation transcripts do not belong here: once the
work has merged, delete the file and carry any open question into the owning
plan. Fully-shipped checklists that are still useful as as-built notes move to
[`completed/`](./completed/) and stay listed under **Landed**.

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
- [`commit-retention-floor-decision.md`](./completed/commit-retention-floor-decision.md) — envelope-on-resource; amended 2026-09-05, `Tree::Envelopes` shipped in #1313.
- [`trust-model-decision.md`](./completed/trust-model-decision.md) — the node that owns the URL is trusted with plaintext; anything that only stores is blind.
- [`schema-routes-decision.md`](./completed/schema-routes-decision.md) — `did:ad:frozen` is the on-ramp, optional schema is the write-path policy.

## Biggest gaps (reconciled against code 2026-09-18)

Ranked by impact. Each links to the plan that owns the work. Gaps closed since
the 2026-09-15 pass (durable Flutter writes, write-endpoint rate limits,
envelope replication, the Rust outbox, desktop CSP, dashboard entry point and
fork review diff) are recorded in their owning plans, not here.

1. **The query index silently drops rows.** A drive-scoped, sorted,
   class-filtered query returns fewer members than exist: the ignored test
   `is_a_encodings_all_match_the_class_constraint` in `lib/src/db/test.rs`
   reproduces `query_sorted_indexed` returning 2 of 3 matching rows, and
   [`silent-failures.md`](./silent-failures.md) carries two open entries for
   the same shape (5 of 22 Houseplants rows). PR in flight.
2. **Flutter and desktop bypass the runtime boundary.** Flutter keeps a
   `static DB: OnceLock<Arc<Db>>` and wraps it in `AtomicNode::from_db` per
   call (`flutter/rust/src/api/simple/state.rs`); the desktop app holds a raw
   `atomic_lib::Db` (`desktop/src/lib.rs`). [`atomic-lib-runtime.md`](./atomic-lib-runtime.md).
3. **`SYNC_PUSH` is an unsigned cross-trust import** gated by one drive-level
   verdict (`admit_drive_write` / write rights in `lib/src/sync/engine.rs`);
   no `AuthorizationProof` type exists in `lib/src`. [`authorization-sync.md`](./authorization-sync.md).
4. **The store grows with every write and is never compacted.** `sign_at`
   (`lib/src/commit.rs`) exports a full Loro snapshot per commit although its
   docstring promises an incremental update, and compaction exists only as the
   `atomic-server compact` subcommand (`server/src/bin.rs`). PR in flight.
   [`disk-storage-and-persistence-optimization.md`](./disk-storage-and-persistence-optimization.md).
5. **npm is seven betas behind**: the workspace is at `0.41.0-beta.7`, the
   registry serves `0.41.0-beta.0`. The `npm` job in `release.yml` exists
   since 2026-09-15 and #1355 (merged 2026-09-18) fixed its build order and
   publish step; the next `v*` tag publishes once the remaining
   trusted-publisher entries are in place. [`production-readiness.md`](./production-readiness.md).
6. **The managed-node bootstrap grace has no reaper.** `SyncPolicy` admits
   any drive for ten minutes after first sight (`lib/src/commit.rs`,
   `lib/src/sync/policy.rs`) and nothing reaps drives that never enroll.
   [`cloud-sync-managed-node.md`](./cloud-sync-managed-node.md) item 4,
   [`foss-public-host-mode.md`](./foss-public-host-mode.md) Phase 3.
7. **Code-first schemas live only in an unmergeable PR.** `defineSchema` and
   frozen `did:ad:` schemas are in #1262, a draft with conflicts last touched
   2026-09-01; nothing of it is on `develop`. The plugin model itself is no
   longer in this position: #1500 (merged 2026-09-17) carried it onto
   `develop`, and #1307 is now behind `develop`. [`json-schema-code-first.md`](./json-schema-code-first.md),
   [`plugins.md`](./plugins.md).

## Active
- [`atomic:` identifier scheme](atomic-scheme.md) — #1584: canonical `atomic:` scheme, dual-accept `did:ad:`, genesis v2.
- [Drive sharing and hosting state](drive-sharing-state.md) — verified transition for unenrolled drives; authoritative seat counts and staging acceptance remain.
- [Website publishing](./website-publishing.md) — FOSS publication on `develop` since #1500 (2026-09-17); managed SaaS adapter and the open follow-ups carried from that PR's handoff.
- [Assistant-authored websites](./assistant-websites.md) — prototype merged with #1500; plugin abstraction audit and remaining SaaS deployment work.
- [Notifications](./notifications.md) — proposal 2026-09-28: the server delivers into the Inbox, a follow model, and kinds for invites, access requests, new and changed resources and meetings.

Remaining work, not "this file exists."

Cross-repository account recovery: the canonical active plan is
`atomic-saas/planning/BACKUP_SECURITY.md`, section “SaaS password sign-in and
assisted recovery — September 10 direction”. Product direction is agreed;
password authentication and server-assisted recovery are not implemented.
It owns the security review, migration and acceptance checklist for the managed
browser flow; standalone recovery remains self-managed.

| Document | Status |
| --- | --- |
| [`production-readiness.md`](./production-readiness.md) | **Gate list.** Still open between `develop` and production: the first npm publish on a `v*` tag (job landed, #1355 merged 2026-09-18), green paired server/SaaS CI, the managed-node abuse gate, private source maps, backend synthetic error reporting, SaaS billing checks. Rate limiting, library-owned durability and desktop CSP shipped 2026-09-15. |
| [`security-audit-2026-09.md`](./security-audit-2026-09.md) | **Mostly fixed** (beta.6, plus B7 CSP, C18 and rate limits on 2026-09-15). Open: C16 process-global import flags, C17 DID watched-query leak, C20, C24 loopback NFS, permissive CORS, client errors as 500, section F, transitive advisories via actix-http and iroh 0.35. |
| [`drive-sharing-state.md`](./drive-sharing-state.md) | **In progress.** Verified transition for unenrolled drives shipped (#1466). Remaining: authoritative per-drive editor usage from the backend, root cause of the retained remote routing, staging acceptance. |
| [`cloud-subscription-panel.md`](./cloud-subscription-panel.md) | **Partial.** Profile and link-invite steps shipped. Remaining: SaaS email invitation to drive authorization in one journey, invitation usage limits, paid-seat approval, real seat counts, 50 GB pool. |
| [`e2e-concurrency.md`](./e2e-concurrency.md) | **Active.** Issue #1461. Shard isolation and harness simplification landed (#1463, #1465, #1472); worker matrix, repeated zero-retry acceptance and budgets remain. |
| [`e2e-light-heavy.md`](./e2e-light-heavy.md) | **Partial.** Automatic PR and feature-branch CI is paused; full Main runs on selected integration batches, `develop`, and tags. `@smoke` and Dagger light mode remain available locally. |
| [`e2e-diagnostic-hygiene.md`](./e2e-diagnostic-hygiene.md) | **Mostly done.** Collector lifecycles shipped. Remaining: pre-release noise pass, pending-upload placeholder, full strict rerun, catalog flows. |
| [`sentry-feedback-readiness.md`](./sentry-feedback-readiness.md) | **Active.** Feedback and React error capture verified on staging. Remaining: independent email receipt check, private source-map upload, backend synthetic reporting. |
| [`passkey-local-drive-unlock.md`](./passkey-local-drive-unlock.md) | **Fix shipped.** Remaining: original-tab NotFound after sign-out, physical passkey verification, deploy. |
| [`desktop-pkarr-restore.md`](./desktop-pkarr-restore.md) | **Discovery shipped** (beta.6). Remaining: private-drive enrollment policy (product decision), signed-in private fetch, packaged-build missing text. |
| [`google-calendar-import-gaps.md`](./google-calendar-import-gaps.md) | **Active audit.** All-day ranges implemented; remaining Google import fidelity work, formats and recurrence integration checklist. |
| [`extension-architecture.md`](./extension-architecture.md) | **Migration in progress.** Shared view protocol, scope policy and installation identity resolution are implemented; package activation and legacy UI signing remain. Apps contain data/views, connections synchronize sources, automations act; one extension lifecycle and host API, with phased convergence of packaged views, source-as-data apps, JS integrations and Reflector, retaining a separate privileged server-extension boundary. |
| [`github-issues-pilot.md`](./github-issues-pilot.md) | **Moved to atomic-plugins (PR #1549).** Pilot record: sandboxed GitHub issues ↔ kanban, background sync and code-first automations. The provider and its tests now live in [atomic-plugins](https://github.com/ontola/atomic-plugins); this repo keeps the runtime, catalog discovery and install. |
| [`plugin-view-contract.md`](./plugin-view-contract.md) | **In progress.** What plugin views need to be as capable as the table editor or Kanban: data, host services, environment, UI kit. Host services for drive apps landed first. |
| [`plugin-model-review.md`](./plugin-model-review.md) | **In progress.** Implemented authority/manifest checks, immutable releases, recovery journals and store UI; remaining connection lifecycle and provider certification. |
| [`connector-scale.md`](./connector-scale.md) | **Partly moved (PR #1549).** Discovery, install, authorization transport and host retrieval stay here; the GitHub and other providers, offline evidence and certification moved to [atomic-plugins](https://github.com/ontola/atomic-plugins). SaaS deployment, live OAuth/canaries, migrations and third-party evidence remain open. |
| [`schema-catalog.md`](./schema-catalog.md) | **Pilot in progress; catalog proposed.** Shared task properties in templates and GitHub table selection; schema discovery, contribution and evolution; connects frozen releases, templates, import mappings, and JSON Schema compatibility. |
| [`unified-sync.md`](./unified-sync.md) | **Active.** One sync API over WS or Iroh. Carries the single **Remaining work (2026-09-03)** checklist for every open sync item across these plans. The 2026-07 audit history is in [`completed/unified-sync-audit-2026-07.md`](./completed/unified-sync-audit-2026-07.md). |
| [`serverless-p2p.md`](./serverless-p2p.md) | **Planned.** Device sync without a hub (written same-agent-first; admission is rights-based since 2026-07-17). AUTH-before-SYNC and the `AUTH.requestedSubject`↔drive binding landed 2026-09-01 (Iroh). Live-link destroys travel as signed `COMMIT` frames since 2026-09-03. P0 remaining: require envelopes on every `remove[]` (`Tree::Envelopes` exists; nothing blocks it). `AtomicTransport` / `SyncSession::serve` first slice landed 2026-09-05 with only `ChannelTransport`; outbox port and the four `sync_drive_with_peer*` variants are open. |
| [`foss-public-host-mode.md`](./foss-public-host-mode.md) | **Partial.** Phase 1–2 built; OQ5 library path closed 2026-09-05 (`admit_unknown_drive`: Public never creates, Owner enrolls only the owner). Phase 3 (rate limits, Iroh stream refusal) is untouched. |
| [`authorization-sync.md`](./authorization-sync.md) | **Draft.** P1 done, P2 partial (`classify_auth_impact` exists). P3 open: no `AuthorizationProof`, signer still auto-inserted into `write`, `genesis_signer()` has no non-test caller. P4 open: `SYNC_PUSH` imports raw Loro on a drive-level verdict. |
| [`unified-data-layer.md`](./unified-data-layer.md) | **Partial.** Browser/JS: one ingress, one outbox, one subscription model. Atomic writes, outbox, ingress entry points and immutable read/save subscriptions shipped. Remaining: boundary extraction and the `CommitBuilder` review (31 non-test references, all in `browser/lib/src`; `addResource(` has no non-test call site left in `browser/data-browser/src`, counted 2026-09-18). |
| [`loro-source-of-truth.md`](./loro-source-of-truth.md) | **Partial.** Sparse `datatypes` map + Phase 2a–2c shipped (`Tree::Resources` is a derived cache). Remaining: drop the untagged heuristic and the 3-way `build_state_doc` fallback, snapshot backfill (Phase 4), Phase 1.6 `Value` reshape (~966 sites), Flutter undo. |
| [`atomic-lib-runtime.md`](./atomic-lib-runtime.md) | **Partial.** `AtomicNode` is the binding runtime; the WASM `ClientDb` is its only adapter. Flutter and desktop still hold a raw `Db`; the node has no blob API; `NodeConfig` was cut. Library-owned durable flush is the first slice. Local KV FTS landed in [`local-search.md`](./local-search.md). |
| [`genesis-self-verifying.md`](./genesis-self-verifying.md) | **Partial.** Server and browser mint and verify inline genesis certs. Remaining: DataRoute verify UI, `genesis` propval immutability, cert-signed `drive` in `check_rights`. |
| [`drive-reconciliation.md`](./drive-reconciliation.md) | **Partial.** Core in `lib/src/sync/rbsr.rs` + TS mirror; **on the WS wire** as the stateless text frames `RBSR_FP`/`RBSR_ITEMS` (full-VV fallback). Not on Iroh; fingerprints still O(range); canonical cross-impl hash unspecified, so the hash-first probe rarely matches. |
| [`auditability-loro-history.md`](./auditability-loro-history.md) | **Mostly built.** `Tree::Envelopes`, `attribute_history`, `/history-attribution`, the History Verified badge, and since 2026-09-15 envelope replication over `SYNC_PUSH` and vault packs. Next: secondary indexes, session certificates, header-only envelopes. |
| [`p2p-presence.md`](./p2p-presence.md) | **Mostly built.** `EPHEMERAL 0x40` codec, peer send/receive and the server bridge are in. Remaining: two-device verification (M12), bandwidth (OQ1), and the OQ3 outbound agent filter, which is a cross-agent presence leak on a multi-agent hub. |
| [`zones.md`](./zones.md) | **Proposal.** Nothing built. Structural fix for the permission-check half of [`index-performance.md`](./index-performance.md). Partly overtaken by the authority-unit decision. |
| [`partial-sync.md`](./partial-sync.md) | **Proposal.** Replicate part of a drive per device. Nothing built. |
| [`drafts-and-suggestions.md`](./drafts-and-suggestions.md) | **Mechanism shipped** (`Fork` class, `diffFork`/`mergeFork`, document body CRDT merge) and, since 2026-09-16, the review diff in `ForkBar`. Open: suggest-for-non-writers, per-property revert, reject-with-reason, Canvas fork. |
| [`device-pairing.md`](./device-pairing.md) | **Proposal.** One-scan pairing; QR is routing only (no secret). P0/P1/P2.5 shipped. Remaining: P2 (`pair` kind, mDNS list, pkarr redial), P3, M4, extra-workspace inventory. |
| [`json-ad-compact.md`](./json-ad-compact.md) | **Phase 1–2 shipped** (resolver, tool I/O, context providers). Remaining: rebase `create_table.rows` on `fromCompact`; server `format=compact`. |
| [`table-view-filters.md`](./table-view-filters.md) | **Views shipped** — Default View (filters, sort, columns, operators) and the multi-view switcher (`TableViewTabs`, `?view=`). Remaining: index-accelerated range scans. |
| [`unified-templates.md`](./unified-templates.md) | **Initial slice shipped** (#1428: catalogue, editable previews, template chat). Remaining: portable format, website adapter, demo-lifecycle extraction, provenance and resume, live-AI acceptance. |
| [`dashboards.md`](./dashboards.md) | **First slice shipped**, reachable from its table as a `dashboard` view tab since 2026-09-16. Open: the set-level action verb, parameters, templates shipping a dashboard. |
| [`content-i18n.md`](./content-i18n.md) | **LocalizedText + template locales shipped.** Nothing in the app resolves translation siblings. Remaining: TranslationsBar, `useTranslation`, `/query` `lang`, search language filter. |
| [`website-templates.md`](./website-templates.md) | Template repair complete (DID), two-locale E2E exists. Its CMS list is the website view of `drafts-and-suggestions.md` and `content-i18n.md`. Open: publication visibility, CMS origin, in-page edit affordance, canonical paths. Self-hosted publishing (#1500) merged 2026-09-17; the assistant-designed-sites prototype PR #1498 is still an open draft against `feat/plugin-model`. |
| [`structural-problems-index.md`](./structural-problems-index.md) | **Live index.** React subscription audit is partial; save-state APIs shipped with two consumers. Browser metadata cleanup and subject-brand consumers remain; server subscription work is complete. |
| [`react-compiler-resource-proxy.md`](./react-compiler-resource-proxy.md) | **Partial.** Immutable read/save status hooks and the data-inspector subscription shipped; about 13% of property reads are still render-time getters, migrating one regression at a time. |
| [`canvas-undo-consolidation.md`](./canvas-undo-consolidation.md) | Phase A + C landed (browser). Phase B (Flutter action-stack removal, `replace_list_items`) open and unstarted. |
| [`index-performance.md`](./index-performance.md) | First tranche shipped. Remaining: exact counts, typed sort keys, batched reads, watched-filter LRU, re-profiling. Structural permission-check fix is `zones.md`, not built. |
| [`disk-storage-and-persistence-optimization.md`](./disk-storage-and-persistence-optimization.md) | **Partial.** Startup size/reclaimable-space diagnostics and automatic compaction shipped (fix 2); fresh e2e data dirs done. Open: incremental Loro updates per commit (fix 1), history pruning (fix 3), SIGTERM path (fix 4). |
| [`virtual-drive.md`](./virtual-drive.md) | **Shipped** as a local NFS mount in the Tauri desktop app (`desktop/src/vfs.rs`, unauthenticated loopback, audit C24). Still proposal: headless-server mount, FUSE/WinFSP, native cloud-sync APIs, mobile providers. |
| [`commit-retention-and-state-certificates.md`](./commit-retention-and-state-certificates.md) | **Superseded.** Envelope-on-resource replaced the retention design; Phase 1 and 2.5 shipped. Only the `stateHash` certificate and per-resource `retention` propval remain from this document. |
| [`s3-blob-storage.md`](./s3-blob-storage.md) | **Partial.** Server-wide S3, verified migration and SaaS enforcement implemented. The backend trait is `get/put/size` only: streaming, delete/GC, per-tenant configuration and encrypted Vault attachments remain. |
| [`plugins.md`](./plugins.md) | **Partial, on `develop` since #1500** (2026-09-17) — one plugin model (`run` end to end, per-app agents, unattended runs): `browser/plugin`, `browser/lib/src/plugin-run.ts`, `integrations/`, the `wasm-plugins` server routes. PR #1307 is still open but behind `develop` (one file only on that branch). Remaining work is the list in #1307 and `extension-architecture.md`. |
| [`json-schema-code-first.md`](./json-schema-code-first.md) | **Proposal**; nothing on `develop`. `defineSchema` + frozen `did:ad:` schemas are in PR #1262, a draft last touched 2026-09-01. |
| [`class-constraints-and-forms.md`](./class-constraints-and-forms.md) | **Proposal** (2026-10-08). Allowed values, limits and linked classes move from Properties to a JSON Schema-style constraints map on the class; what that means for forms, tables and kanban. Nothing built. |
| [`android-data-reuse.md`](./android-data-reuse.md) | **Draft.** One store/agent/Iroh node per Android device. Nothing built. Supersedes `on-device-atomic-daemon.md`. |
| [`SDK-API-design.md`](./SDK-API-design.md) | SDK / agent DX direction. |
| [`api-plugins.md`](./api-plugins.md) | **Exploratory; providers moved to atomic-plugins (PR #1549).** Rebuilding PR #1383 (OpenAPI/OAuth imports) on the plugin model. The WASM Syncables path is removed (#1618), so LocalThought connect/sync is broken until its proxy calls move into the plugin iframe. |
| [`mcp-endpoint.md`](./mcp-endpoint.md) | **Proposal.** Atomic as an MCP server. Local stdio signs as the user; remote HTTP is read-only until issued-agent writes. Does not wait on #1310; remote auth is the #1275 AS shape. |

### Explorations with no code

Design intent, kept for direction. None has a line of code behind it.

| Document | Scope |
| --- | --- |
| [`reticulum-sync.md`](./reticulum-sync.md) | Atomic sync protocol over Reticulum. |
| [`nextgraph-interop.md`](./nextgraph-interop.md) | `did:ng:` via a scheme-routed Store backend. PR #1360 (optional NextGraph mirror) is open. |
| [`personal-information-suite.md`](./personal-information-suite.md) | Contacts, calendar, email. |
| [`social-apps.md`](./social-apps.md) | Requirements for social-network-shaped apps. Companion to `zones.md`. |
| [`atomic-assistant-browser-extension.md`](./atomic-assistant-browser-extension.md) | Local-first Chromium extension. |
| [`tours.md`](./tours.md) | Recorded tours; `unified-templates.md` defers them. |
| [`atomic-forms.md`](./atomic-forms.md) | **Planned.** Forms/Survey feature — schema, builder UI, agent-less submission endpoint, `/form/:id` runtime, results in Tables. Research: [`atomic-forms-research.md`](./atomic-forms-research.md). |

## Slices and companions

Not top-level plans. Indexed so they do not go missing.

| Document | Status |
| --- | --- |
| [`unify-subscription-primitives.md`](./unify-subscription-primitives.md) | **Done in reduced form (2026-09-04).** One `SUB <subject>` frame; `SUBSCRIBE` and `SUBSCRIBE_QUERY` removed. Design text kept as the record. |
| [`unify-resource-representations.md`](./unify-resource-representations.md) | **Mostly shipped.** `Resource#cache` is derived from the Loro doc. The `_auxValues` overlay stays for binary values Loro cannot hold; the proposal body predates that. |
| [`unify-resource-dirty-signals.md`](./unify-resource-dirty-signals.md) | **Partial.** `getSaveState(resource)`, the React hook and scheduled-save ownership shipped; two consumers so far. Other save UIs remain. |
| [`subject-types-end-to-end.md`](./subject-types-end-to-end.md) | Partial. Rust `DidKind` shipped; the browser brand has zero consumers, the app still calls unbranded `Client.isValidSubject`. |
| [`arc-actor-message-payloads.md`](./arc-actor-message-payloads.md) | **Stretch shipped.** `SendFrame { Arc<[u8]> }` encode-once is in; only the `atomic_lib` `loro_update: Vec<u8>` question remains and is low value now. |
| [`sync-onboarding-ux.md`](./sync-onboarding-ux.md) | Reference. Cross-client copy for what can reach what. Companion to [`device-pairing.md`](./device-pairing.md). |
| [`main-drive-and-paths.md`](./main-drive-and-paths.md) | Strategy. DID-branch deployment: root drive, legacy URLs, human-readable paths. Phases 1–3 unstarted. |
| [`actions.md`](./actions.md) | **Steps 1–4 shipped.** Registry drives ⌘M, ⌘K (capped prefix match), hotkeys, the shortcuts overlay/page, and simple AI tools. Remaining: MCP projection when a server exists ([`mcp-endpoint.md`](./mcp-endpoint.md), #1347 merged 2026-09-18). |
| [`silent-failures.md`](./silent-failures.md) | Living log of error-handling failures that reported success (2026-08-21). Carries the two open query-index entries (gap 1), M8 from the pairing field test, the unreproduced Safari fork query and the e2e harness traps from the #1500 pass. |
| [`app-setup.md`](./app-setup.md) | Typed app setup checklist: shared JSON Schema input contract, generic setup form, assistant handoff. |
| [`plugin-secrets.md`](./plugin-secrets.md) | **Built** (2026-08-21, encrypted at rest 2026-08-22). Host-side `secret:<name>` substitution for plugin fetch. |
| [`plugin-runtime-convergence.md`](./plugin-runtime-convergence.md) | **Proposal** (2026-09-18, #1546). One plugin host across JS and WASM worlds. |
| [`durable-after-commit.md`](./durable-after-commit.md) | **Design** (2026-09-29, #1851). Durable, queued JS `afterCommit` for user-installed plugins on tables showing their view; reads #1850's change list, writes through #1788's row grant. Nothing built. |
| [`devonian-reconnect.md`](./devonian-reconnect.md) | Task note: concurrent route resumes consuming one PKCE verifier. The Devonian demo it touched has been removed. |
| [`account-ai-credits.md`](./account-ai-credits.md) | Included AI for SaaS accounts; contract lives in atomic-saas. |
| [`ai-chat-draft-persistence.md`](./ai-chat-draft-persistence.md) | **Diagnosed, not fixed** (2026-08-24). AI chats are lost while the model is still generating. |
| [`live-conversations.md`](./live-conversations.md) | Push-to-talk voice chat with OpenRouter and SaaS credits. |
| [`dart-sdk-package.md`](./dart-sdk-package.md) | **Proposal** (2026-09-18). Publish `flutter/lib/atomic/` as a Dart SDK package. |

Closed decisions, as-built records, closed explorations and fixed notes live
in [`completed/`](./completed/): the five decisions above, the 2026-07 sync
audit, the outbox data-loss race, `encryption.md` (closed 2026-09-01: at-rest
plus vault), the pairing field test (2026-08, open items carried into
`device-pairing.md`, `silent-failures.md` and `p2p-presence.md`), the
table-creation observation log, the kanban test spec, and the as-built notes
below that have no follow-ups.

## Landed

As-built notes. Remaining follow-ups, if any, live in the Active table or in
the document itself.

| Document | What shipped |
| --- | --- |
| [`deterministic-personal-drive.md`](./deterministic-personal-drive.md) | Personal-drive DID derived from the Agent key. Repeat genesis merges. Pointer is not identity. `Db::create_drive` lists on the personal drive. |
| [`multi-property-filter.md`](./multi-property-filter.md) | AND filters, full-stack (Rust → server → lib → WASM → React → e2e). UI lives in `table-view-filters.md`. |
| [`table-templates-and-mini-apps.md`](./table-templates-and-mini-apps.md) | Computed and derived columns, aggregates, assistant tools, thirteen table templates, derived columns in filters and aggregates. |
| [`sync.md`](./sync.md) | WS `COMMIT`, echo suppression, unified `UPDATE`/`DESTROY`; Flutter WS session shipped. One open line: overlap trim (AUTH repetition, `SYNC_PUSH` chunking, HELLO codec tests). |
| [`encrypted-vault-format.md`](./encrypted-vault-format.md) | Vault backup v1 in `lib/src/vault/` (2026-08-04). Open spec: compression, blob chunking, per-object signatures. |
| [`meetings.md`](./meetings.md) | Meeting resource, page, prepare-then-start flow. Open: stale-meeting reaping, attendance events. |
| [`demo-experience.md`](./demo-experience.md) | v1 and v2 demo workspace. |
| [`local-search.md`](./local-search.md) | KV inverted index in `atomic_lib` (redb/OPFS/sled): BM25 + prefix + 1-edit prefix-fuzzy + PropValSub filters. Hosted `/search` is the same engine; Tantivy is gone. |
| [`cloud-sync-managed-node.md`](./cloud-sync-managed-node.md) | Onboarding, managed-node detection, enrollment, heartbeat and replication pull. Verified against the SaaS `LocalProcessNodeProvider` only; the sync-path admission gate and reaper are not built. |
| [`completed/commit-fanout-drive-isolation.md`](./completed/commit-fanout-drive-isolation.md) | Drive-scoped WS commit fan-out + server-side drive safety net. |
| [`completed/cleanup-update-encoding.md`](./completed/cleanup-update-encoding.md) | Unified `decode_update`; TS client exports compact Loro deltas. |
| [`completed/sign-at-drain.md`](./completed/sign-at-drain.md) | One signed commit per dirty subject per drain pass. |
| [`completed/opfs-per-agent-encryption.md`](./completed/opfs-per-agent-encryption.md) | One encrypted OPFS database per agent. Session isolation on sign-out. |
| [`completed/node-did-canonicalization.md`](./completed/node-did-canonicalization.md) | `did:ad:node:<hex>` is the only user-facing node ID form. |
| [`completed/migrate-jsonarray-to-json.md`](./completed/migrate-jsonarray-to-json.md) | Canvas `strokeData` datatype is `json`. |
| [`completed/emoji-cover-images.md`](./completed/emoji-cover-images.md) | Emoji + cover images on resources. |
| [`completed/presence-views.md`](./completed/presence-views.md) | Presence on canvas, tables, navbar, sidebar. |

## Agent Workflow

Before architectural work, read:

1. [`atomic-lib-runtime.md`](./atomic-lib-runtime.md) for the long-term boundary.
2. [`unified-sync.md`](./unified-sync.md) for sync/transport work (Flutter, WS, Iroh).
3. Any other domain-specific plan that matches the task.
4. Relevant code and tests; treat plans as direction, not proof that code already matches.

Keep `planning/` concise. Avoid session transcripts, stale estimates, and
postmortems that duplicate current plans.

- [Plugin runtime v1](plugin-runtime-v1.md) — implemented authoring/approval contract and remaining release gates.

Shared integration actions now have a first GitHub pilot; grants, event/cron continuation,
MCP stdio, recovery, indexed history pagination and cleanup of abandoned and settled manual action payloads plus durable completion acknowledgement and tracked automation receipt cleanup with explicit abandonment are implemented; scaling work is tracked in [connector scale](connector-scale.md)
and the [action contract](../integrations/ACTIONS.md).

- [Shared import identity](import-identity.md) — native localId reuse, source baselines and remaining cross-node/recovery work.
