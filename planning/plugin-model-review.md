# Plugin model review for the integration ecosystem

**Status:** Implementation in progress, 2026-09-05, on `feat/plugin-model`.
The findings below describe the original static review at `ccfbb1e14`; the
implementation checklist records what has since changed. The user authorized
addressing the findings. This is not an exhaustive security audit.

## Keep the foundation

Keep one Plugin model with view/run entrypoints, source-as-Atomic-data for
authoring, TypeScript/JS connector logic, host-owned credentials, existing
browser isolation and server interpreter, and previewable Atomic changes.
Start continuous execution inside atomic-server. Neither a separate service nor
a DSL replacement is necessary to address the findings. A DSL/OpenAPI compiler
can target the same contract later.

## Findings, ordered by consequence

### 1. The host does not yet enforce the promised read boundary

`server/src/plugins/js_runtime.rs:173` StoreHost holds Db/drive/plugin but no
caller or effective grant. Its get_resource at line 303 directly reads Db;
query at 315 uses Query::default, whose for_agent is Sudo
(`lib/src/storelike.rs:806`). The manual endpoint checks write access to the
plugin, then supplies this host (`server/src/handlers/plugin_run.rs`). Permission
to edit a plugin does not authorize reading unrelated private resources on the
same server. The drive value is also supplied by the request; bind it to verified
plugin ownership before credential lookup. No exploit was executed.

Change: construct one effective execution grant, intersect caller/app rights
with installed capability scope, and enforce it on every get/query/mutation and
egress path. Query results need authorization filtering as well as subject GETs.

### 2. The proposal-only run promise is false for external effects

`StoreHost::fetch` parses arbitrary HTTP methods and immediately calls send
(`js_runtime.rs:258-280`). This happens during run, before the verdict exists.
Origin-scoped credentials constrain destination, not whether a request modifies
the remote system. Therefore the plan's "run returns a proposal, never a side
effect" and "one undo" cannot describe the whole operation.

Change: distinguish approved read operations from mutating remote operations.
Reads may need POST for query APIs, so an HTTP-method-only rule is insufficient.
External mutations become durable host-executed intents with explicit operation
permissions and receipts. Preview runs use read-only/simulated access; a live
write test is a separate explicit action. Remote compensation is not guaranteed
undo. This is the highest-value contract extension for sync.

### 3. Approval does not identify the code subsequently executed

AutoApplyGrant (`lib/src/db/plugin_schedule.rs:45`) records agent, time and a
reviewed run, but no release/source digest or capability snapshot. Scheduler
run_one (`server/src/plugins/scheduler.rs:230`) loads current mutable source.
Changing that source does not invalidate the grant in this path.

Change: bind execution to an immutable release (code, manifest, dependencies,
runtime contract), and bind a connection's approval to that release and its
scopes. Editing creates a draft. Upgrades are explicit or follow a separately
approved update policy; permission expansion cannot inherit approval silently.

### 4. A schedule is not yet a recoverable sync connection

The schedule has one pending_verdict slot. run_due advances only its in-memory
copy before execution, persists after execution, and has no durable per-run
claim/journal. A crash after writes but before recording the schedule can replay
work. A later verdict overwrites the earlier pending proposal. Query-triggered
verdicts without auto-apply are discarded (`triggers.rs:215`). Scheduler input
contains no restored cursor. run_log writes a cursor if applied > 0, including
partial results, but cannot progress an empty successful page. auto_apply returns
Ok for reports with failed changes and run_due then clears last_error/pending.
Partial status exists in the run log, but the schedule summary loses it.

Change: add a small durable Run record/state machine, checkpoint state and
per-operation outcomes keyed by connection; recover rather than restart blindly.
Advance checkpoints only once the page is durably accounted for, including
empty pages. Retain pending proposals and partial failures. Keep one scheduler
in one server initially; no distributed job platform is required. Record identity
bindings and last-agreed projections for bidirectional reconciliation.

### 5. The planned manifest and implemented manifest are different products

The plan specifies granular Atomic/network/runtime/UI capabilities. Current
`browser/lib/src/plugin-manifest.ts` defines only secrets and permissively drops
malformed declarations. The server's allowed_origins derives from stored secrets
(`js_runtime.rs:188`), contrary to the plan's declaration-driven egress direction.

Change: publish a small, versioned manifest contract, strictly validate it at
activation, and generate TS/Rust representations or share conformance fixtures.
Separate operations/origins from credentials, supporting public APIs naturally.
Source scans can help an author fix a draft but cannot establish permissions.
Add config schema, schema dependencies, entrypoints and capability declarations;
derive store-facing read/write coverage from separately tested connector metadata.

### 6. Copying an app is insufficient distribution for a supported store

The App section explicitly says "no registry, no versions" and makes copying a
subtree the distribution mechanism. That is useful for private experiments but
cannot support pinned releases, upgrades, maintenance ownership, test evidence,
or two account connections to the same adapter without copying its code.

Change: three concepts, all ordinary Atomic resources: editable Plugin source,
immutable PluginRelease, and installed Connection/AppInstance. The catalog
indexes releases; Git PRs are one authoring/review route, not a second runtime
format. Release packaging excludes user data, secrets and activation. Installation
creates fresh local state and points at shared definitions. No generic package
manager or new standalone worker service is needed initially.

### 7. App-local schemas prevent collisions but don't establish reuse

createApp (`browser/lib/src/plugin-app.ts`) always creates a local row class.
ensureSchema (`plugin-schema.ts`) identifies definitions by shortname; its spec
does not declare external property bindings. Scheduler vocabulary discovery also
walks a drive ontology and uses shortname maps. This is fragile bootstrap
plumbing, not the frozen schema/dependency contract the new catalog needs.

Change: allow apps/connectors to bind existing classes and properties, mint only
extensions, and pin schema dependencies in releases. Keep labels and views local.
Use explicit stable plugin-runtime vocabulary or a persisted binding map instead
of rediscovering infrastructure identities by shortname on every run.

### 8. Tests prove useful pieces, not release compatibility

The branch has parser/sandbox/planner/applier tests, shared planner fixtures,
and scheduler integration tests. These should be retained. The inspected tests
do not establish the new lifecycle guarantees above or external API convergence.
Fixtures authored alongside a generated connector are not independent evidence
that its interpretation of an API is correct.

Change: a connector conformance harness with independent expected behavior,
replay fixtures, fake provider fault tests, target-engine checks and live sandbox
checks. Publish supported objects/operations, test environment and last validation
with each release. First-party/partner/community support is distinct from code
origin; LLM-written and handwritten connectors meet identical gates.

## Additional bounded implementation debt

The JS host buffers response.bytes() before checking the size limit
(`js_runtime.rs:284`); enforce a streaming byte limit. `egress::refuse_url`
documents resolving an address and then resolving again for the request; pin
the checked address to the connection. These are concrete host-hardening items,
not a reason to replace the plugin architecture. Add narrowly authorized local
network access later for self-hosted connectors without weakening managed defaults.

## Recommended sequence

Implemented and tested:

- [x] Carry the execution principal into server get/query authorization. Bind
      credentials to the plugin's verified drive, including legacy parent chains.
      Negative test uses an agent authorized to edit the plugin but denied an
      unrelated private record; a mismatched drive is refused.
- [x] Pin unattended source in the approval. Manual run records carry the exact
      executed source; an older-source review cannot authorize a newer draft.
      Existing approvals without a snapshot require renewed authorization.
- [x] Preserve MessagePack compatibility by appending defaulted fields; test an
      old schedule containing an old grant.
- [x] Persist schedule claims before execution and proposals before application.
      Do not replay interrupted or pending runs. Preserve partial/blocked errors.
- [x] Checkpoint successful empty pages, never partial pages; restore the last
      successful recorded cursor for scheduled execution.
- [x] Save trigger proposals for review instead of discarding them. Pause while a
      proposal is pending. This is a single pending proposal, not an event queue.
- [x] Add a strict version-one network manifest, independently validated in Rust
      and TypeScript against shared fixtures. Evaluate the server declaration
      without I/O. Public API reads no longer require stored credentials.
- [x] Require declared read operations for version-one preview fetch; legacy fetch
      permits GET/HEAD only. A declared write is rejected during preview.
- [x] Pin checked DNS addresses, bypass ambient proxies, disable redirects, and
      enforce the response cap while consuming chunks. Cache the compiled runtime.
- [x] Allow createApp to bind an existing row class, and ensureSchema to bind
      existing classes/properties without reconciling or copying shared terms.

Second implementation pass:

- [x] Intersect Atomic reads and writes with the app signing identity when present;
      fail closed on broken/cyclic parent lookup. Legacy account-only plugins remain.
- [x] Store content-addressed source/manifest/runtime/schema-binding packages. New
      approvals pin a package; reviewed schema bindings must match the draft.
- [x] Journal local scheduled effects and receipts. Resume the saved plan without
      re-running plugin code; reuse successful creates and their identity mappings.
      An effect without a receipt pauses for reconciliation rather than duplicating it.
- [x] Add a signed host API for declared external writes, durable operation identities
      and receipts. Duplicate delivery reuses receipts; a lost response blocks replay.
- [x] Provide three-way projection reconciliation in the SDK: independent field edits,
      explicit tombstones, conflicts and acknowledgement before baseline advancement.
- [x] Publish releases explicitly, browse/search the integration store, and create an
      independent local draft with schema bindings. Private approval packages stay out
      of the public catalog. All published entries currently say Unverified.

Third implementation pass (2026-09-06):

- [x] Authenticated external-operation inspection and confirmed-applied resolution.
      Evidence, authenticated actor and server timestamp are retained. Confirmation
      cannot overwrite a receipt or cause another send. This is an operator assertion
      after checking the provider, not automatic provider verification.
- [x] Durable connection identity mappings, acknowledged projections and cursor.
      Revision checks reject stale writers; divergent projections and identity
      reassignment are refused. A page is persisted as a whole after validation;
      empty pages retain bindings and explicit tombstones preserve identities.
- [x] Export signed SDK functions for inspection, confirmation, state reads and
      checkpoints. Transport conflicts and uncertain results are never blindly retried.

Historical remaining work after the third pass (superseded by the provider and
runtime plans below; these checkboxes are not the current delivery checklist):

- [ ] Wire external intents into proposal review and scheduled connection execution;
      add automated provider-backed verification and local-effect resolution.
      Remote confirmed-applied resolution is available through the signed host SDK;
      confirmed-not-applied retries and a recovery UI are still open.
- [ ] Separate connection configuration and explicit upgrade/permission-diff lifecycle.
      Packages pin schema identities, not snapshots of mutable schema contents.
- [ ] Durable query-event queuing/backfill while paused; the stored pending proposal
      prevents overwriting, but intervening membership edges are not journaled.
- [ ] Configuration schemas, broader capability declarations, stable runtime
      vocabulary bindings and JSON Schema compatibility.
- [ ] Wire the persisted identity maps/baselines into provider adapters and
      cover pagination, rate limits and provider-specific normalization.
- [ ] Two bounded connectors against independent failure fixtures/live sandboxes,
      plus a third shipped by another maintainer without a core change. Provider
      selection and sandbox documentation were requested from the user.
- [ ] Release conformance evidence/badges, maintenance ownership and PR automation.

Validation: 164 JS plugin tests, 76 Rust server plugin tests, two immutable-release
storage tests, and the old MessagePack schedule/grant compatibility test pass.
Chromium publication → discovery → independent draft passes against isolated real
servers; screenshot reviewed. The first attempt was interrupted by a Vite reload.
Library typecheck passes. Frontend typecheck currently fails in untouched Document
migration code and an unused loro-loader ts-expect-error directive.
Translation catalogs were settled by Vite; added messages and removed entries were
reviewed separately from formatting/reference churn.

Success is a simple public SDK over reliable shared machinery. Do not expose
queue mechanics, interpreter choices or deployment placement to generated code.

Third-pass validation: 167 JS plugin tests and 79 Rust server plugin tests pass;
library typecheck and whitespace checks pass. This pass changes no rendered text.
No provider has been certified. The state API checks projection equality supplied
by its authorized caller; only a provider-specific adapter can establish that the
projections reflect the actual latest remote/local records. The current state store
is bounded to eight MiB per plugin instance and should be paged before large-scale
connector rollout.

## GitHub pilot evidence (2026-09-06)

See [github-issues-pilot.md](github-issues-pilot.md). A separate provider package now
exercises the host APIs against GitHub-shaped fixtures and an actual Atomic kanban.
The pilot adds repository-scoped numeric URL slots, private release pinning and a
strict connector query helper. It verifies title/body/status reconciliation,
creation, conflict pauses and receipt-based retry refusal. Real GitHub compatibility
and sandbox/scheduler integration remain unverified; this is a manual host runner.

## Delivery audit (2026-09-08)

- [x] Classify the accumulated changes against this thread: runtime isolation,
  import identity/recovery, four provider pilots, assistant/automation flows,
  shared schemas/templates and workspace UX belong together.
- [x] Keep the unrelated Firefox-transition plan, connection-toast experiment and
  generated Vitest cache out of the delivery commit.
- [x] Verify remote branch changes survive the develop rebase before pushing.
- [x] Run client/frontend suites, typechecking and frontend production build.
- [x] All four providers pass the offline JS and native sandbox certification;
  regenerate the repository evidence asset against the exact shipped bundles.
- [x] Native server suite: 203 passed, three ignored subprocess helpers.
- [x] Focused installation recovery and creation catalog: five Chromium flows passed.
- [x] Update publication and importer test navigation for tabs, scope template
  selectors to their dialog, and expect evidence for all four integrations.
  Publication, Notion validation, Clockify import/reimport/upgrade and MT940
  import/reimport focused Chromium checks pass.
- [ ] Migrate and rerun the seven remaining legacy `plugins.spec.ts` scenarios,
  including the old automation form assumptions. Full regression is unverified.
- [ ] Live-provider and live-model acceptance remain separate from fixture checks.

Current implementation and remaining scope are tracked in `plugin-runtime-v1.md`,
`connector-scale.md`, `import-identity.md`, `github-issues-pilot.md`,
`notion-sync.md`, `clockify.md`, `mt940.md` and `schema-catalog.md`. The marketplace
governance and broad JSON Schema compatibility remain design work.
