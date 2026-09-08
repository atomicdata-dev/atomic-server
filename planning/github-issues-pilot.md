# GitHub issues ↔ kanban pilot

In progress, 2026-09-06. Private live test repository: `ontola/atomic-github-sync-sandbox`.

- [x] Standalone adapter with repository-scoped capabilities and host-owned credentials.
- [x] Full issue pagination; exclude pull requests; stop on rate limits/errors.
- [x] Title/body/status three-way reconciliation, independent edits and conflicts.
- [x] Todo=open; Doing=open + atomic:doing; Done=closed. Preserve other labels.
- [x] Existing kanban table schema and persistent issue identities.
- [x] Explicit preview/apply, durable remote writes and acknowledged checkpoints.
- [x] Fixture tests, crash/retry tests and typechecks.
- [x] Live pilot against the authorized private Ontola sandbox; production issues untouched.

First scope: issues, titles, Markdown bodies and column status. Closing is not
resource deletion; missing/deleted/inaccessible issues must not cause deletion.
Comments, assignees, milestones and GitHub Projects follow later. Background polling is available after a completed reviewed sync.

## Current implementation and limits

Package: `integrations/github-issues`. Its bundled `plugin.js` runs inside the
existing QuickJS/WASM sandbox on AtomicServer. `run()` can read and propose;
a generic durable session driver owns external writes, Atomic plan/apply,
receipts, continuations and acknowledged checkpoints. The CLI only installs,
requests a server preview and approves/resumes its saved run identity. The
browser connection page uses those same signed endpoints.

- [x] Move provider execution out of the trusted CLI into the real sandbox.
- [x] Persist each proposed effect before execution; resume from saved receipts.
- [x] Pin source/configuration and bind approval to a saved run and account.
- [x] Private connection configuration stored on the integration resource.
- [x] Sidebar discovery, individual icons and browser preview/approve/resume.
- [x] Declared events create independent JavaScript automations with explicit integration references.
- [x] Real QuickJS/WASM + Atomic persistence tests, including trigger → message.
- [x] Live GitHub happy-path verification in the private Ontola sandbox (not production certification).
- [x] Background scheduling, transactional event queue and external-receipt recovery UI.
- [ ] Guided provider reconciliation and recovery for uncertain Atomic writes.
- [ ] Multi-connection throughput and large-repository performance measurements.

Live tests now read and modify synthetic issues in the authorized private sandbox
repository. Provider replies in the Rust tests remain simulated; Atomic reads/writes, runtime isolation, journaling and triggers are real.
The opt-in HTTP test installs the actual bundled source and kanban on a disposable
local Atomic drive. Dagger changes are not yet container-verified. Frontend
whole-project typechecking has existing errors in unrelated tests and Document
migration code; changed integration components have no reported type errors.

The same missing-data and conflict policy remains: no inferred deletions, no
blind retry after an uncertain remote write, no claim of cross-system atomicity.

## Sandbox migration friction log (2026-09-06)

Requested by the user: record architectural shortcomings, slowdowns and testing friction as work proceeds.

- **Trusted-runner detour:** the first pilot exercised host APIs but bypassed the
  actual sandbox. Replace it; CLI execution of provider logic is not evidence for
  the plugin architecture. The CLI should only install/preview/approve/resume.
- **Continuation missing:** `run()` can read and return an Atomic verdict, but a
  sync needs to consume a remote-create receipt before proposing its local card.
  Add a small, durable effect/continuation protocol over the same sandbox, not a
  second JavaScript runtime or provider-specific Rust implementation.
- **Replay cost:** restarting the entire provider algorithm after every effect
  would repeatedly scan/read old records. Use explicit per-record stages instead.
- **Checkpoint crash window:** successful state CAS followed by a crash before
  recording its receipt needs an operation identity, just like an external write.
- **Query semantics:** UI collections swallow read failures. A connector must
  fail closed rather than infer missing records from a failed query. The existing
  server sandbox query uses account/app authorization but needs explicit bounds
  and must not silently return a truncated subset.
- **Testing fidelity:** mocks missed required fields in initial Atomic genesis
  commits. Keep real Atomic persistence tests, and run the provider fixtures
  through QuickJS/WASM rather than merely invoking exported TS functions in Node.
- **Packaging friction:** Rust runtime tests need exactly the JS artifact installed
  by the client. A reproducible bundled source artifact and a drift check are
  needed; handwritten copies or test-only versions would hide packaging failures.

This log is ongoing. Each entry should distinguish implemented fixes from known
limits; passing fixture tests is not live GitHub compatibility certification.

### Findings during the real sandbox migration

- **Fixed: async runtime mismatch.** Server QuickJS serialized a Promise as `{}`
  instead of awaiting `run()`. Node adapter tests could not detect this. The shared
  runtime now awaits the result; the real sandbox tests exercise async reads.
- **Fixed: serialization ordering.** Rust persists JSON with sorted keys. Comparing
  projections with `JSON.stringify` produced false stale-preview conflicts after
  crossing that boundary. The adapter compares its actual projection fields.
- **Fixed: query scope and completeness.** Sandbox queries are now drive scoped,
  capped at 10,000 and refuse incomplete/unauthorized result sets and read errors.
- **Fixed: checkpoint replay.** A stable effect identity allows a successful
  checkpoint to be replayed after a lost session receipt without advancing twice.
- **Testing setup friction:** the shared server fixture requires an Actix runtime
  and creates vocabulary but no plugin until `write_plugin` is called. Mistaking
  either for a ready connection produced setup failures unrelated to sync logic.
- **Build friction:** the local `pnpm` launcher hung without output; invoking the
  installed tsup binaries worked. CI's light feature set excluded all sandbox tests
  and its selective mounts omitted the runtime crate. Mounts and the Rust test
  feature selection now include them; the Dagger container still needs a real run.
- **Fixed in the end-to-end slice: execution throughput.** The initial session driver serializes sessions
  through one process-wide mutex. This prevents races but stalls unrelated
  connections behind slow reads. Replace it with bounded per-connection execution
  leases before large-scale operation. There is no background sync scheduler yet.
- **Fixed in the end-to-end slice: automation delivery.** Integration events reuse ordinary query-enter
  triggers, including an imported issue becoming a real Atomic card. Existing
  trigger delivery is an in-memory broadcast, with a rate guard and one pending
  preview. Events during downtime or a paused preview are not a durable queue.
  Guaranteed notifications require an outbox/replay design and backpressure tests.
- **Fixed for new installations: event meaning.** “Issue added to Atomic” includes historical backfill and
  local cards gaining a provider identity. It does not mean “GitHub created an
  issue just now.” Configure after initial import to skip historical arrivals.
- **UI scope:** Integrations is a sidebar destination with installed entries and
  catalog discovery. Connections expose sync preview/resume and a message-action
  automation starter. This posts an ordinary chatroom Message; OS push/email
  notifications and a general automation canvas are separate capabilities.

- **Fixed: browser JSON materialization.** A connection's JSON property can arrive
  as a serialized string after a real store round trip. An object-only UI check
  hid all sync/automation controls. Decode either form; the browser test exercises
  configuration saved and read back through the real server.

- **Fixed: navigation cleanup.** Reviewing the automation screenshot exposed an
  existing Prism timer dereferencing a cleared DOM ref after navigation. Cancel
  the timer on unmount; the focused browser flow now asserts no uncaught errors.

### Validation recorded in this pass

- 86 server plugin tests passed before the additional import-to-message test;
  that additional real trigger test passed too. The six sandbox integration
  scenarios are also run together after the final bundle rebuild.
- 45 focused SDK/reconciliation/manifest/log tests passed.
- Seven provider/package/HTTP tests passed with the isolated local server;
  without the opt-in server, six run and the HTTP installation test skips.
- Integration typecheck, library/react builds and CLI bundle passed.
- Focused Chromium flow verifies sidebar, icons, saved sync approval and creation
  of a message automation. Full frontend typecheck remains blocked by unrelated
  test Node typings and Document migration errors.

- **Fixed: localization tooling noise.** An earlier browser run displayed an
  existing success toast as `[i18n-404:439]`, even after restarting Vite. The new
  integration labels were present in all four catalogs and their diffs were read.
  This is not an integration execution failure, but it prevents calling the
  overall UI fully polished at that point; the callback fix and current verification
  are recorded below.

## Dependable end-to-end slice (2026-09-06)

- [x] Persist query-trigger events in the same transaction as membership changes.
- [x] Queue later arrivals while a proposal waits; stable event IDs own execution journals.
- [x] Replace sync, external-write and checkpoint global locks with database-local connection locks.
- [x] Persist background polling grants pinned to a completed reviewed release/configuration.
- [x] Background worker resumes running sessions without a browser; four connections per pass.
- [x] UI setup for the GitHub pilot, background toggle, saved external-result inspection and evidence recovery.
- [x] Replace the notification-specific form with event selection and an editable JavaScript automation.
- [x] Verify new UI setup and background controls through Playwright.
- [x] Hard-process interruption tests for delivery, background continuation and uncertain provider-create recovery.
- [x] User authorized creation of private `ontola/atomic-github-sync-sandbox`.
- [x] Live GitHub test passed: both directions, kanban mapping, background discovery and JS automation.

New friction: the provider installer lives outside the browser TypeScript root;
its shared use from the UI required expanding that root. Provider setup currently
ships with the pilot UI; a catalog-driven declarative installer remains a separate
abstraction to extract after a second connector. Recovery of uncertain external
writes currently requires a verified receipt, rather than provider-guided lookup.
Do not mark this as a polished recovery experience yet.

### Automation relationship and current limits

An automation **uses** integrations; it is not owned by one integration. New
automations live independently in the drive, with `automation-integrations`
references and `automation-trigger` metadata. An integration exposes events; the
UI selects an event and opens an ordinary JavaScript script. Conditions and any
number of Atomic intents are code. There is no message-specific form or separate
visual workflow language. Message creation remains a commented example.

The current executable action surface is Atomic intents: create, set, remove and
destroy, with planned local references. Edits to connected records propagate
through their integration's sync. A general API for calling several integrations'
remote actions with per-connection credentials is **not yet implemented**; do not
present the script starter as a complete n8n replacement. Persisted trigger work
is separate from sync continuations and still needs that unification.

New GitHub installations mark remote discoveries after the initial checkpoint,
excluding initial backfill and locally-created issues. Existing installations
retain their explicitly named old “Issue added to Atomic” event semantics.

Queue events are part of the membership transaction. A pending review no longer
drops later arrivals; enabling auto-execution preserves its waiting proposal.
Stable event identities own the action journal. An uncertain Atomic receipt still
pauses for inspection; no cross-system exactly-once promise is made. The queue
currently scans stored events and triggers, so large backlogs need indexing and
retention/backpressure work. Sync polling scans saved sessions, bounded to four
active connections per pass. Session payloads remain capped at eight MiB.

Hard-restart tests terminate subprocesses without destructors: saved arrivals
replay once; approved sync continues from its saved cursor; an accepted remote
create with a lost response stops and then resumes from a verified receipt without
another provider write. Provider replies remain simulated. The production server
build is tested separately because dev-only dependencies can hide missing imports.

The connection toast's missing translation was traced to a callback capturing an
old translation runtime. Messages now resolve during render and refresh the
listener when they change; the reviewed screenshot no longer shows the placeholder.

### Latest validation

- [x] 94 server plugin tests passed, plus the subsequently added stable event-ID
  sandbox test. Three subprocess helpers are ignored as standalone tests and
  exercised by their parent restart tests.
- [x] 34 focused SDK tests and seven provider/package/local-server tests passed.
- [x] Two Chromium E2E tests passed, including a completed scheduled run after
  closing the entire browser context.
- [x] Production server build and client library builds passed.
- [ ] Full frontend typecheck remains blocked by existing Document migration
  errors and an unused Loro loader suppression outside this change.
- [x] Disposable private repository created in Ontola at the user's request.

### Live provider friction (2026-09-06)

The user authorized creating the private repository
https://github.com/ontola/atomic-github-sync-sandbox. The opt-in
`github.live.test.ts` mutates only that repository, uses an isolated loopback
AtomicServer, and closes its test issues afterwards. Credentials are supplied by
the environment and stored only in the host's credential store.

- GitHub acknowledged issue creation before the issue appeared in its list API
  (observed in three initial runs). The first backfill fixture must wait for list
  visibility. A completed scan means the records returned by that scan were
  reconciled, not that an eventually consistent provider has exposed every write.
  Keep missing-record handling conservative; future incremental cursors need an
  overlap/reconciliation policy so late-visible records are not skipped.
- The SDK's fetched Loro snapshots must be materialized before direct property
  assertions. The live test uses a shared fresh-read helper for this.
- A fresh local server logs missing canonical table-view properties during setup;
  installation proceeds, but this ontology/bootstrap warning remains a separate
  polish issue to investigate.
- Notification example dependency: a fresh server also lacks the optional
  canonical `about` property. The strict planner correctly blocks that example.
  The generic live notification uses core name/description properties and embeds
  the card subject in its text. Templates must declare/install their schema
  dependencies before presenting examples as ready-to-run chat automations.
- Repeat live runs scan previous closed fixture issues too. Full-scan and
  per-record reconciliation costs increase even for a small disposable repo;
  isolate scenario setup and capture provider calls when prioritizing incremental
  checkpoints. Do not confuse repeated fixture setup with steady-state latency.
- **Fixed: generated query snapshots merged as CRDT documents.** Polling the
  notification inbox produced `Incomplete connection query response`. A local
  HTTP regression reproduced this with sequential inserts (no provider and no
  concurrent writer), proving it was not merely a pagination race. Successive
  generated Loro snapshots retained obsolete membership alongside a newer total.
  `readConnectionSubjects` now requests `forceOverride` for these read-only query
  snapshots. The regression failed before and passed after the change. Ordinary
  editable resource reads retain their existing merge behavior.

### Live verification result

The opt-in real-provider test passed in 207.5 seconds after the query snapshot
fix. Verified backfill, bidirectional title/body edits, Doing label preservation,
Done closes, remote reopening, Atomic-created GitHub issues, and one scheduled
remote discovery producing one independent JS notification in addition to the
reviewed sample. No browser was running. All synthetic issues were closed and
polling paused. The repository remains private for repeat tests.

Also passed: sequential-membership local HTTP regression (failed before the fix),
seven connector SDK unit tests, six default package tests (three opt-in tests
skipped), provider TypeScript check and SDK build. The live test creates an Atomic
notification resource; it does not send email, OS push or a chat message. Real
provider rate-limit/failure recovery and larger repositories remain uncertified.
# Token setup shortcut

- [x] Link from the connection form to GitHub's prefilled fine-grained token page,
  with Issues write access, a 30-day expiry and the entered repository owner.
  Explain that repository selection and token generation still happen on GitHub.
- [ ] Replace manual token setup with a GitHub App installation flow.

## Automation creation entry point

- [x] Add New automation beside Your automations, including the empty state.
- [x] New automation opens a fresh Atomic assistant chat with drive/connection context. Ask for intent before creating a draft; integration shortcuts preselect their context.
- [x] Replace the integration's embedded creation form with a dialog shortcut; collapse one-off actions and permissions under Advanced.
- [ ] Browser acceptance of the chat entry points and end-to-end assistant creation.
- [ ] Move action grants into the automation enable/review flow; currently still available under integration Advanced.

- [x] Integration setup dialog headings now match discovery cards: bold heading with provider icon.
