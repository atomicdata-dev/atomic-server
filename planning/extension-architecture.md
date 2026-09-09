# Atomic extensions: one lifecycle, explicit boundaries

Status: product direction agreed with the user, 2026-09-08; technical migration
in progress. This describes the target, not guarantees already implemented. Current
extension work is on PR #1307; Reflector integration is proposed in PR #1383.
Workspace navigation, shared view protocol and installation identity have implementation checkpoints below;
the complete package and permission migration remains open.

**An extension is a package of capabilities. Atomic owns its authority and
execution. Apps contain the work, connections synchronize external data, and
automations act on it.**

The goal is fewer concepts and fewer independent implementations, not one runtime
for every kind of code. A new provider should add a package and tests, not a new
credential system, scheduler, permission dialog or resource-writing path.

This proposal owns consolidation across extension models. [plugins.md](plugins.md)
retains the earlier design and implementation history; [plugin-runtime-v1.md](plugin-runtime-v1.md)
describes the existing JS contract. Provider details belong in their own plans.

## The product model

Users create an app, connect a service, or describe an automation. They do not
choose between WASM, JS and Reflector. These use one extension foundation but
remain distinct product concepts because they have independent lifecycles.

| User concept | Meaning | Example |
| --- | --- | --- |
| App | A workspace bringing together data, views and optional behavior | Project tracker |
| View | A way to work with the app's data | Board, table, calendar, custom interface |
| Integration | A connector available in discovery, before configuration | GitHub |
| Connection | A configured external account/source attached to a workspace | `ontola/searchlauncher` connected to the task table |
| Automation | Separately editable behavior that can use connections | Notify a chat when an urgent issue arrives |

```text
Project tracker
  Views: Board · Table · Calendar
  Connections: GitHub repository
  Automations: Notify on urgent issues
```

An app works without a connection. A connection can synchronize without an
automation. An automation can use multiple connections, including connections
associated with other apps where explicitly authorized. An external connection
can expose actions without syncing a dataset. Ordinary Atomic-data automations
need no external connection at all.

“App” is a product/workspace concept, not a requirement to wrap every table in a
new resource or executable package. Reuse existing native table, folder and custom
App resources where they already represent the workspace. A simple table remains
simple; making its connections discoverable must not create a competing table or
force a hierarchy migration. The custom executable App class is one implementation
of an app, not the definition of everything users call an app.

### The implementation vocabulary stays behind the product

| Developer concept | Meaning |
| --- | --- |
| Package | Reusable views, connector capabilities, actions, schemas and templates |
| Release | An immutable package revision identified by its complete content |
| Installation | A release installed in a drive, with identity and granted capabilities |
| Run | An invocation with its proposal, effects, receipts and checkpoint |

There is no mandatory one-to-one relationship between app and package. A task
workspace may use several packages; installing a connector need not create a new
app. Installation identity controls code authority; workspace ownership controls
where users organize their data. A connection references its installation/release,
configuration and explicit destination. An automation is its own script and
approval scope, referencing capabilities rather than embedding provider code.
A local custom app or automation need not be published to a store.

### What users should experience

- **Create a project tracker:** create its data and views from a template; open the
  board. No connector, package or credential setup is required.
- **Connect GitHub:** offer an existing compatible destination or a ready-made
  Issue Tracker workspace. Review the mapping and first sync. Open the workspace
  after setup, with a small connection status and access to connection settings.
- **Automate it:** “New automation” opens the assistant with workspace and selected
  connection context. The resulting JS draft has a test/review/enable lifecycle.
  Creating that draft does not enable or alter synchronization.
- **Connect another source:** attach it to a compatible table or create another
  table in the workspace. Do not merge records merely because their names match.
- **Disconnect GitHub:** stop its jobs and revoke its usable authorization without
  deleting the task board. Dependent automations explain which connection is
  unavailable; unrelated work keeps functioning.

The workspace opens its selected view, with other views prominent. Connections
and Automations are discoverable workspace controls. Secrets, code, provider
configuration and recovery belong in the relevant connection or automation
settings, not in every workspace's top-level view tabs. Custom app code remains
available through app settings and “Edit with AI.” The drive-level Integrations
catalog remains a discovery and connection-management entry point; it is not the
owner of every connected workspace.

Default imported data is nested in the chosen workspace, usually under its table.
Shared properties/classes use the existing ontology placement rules rather than
being copied per connection. Selecting an existing destination requires explicit
configuration and write authority. Neither an automation nor another workspace
copies a connection's credentials or takes ownership of its sync schedule.

## The architecture

```text
Handwritten code   Assistant-generated code   OpenAPI + overlays
         \                  |                    /
          Package: views, actions, sync, schemas, templates
                              |
               Installation + pinned release + grants
                              |
                       Atomic host API
                /             |              \
       UI interaction    Background run    Credential access
       isolated iframe   JS in sandbox     host or OAuth broker
                \             |
                 Authorized effects + shared importer
                              |
                 Atomic resources and provider APIs
```

These are boundaries inside the current product, not new deployable services.
AtomicServer remains the initial owner of unattended execution and durable state.
A separate worker fleet is a future scaling choice, not a prerequisite.

### One package lifecycle

Use one versioned package envelope for identity, entrypoints, configuration,
schema bindings and requested capabilities. Reuse the existing versioned JS
manifest where it fits; adapt the installed ZIP manifest at the boundary rather
than adding another parallel manifest for new features.

Source-as-data and a compiled artifact are authoring/distribution choices. Both
must resolve to the same installation lifecycle: draft, review, activation,
upgrade, pause and removal. Release identity covers executable code, manifest and
dependencies. Mutable schema references must have an explicit version policy;
pinning code alone does not pin their meaning. Follow the accepted schema identity
decision in [schema-catalog.md](schema-catalog.md); URI migration is not a gate
for consolidating the runtime.

Editing a draft never silently changes an active job. An upgrade reviews the
capability/configuration/schema difference and preserves identities and receipts.
Existing approved work remains attached to its old release until completed or
explicitly abandoned. Rolling back code does not undo provider writes or data
migrations. A migration therefore needs its own preview and recovery plan.

### One authority model, appropriate interaction styles

Every host operation carries installation identity, acting principal, target
scope and, where applicable, the approved release and run. The host validates
these rather than trusting identity or grants supplied by guest code. Effective
authority is the intersection of the actor's rights, installation grants and
declared capabilities. Review UI, assistant calls, MCP calls and scheduled jobs
must not become alternative ways to bypass that check.

Consolidate the old PluginView RPC and AppFrame bridge behind one public UI API.
Keep a compatibility adapter during migration. Views retain a null-origin iframe,
subscriptions and interactive editing. A user editing an authorized table cell
does not need a background run or approval dialog for every keystroke.

Background functions propose effects. Preview cannot perform provider writes;
execution uses the reviewed release and records outcomes durably. Read-like POST
operations need explicit provider semantics, not a blanket HTTP-method rule.
Unknown write outcomes remain uncertain until reconciled; a timeout is not
permission to resend. Interactive local edits and reviewed external effects share
authorization primitives without pretending they have identical transaction or
approval semantics.

Call mutations `changes` or `intents` in author-facing APIs. The host turns them
into actual signed Loro commits. Deprecate SDK “Commit” structures that imply the
old `set/push/remove` wire protocol; retain translation only in legacy adapters.

### One background contract

Actions, sync and automations use the existing JS sandbox and effect machinery:

- An **action** is an invocation with typed input and output. It can be called by
  a person, an automation or the assistant under the same authority rules.
- A **sync function** reads provider changes, maps records, reconciles against the
  last acknowledged state and proposes effects. It checkpoints only durably
  accounted-for work. Two-way sync is explicit reads plus writes and conflict
  policy, not permission to overwrite either side.
- An **automation** is JS that calls capabilities in response to an event or
  schedule. It has its own approval and history. Sync works without an automation.

Define one durable run/effect vocabulary while preserving specialized state where
needed. Do not replace working journals in a single migration. Map each existing
record to the common lifecycle, then remove duplicate ownership incrementally.
There must be one scheduler owner per job and one owner of its checkpoint.

The server runtime is authoritative for installed/background logic. Keep browser
execution only for a defined pure-computation subset with shared conformance
fixtures; it must not provide a weaker route to the same privileged operation.
If maintaining that subset costs more than it saves, retire browser `run` execution
without removing browser-rendered views or ordinary UI code.

### One importer and meaningful schema bindings

All connectors and file importers feed the common importer with source identity,
destination, schema mapping and observed values. That path owns scoped local IDs,
reference resolution, source baselines and reviewed duplicate handling. Provider
adapters own provider-specific normalization, deletion interpretation and field
support. No provider gets a second direct persistence path.

OpenAPI describes transport and response shapes; overlays/code supply missing
semantics. Reflector can discover endpoints and derive candidate mappings. Its
first convergence milestone is emitting records into the shared importer, not
introducing another UI, credential store or continuous scheduler. Initially it can
remain a trusted Rust adapter behind the host. It cannot be advertised as equivalent
to untrusted sandboxed JS until its isolation and authority are demonstrated.
Do not require a new OpenAPI-to-JS compiler before testing this boundary.

Generated provider schemas are useful staging definitions, not automatically
cross-provider standards. Prefer existing Atomic properties where meanings agree;
preserve unmatched provider fields with provenance. Templates reference the same
schema bindings so imported issues immediately work in a task board. Schema reuse
must not imply unsupported write-back or lossless conversion.

### Shared hosting, optional managed authorization

FOSS and SaaS use the same package, host API, importer and run implementation.
An optional managed OAuth broker handles provider registration and authorization
handoff; it does not own another copy of connector business logic or sync state.
Self-hosted installations can use configured OAuth apps or supported manual
credentials. Secrets stay behind host APIs and out of guest code and chat context.

Only the assigned execution host owns a connection's active jobs. Copying a drive
or syncing it to another node must not activate duplicate provider writes or copy
private credentials implicitly. Moving execution requires an explicit ownership
handoff; distributed execution is outside this migration.

### Server extensions are a different trust boundary

Keep read/commit class extenders explicitly named **server extensions**. They
participate in database behavior and may need privileged hooks that user-installed
integrations must never acquire. Installation is an operator decision. Share
packaging utilities where useful, but do not collapse this boundary into ordinary
app permissions or migrate hooks into unattended JS jobs merely for uniformity.

## Migration: prove one seam at a time

Each phase can land independently. Preserve identifiers, configuration, grants
and in-flight receipts; migrations must be repeatable and must not contact a
provider merely because a package was migrated.

### 1. Establish the workspace/connection distinction

- [x] Trace one existing GitHub installation from connection to task table, default
  view, automation and credentials; specify those relationships without assigning
  new subjects or changing ownership.
- [ ] Make that existing table/board the workspace entry point, with connection
  status/settings and a contextual “New automation” action. Preserve old connection
  URLs as routes to its settings; do not break bookmarks or recovery links.
- [ ] Offer “existing workspace” or “new workspace” during connection setup and
  verify independent sync, automation enablement and disconnect behavior.
- [x] Identify the workspace root using existing resource relationships. Do not
  introduce a new App class or silently reparent existing resources to satisfy UX.
- [ ] Inventory manifests, UI bridges, execution paths, grants and state owners;
  link each to its replacement or explicitly retained role.
- [ ] Define the package envelope and host API in one owning SDK/spec location,
  with shared fixtures consumed by TS and Rust implementations.
- [ ] Require new providers to use the existing integration path. Exceptions need
  a documented boundary and retirement condition, not another product entry point.

Exit: an existing GitHub user lands on their board, can find connection settings
and create a separate automation, and keeps their data after disconnecting. There
is one documented place for an author to start; every old surface is accounted
for. No new runtime is required to achieve this phase.

### Implementation checkpoint: workspace navigation (2026-09-08)

- [x] Shared `@tomic/lib` workspace resolver and `plugin-workspace` property.
  GitHub, Notion, Clockify and MT940 installers write it. Existing connections
  resolve their old JSON destination without migration writes.
- [x] Native tables own rendering and default views. Connection pages link back to
  the workspace and retain sync, credentials, activity and code; the duplicate
  embedded table renderer is removed.
- [x] Tables expose Connections and Automations. The assistant gets explicit
  workspace context; script creation saves source and workspace/connection links
  together. Empty connection references identify an independent on-demand
  automation, without enabling a job or granting access.
- [x] Catalog connections link to workspace and settings separately. GitHub and
  Clockify setup accept a compatible existing workspace; Notion and MT940 disclose
  that they create a new one.
- [ ] Surface live connection status in workspace controls and implement explicit
  disconnect with revocation across schedules/actions. Pause is not disconnect.
- [ ] Consolidate sidebar presentation without rewriting existing containment.
  Old tables remain nested under their connection; navigation association grants
  no authority and is intentionally separate from the resource parent.
- [ ] Generalize workspace discovery beyond native tables to generated apps and
  multi-table workspaces. This checkpoint is the first vertical slice, not a
  complete migration of all plugin models.

Findings: GitHub currently excludes tables already used by a connection. Keep
that safeguard: two repositories targeting the same table can publish each
other's cards until sync has explicit row ownership. Workspace relationships can
represent several connections, but that does not override provider restrictions.
Legacy workspace discovery scans authorized, paginated plugin resources on opening
controls; an indexed migration is still needed for large catalogs. Query failures
remain visible instead of appearing as an empty workspace.

### 2. Unify views before migrating all packages

- [ ] Adapt one existing packaged UI plugin and one generated app to the same
  bridge, retaining their authorized behavior and identities.
- [ ] Test load, theme, subscription, permitted edit, denied cross-scope edit,
  grant revocation and host navigation through both entry paths.
- [ ] Move callers to the canonical SDK; keep legacy wire messages in the adapter.

Exit: neither view implementation has its own permission policy. Delete the old
bridge only after supported installed packages have an explicit migration path.

### Implementation checkpoint: one frame transport (2026-09-08)

- [x] `helpers/extensions/FrameBridge.ts` owns frame source validation, theme
  delivery, subscription teardown and reply lifetimes for both generated apps
  and packaged views. Three message listeners and two subscription owners become
  one transport implementation.
- [x] Remove transport from `AppFrame` and the old `RPCServer`. Keep a
  `LegacyViewAdapter` for the installed SDK wire format and existing grants;
  `pluginRPC.tsx` now only connects React context and dialogs to that adapter.
- [x] A ready handshake invalidates the prior document's subscriptions and late
  replies. A normal load event only sends style: it must not delete subscriptions
  the new document established while loading. Unmount cleans up once.
- [x] Recheck packaged view read grants before each notification. Closing a view
  while its write-permission dialog is pending cannot resume that write. Changing
  an app, drive or table remounts its frame session and drops the old source token.
- [x] Share the authorization evaluator and version the public SDK envelope (see next checkpoint). Generated app
  writes still use the app identity and host endpoint; packaged views retain their
  existing scope/grant rules. Sharing transport does not widen either policy.

No additional runtime or installed-package migration was introduced. Existing
source-generated `__atomic` messages and packaged SDK `requestId` messages remain
compatible adapters. This checkpoint removes duplicated plumbing; it does not
claim that all extension execution and permission models are now unified.

### Implementation checkpoint: shared policy and v1 wire contract (2026-09-08)

- [x] Replace duplicated ancestry/grant checks with `canViewAccess`, using
  host-selected app and packaged profiles. Preserve signing identities, class
  scope, public/agent grants, app depth limits and packaged deep ancestry.
- [x] New packaged and generated SDK clients use one versioned request/reply
  envelope and resource shape. Keep decoding installed clients at the boundary.
- [x] Reject unsupported operations explicitly; acknowledge subscription setup
  and removal instead of retaining unresolved requests.
- [x] Test both actual clients against the contract, wrong-window replies,
  scope spoofing, deep grants, cycles, teardown and compatibility replies.
- [ ] Migrate operation capabilities and backend signing to one installation
  authority model. Shared preflight policy does not itself unify those identities.

New SDK builds require a v1 host; rollout order and supported operations are in
`browser/plugin/README.md`. There is no speculative retry of writes in a legacy
format. This removes duplicated policy traversal and wire formats for new clients,
while retaining thin compatibility decoders for already installed packages.

### 3. Converge installation and background state

- [ ] Map existing app/plugin resources to the package and installation concepts
  without mass-changing their subjects or cloning their data.
- [ ] Route manual, assistant, MCP and automation action calls through common
  authorization/release validation; centralize shared run transitions.
- [ ] Exercise upgrade, revocation, restart after a provider accepted a write,
  stale approval, duplicate event and paused-job behavior across callers.
- [ ] Migrate one GitHub connection and its separate automation with no reimport,
  credential loss, changed table view or duplicate issue creation.

Exit: each connection has one execution owner, one approval model and one recovery
history. Keep specialized sync records where they represent real semantics.

### Implementation checkpoint: installation identity lifecycle (2026-09-08)

- [x] Resolve existing entrypoints to their nearest installed identity and verify
  the owning drive through one resolver. Keep existing subjects, keys, provider
  secrets, connection mappings and receipts; no data-copy migration.
- [x] Use the resolver for runtime binding and signer selection. Manual app writes,
  sync application, background sync, schedules and triggers share the effect-host
  constructor. Actor rights and installation rights both bound manual writes.
- [x] Distinguish legacy (no stored identity), active and revoked in the existing
  key store. Revoke atomically erases key material and persists a tombstone;
  selecting a signer before revocation cannot fall back to the server afterward.
- [x] Retain decoding of old key records, explicit reconnect and legacy behavior.
- [ ] Migrate legacy packaged browser commits into installation-signed effects.
  Their interactive grants still use the existing user-signed adapter.
- [ ] Consolidate package activation/upgrade and common run-state transitions.
  Release validation and action journals remain their existing shared mechanisms.

The revocation tombstone prevents future fallback, including after process exit.
A deletion made by an older version left no evidence: it cannot be distinguished
retrospectively from a legacy installation. Such installations require explicit
re-enrollment/revocation. Revocation cannot undo an already accepted provider write;
existing uncertainty/recovery receipts must remain intact. This checkpoint does not
claim the deferred GitHub live migration or all extension lifecycles are complete.

### Implementation checkpoint: activation snapshots and upgrade review (2026-09-08)

- [x] Use the existing connection resource as the current release/configuration
  binding, read through one module shared by actions and sync.
- [x] Refuse a stale sync preview approval or background-sync grant after release
  or settings change. Stop due work with a stored, user-visible error requiring
  a new preview/review; do not silently execute its older configuration.
- [x] Remember whether a preview/grant requires a connection binding, so removing
  activation cannot turn it into a legacy unbound run. Preserve old stored formats.
- [x] Keep already-approved recovery on its original release/configuration and
  receipts. Upgrade/rollback must not replay an uncertain provider write.
- [x] Test compatible upgrades with a real active binding, unchanged record IDs,
  stale approvals, changed polling settings, and missing activation.

This uses existing resource edits as activation and existing preview approval as
review; it adds no second activation database or provider-specific migration.
Package editing/publishing UX and legacy packaged UI grants remain open. Packaged
plugins already have server-held identities in PluginMeta; their interactive write
grants are browser-held. Migrating the signer requires migrating those grants and
validating page scope server-side, not copying keys into another store or silently
broadening plugin ACLs.

### Implementation checkpoint: consent isolation and delete authorship (2026-09-09)

- [x] Bind browser-held packaged-view consent to server, drive, acting account and
  concrete installation subject. Do not import ambiguous plugin-name grants;
  existing users review consent again instead of sharing it across accounts.
- [x] Remount the view/session on identity changes and deny queued permission
  requests on teardown. Resource-picker consent uses the same installation key.
- [x] Preserve the selected installation signer for deletion as well as create /
  update. A real persisted destroy-commit regression exposed default-server signing.
- [ ] Migrate packaged UI grants to portable authorization before changing its
  commit signer. Local browser consent is not proof a receiving Atomic node can
  validate. Do not turn it into permanent ACL entries without explicit user review.

Packaged UI commits remain user-signed for now. This checkpoint fixes consent
isolation and the shared effect host; it does not claim the remaining signer
migration is complete. An explicit reviewed Atomic grant or portable delegation is
needed to retain authorized interactive editing across replication boundaries.

### 4. Prove declarative authoring fits

- [ ] Adapt one Reflector provider, preferably its existing Google Calendar pilot,
  to shared setup/configuration and the common importer.
- [ ] Test stable identity, repeated import, nested destination, schema mapping,
  partial failure and credential expiry without a separate lifecycle.
- [ ] Make its trusted execution status explicit. Decide on compilation or a
  sandboxed interpreter only from the demonstrated gaps of this adapter.

Exit: adding another OpenAPI-backed provider does not require host routes or
provider-specific database writes. One-off import remains useful before scheduled
or bidirectional support exists.

### 5. Retire duplication and certify the author experience

- [ ] Remove superseded UI RPC, manifest parsing and SDK mutation types after
  compatibility gates pass; publish migration notes for existing authors.
- [ ] Remove dead authoring UI and migrate the remaining legacy browser tests.
- [ ] Have another maintainer add a small integration using only the public SDK,
  fixtures and package tooling, without changing core Atomic code.
- [ ] Keep per-release evidence for contract, fixture, sandbox and UI checks;
  label live-provider validation separately. Run the full regression suite.

Exit: a maintainer can explain which API to use without knowing Atomic's plugin
history. There is one extension lifecycle and a separately named server-extension
boundary, with no hidden second implementation for SaaS.

## What we deliberately defer

No new marketplace governance, workflow language, distributed worker platform,
universal provider schema or total rewrite is required for this consolidation.
Store scale and richer schema compatibility remain separate plans. The first
implementation should reduce two existing UI bridges to one contract, not create
a framework that every existing path must immediately be rewritten to use.
