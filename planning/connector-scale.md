# Bidirectional connector ecosystem

**Status:** Active implementation, 2026-09-06. User direction: reliable bidirectional sync
with many major and niche domain applications without bloating Atomic.
GitHub and Notion pilots now run in the shared sandbox and have bounded live
checks. Broader support, monitoring and release operations remain incomplete.

## Product direction (2026-09-08)

Follow [extension-architecture.md](extension-architecture.md): an app is the
workspace; an integration is a discoverable connector; a connection attaches a
configured source to that workspace; an automation is independent JS behavior
that may use connections. The current connection-as-workspace UI is a migration
starting point, not the target. Sync must remain useful without an automation.
Existing implementation checklists below do not claim this UX migration is done.

## Maintenance pipeline progress

### Discovery and automation journey

- [x] Searchable bundled capability cards; credentials appear only after setup is chosen.
- [x] Supported scope and dated evidence remain secondary disclosures.
- [x] Connected integrations offer a direct automation entry point using their event metadata.
- [x] Named automation drafts open a JavaScript workspace with save-and-test and proposed-change review.
- [x] Verify discovery, setup, sample review and enable/require-review in the browser.
- [x] Assistant-led automation requests create the same review-only draft and attach the selected integration; JavaScript authoring remains an advanced path.
- [x] Sync remains the primary connection flow. Automation setup is optional and hidden when an integration exposes no events.
- [x] Preserve the assistant request during provider setup and prevent automatic page context from replacing handoff context.
- [x] Notion OAuth and named data-source selection using administrator-configured OAuth credentials; manual token/ID setup is an advanced fallback.
- [ ] Managed authorization deployment and live Notion OAuth verification (see shared authorization architecture below).
- [ ] Rich JavaScript completion, sample-event selection and capability-linked action examples.

The editor and event selector use the existing automation runtime and permission
review. No provider-specific automation execution path is introduced.
Assistant handoff is tested without live model generation; generated automation
quality still depends on the configured model and its available tools. Credentials
remain in integration setup, and the handoff does not change sync schedules.
The browser journey exposed an HTTP contract mismatch: GET returned tagged
database filter values while POST accepted strings. The response now projects
the public string shape; a Rust round-trip test and browser enablement cover it.

### Certification

- [x] Automatic package discovery and required owner/API/capability/test metadata.
- [x] One offline command: reproducible bundles, provider types, fixture tests,
  exact named Rust sandbox tests; fail on zero executed tests.
- [x] JSON evidence with bundle hash, counts, explicit selected layer and live
  not-run status. Default runs strip existing opt-in provider-write switches.
- [x] CI JS gate discovers both providers; Rust gate mounts all provider fixtures.
  Dagger can export the JS-layer report; it does not claim separate Rust results.
- [x] Contribution/maintenance instructions in `integrations/README.md`.
- [x] Bundled store cards show dated offline evidence only for matching source hashes.
- [ ] Capability-to-test links and trusted evidence for third-party releases.
- [ ] Dedicated live-test accounts and a bounded separately authorized runner.
- [x] Compatible GitHub code upgrade preserves bindings and pins uncertain effects.
- [ ] Mapping/checkpoint migrations, staged rollout and owner alerts.

The report records declared capabilities separately from executed checks. This
is offline evidence, not a blanket production-support or live certification badge.

Verified locally: full certification passes for both providers (22 fixture tests,
four opt-in tests skipped, six exact sandbox tests), plus four pipeline guard
tests. Both bundles reproduce and both provider typechecks pass. Dagger source
typechecks with the existing Node-resolution deprecation suppressed; the complete
Dagger container pipeline has not been executed locally.

## Shared authorization architecture

**Direction agreed 2026-09-06:** one open-source authorization implementation,
with managed and independent deployment modes. Do not build separate SaaS and
FOSS versions of each integration.

| Concern | Shared implementation / deployment responsibility |
| --- | --- |
| Provider authorization, code exchange, refresh and revocation | Shared FOSS authorization code; provider-specific adapters/configuration |
| Managed authorization | `atomic-saas` deploys that code using Atomic's registered provider apps and client secrets |
| Independent authorization | A self-hoster deploys the same code using their own provider apps and client secrets |
| Resource discovery, mapping, sync, automation and assistant actions | Same host APIs and sandboxed plugins in either mode |
| User credentials, mappings, checkpoints and execution history | Stay on the user's AtomicServer; authorization service handles credentials during exchange/renewal as required |
| SaaS-only operations | Hosting, account management, abuse prevention and any billing; no duplicate provider or sync implementation |

Keep the reusable implementation in `atomic-server` or extract a small FOSS
package when the deployment boundary requires it. The exact package/process
layout is still open. `atomic-saas` consumes and deploys it rather than owning a
second implementation. The Notion handlers support local administrator-configured OAuth and optional
remote authorization through the shared service. Deployment remains separate.

The host selects its authorization service through configuration. Plugins
should declare their authorization needs and receive scoped host capabilities,
not OAuth client secrets. The same authorized connection can support several
syncs and be used through integrations by automations and the assistant.
Credential reuse does not broaden plugin permissions or approve writes.

A central service is optional infrastructure for providers that need it, not a
requirement for all plugins. Token-based and local integrations can remain direct.
Provider API traffic and synced content should flow directly between the user's
AtomicServer and the provider. Authorization/refresh may involve the service;
it must not become a general data proxy. A future webhook relay is a separate,
optional capability, not part of the initial authorization milestone.

### Shared service implementation progress

- [x] Extract the Notion token exchange from HTTP handlers into
  `server/src/oauth/notion.rs`; the existing local handler uses that adapter.
- [x] Implement a provider-independent handoff store in
  `server/src/oauth/handoff.rs`: server/agent/drive/provider/attempt binding,
  separate retrieval proof, ten-minute expiry, encrypted credentials,
  single-use delivery and paginated cleanup.
- [x] Wire authenticated service HTTP endpoints and outbound host retrieval.
  Server identity comes from administrator-provisioned per-host credentials;
  admission limits and periodic paginated cleanup are enabled.

The optional service transport is implemented; SaaS deployment/provisioning and
live provider verification remain open. See `integrations/AUTHORIZATION.md`. The handoff
proof stays on the initiating host and its hash is stored in metadata; provider
credentials use the node-key-wrapped secret store. A lost redemption response
requires fresh authorization because consumption precedes delivery. Transport
must not serialize tickets/proofs into browser responses or log credential
payloads. Direct OAuth keeps its existing callback flow; managed mode uses outbound
retrieval and browser polling of the local host. Refresh and SaaS deployment remain open.

### Remaining design and implementation

- [x] Define one provider-independent handoff protocol that binds authorization
  to the initiating AtomicServer, agent, drive, provider and login attempt.
  Cover single-use state, expiry, replay prevention and reconnect ownership.
- [x] Support localhost/private servers without requiring an inbound public
  callback on every server. Implement authenticated outbound retrieval of the
  authorization result; credentials must not appear in URLs, browser messages
  or graph resources. Keep provider callback handling in the selected service.
- [ ] Specify which service handles refresh when the provider requires the app
  secret. Define credential retention, rotation, revocation and service-outage
  behavior explicitly; do not assume the managed service never sees tokens.
- [x] Extract/reuse the current Notion authorization code behind that boundary,
  preserving the existing direct self-hosted mode and one credential model.
- [ ] Add Atomic SaaS deployment/configuration for the shared service and register
  Atomic's provider apps. Never ship their client secrets in FOSS distributions.
- [ ] Run the same conformance suite against managed and independent deployments:
  cancellation, wrong actor/server, expired/replayed handoff, inaccessible
  resources, reconnect, refresh, revocation and authorization-service outages.
- [ ] Use GitHub as the second provider to check that the protocol generalizes
  without a second sync engine, resource picker contract or automation API.

## Strategy

Build one reconciliation engine, independently released connector plugins, and
shared domain schema profiles. Each provider integrates with Atomic once; do
not build every pair of applications. Common semantics reduce mappings, but
cannot remove provider-specific representations, workflows, and write limits.
Interoperability is stated for specific objects, fields, operations and versions,
not a vendor logo. An import is not a bidirectional integration.

The business wedge becomes coexistence: users can gain useful Atomic workflows
while incumbent systems remain in place. Council information systems and primary
school administration are explicit examples supplied by the user. This broadens
the integration ecosystem beyond the SaaS vertical plan's initial agency and
field-research focus; it does not require building a replacement for every
incumbent. The earlier public-sector acquisition exclusion must not be treated
as a blanket exclusion on council-system interoperability.

## Reuse boundaries

| Component | Owns | Distribution |
| --- | --- | --- |
| Atomic core/runtime | Resource identity, grants, commits, generic durable integration state | Existing core |
| Shared sync service | Queues, checkpoints, leases, reconciliation, retries, audit and recovery | Optional host service; same contract on self-hosted/managed nodes |
| Provider adapter | API operations, pagination, revisions, errors, provider-specific quirks | On-demand versioned plugin |
| Domain profile/mapping | Shared semantics, standard links, conversions, extensions and tests | Pinned schema/mapping package |
| Connector catalog | Discovery, capabilities, maintenance status and compatibility evidence | Portable metadata with curated index |

Keep vendor SDKs, schemas, UI, credentials and domain rules out of default
browser bundles and the Atomic core release cycle. Prefer the existing
TypeScript plugin substrate; host large SDKs or unusual protocols in optional
workers. Core change should be exceptional after the first few connectors.
Only installed integrations consume storage/runtime resources; impose job,
memory, network, concurrency and retention limits per installation.

Reuse [plugins.md](plugins.md)'s Plugin manifest, `run`, scoped credentials,
host-owned egress, and reviewed grants. Connection/checkpoint/conflict resources
are operational state, not a second kind of executable plugin. The existing
`Verdict` only proposes Atomic writes; bidirectional work additionally needs a
host-executed, durable remote-operation intent contract. Plugins describe remote
operations; credentials are injected by the host. No unlogged direct mutation
inside a transform. This is proposed work, not existing capability.

## Connector contract

Describe capabilities per object and field: list/read/create/update/delete,
attachments, relationships, incremental discovery, webhook support, revision
preconditions, idempotency support, and API/profile version. Unsupported fields
remain local or read-only, visibly. Provider workflow actions such as publishing
a council decision or sending a notification are explicit commands, not implicit
effects of mirroring a field. Installing a connector does not authorize all
of its operations.

Keep API access separate from mapping. A standard transport adapter may support
multiple vendors with small overlays; vendor-specific fixtures still establish
whether they really conform. A source-native extension area preserves unmapped
data and original IDs, with retention and access controls. Never publish real
customer records as connector fixtures.

## Shared reconciliation semantics

Store, per binding, connection + tenant/account + object kind + remote ID ↔
Atomic subject, pinned mapping version, provider revision, normalized base
projection, local version, and pending operation state. IDs from two schools or
municipalities must not collide. Entity linking across providers is explicit;
matching names must not merge records automatically.

For each sync, compare the shared mapped base with the current local and remote
projections. If only one side changed, propagate according to field ownership;
disjoint field edits can combine; conflicting same-field edits require an
explicit policy or retained conflict. Source-authoritative, Atomic-authoritative,
and bidirectional are per-field modes. Compare semantic values, not provider
formatting. Atomic's CRDT does not automatically merge a proprietary remote API.

Reliability is shared engine work:

- Durable inbox/outbox and checkpoint transactions. Advance an inbound cursor
  only after its changes or recoverable work items are durably recorded.
- At-least-once delivery with idempotency, provider revisions/ETags where
  available, and read-back reconciliation. Persist operation intent before
  dispatch; if a create succeeds but its response is lost, reconcile by a
  stable operation marker/provider lookup rather than blindly retrying.
  Where no safe lookup exists, pause an uncertain operation for resolution.
  Do not promise exactly-once remote effects.
- Recheck local versions before applying a merge, and use conditional remote
  writes where supported. Without them, report weaker race guarantees.
- Persist acknowledgement and returned provider values as the next base.
  Suppress echoes using operation identity, revisions and normalized base,
  not an in-memory list of subjects or a short timing window. Model A→B→C
  routing explicitly; an origin stamp alone does not prevent every loop.
- One active worker per connection partition, with leases/fencing for failover;
  provider idempotency still protects in-flight requests from an old worker.
  Rate limits are shared per provider/account, with fair queuing and backoff.
- Webhooks signal work; durable ingestion and periodic reconciliation repair
  missed/out-of-order events. Handle expired cursors through safe resnapshot.
- Distinguish deletes, archive, permission loss, filtered-out records, and
  incomplete listing. A missing record is not proof of deletion. Configure
  delete propagation separately; retain tombstones and recoverable history.
- Local work survives offline periods. Expose per-object pending/failed/conflict
  state, last successful checkpoint, freshness, and actionable reconnect steps.

Pin adapter and schema versions per installation. Upgrade with migrations of
checkpoints/base projections, a shadow comparison where practical, and canary
rollout. Rolling code back cannot reverse already completed external writes;
compensation is separately planned and may be impossible. Authorization revocation
must stop queued writes as well as future polling.

## Execution placement and trust

Offer desktop execution while the device is running, an always-on self-hosted
runner, or a managed runner. Share the adapter contract, not an assumption of
browser uptime. Workers need access only to explicitly bound objects, fields and
operations. Do not mirror provider permissions implicitly into Atomic rights.
School tenant boundaries and nonpublic council documents make this essential.

A managed connector processing plaintext is a trusted service, not a blind Vault
feature. Users choosing private local execution keep credentials and processing
there. Keep auth handles, logs and pending payloads scoped and protected.
This integrates with the existing plugin-agent and SaaS trust boundaries.

## Produce and maintain many connectors

1. Build the first two against different APIs and shared schema objects to
   expose assumptions. Add a third through the documented SDK with no core edit.
2. Provide a connector kit: manifest, API client scaffolding, mappings, fixtures,
   sandbox runner, replay/fault tests and publication tooling. Generate routine
   clients from OpenAPI when available; use AI to draft adapters and tests.
3. Treat AI output as candidates. Promote only after deterministic contract
   tests and live vendor sandbox tests. Runtime sync is deterministic and does
   not require an LLM to reinterpret every record.
4. Share adapters for genuine common protocols, with narrow vendor overlays.
   Choose standards based on APIs actually available to customers, including
   write permissions and vendor partnership/access requirements.
5. Give each package a maintainer, supported API versions, test coverage,
   compatibility matrix and deprecation policy. First-party support for common
   apps; partner-maintained niche adapters; experimental community packages
   clearly distinguished. Contributions share the same release gates.
6. Sell managed execution, monitoring and supported connectors; fund niche
   coverage through customers, vendors or domain partners. Avoid permanent
   bespoke customer forks: tenant variation is configuration or a reusable
   adapter change. Standards/SDK/mappings remain portable.

Tests must cover reconnect, duplicate/out-of-order events, partial pages, rate
limits, token expiry, crash before/after remote success, concurrent edits,
delete-vs-edit, relationships, schema drift and remote normalization. Use replay
fixtures for broad cheap coverage and live test tenants for provider behavior.
Run provider checks at a frequency appropriate to API stability and cost.
Measure active supported connections, freshness, convergence, unresolved
conflicts, and maintenance hours—not merely number of published adapters.

## The user's example domains

- **Council information systems:** start with meeting, agenda item, document,
  decision and their relationships. [Open Raadsinformatie API docs](https://github.com/openstate/open-raadsinformatie/blob/master/API-docs.md)
  provide a retrieval surface; they do not establish vendor-system write access.
  Inventory each vendor's authenticated write API and workflow restrictions
  before advertising two-way support. Public meeting ingestion is a valid first
  capability, but must be labelled as such.
- **Primary-school administration:**
  [EDEXML](https://www.edustandaard.nl/standaard_afspraken/edexml/edexml-2-1/)
  defines exchange of pupil, group and teacher administration data. A file
  exchange schema is not a change feed or a write API.
  [Edu-V administration](https://www.edu-v.org/doorgifte-administratie/)
  is a relevant route for provider alignment; supported exchanges and roles
  must be checked per supplier. Begin with a narrowly agreed dataset and
  field ownership. Bidirectional capability never implies every field should
  be editable from both systems.

Evaluate optional infrastructure such as [Nango](https://nango.dev/docs/guides/functions/functions-guide)
for authentication, API operations, sync scheduling and webhooks before rebuilding
commodity pieces. Use a replaceable host adapter; assess licensing, deployment,
data location and actual provider coverage. Such infrastructure does not replace
Atomic's semantic mapping, conflict policy or end-to-end correctness contract.
No platform selection is made here.

## Delivery gates

- [ ] Inventory candidate providers: customer demand, API access, read/write
      scope, standards, sandbox, limits, maintenance owner and commercial access.
- [ ] Specify remote-operation intents and durable reconciliation state on the
      existing plugin substrate; resolve the queue/cursor gaps in plugins.md.
- [ ] Deliver one bounded two-way workflow with recovery and conflict UI.
- [ ] Add a second provider for the same shared concepts; prove convergence
      under faults without erasing provider-specific information.
- [ ] Have another maintainer ship connector three with no core modifications.
- [ ] Pilot one council or school connector with a real domain partner and
      supported vendor access; label direction and scope accurately.
- [ ] Publish the connector kit and capability catalog; scale supported
      inventory only when monitoring and maintenance ownership scale with it.

## Lessons from alternatives (2026-09-06)

These are documented design constraints and our deductions, not claims that the
other products are broken. Apply them to the pilot before expanding connector
count. User preference: automations may be JavaScript; avoid a separate visual
workflow language unless it earns its maintenance cost.

- **Separate reusable integration code, configured connections and automations.**
  Pipedream associates connected accounts with workflow steps. Atomic should keep
  credentials on a connection and make an automation's connection references
  explicit. Containment is not a capability grant. New automations now live in the
  drive, independently of their source integration, and record their references.
  Direct remote-action invocation will need a host check for each referenced
  connection and pinned action release; copying credentials into generated code
  is not an acceptable shortcut.
  [Pipedream connected accounts](https://pipedream.com/docs/apps/connected-accounts)

- **Plain JS does not remove the need for an execution contract.** Temporal
  requires replay to produce the same command sequence. Our explicit saved
  continuations avoid pretending an arbitrary script can resume at any await.
  Keep the small protocol; later SDK helpers can generate its repetitive stages.
  Pin approved code and inputs, and journal effect results. Do not claim arbitrary
  Node/npm compatibility or Temporal's full guarantees.
  [Temporal determinism](https://github.com/temporalio/documentation/blob/main/docs/encyclopedia/workflow/workflow-definition.mdx)

- **Event identity and attempt identity are different.** Pipedream separates an
  execution ID from a stable trace ID for the originating event. Atomic's durable
  queue event ID now reaches JS as `ctx.trigger.id`; its journal already uses that
  stable identity. A retry must not mint a new identity for the same external
  create. `ctx.read()` is explicitly a current authorized read, not a historical
  event snapshot. Captured event payload/version semantics remain future work.
  [Pipedream trigger identities](https://pipedream.com/docs/workflows/building-workflows/triggers)

- **A retry setting is not an idempotency guarantee.** Separate safe read retries,
  provider-idempotent writes and ambiguous writes. The last category pauses for
  reconciliation; retrying the entire script may duplicate an earlier effect.
  Keep the accepted-write/lost-response subprocess test as a release gate. Add
  provider-specific lookup/recovery before replacing the current receipt form
  with a convenient retry button.
  [Temporal activity/idempotency discussion](https://temporal.io/blog/idempotency-and-durable-execution)
  [Pipedream error handling](https://pipedream.com/docs/workflows/building-workflows/errors)

- **Two progress markers, not one giant snapshot.** Nango distinguishes upstream
  sync checkpoints from downstream consumer cursors. Atomic likewise needs small
  per-page provider progress plus a separate durable event delivery position.
  Current full repository scans and eight-MiB session snapshots are pilot limits.
  Re-scan should preserve identity/baselines; clearing them is a separate explicit
  operation because it can make old records look new again. A missing record on
  an incomplete scan is never evidence of deletion.
  [Nango checkpoints](https://nango.dev/docs/guides/functions/syncs/checkpoints)

- **Keep untrusted execution isolated from credentials.** n8n documents the
  distinction between internal runners and externally isolated runners. Atomic
  keeps a restricted QuickJS/WASM boundary and host-owned network/secret access.
  That is a capability boundary, not a claim that an in-process runtime provides
  OS-process isolation. Preserve an interface that can move execution into a
  separate process without rewriting connector code if the hosting threat model
  requires it.
  [n8n task runners](https://github.com/n8n-io/n8n-docs/blob/main/docs/deploy/host-n8n/configure-n8n/set-up-task-runners.md)

- **Code-first can still be discoverable.** Pipedream's code components expose
  typed/configurable inputs and connected accounts. Atomic can retain JavaScript
  as behavior while storing event metadata, schema bindings, connection references
  and examples as ordinary inspectable data. Avoid a provider-specific UI branch
  for each possible automation. The message form has been replaced by a generic
  event-to-script entry point.
  [Pipedream code components](https://pipedream.com/docs/workflows/building-workflows/code/nodejs)

### Next gates before scaling the store

- [x] Independent automations, explicit used-integration references, code editor.
- [x] Durable queued events, stable IDs, paused-review delivery regression tests.
- [x] Subprocess restart tests and browser-closed scheduled execution.
- [x] Shared named action invocation for UI, assistant, MCP adapter and server
  automations; pinned releases, explicit references and actor checks.
- [x] Revocable 30-day action grants pin actor, actual executing code and connection;
  review or automatic writes. Durable event/cron continuation after action approval.
- [x] MCP stdio host using signed Atomic requests; history, cancellation, provider
  lookup recovery and 60 fresh actions/minute per actor/connection.
- [x] History pagination: actor-scoped index, bounded redb reads, restart-safe migration, UI load-more and 2,001-record regression.
- [x] Explicit bounded cleanup for old unsent manual proposals; preview, reserved IDs, payload hashes and actor authorization.
- [x] Completed manual receipt retention with explicit opt-in, settlement age and atomic journal tombstones.
- [x] Tracked automation retention after all consumers finish and age out; explicit opt-in and conservative legacy handling.
- [ ] Production load and remote MCP
  HTTP/OAuth hosting if needed. See `integrations/ACTIONS.md`.
- [ ] Page-level provider checkpoints, reset semantics and large backlog bounds.
- [ ] Event payload/version policy, retention and indexed queue delivery.
- [x] Named-action recovery uses a declared provider read and saved confirmation.
- [ ] Extend guided matching to sync sessions and provider-specific reconciliation.
- [ ] Live provider certification, then a second connector with different API
  behavior to prove the abstractions. Fixture passes are not compatibility badges.

### Action pilot findings

- [x] Server and plugin runtime now consume one WIT source; removed the duplicate.
- [ ] Generate action schema fixtures; manifest validation still has Rust and
  TypeScript implementations with conformance tests.
- [ ] Make test-server restart wait for process exit/database-lock release.
  A graceful shutdown retained the redb lock long enough to fail the immediate
  replacement and disconnect the browser installation test. In the next run it
  held the lock after 45 seconds with its listener closed; only force-stopping
  that identified isolated process released it. Track graceful shutdown itself,
  not just port availability.
- [x] Expose persisted action outcomes and read-based recovery in Action history.
  History now pages in groups of 50; archival remains open.

- Build friction: Rust incremental caches exhausted local disk during the
  server archive build. Removing only regenerable `atomic_server*` incremental
  directories recovered space; source and test databases were preserved.

### History scaling follow-up (2026-09-06)

- [x] Replace full history reads/sorts with a timestamp + ID index. Preserve old
  API callers and atomically index new proposals; migrate existing records in
  bounded batches under the existing action lock.
- [x] Bound pending-review queries to the approval window; old records no longer
  make every new action deserialize the connection's full history.
- [x] Add local migration/pagination load coverage and a browser load-more check.
- [x] Compact unsent manual proposals older than 30 days, retaining a permanent
  ID tombstone and original outcome. Signed preview/apply API and history UI ship;
  tests verify preview, payload reduction, no replay and protected-record exclusions.
- [x] Compact successful manual receipts only after 30 days from settlement,
  preserving journal IDs/status/hashes and recovery evidence. Older clients keep
  unsent-only behavior unless they opt in with `includeCompleted`.
- [x] Durable run completion marker after effects and run-log persistence; cron
  and query workers acknowledge completed runs before reading saved action waits.
- [x] Link automation receipts to every consuming run before compaction.
  Failed/uncertain results and legacy receipts without settlement dates stay intact.
  No automatic retention worker or journal-key deletion is enabled.
- [ ] Live GitHub recovery verification: the opt-in target remains the private
  `ontola/atomic-github-sync-sandbox`; this process has no `GITHUB_TOKEN`.
- [ ] Production load measurements, especially migration lock duration and disk
  usage. The local regression is correctness coverage, not a throughput claim.

New friction: redb's existing range iterator eagerly copies the entire range.
The bounded `range_page` override fixes that for history without changing existing
callers. Other backends use the default iterator implementation; measure before
claiming the same memory bound there. Translation extraction again dropped text
after a mapped JSX list; wrapping the history list isolates that extractor issue.

Retention follow-up: compaction seeks directly to 30-day-old history and processes
at most 100 records per request. Actor-specific history and both existing action
and external locks protect eligibility rechecks. IDs/index entries are never deleted.
The cleanup UI previews counts before explicit application. This reduces manual action
payloads; it does not yet bound total journal growth or shrink redb files.

Completed-manual retention: response persistence and recovery confirmation now
record settlement time. Cleanup updates the proposal, external tombstone and any
duplicate recovery lookup in one batch. Both named-action and direct-executor
retries refuse archived IDs. Tests cover recent settlement, legacy unknown age,
failed writes, automation exclusions, opt-in compatibility and no executor resend.

Remaining design gap found while tracing continuation: scheduler/event pending
verdicts describe current waits, but are not a permanent record of which receipts
a successfully completed run consumed. Absence from a wait list is insufficient
for safe automation receipt deletion, especially around a crash/replay.

### Automation completion boundary (2026-09-06)

- [x] Persist `plugin-journal/v1/.../finished` with completion time and summary
  only after the plan applied successfully and the run log was saved.
- [x] Recover the crash window between completion and queue/schedule acknowledgement
  without rerunning JavaScript or revisiting old integration waits.
- [x] Regression tests restore stale durable claims/waits after an actual successful
  cron/query run; workers acknowledge them without creating another effect.
- [x] Record trusted per-run receipt usage before returning a receipt to JavaScript.
  A stable action ID can be shared by multiple runs, so one completed consumer is
  not sufficient. Each active consumer must prevent compaction.
- [x] Under the connection lock, archive only when every recorded consumer has a
  durable completion marker older than the retention period. Legacy receipts with
  no ownership record remain protected. A new consumer must acquire protection
  before cleanup can remove its response.

The run marker is now linked to a receipt-consumption ledger. Only fully tracked
receipts whose consumers have all finished and aged out are eligible. A crash before this marker
still follows existing reconciliation behavior; a crash after it retries only the
queue/schedule acknowledgement. Existing records are not inferred as completed.

### Receipt ownership and automation retention (2026-09-06)

- [x] Register each consumer durably before exposing the receipt, under the same
  connection lock used by cleanup. Reusing an action across runs adds owners.
- [x] Require all consumers to have completion markers at least 30 days old.
  Recent/unfinished consumers block cleanup; archived IDs refuse new consumers.
- [x] Keep legacy and subsequently untracked/manual access protected permanently.
- [x] Separate trusted cron/query execution from public runtime execution. A public
  `input.trigger` cannot claim ownership or spend an automatic grant. JS cannot
  change the host-captured run ID by mutating its input object.
- [x] Explicit `includeAutomation` opt-in preserves old-client cleanup semantics.
- [x] Explicit abandonment of recorded consumers, with reason/actor/time, busy
  worker refusal, terminal worker acknowledgement and a fresh retention period.
- [ ] Owner reconciliation when the automation was deleted or access is lost.
  Current abandonment requires write access to the original automation.
- [ ] Benchmark many-consumer cleanup. The current cap is 1,000 consumers per action
  and 100 actions per batch; this is bounded, but worst-case latency needs measuring.

Regression coverage includes two completed consumers, a third newly active one,
untracked access, old-client opt-out, and forged/mutated runtime trigger identities.
Public-run trigger spoofing was found during this work and closed alongside the
ownership implementation. No extra service or retention worker was introduced.

### Explicit consumer abandonment (2026-09-06)

- [x] Separate immutable abandonment audit from successful completion. The API
  requires the action owner and write access to the original automation.
- [x] Refuse busy cron/query workers; serialize with the connection and retain all
  effect journals. An abandoned run cannot plan, consume or become successful.
- [x] Ack abandoned schedule/event claims without replay. Abandonment affects only
  the selected run; future scheduled runs stay enabled.
- [x] Prevent a pending provider write if every tracked consumer was abandoned.
- [x] List consuming runs in action history and collect an explicit reason in UI.
- [x] Retention waits 30 days after abandonment; uncertain/failed/legacy safeguards
  remain intact. No automatic age-based abandonment.
- [ ] Busy exclusion is currently per worker, not per run; an unrelated active run
  can temporarily prevent abandonment. Finer-grained run locking is future work.

Tests cover unrelated run IDs, wrong actors, blank reasons, busy workers,
immutable audit, terminal planning/consumption refusal, retained uncertainty,
and cron/query acknowledgement without applying the saved plan.

Testing friction update: repeatedly deleting only incremental directories was not
sufficient for disk pressure. A crate-scoped `cargo clean -p atomic-server` removed
35,712 generated files (39.4 GiB reported), leaving about 21 GiB available and
allowing a clean rebuild. Source and isolated databases were preserved. Prefer a
scoped clean over repeated failed links when server artifacts have accumulated.
Graceful test-server shutdown can take tens of seconds after its listener closes;
check the database owner and allow the grace period before forcing termination.

### HTTP transport validation (2026-09-06)

- [x] Opt-in service routes, per-host authentication and bounded admission.
- [x] Single-use callback code exchange and encrypted outbound redemption.
- [x] Host-only ticket storage, same signed local UI API, direct/managed mode selection.
- [x] Real loopback HTTP client/service test plus direct and managed browser fixtures.
- [ ] Live Notion consent and real two-way sync after app registration.
- [ ] Automated enrollment/key rotation, remote cancellation and provider refresh.

The loopback test needs permission to bind a socket in the local sandbox; a
permission-denied bind is an environment failure, not a protocol test result.

### Assistant capability work (2026-09-07)

- [x] Add `discover_integrations`: search installed connection names and declared action capabilities without fetching provider records; retain partial results when a connection fails.
- [x] Resolve `run_plugin` source through the canonical plugin-source property instead of guessing from string contents.
- [x] Unit coverage for capability filtering, draft exclusion, partial failures and empty drives.
- [x] Accept explicit recorded/synthetic event input in assistant previews, preserving manual review authority regardless of event kind.
- [ ] Add recorded-event browsing and sample selection UI.
- [x] Render a host-refetched proposal with approve/cancel and returned receipt in chat.
- [ ] Browser-test in-chat approval, stale proposals and reload recovery; feed completion back into model context.
- [x] Default new actions to the SDK tool invocation ID and return it on success and failure.
- [ ] Automatically associate a new follow-up retry invocation with the original logical action.
- [ ] Add live-model author/test/repair evaluations and hostile provider-content scenarios.

Discovery reports declared capabilities, not verified provider credential health.
Search currently matches all whitespace-separated keywords; it is not semantic search.

Validation: four preview/discovery unit tests pass. The Rust runtime test
`only_host_triggered_runs_own_receipts_and_js_cannot_change_the_identity` passes:
event-shaped manual input does not acquire automatic action authority. The
hostile-text fixture only verifies data preservation, not model injection resistance.
Live-model evaluations and browser acceptance for the new chat controls remain open.
