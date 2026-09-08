# Notion two-way sync and table/view parity

Status: implemented pilot, 2026-09-06. Sandboxed provider, native installer and
shared UI are implemented. Live workspace verification and broader parity remain
open. A disposable personal Notion database and restricted test connection are
now created; live conformance testing is in progress.

## First acceptance scenario

Connect one disposable Notion database/data source containing Tasks. Preview its
schema, rows and saved table/board views in Atomic. Approve, then edit titles,
checkboxes, numbers and supported select/status values on either side. Create a
row on either side. Rename a property without losing its mapping. Adjust a
supported view's name, visible column order and grouping, and sync that change.
Background execution works without the browser. A discovered row can drive the
same independent JS automation contract as GitHub.

## Implementation sequence

- [x] Check current official API and Atomic view implementation.
- [ ] Define tested capability/mapping metadata: read, write, preserved-only,
  unsupported, with a reason per field/configuration. Unknown data must survive
  an unrelated edit; never serialize a lossy projection as a full replacement.
- [x] Implement the Notion provider in the existing QuickJS/WASM plugin model,
  with pinned release/config, host credentials, durable effects and receipts.
  Reuse the generic sync driver; no Notion-specific Rust scheduler or browser SDK.
- [x] Map one selected data source to a native Atomic table/class and page IDs to
  row identities. Use stable property IDs, not display names. Track schema
  reconciliation separately from row and view reconciliation.
- [x] Add editable scalar fields first: title, number, checkbox, URL/email and
  explicitly supported text. Treat rich-text annotations, date ranges/time zones,
  status groups and select option identities as fidelity work, not string casts.
- [ ] Add supported table/board view mapping and reviewed edits. Name, columns,
  grouping, filters and sorts require individual fidelity checks.
- [ ] Extend calendar mapping after testing date semantics. Preserve other views
  as provider metadata with an explicit unsupported message, not a silent table
  fallback. Never claim that storing configuration means rendering it correctly.
- [ ] Test independent edits, same-field conflicts, rename stability, null/empty
  distinctions, unsupported fields, page/property pagination, access loss,
  late-visible records, rate limits and uncertain creates.
- [ ] Build an opt-in live test on a disposable Notion page shared with the
  integration. A selected parent page and authorized connection are needed;
  existing business databases are not test fixtures.
- [ ] Use the second provider to extract shared installer/configuration metadata
  and generic preview rendering from the current GitHub-specific UI.

## Parity findings from current code

`tableViewKinds.ts` implements table, kanban, calendar and timer. Notion board maps
to kanban. Other layouts need new Atomic rendering or explicit unsupported state.
`useTableView.ts` currently exposes a single sort and a flat filter list; nested
Notion predicates and multiple sorts must not be flattened silently. Native
column visibility/order and grouping exist, but their exact semantics still need
round-trip tests. Audit widths, wrapping, groups/subgroups and date ranges before
advertising view parity.

Prioritize list/gallery and richer filtering/sorting based on real fixture gaps;
timeline, forms, charts and dashboard parity are separate product milestones.
Formula/rollup results can initially be read-only; translating formula engines is
not ordinary property sync. Relations need a mapping across connected data
sources. Page block/document content follows the table slice and needs its own
lossless format policy. No destructive schema or row deletion inferred from a
missing result or removed permission.

## Provider constraints and sources

The current Views API exposes view resources and requires a sufficiently recent
API version. Database containers and data sources are distinct; linked views do
not imply copying rows into separate tables. Pin the tested API version and scope
one data source first. [Notion views](https://developers.notion.com/guides/data-apis/working-with-views)

Schema changes should address stable property IDs. Read-only or unrepresentable
property types need explicit capabilities. [Data source updates](https://developers.notion.com/reference/update-a-data-source),
[page properties](https://developers.notion.com/reference/page-property-values)

Treat webhook events as wakeups and fetch current authorized state. Preserve
periodic reconciliation for missed signals. Implement bounded read backoff and
respect provider rate limits; uncertain creates still require reconciliation.
[Webhooks](https://developers.notion.com/reference/webhooks-events-delivery),
[request limits](https://developers.notion.com/reference/request-limits)

This deliberately uses Notion to expose shared product/connector gaps without
making Atomic's core schema a copy of Notion's API. Mapping metadata belongs to
the connector; native tables/views and domain semantics remain reusable.

## Current delivery and friction

- [x] `integrations/notion` provider bundle, stable field/page IDs, independent
  schema/row/view baselines and sparse remote patches.
- [x] Existing table/board view names, visible columns and supported grouping.
  Filtered/sorted views and status-group boards deliberately remain unsupported.
- [x] Connection setup in Integrations with icon, host-owned token, compatibility
  notes and lazy-loaded provider code. Generic preview renders arbitrary fields.
- [x] Model/package tests and a local HTTP installer test using simulated Notion.
- [x] Actual QuickJS/WASM test with real Atomic writes: row sync, independent
  edits, property rename, local page creation and uncertain-create refusal.
- [x] Chromium setup validation and existing shared background integration E2E.
- [ ] Live Notion test page/token access and provider conformance checks.

Notion exposed further shared requirements:

1. Field renames cannot rename shared `core.name`. The installer creates a local
   title property and the provider reconciles it with the row display name.
2. Read-only query operations can use POST. Manifest effect classification, not
   HTTP method alone, must determine whether they can execute during preview.
3. Preserve provider-only fields and view details when changing mapped fields;
   never rebuild a remote object from a partial Atomic projection.
4. Initial setup remains imperative and may leave a partial draft after failure.
   A resumable declarative setup/picker still needs extraction across providers.
5. Plain-text conversion must reject formatting and mentions. Relations, date
   ranges, formulas and page blocks need dedicated fidelity work.
6. Data-browser's typecheck script used its dist/composite config despite source
   imports shared with integrations. It now uses the existing source-aware
   tsconfig; remaining failures are pre-existing Document/Loro errors.
7. A guarded compatibility notice caused Wuchale to drop sibling status strings.
   Extracting it into a component restored those messages in all four catalogs.
8. Full scans and repeated schema/record verification will pressure Notion's
   limits. Incremental pages and provider-paced reads remain a prerequisite for
   scale, not a solved capability in this pilot.

## Verification result

- 16 mapping/package/installer tests passed, including the optional real-local-HTTP
  installer test (Notion replies simulated).
- The actual QuickJS/WASM + Atomic persistence test passed, including property
  rename, independent row edits, view rename/column-order reconciliation with
  preserved provider width, and an accepted-create/lost-response refusal.
- Three distinct Chromium cases passed: Notion setup validation, GitHub setup,
  and the shared integration background/automation flow. The two setup cases were
  rerun after the translation extraction adjustment.
- Provider TypeScript check passed. Frontend source typecheck reports only the
  existing two Document migration errors and unused Loro suppression.
- All four translation catalog diffs were reviewed; existing status/count strings
  remain active after extracting the compatibility notice into its own component.

Live setup (2026-09-06): Ontola's free block limit prevented creating rows, so
the user approved a personal workspace. Created `Atomic integration sandbox`
with one synthetic row, and `Atomic sandbox sync test` with access only to it.
The user approved the connection token and Developer Terms. The token is stored
only on the isolated local host; never include it in fixtures or logs.

- [x] Reproduce the live setup permission failure: the provider used `{id}` but
  the host only implemented `{number}`. Added constrained `{uuid}` segments,
  rejecting malformed UUIDs, encoded paths, other endpoints and suffixes.
- [x] Make the sandbox provider fixture enforce the real manifest matcher for
  every mocked read/write; its manifest is checked against the TS declaration.
- [ ] Complete live row/schema/view round trips and background event checks.

Live UI results: the restricted connection installed through Atomic's own UI;
the real Notion schema, view and initial row imported. Edited the title in Atomic,
verified it in Notion, edited it back in Notion and verified the saved value in
Atomic. Created a second row in Atomic and verified its creation in Notion; a
second approved sync left exactly those two rows, without duplicates. Both
directions ran through the QuickJS/WASM host, not browser-side API
calls. Scalar/board/schema-renaming live coverage still remains.

Fixed a second setup bug: dynamic `import('plugin.js?raw')` returned no default
source in the dev UI. A lazy installer module with a static raw import loads the
bundle correctly. Installer validation now refuses missing source before any
resource/credential writes, with a regression test.

Open UX gaps observed live:
- [ ] Table membership initially displayed zero rows after successful import;
  a fresh page load displayed the persisted row. Investigate query invalidation
  after server-side plugin writes; do not hide this behind test reloads.
- [ ] Preview lists unchanged schema/view records alongside changed rows; show
  actual effects/differences rather than making every checkpoint look like a write.
- [ ] Generic error UI dumps the full JSON-AD error (including Loro payload).
  Render its description, retaining details separately for diagnostics.
- [ ] Remove partial setup drafts or implement resumable setup. Failed attempts
  currently add indistinguishable Notion data source entries to the sidebar.

Background enablement was rejected by automatic approval review as an ongoing
process beyond the bounded live test. It remains disabled pending explicit
approval; manual verification continued without bypassing the rejection.

Current verification: 16 Node tests passed (one optional simulated HTTP installer
test skipped), four Rust manifest tests and the enhanced QuickJS/WASM fixture
passed. Provider typecheck passed; frontend source typecheck retains the same
three pre-existing Document/Loro errors. Local server on 9898 and frontend on
6747 retain the isolated test connection for follow-up; no background sync enabled.

Additional friction: Zen's remote accessibility capture needed a fresh window;
Notion's database ID is different from its data source ID, copied through Manage
data sources. A friendly database picker and resumable setup would avoid this.
The failed installer left a partial local draft, which must not count as connected.

## Setup UX correction (2026-09-06)

- [x] Remove the nested card and duplicate title from connection dialogs.
- [x] Use the existing Field and bordered Input components for Notion and GitHub.
- [x] Submit empty forms with visible feedback rather than a silently disabled
  button; support Enter and retain errors after rejected requests.
- [x] Reproduce the disabled-button failure in Playwright; verify empty input,
  invalid identifier before credential storage, and a rejected setup request.
- [x] Replace the default manual developer setup with provider sign-in and a named
  database picker. Live sign-in requires server OAuth configuration.
- [x] Implement OAuth server configuration, actor-bound one-time state, callback
  exchange and secure credential storage, then paginated database discovery.
  Tokens must stay on the host. Reuse the integration permission boundaries;
  do not put app secrets in the browser or fake a working sign-in button.

## OAuth and named database setup (2026-09-06)

- [x] Actor/drive-bound single-use OAuth state with expiry and signed completion.
- [x] Host-only token exchange and wrapped reusable credentials; same-drive,
  exact-origin references let reconnect update linked syncs without token copies.
- [x] Configured callback and frontend origins, popup origin/source/state checks,
  cancellation and expired/revoked-access feedback.
- [x] Search accessible data sources by name with pagination and emoji; retain
  manual setup under Advanced, and reuse the existing mapping/review flow.
- [x] Test state ownership/expiry/consumption, popup spoofing/cancellation,
  credential rotation/revocation and compatibility with old stored credentials.
- [ ] Configure a real public Notion OAuth app and verify popup authorization,
  missing database recovery, reconnect and a two-way edit on a disposable database.
- [ ] Automatic refresh-token rotation and operator-visible shared-connection
  revocation UI. Access failures currently require reconnect.
- [ ] Bound/index the connection listing for very large multi-tenant servers.
- [ ] Preserve/resume a partially installed mapping if a setup request fails.

Testing found a persistence trap: secrets use positional MessagePack, so a new
optional reference must be appended with a default, not inserted among existing
fields. A legacy credential decoding regression now protects upgrades.

Validation for this slice: four OAuth host tests, 20 credential-store tests,
three browser-message unit tests and 16 provider fixture tests pass. Browser
coverage now follows mocked OAuth through named database selection and native
mapping creation; the advanced setup regression also passes. Provider typecheck
passes. Frontend typecheck retains the three existing Document/Loro errors.

## Managed and independent authorization deployment

Follow the [shared authorization architecture](connector-scale.md#shared-authorization-architecture):
Atomic SaaS deploys the same FOSS authorization implementation that independent
operators can run with their own provider app credentials. No separate SaaS
Notion connector, picker or sync engine. The current local OAuth handlers are
an implementation starting point, not a reason to duplicate them in SaaS.

- [x] Adapt Notion authorization to the shared service boundary and its secure
  server/agent-bound credential handoff, including localhost servers.
- [ ] Register Atomic's Notion app for managed deployment; retain the existing
  administrator-configured app option for independent deployments.
- [ ] Implement refresh/revocation once in shared code, testing both deployment
  modes. Keep user credentials on the AtomicServer and document any transient
  service handling needed for exchange/renewal.

Managed deployment remains pending. The handoff protocol and HTTP transport
are implemented and tested with fixtures; live provider consent remains unverified.

### Shared authorization extraction

Notion code exchange now lives in `server/src/oauth/notion.rs`, called by the
existing local HTTP handler. A generic encrypted single-use handoff store is
available alongside it. Remote endpoints and outbound host retrieval are now implemented; see
`integrations/AUTHORIZATION.md`. Refresh, SaaS deployment and live registration
remain pending. Managed mode can be configured by an administrator.

### Browser UX walkthrough (2026-09-07)

- [x] Visually inspect discovery and Notion setup in the desktop browser; inspect GitHub setup controls.
- [x] Use the standard bordered search input and distinguish community code drafts from app connections.
- [x] Label the database action “Continue to sync setup” and show operation-specific progress. Make additional workspace authorization secondary.
- [x] Run direct/managed Notion setup, manual validation and GitHub-to-automation browser regressions (4 passed; provider fixtures).
- [ ] Move connected integration developer controls and source behind an advanced disclosure, keeping sync status primary.
- [ ] Replace GitHub token setup with provider authorization and repository discovery.
- [ ] Offer actionable administrator guidance when Notion authorization is unavailable.
