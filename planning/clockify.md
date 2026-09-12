# Clockify pilot

First prove a useful import into the existing Time Tracker template. Two-way sync
and active timers follow only after reviewing actual imported records.

## Delivered

- [x] Discover Clockify in Integrations with an icon, scope and setup dialog.
- [x] Store the API key on AtomicServer; discover the current user and named workspaces.
- [x] Offer personal completed entries from the past 7 or 30 days.
- [x] Run bundled JavaScript in the existing sandbox, with GET-only provider operations and normal reviewed Atomic proposals.
- [x] Reuse time interval, project, person, billable and source-identity properties within a drive; use Time Tracker views and derived duration.
- [x] Deduplicate by provider/workspace/record identity; never merge by display name. Shared baselines allow clean source updates and protect local edits.
- [x] Fixture tests for mapping, timestamps, pagination, duplicate identity, malformed records and provider errors.
- [x] Real Rust sandbox execution test and offline connector certification.
- [x] Workspace discovery/response projection executes in the provider JS sandbox; the UI renders its result through the shared host execution client.
- [x] Real TypeScript Store apply regression verifies final DID links, typed values, signed Loro commits and duplicate skipping with mocked HTTP.
- [x] Browser-to-sandbox-to-local-server approval/apply test with synthetic provider transport; a second run queries the real DB and proposes no duplicates.
- [x] Browser setup regression: named workspace discovery, default date range, visible errors and retry after transport failure.

## Still open

- [ ] Inspect a live Clockify account and review/apply a small sample; verify totals against Clockify and repeat-import behavior against a live AtomicServer.
- [x] Existing-table selection by shared property identity and datatype, preserving views and custom property names. Reject unmapped required fields and incompatible related classes.
- [x] Saved setup links to its table and generic import page for future runs, review and scheduling.
- [ ] Project filtering and cleanup/resume of abandoned setup drafts.
- [ ] Regional/private API origins. This pilot supports only the global API origin.
- [x] Expose hash-matched Clockify certification evidence in the catalog, with live checks explicitly separate. Refreshed complete offline evidence for all three bundled providers.
- [x] New imports use rolling date windows resolved from each host trigger; legacy fixed-window configurations remain supported.
- [ ] Expose reusable Clockify connection actions to the assistant and other automation plugins.
- [ ] Two-way edits, conflict review, deletions and safe checkpoint/retry behavior.
- [ ] Active timers and breaks; task links, tags, rates and custom fields.
- [ ] Frozen cross-drive schema packages and reviewed migration of existing Time Tracker tables.

## Findings and limits (2026-09-07)

The first browser test caught a datatype mismatch: table relation columns are
single resource links, not resource arrays. Project and Person now use those
same link types. A cancelled preview also produced duplicate failure toasts;
its rejection handler now respects cancellation.

The plugin bounds date ranges to 31 days and pagination to 20 pages of 50
records for each scan. An unterminated scan fails the entire proposal. Large
imports may also hit the normal host proposal limits; they are not silently
truncated. Unchanged source entries are skipped. Changed source fields update clean values; divergent local edits block the proposal.

Schema reuse is currently within a drive using ensureSchema. It is not a global
standard or the finished frozen-schema catalog. Project/Person resources are
shared across these imports, but names are not evidence of identity.

Live validation remains blocked: browser control now explicitly reports that
the Mac is locked and cannot be automatically unlocked. No live Clockify
credentials or data were read or imported. Fixture credentials are disposable.
Do not store personal provider responses in checked-in tests.

The Store apply regression found a shared planner gap: its temporary `_new:`
subjects were rejected as invalid Atomic URLs when proposals linked new records.
The planner now defers URL validation only for targets created by that same plan;
class constraints, unrelated temporary subjects and other datatypes remain
validated. Apply rewrites references to signed genesis DIDs before saving.

## Execution boundary

Clockify-specific discovery, provider response validation, date windows,
pagination and data mapping execute as JavaScript in the existing sandbox.
React owns forms and Atomic table/template installation. The generic Rust host
owns authentication, credential injection, network permissions and durable
execution; the host planner/apply path controls approved writes. No Clockify
business logic was added to Rust (only sandbox regression tests).

API reference: https://docs.clockify.me/ (v1, X-Api-Key, page/page-size).

## Existing table and saved import follow-up (2026-09-07)

Table selection is Atomic-side installation logic, not provider code. The
selected table is rechecked before configuration. Reuse does not call the schema
reconciler, so it cannot reset customized property names. Required Project links
are excluded because Clockify entries may have no project; added required fields
on Project/Person classes and incompatible relation constraints also disqualify
reuse. New Time Tracker creation stays available.

After setup, Open time entries and Manage import lead to the saved resources.
After an approved import, workspace and destination are locked within that setup
session to prevent accidentally redirecting an already-applied import. Date-range
selection and preview remain available. Closing setup before completing it can
still leave a draft; explicit resume/cleanup remains open.

The table/links browser regression runs provider code in the real sandbox with
synthetic HTTP, applies linked resources to the local server, skips repeats,
opens the selected table, and verifies its views and a customized property name.
Six compatibility fixtures cover schema identity, datatype and required-field
constraints. The catalog browser check opens evidence for all three integrations.
Copy in guarded JSX was silently missing from translation extraction; separating
the import help and navigation components preserves those messages.

## App containment correction (2026-09-07)

- [x] New Clockify tables and supporting Project/Person records nest beneath the
  Clockify plugin resource. Rows stay beneath the table. An explicitly selected
  existing table is not moved. Legacy configuration without `container` falls
  back to nesting new support records beneath its table, not the drive.
- [x] The updated JS bundle proposes moving recognized imported Project/Person
  records still at the old drive-root location into the container. These moves
  require the normal preview/apply approval; custom parents and mismatched
  classes/identities are untouched. Only records encountered in the selected
  import window are considered. Cache support lookups within a run.
- [x] Fixtures cover nesting and conservative migration. The real sandbox/browser
  flow verifies app children, moves one synthetic project to the old root,
  reviews/applies its move back, and confirms the next import proposes no changes.
- [ ] Upgrade existing installed Clockify sources and review the user's live root
  cleanup. Repository changes do not silently replace stored plugin source or
  move already-created user data.

The previous `parent: drive` was an importer bug, not a shared-schema requirement.
Sharing a linked Project's identity does not require placing it at the drive root.
