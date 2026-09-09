# Clockify completed-entry importer

Experimental, read-only provider access. Uses the shared sandbox and normal
proposed Atomic changes; no parallel execution engine. Credentials remain in
AtomicServer secret storage. API v1: https://docs.clockify.me/.

Setup reads the current user and their available workspaces, then offers a
rolling 7/30-day bounded import into the Time Tracker template. Projects and the person
are linked resources, keyed by provider-qualified identity, never merged by name.
Repeated imports skip unchanged source records, update clean source fields, and
preserve local edits. Divergent local/source edits block the proposal for review.
The shared importer persists native `localId` and a last-source `importBaseline`. This is not bidirectional sync: no
updates, deletions, running timers, breaks, rates, tasks, tags or custom fields.
Up to 1,000 projects/entries per scan; incomplete pagination fails the preview.
The pilot uses the global API origin; regional/private deployments need explicit
origin support. Existing time-tracker tables are not automatically migrated.

The shared time-tracking schema is reused within a drive through ensureSchema.
Frozen cross-drive schema packages remain pending; no external standard
conformance is claimed. Live account data must never be checked into fixtures.

Discovery and response validation run inside the same JavaScript sandbox as the
importer. New installations derive the range from each host trigger timestamp;
legacy fixed-window configurations continue to run unchanged. React only renders
setup/results and installs Atomic template resources. There is no Clockify-specific
Rust implementation; the host enforces secrets, network access and approved writes.

Setup can target an existing compatible Time Tracker table or create a new one.
Compatibility uses property identities and types, never column names, and refuses
required fields the importer cannot supply. Reuse preserves views and schema names.
After setup, the table and saved importer are directly accessible from the dialog.

New tables, projects and people nest beneath the Clockify integration; rows nest
beneath their table. Existing selected tables keep their location. The updated
bundle can propose moving recognized imported support records still at the old
drive root; approval is required, and custom locations are preserved. Installed
plugins retain their stored source until explicitly upgraded.

## Updating existing installations

Open the installed importer and choose **Review Clockify update** when available.
Review the replacement code and apply the update. It preserves the JSON settings
and server-stored secret; custom code is replaced only after this review. The next
preview adopts matching legacy records and reports edited records for resolution.
Conflict review offers keeping the local value or using the source value, followed
by a fresh preview. Saved resolutions are checked again at commit time.
