## Connect in the app

Open **Integrations**, enter `owner/repository` and a repository-scoped GitHub
Issues read/write token, then **Connect GitHub**. Preview and approve the initial
sync. After it completes, enable background sync to poll every minute with the
browser closed. Errors pause execution; the connection shows saved results and
allows verified external-receipt recovery without resending a write.

Choose an event and **Create automation** to open an independent JavaScript
script. It references the integration explicitly. Add conditions and Atomic
intents, review a sample, then enable automatic execution. New discoveries exclude
initial backfill and issues created from Atomic cards. Automations can edit synced
records; direct multi-integration remote-action calls are still future work.

# GitHub issues ↔ Atomic kanban (pilot)

A reviewed, optionally scheduled two-way sync for one repository and one ordinary Atomic
kanban table. Provider code stays here; credential storage, release permissions,
external receipts and reconciliation checkpoints use AtomicServer's shared APIs.
The provider's `run()` executes inside AtomicServer's existing QuickJS/WASM
sandbox. It can read and propose effects; the server saves continuations, applies
approved effects and returns receipts. The CLI and browser use the same signed
preview/approve/resume APIs. A persisted polling grant lets the server continue
with the browser closed.

## Mapping

| GitHub | Atomic |
|---|---|
| Issue title | Card title |
| Markdown body (`null` becomes empty text) | Description |
| Open, without `atomic:doing` | Todo |
| Open, with `atomic:doing` | Doing |
| Closed | Done |

Dragging a card to Done closes its issue; moving it back reopens it. Other labels
are preserved: the adapter adds/removes only `atomic:doing`, never replaces the
whole label set. Create that label in the test repository before using Doing.
Pull requests are excluded. Comments, assignees, milestones, GitHub Projects and
issue deletion are outside this first scope. A missing issue/card is a conflict,
not permission to delete the other side.

## Run from the repository root

Build the current server and pilot. The output goes in the existing ignored
library dist directory so it resolves the library's installed Node dependencies.

```sh
ATOMICSERVER_SKIP_JS_BUILD=true cargo build -p atomic-server
./browser/node_modules/.bin/esbuild integrations/github-issues/cli.ts --bundle --platform=node --format=esm --packages=external --outfile=browser/lib/dist/github-issues-pilot.mjs
```

Run that server, then supply these environment variables through your local
secret-management workflow (do not put keys in command arguments or connection
files):

- `ATOMIC_SERVER_URL`: the running server URL.
- `ATOMIC_AGENT_SECRET`: an Atomic agent authorized to write the drive.
- `ATOMIC_DRIVE`: target drive subject, needed only for installation.
- `GITHUB_TOKEN`: GitHub token restricted to the test repository, with Issues
  read/write permission; needed only for installation. The installer stores it
  server-side and subsequent runs use an opaque `secret:github` handle.

```sh
node browser/lib/dist/github-issues-pilot.mjs install connection.json OWNER/TEST-REPO
node browser/lib/dist/github-issues-pilot.mjs preview connection.json preview.json
# Read preview.json: it contains proposed values and field conflicts.
node browser/lib/dist/github-issues-pilot.mjs apply connection.json preview.json
```

Installation prints the table subject. Open it in Atomic to use the existing
kanban UI. Add a titled card without an issue number to create an issue on the
next approved sync. Edit either side, generate a new preview file, review it,
and apply. Connection/preview files may contain private issue data but no tokens.
Existing files are not overwritten by install/preview.

The server serializes session execution. A saved partial run can be resumed with
the same operation identities:

```sh
node browser/lib/dist/github-issues-pilot.mjs resume connection.json
```

A lost remote response remains blocked until the operation is inspected and
confirmed through the shared recovery API. Do not discard the saved run or invent
a new run ID to retry an uncertain create. Local imports reuse durable Atomic receipts; an attempt without a receipt also
stops for reconciliation. The final baseline advances only when both sides have been re-read and
agree. Same-field conflicts pause the whole preview; resolve the data and preview
again before applying. Mid-run conflicts stay saved and currently need operator
recovery. The UI accepts inspected external receipts with evidence; it does not
yet guide provider-specific lookup or offer automatic abort/rollback.

## In the browser

Open **Integrations** in the sidebar, select the installed connection and choose
**Preview sync**, then **Approve sync**. The connection's icon appears in its
listing and page. **Resume sync** continues a saved interrupted run.

Under **Use in an automation**, select “New issue discovered” and create an
independent JavaScript automation. Review a sample in the editor, add conditions
and Atomic intents, then enable **automatic execution**. Initial backfill and
issues created from Atomic are excluded for new installations. Existing
installations retain their older “Issue added to Atomic” event semantics.

Events are durably queued during downtime and pending review. Scripts receive a
stable `ctx.trigger.id`; `ctx.read()` reads current data, not an event-time
snapshot. See the remaining limits in `planning/github-issues-pilot.md`.

## Verification

```sh
./browser/node_modules/.bin/vitest run --config integrations/github-issues/vitest.config.ts
./browser/node_modules/.bin/tsc -p integrations/github-issues/tsconfig.json
# Creates disposable resources only on this Atomic test server; no GitHub calls:
ATOMIC_GITHUB_TEST_SERVER=http://localhost:9897 ./browser/node_modules/.bin/vitest run --config integrations/github-issues/vitest.config.ts
```

The Rust tests run the installed bundle through QuickJS/WASM with real Atomic
storage: independent edits, conflicts, column transitions, preserved labels, new
issues, rate-limit refusal, uncertain responses and query-triggered messages.
Node tests check pagination, PR exclusion, reproducible packaging and the generic
event-to-JavaScript starter. Run the sandbox tests with:

```sh
ATOMICSERVER_SKIP_JS_BUILD=true cargo test -p atomic-server --lib sync_session_tests
```

These are authored API-contract fixtures, not independent proof of GitHub compatibility. A separate opt-in live test passed against the private Ontola sandbox;
provider failure recovery and larger repositories remain uncertified.

### Opt-in real GitHub test

`github.live.test.ts` is skipped by default. It requires `GITHUB_TOKEN` in the
process environment, a disposable local AtomicServer, and an explicit repository
opt-in. It refuses any repository other than the private Ontola test sandbox:

```sh
ATOMIC_LIVE_GITHUB_REPO=ontola/atomic-github-sync-sandbox ATOMIC_GITHUB_TEST_SERVER=http://localhost:9897 ./browser/node_modules/.bin/vitest run --config integrations/github-issues/vitest.config.ts integrations/github-issues/github.live.test.ts
```

This creates, edits and closes synthetic issues. It tests the shipped WASM
connector, both sync directions, kanban status/label mapping, and scheduled issue
discovery driving an independent JavaScript notification. It closes its test
issues and pauses polling afterwards. Use temporary server state and remove that
state after stopping the server to discard the test connection's stored credential.
The test notification is an Atomic resource, not email or OS push.

The pilot scans all pages, capped at 10,000 issue/PR entries, and uses indexed
Atomic lookups for individual cards. Persistent state is currently limited to
eight MiB per connection. Rate limits pause execution instead of automatically
retrying writes. Pre-write re-reads detect stale previews, but GitHub updates and
Atomic writes are not one transaction; concurrent edits in the final read/write
window remain a limitation. No exactly-once or production certification is claimed.

API reference: https://docs.github.com/en/rest/issues/issues
Label operations: https://docs.github.com/en/rest/issues/labels

### Shared task table pilot

New boards use the experimental built-in task vocabulary v1. Setup also accepts
an existing table on the selected drive when its row class includes the shared
Status and Description properties. Display names alone do not establish
compatibility. Tables already referenced by an integration are excluded; this
is a setup check, not a transactional multi-connector ownership mechanism.
Existing row classes and views are preserved. Preview includes existing cards.
Todo, Doing and Done map to GitHub; Blocked is intentionally not mapped and
must be resolved before sync. Old tables are not automatically migrated.
The vocabulary is an embedded HTTP-identity pilot, not the planned frozen
schema catalog or a claim of external standards conformance.
