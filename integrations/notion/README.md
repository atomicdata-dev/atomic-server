# Notion data source ↔ Atomic (pilot)

Connect from **Integrations → Notion** using a data source UUID and a Notion
connection token. Share the database containing that data source with the Notion
connection. Setup reads metadata through AtomicServer, creates native Atomic
properties/table/views and records compatibility notes. Preview and approve the
first sync before enabling background polling. Notion credentials stay on the
host; the browser does not call Notion directly.

The shipped `plugin.js` executes inside the existing QuickJS/WASM sandbox. It
uses the same durable preview/effect/continuation/checkpoint protocol as GitHub.
No Notion-specific scheduler, Rust provider code or second runtime was added.
The UI loads the installer and bundle on demand when connecting.

## Supported subset

- Row creation and editing in both directions: plain title/text, number,
  checkbox, URL, email/phone and existing select/multi-select/status options.
- Stable Notion page/property/option IDs. Property renames sync separately from
  row values, without renaming shared canonical Atomic properties.
- Atomic's display name and the mapped title column reconcile against a shared
  baseline. Conflicting local edits to both are reported, not silently chosen.
- Existing compatible table/board views: name, visible columns/order and mapped
  option grouping. View renames and column edits have independent baselines.
- Discovery event after the first checkpoint for independent JS automations;
  initial backfill and locally-created pages are excluded.

Patch requests contain only changed mapped properties. Null removes an optional
Atomic value; false/zero/empty arrays retain their distinct meanings. Long plain
text is chunked without truncation. Rich text formatting/mentions, changed field
types, option identity/name drift, unknown option values and missing pages pause
sync before unsafe writes. Uncertain remote creates use host journals and cannot
be blindly retried.

## Explicit limits

- A restricted disposable personal Notion database has passed live UI import and
  title edits in both directions through the sandbox. Broader field/view fidelity
  and background event delivery remain uncertified.
- One selected data source; database containers and linked views are not copied
  as separate row stores. New fields/views/options need reviewed mapping refresh,
  which is not implemented yet. Reinstallation is not a safe reset/recovery tool.
- Filtered/sorted views, status-group boards, subtasks and subgroups are skipped
  at setup with a reason. A supported connected view changing into an unsupported
  shape pauses sync. Calendars, list/gallery/timeline and other renderers remain
  future work. Provider-only widths/covers/wrapping are preserved when patching a
  configuration, but are not equivalent Atomic presentation.
- Formula/rollup/relation/date/file/person fields are preserved in Notion and not
  synced. Page blocks/content, archive/delete propagation and schema creation or
  deletion are outside this slice. Missing data never implies permission to delete.
- Full scans, 100-page cap, host session-size limits, and frequent verification
  reads. No incremental checkpoints, webhook intake or provider-paced read retry
  yet; rate limits pause the run. Concurrent writes between a re-read and remote
  mutation remain a cross-system race, not an exactly-once guarantee.
- Setup failures can leave a partial local draft; no resumable setup flow yet.
  The user supplies a data source UUID rather than a friendly database picker.

## Tests

From the repository root:

```sh
./browser/node_modules/.bin/esbuild integrations/notion/plugin.ts --bundle --format=esm --platform=neutral --target=es2022 --outfile=integrations/notion/plugin.js
./browser/node_modules/.bin/vitest run --config integrations/notion/vitest.config.ts
./browser/node_modules/.bin/tsc -p integrations/notion/tsconfig.json
ATOMICSERVER_SKIP_JS_BUILD=true cargo test -p atomic-server --lib notion_bundle --no-default-features --features light,wasm-plugins
```

Optional installer test with a disposable local AtomicServer, simulated Notion
metadata and no external Notion calls:

```sh
ATOMIC_NOTION_TEST_SERVER=http://localhost:9898 ./browser/node_modules/.bin/vitest run --config integrations/notion/vitest.config.ts
```

The Rust fixture executes the shipped bundle with real Atomic persistence and
host effect journals. Node tests cover mappings, pagination refusal, conflicts,
view preservation, manifest classification and reproducible packaging. Browser
coverage checks setup validation and the existing shared sync/automation flow;
it does not certify live Notion setup.

API version pinned to `2026-03-11`.
Sources: [page values](https://developers.notion.com/reference/page-property-values),
[data source queries](https://developers.notion.com/reference/query-a-data-source),
[view configuration](https://developers.notion.com/guides/data-apis/working-with-views).

## OAuth connection setup

Server administrators register a public Notion connection with read, insert and
update capabilities, then configure these environment variables on AtomicServer:

```
ATOMIC_NOTION_CLIENT_ID=<Notion client ID>
ATOMIC_NOTION_CLIENT_SECRET=<server-only secret>
ATOMIC_NOTION_REDIRECT_URI=http://localhost:9898/integration-oauth/notion/callback
ATOMIC_NOTION_FRONTEND_ORIGIN=http://localhost:6747
```

Register the exact redirect URI with Notion. Use HTTPS for deployed servers and
frontends; HTTP is accepted only on localhost/127.0.0.1. The frontend origin has
no trailing slash or path. Restart the server after configuring it. Do not put
client secrets in frontend environment variables or source control.

Users open Integrations → Notion → Connect Notion. Notion handles page access;
Atomic then searches accessible data sources by name. Preview creates the native
mapping and opens the existing sync review screen; it does not enable background
sync or approve external writes. Multi-source databases appear as individual
named data sources. Reuse the authorized workspace for further database syncs.
Manual token/ID installation remains under Advanced setup for developers.

Authorization belongs to the initiating Atomic agent and drive. Signed completion
requires the single-use state issued to that actor; the popup reply must match
origin, window and state. The host exchanges the code. Credentials use the node's
wrapped secret store, not graph resources. Plugins hold one-hop, same-drive secret
references with exact-origin checks. Reauthorization updates all references;
reconnecting to a different Notion workspace is refused.

Current limits: access-token failures prompt explicit reconnect. Refresh tokens
are retained privately, but automatic refresh is not implemented. Popup/opener
behavior on real Notion and a real two-way edit still require configured OAuth
credentials and a disposable database. Mocked OAuth tests do not certify live
provider behavior. Self-hosted operators currently bring their own OAuth app;
there is no Atomic-hosted authorization broker.

For an optional separately hosted authorization service, see
[shared authorization deployment](../AUTHORIZATION.md). It uses the same Notion
adapter; user servers need no public callback or Notion app secret in this mode.
