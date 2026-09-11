# LocalThought browser integrations

The LocalThought flow runs entirely in the browser: catalog discovery, OAuth
consent, PKCE-protected return handling, paginated Syncables reads, ontology
creation and local Store/OPFS writes. Installation validates access once, creates
a folder, and starts an automatic inbound import without a proposal dialog. No AtomicServer HTTP
instance is needed. LocalThought remains the remote OAuth and API proxy.

Open Integrations, select a platform and choose **Install and connect**. The
browser creates a PKCE verifier and opens LocalThought's consent page, where
the selected platform is shown before you approve access. OAuth returns to the
same frontend `/app/integrations` page, and the browser redeems the one-time
handoff with the verifier. No tenant secret is entered in the browser. The
short-lived return is bound to the agent, drive and proxy; its code is removed
from the address bar immediately. A ten-minute, non-secret session marker resumes
setup if removing those parameters remounts the page; completing installation or
closing its setup dialog clears the marker.
Connection codes are stored in this browser's localStorage, outside the synced
graph, and may be read by code running on this frontend origin. Clearing site
data requires reconnecting. Existing server-held connections require reconnecting.
Web Locks serialize rotating codes across tabs; a request consumes its code
before dispatch and saves the replacement before processing data. Uncertain
requests cannot silently replay credentials.

Syncables is vendored temporarily under `syncables/` with upstream provenance in
`UPSTREAM.md`; the matching upstream branch is `codex/browser-integrations`.
`wasm/src/integrations.rs` exposes its in-memory engine through wasm-bindgen.
The shipped pure import mapper reads a local snapshot and produces the existing
reviewed intents; user-edited plugin source is not executed on this path.
Local edits and repeated imports retain the existing reconciliation behavior.

## Installation and browser refresh

After connecting, choose the scope and select **Complete installation**. The
browser checks one catalog-selected provider API URL (HTTP success and a JSON
response), without following pagination or saving that response. This is an
access check, not a guarantee that every collection can be imported. Catalog
metadata requests are separate from that one provider request.

Installation immediately creates a normal folder and offers **Open folder**.
The full, paginated import runs in the background and creates typed tables and
views inside it. There is no JSON preview or Apply step for inbound records.
Opening the folder or a table refreshes it automatically, including after a
reload. While it remains open, a visible, online tab refreshes every five
minutes; returning to the tab or reconnecting the network also triggers refresh.
**Sync now** is available alongside **Syncing…**, the last successful sync time,
and any error. An import already started continues when navigating elsewhere
within the app. Closing the page stops it; reopening retries from the provider.

Settings, connection identifiers and sync status are saved only in this browser,
scoped to the installing agent and drive. The folder and imported records are
normal Atomic data. Another browser can read those records but needs its own
connection to refresh them. No server runner or closed-tab schedule is created.
A Web Lock covers the whole fetch/map/apply cycle, so simultaneous folder opens
across tabs cannot independently import the same snapshot.

Refresh uses the shared import baselines: stable source IDs reuse existing rows,
Atomic-only fields and local edits are preserved, and conflicts stop application
with a visible error. Missing rows do not imply deletion. Failed fetches leave
existing records readable and retain the last success time. A partial local
write is retried through the same stable identities on the next refresh.
Provider writes are still explicitly reviewed; opening a folder never sends
edits back to a provider.

Existing manual installations remain readable. Completing installation with an
existing connection creates a new browser-refresh folder; it does not move or
silently take over the old plugin tables.

## Build and proxy requirements

- Build `atomic-wasm` using `cd browser/data-browser && pnpm build:wasm`.
- Open **Settings → Integration** to select the integration-proxy URL. The
  preference is saved in this browser and applies without rebuilding. Connections
  are isolated by proxy origin; switching back restores that proxy’s connections.
  HTTPS or loopback HTTP origins only. **Reset to default** uses the deployment’s
  `VITE_INTEGRATION_PROXY_URL`, or `https://localthought.io` when unset.
- Existing bundled GitHub, Notion, Clockify and MT940 plugins remain available
  independently. Proxy cards have an accent border and a “Via integration proxy” label.
- Deploy the companion integration-proxy CORS change. It handles preflights for
  explicit Authorization headers and exposes `X-Connection-Code`, `Link`,
  pagination/count headers, `ETag` and `Retry-After`. Cookie credentials are not
  enabled; login and consent use top-level navigation. The browser sends
  `platform`, `redirect_uri`, `user_id`, `code_challenge`,
  `code_challenge_method=S256` and `credentials=connection` to `/connect`, then
  redeems the callback code at `/connect/redeem` with its PKCE verifier.
- Native AtomicServer's `TENANT_SECRET`, `ATOMIC_INTEGRATION_PROXY_URL` and
  `ATOMIC_INTEGRATION_FRONTEND_ORIGIN` no longer configure this flow. Its
  `/integration-proxy/*` handlers and Syncables dependency have been removed.

Consumer limits are 10,000 requests, 5,000 records, 10 MB per page/document
and 30 minutes per import, with a 30-second timeout per provider request. Calendar imports require explicit UTC date bounds.
Closed tabs do not run schedules. Other legacy integrations,
server plugin execution, actions and schedules are outside this migration.

## Checks

```sh
cargo check -p atomic-wasm --target wasm32-unknown-unknown
browser/node_modules/.bin/vitest run --config integrations/localthought/vitest.config.ts
node integrations/localthought/wasm-smoke.mjs # after building wasm/pkg
```

For the browser-only mock journey (no AtomicServer on port 19999):

```sh
MOCK_PROXY_PORT=19091 MOCK_FRONTEND_ORIGIN=http://localhost:6748 node integrations/localthought/mock-proxy.mjs
# Separate terminal, browser/data-browser:
VITE_INTEGRATION_PROXY_URL=http://127.0.0.1:19091 VITE_ATOMIC_SERVER_URL=http://127.0.0.1:19999 pnpm exec vite --host 127.0.0.1 --port 6748
# Repository root:
node integrations/localthought/browser-smoke.mjs
```

The mock is test-only. It uses a synthetic signed-in identity and data; never
deploy it.

## Historical server-flow verification

The server-owned tenant-secret flow described by the historical notes below is
superseded by the browser redirect and PKCE flow. Live verification of the new
LocalThought login, selected-platform consent and one-time redemption is checked
separately after matching deployments and recorded in PR/release verification.
The fixture tests below do not claim live-provider verification.

Live verification on 2026-09-09 succeeded against proxy Heroku release v38
(`5960ae43`): OAuth returned to AtomicServer, Syncables fetched 29 issue/PR
records from `localthought/integration-proxy` and queried all 29 comment
collections (empty), and the reviewed records were applied and displayed in
the local AtomicServer table with generated platform properties.

Proxy fixes [#28](https://github.com/localthought/integration-proxy/pull/28)
and [#29](https://github.com/localthought/integration-proxy/pull/29) add the
required GitHub User-Agent and preserve query parameters and Link headers.
This live repository fit on one issues page; multi-page traversal is covered
by the mock and Rust tests. Google Calendar was also live-verified against proxy v39 after
[PR #30](https://github.com/localthought/integration-proxy/pull/30) fixed matching
OpenAPI server base paths. OAuth returned successfully, and a UTC range from
2026-09-09 through 2026-10-09 (exclusive) imported 22 calendar-list entries and
32 events after review. Event contents are not included in these test notes.
An unbounded fetch successfully traversed multiple pages but exceeded the
5,000-record preview limit; the UI now defaults to the next 30 days. Date
bounds and recurrence expansion are passed to Syncables as collection query
settings. That historical verification exercised the earlier manual snapshot importer.

## Calendar view

Google event imports now install a Calendar view alongside the source table.
The projected date uses the day in Google's supplied start offset (or the
unchanged all-day date), so mixed all-day/timed events share one DATE column.
The original Start and End objects retain timezones and exclusive end values.
All-day events display on every covered day, excluding the end date, and are
marked All day. Their DATE projection does not shift with the viewing timezone.
Timed events still display on their start day only. Refresh existing imports
to install the new exclusive end-date projection. Additional notes identify recurring events, attendees,
reminders and conferencing when those fields are returned by the catalog.
Recurring instances are expanded by the existing bounded provider fetch.

Open the installed folder or its Calendar table to refresh automatically.
Existing source identities and import baselines prevent duplicates and preserve
Atomic-only fields and local edits. Cancellation records are retained with a
note; absence from a bounded fetch never deletes an Atomic resource. Google
may omit cancelled events from list results, so this is not a deletion feed.
Removed optional provider fields are not cleared by the shared snapshot importer.
### Reviewed two-way event edits

From the installed folder or table, use **Preview edits for
Google** and **Apply edits to Google**. Name/Summary, Description, Location,
Start and End on existing imported events sync back to their original calendar
and event ID, including individual recurring instances. Incoming Google changes refresh automatically when the folder or table opens.

Preview compares the import baseline with a fresh Google event. Conflicts block
preview. Apply checks local values still match the review and sends only changed
fields with `If-Match`; a changed Google ETag blocks the write. Successful writes
checkpoint the baseline. After a lost checkpoint, preview acknowledges matching
Google values without another PATCH. Uncertain transport requires reconnection.
Partial batches retain completed checkpoints and must be previewed again.
Google guest notifications are enabled (`sendUpdates=all`).

New events, deletion, recurrence rules, guests/RSVP, reminders and conferencing
remain managed in Google. Change Start/End together for timed/all-day conversions;
projected Calendar day/all-day columns are display fields refreshed on import.
Atomic-only fields are preserved. Outbound editing of existing events remains manual. Inbound refresh runs in
the browser; this is not a complete Calendar mirror.

**Deployment requirement:** deploy the companion integration-proxy change in
`calendar-proxy.patch` (based on proxy main `71115c2`). It requests
`calendar.events` and `calendar.calendarlist.readonly` and forwards/allows
`If-Match` through CORS. Reconnect existing Google accounts for write access.
Calendar reconnection retains the original installation identity and imported tables.
The companion worktree is `/private/tmp/calendar-sync-proxy`, branch
`codex/google-calendar-two-way`. No production deployment or live account writes
were performed as part of these checks.

`calendar-sync.test.ts` covers minimal patches, conflict detection, stale local
and remote previews, write-in-flight edits, lost checkpoints, date validation,
identity isolation, unsupported fields and denied writes. The browser transport
test checks conditional headers alongside rotating credentials.

`calendar.test.ts` exercises mixed dates, offset boundaries, exclusive ends,
recurrence/attendee notes, cancellations, malformed starts, cross-calendar
identity and repeated imports with private local fields.

## Browser-only Calendar regression

`browser/e2e/tests/google-calendar-import.spec.mts` starts the shared mock
integration-proxy with a synthetic Google Calendar. The test selects Calendar,
completes the mock PKCE consent and redemption, and exercises real browser
credential rotation, one-request access validation, WASM pagination, local schema
installation, automatic OPFS application, and Calendar rendering. It holds the
initial import until the installed folder is open, refreshes changed provider
data on reopening without a button, and checks that native identities and
Atomic-only notes and local title edits survive reload. A browser clock verifies
the five-minute timer. It also verifies failed refreshes preserve
records and reopening recovers. Both expanded instances and retained recurring
series are covered.
AtomicServer HTTP and all WebSockets are blocked throughout; only GET requests
are permitted for provider data. The configured LocalThought origin is forwarded
to the isolated HTTP fixture, so no live provider credentials or data are used.

Run with a dev frontend built from this branch and its matching WASM bundle:

```sh
FRONTEND_URL=http://127.0.0.1:6747 SERVER_URL=http://127.0.0.1:19999 \
  browser/e2e/node_modules/.bin/playwright test \
  --config browser/e2e/playwright.config.ts \
  browser/e2e/tests/google-calendar-import.spec.mts --project chromium
```

If the frontend uses `VITE_INTEGRATION_PROXY_URL`, pass the same value to the
test process. The test forwards that origin to its own fixture. Live Google
OAuth on the browser path still depends on the proxy CORS deployment described
above; this fixture test does not claim live-provider verification.

Verification: the focused LocalThought fixture and frontend checks cover the
redirect, PKCE, rotation and import paths. Live LocalThought login, consent,
redemption and Google write verification remain pending.

Each OAuth authorization creates a separate import installation. The proxy does
not provide a verified provider account identity, so reconnecting (even to the
same account to change scopes) creates new tables instead of reusing a previous
account’s tables. Repeated imports using the same connection reuse its tables.
