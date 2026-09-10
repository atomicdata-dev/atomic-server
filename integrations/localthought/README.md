# LocalThought browser integrations

The LocalThought flow runs entirely in the browser: catalog discovery, OAuth
consent, PKCE-protected return handling, paginated Syncables reads, ontology
creation, proposal review and local Store/OPFS writes. No AtomicServer HTTP
instance is needed. LocalThought remains the remote OAuth and API proxy.

Open Integrations, select a platform and choose **Install and connect**. The
browser creates a PKCE verifier and opens LocalThought's consent page, where
the selected platform is shown before you approve access. OAuth returns to the
same frontend `/app/integrations` page, and the browser redeems the one-time
handoff with the verifier. No tenant secret is entered in the browser. The
short-lived return is bound to the agent, drive and proxy; its code is removed
from the address bar immediately.
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

## Build and proxy requirements

- Build `atomic-wasm` using `cd browser/data-browser && pnpm build:wasm`.
- Set `VITE_INTEGRATION_PROXY_URL` at frontend build/dev time to override the
  default `https://localthought.io`. HTTPS or loopback HTTP origins only.
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

Limits remain 200 requests, 5,000 records, 10 MB per page/document and 120
seconds of network work. Calendar imports require explicit UTC date bounds.
Imports are manual; closed tabs do not run schedules. Other legacy integrations,
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
settings. The importer remains a manual snapshot, not a background sync.

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

Use **Fetch and preview** again to refresh, then review and apply changes.
Existing source identities and import baselines prevent duplicates and preserve
Atomic-only fields and local edits. Cancellation records are retained with a
note; absence from a bounded fetch never deletes an Atomic resource. Google
may omit cancelled events from list results, so this is not a deletion feed.
Removed optional provider fields are not cleared by the shared snapshot importer.
### Reviewed two-way event edits

After importing (or fetching an existing installation), use **Preview edits for
Google** and **Apply edits to Google**. Name/Summary, Description, Location,
Start and End on existing imported events sync back to their original calendar
and event ID, including individual recurring instances. Use **Fetch and preview**
to review incoming Google changes as before.

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
Atomic-only fields are preserved. This is manual two-way editing of existing
events, not a background sync or a complete Calendar mirror.

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
credential rotation, WASM pagination, local schema installation, proposal review,
OPFS application, and Calendar rendering. It refreshes changed provider data
and checks that native identities and Atomic-only notes survive reload.
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
