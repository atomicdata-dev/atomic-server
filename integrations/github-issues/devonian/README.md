# Browser issue tracker demo

Open `/app/devonian-demo` in the Atomic web app. Choose **Try sample data**,
create issues or comments on either side, close/reopen an issue, and press
**Sync now**. **Open Atomic kanban** opens the real native tracker, whose issue
pages also have the normal Comments panel. Reload and choose the same mode to
resume saved resources and mappings without importing duplicates.

The JavaScript runs in the browser. Devonian's native resource lenses run there;
Atomic resources live in a local-only drive in the browser's WASM/OPFS database.
The intermediate graph, scoped identity mappings, baselines and request journal
live in IndexedDB. No Node runtime, custom AtomicServer endpoint, server-side
plugin executor, tenant secret on AtomicServer or server worker is used. Enable
the browser database if it has been disabled.

## Live GitHub

Expand **Connect a real GitHub repository**, enter the integration-proxy origin,
`owner/repo`, and your **LocalThought tenant secret**, then choose **Connect GitHub
tracker**. The demo uses #1401's shared `BrowserIntegrations` client to sign the
tenant challenge in the browser, navigate to proxy consent, and bind the return
to this agent and local drive. The secret is cleared from the form and never
persisted. The callback code is removed from the address bar immediately.

After consent, **Sync now** authorizes two-way writes. The shared transport
serializes requests with Web Locks, consumes each code before dispatch, and
persists rotated credentials in browser localStorage, outside the Atomic graph.
Reloading the tab resumes the local tracker and connection. Use a dedicated
demo repository; writes use the connected GitHub account.

The browser calls `/proxy/github-issues/repos/{owner}/{repo}/issues...` directly.
The proxy instance must answer unauthenticated OPTIONS preflights, allow the
app's origin and GET/POST/PATCH/DELETE with Authorization and Content-Type,
expose `X-Connection-Code`, preserve query parameters, and allow issue/comment
and label operations in its catalog. CORS headers must cover error responses too.

**Live verification (2026-09-09):** Browser-only sync against
`localthought/integration-proxy` succeeded with AtomicServer unavailable, using
Heroku proxy release v40 (`bc02f13f`). The Atomic Server GitHub App requires
Issues read/write and installation on the target repository; OAuth authorization
alone previously allowed public reads but returned 403 on creation. The private
`ontola/atomic-github-sync-sandbox` returned 404 and remains outside the installed
repository access.

Disposable issue #34 was created from Atomic, received an Atomic-origin comment,
and was closed through browser sync. Reopening it and adding a comment on GitHub
synced back to Atomic, as did GitHub-created issue #35. Both issues were closed
through browser sync afterward. Independent GitHub CLI checks confirmed these
results and unchanged titles/states for existing issues.

The earlier failed write remains protected by the uncertain-write journal. Live
verification used separate browser storage at `http://localhost:6769`; the old
tracker at `http://127.0.0.1:6769` was preserved. Reconnecting does not clear an
uncertain write. **Connect another tracker** returns to the connection form
without clearing existing local trackers.

## Mapping

`GitHubPort` reuses `github-issues/adapter.ts`'s projection and request builder.
`tracker-actions.ts` adds scoped issue/comment request construction for the
browser transport. The installed server plugin's actions remain unchanged.

- Title/body map to the native row's name and Markdown description.
- Open maps to Todo; open with `atomic:doing` maps to Doing; closed maps to Done.
  Other labels are preserved. Provision `atomic:doing` before using Doing.
- A comment is a native Message whose `about` points to its issue and whose
  `parent` is the drive's Comments folder. Body edits synchronize both ways.
- GitHub identity, author and original timestamps are retained in a separate
  provenance property. The importing Atomic agent is distinct from the original
  author. GitHub writes use the connected account's authorship.
- The demo creates drive-local task properties so setup works offline. The
  intermediate Devonian graph uses the shared task vocabulary and maps native
  properties explicitly. Atomic DIDs are scoped external IDs because Devonian's
  current native subjects must be HTTP(S) URLs.
- Explicit issue numbers can bind existing rows; matching text never does.
  Comments have their own scoped IDs; identical comments remain distinct.

## Persistence and limits

A Web Lock serializes syncs. Three-way reconciliation preserves independent
field edits and stops on same-field conflicts. Reloads resume saved operations
before discovering new records. Ingest never automatically publishes an echo.
Missing records are conflicts; neither side is deleted.

The proxy does not provide idempotent GitHub creation. Writes are journaled
before sending. Successful receipts can be replayed; an uncertain/lost response
stops without resending. An operator must inspect and reconcile that operation;
there is no recovery wizard yet. Do not clear IndexedDB to retry a create.
Concurrent edits during a multi-request status transition may also require
reconciliation. Pre-write reads and verification do not make local/provider
writes one transaction. Sync is explicit while the tab is open, with a
10,000-record scan cap. Clearing browser site data loses the demo and its state.

## Source and verification

- `browser/data-browser/src/chunks/DevonianDemo/demo.mjs`: browser entry script.
- `bridge.mjs`: Devonian lenses and checkpointed reconciliation.
- `ports.mjs`: native Atomic and GitHub projections/transports.
- `proxy.mjs`: rotating-code transport and labelled sample fixture.
- `browser/data-browser/src/routes/DevonianDemoRoute.tsx`: demo controls.

The committed `DevonianDemo/devonian.js` bundle contains only the native resource
API from Devonian main `e11104f78ebd151a361171ca0b21489b25e1e2c8`, with its
Apache-2.0 license alongside. Regenerate at development time:

```sh
DEVONIAN_PATH=/path/to/devonian node integrations/github-issues/devonian/build.mjs
browser/node_modules/.bin/vitest run --config integrations/github-issues/devonian/vitest.config.mjs
browser/node_modules/.bin/vitest run --config integrations/github-issues/vitest.config.ts
cd browser/data-browser && pnpm typecheck
```

Tests use real Devonian lenses and deterministic connectors: creation, identical
content with distinct identities, independent edits, close/reopen, comments,
conflicts, missing resources, replay after lost receipts, label preservation,
pagination, scoped URLs and serialized code rotation. The browser sample flow
was manually verified with native OPFS resources, issue creation on both sides,
comments both ways, closing from Atomic and reopening from the GitHub fixture,
then reloading and resuming the same three issues and two comments without duplication.

## Playwright two-way regression

`browser/e2e/tests/devonian-issue-sync.spec.mts` starts an isolated HTTP integration
proxy with stateful, repository-scoped GitHub issue/comment endpoints. It fills
the tenant-secret form with the **public mock secret** (no real credentials),
completes consent, and exercises the live transport mode rather than sample mode.
It verifies creation and comments in both directions, close/reopen in both
directions, matching parent issues, and reload without duplicate resources or
provider writes. Legacy server integration endpoints, commit POSTs and all WebSockets are blocked.
The local run uses an unavailable AtomicServer port to verify browser-only storage.

With Vite and the built browser/WASM packages available:

```sh
cd browser/e2e
FRONTEND_URL=http://localhost:6747 playwright test tests/devonian-issue-sync.spec.mts --project chromium
```

The test is in the full E2E suite, without a smoke tag. The mock is local test
infrastructure only; the runtime demo uses the real integration-proxy protocol.
