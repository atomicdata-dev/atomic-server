# LocalThought API plugins

AtomicServer reads `/catalog` from `https://localthought.io` and offers one
connection card per advertised platform. It loads `/catalog/{platform}.yaml`
for collection discovery, required scope parameters, pagination and ontology.

`syncables-rs` is pinned in `server/Cargo.toml`. Its `SyncClient` receives the
catalog's overlaid OpenAPI document and a host-owned transport that forwards
GET requests through `/proxy/{platform}/{path}`, preserving query parameters
and pagination headers. Rotating connection codes are held in AtomicServer's
secret store, scoped to a connection, drive and authenticated agent. The
browser carries a one-time OAuth return code to signed completion and removes
it from the address bar. Tenant secrets and provider tokens never enter graph
resources, plugin source or browser storage.

Each platform gets drive-local classes and properties derived by Syncables.
The platform ID prefixes every generated schema identity. Scalars retain their
datatypes; RFC3339 timestamps become milliseconds; arrays and nested objects
use Atomic JSON properties. API-required fields are recommended in Atomic
because nullable/partial API representations may omit them. Each resource type
gets a table and view. The shared sandbox importer proposes changes for review,
uses provider/resource/namespace/ID for reconciliation, and preserves local edits.
A failed collection aborts the preview instead of applying a partial snapshot.

This is a manual read/import flow, with limits of 200 requests, 5,000 records,
10 MB per page/document and 120 seconds per import. No provider writes or
background syncing are enabled. The existing direct GitHub token workflow
remains available explicitly in the GitHub connection dialog.

## Server configuration

- `TENANT_SECRET`: the LocalThought tenant secret, stored only on AtomicServer.
- `ATOMIC_INTEGRATION_FRONTEND_ORIGIN`: exact frontend origin, e.g.
  `https://your-atomic-app.example` (no trailing slash). Returns must use its
  `/app/integrations` path.
- `ATOMIC_INTEGRATION_PROXY_URL`: optional; defaults to `https://localthought.io`.
  Loopback HTTP is accepted for development.

Live verification on 2026-09-09 succeeded against proxy Heroku release v38
(`5960ae43`): OAuth returned to AtomicServer, Syncables fetched 29 issue/PR
records from `localthought/integration-proxy` and queried all 29 comment
collections (empty), and the reviewed records were applied and displayed in
the local AtomicServer table with generated platform properties.

Proxy fixes [#28](https://github.com/localthought/integration-proxy/pull/28)
and [#29](https://github.com/localthought/integration-proxy/pull/29) add the
required GitHub User-Agent and preserve query parameters and Link headers.
This live repository fit on one issues page; multi-page traversal is covered
by the mock and Rust tests. Google Calendar OAuth/import is not live-verified.

## Local mock and tests

The mock is test-only, with a synthetic tenant, consent screen, expiring-by-use
challenges, rotating single-use codes, and an OpenAPI document serving five
Pets over two pages. Never deploy it as a real credential service.

```sh
node integrations/localthought/mock-proxy.mjs
```

Start AtomicServer with:

```sh
TENANT_SECRET=bW9jay10ZW5hbnQ.mock-signature \
ATOMIC_INTEGRATION_PROXY_URL=http://127.0.0.1:19090 \
ATOMIC_INTEGRATION_FRONTEND_ORIGIN=http://localhost:6747 \
ATOMICSERVER_SKIP_JS_BUILD=true \
cargo run -p atomic-server --features light,wasm-plugins -- --port 9883
```

Run one Vite server with `VITE_ATOMIC_SERVER_URL=http://localhost:9883`, then:

```sh
cd browser/e2e
ATOMIC_MOCK_INTEGRATION_PROXY=1 pnpm exec playwright test tests/plugins.spec.ts \
  --project chromium --grep 'Pets imports'
```

Additional checks from the repository root:

```sh
node --test integrations/localthought/mock-proxy.test.mjs
browser/node_modules/.bin/vitest run --config integrations/localthought/vitest.config.ts
browser/node_modules/.bin/tsc -p integrations/localthought/tsconfig.json
ATOMICSERVER_SKIP_JS_BUILD=true cargo test -p atomic-server --lib \
  --features light,wasm-plugins integration_proxy
```

Dagger's E2E server starts the mock alongside AtomicServer, and the focused
GitHub Actions workflow runs the typed Pets journey on the API-plugin branches.
