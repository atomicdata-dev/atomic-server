# Importing an API with OpenAPI and overlays

`atomic-server import-oad` runs one import from an API into your local server's
store. [Reflector](https://github.com/localthought/reflector-rs) renders the
records and derived ontology as Atomic Data;
[syncables](https://github.com/localthought/syncables-rs) interprets the OpenAPI
document and ordered overlays to discover resources and follow pagination.
Adding an API means providing a document and overlays, without generating
API-specific Rust or JavaScript.

This initial integration uses Reflector revision
`4aef40d6eb76be0cf23c5994c7b2c764255db37e`. It supports a full read into local
storage, including Reflector's bearer-token authentication and optional GitHub
OAuth fallback. It does not run continuously or send local changes back to the
source API. It is a server CLI workflow; there is no GUI importer yet.

## Try the GitHub Issues example

Build `atomic-server` from this branch, then obtain Reflector's example document
and overlays:

```sh
git clone https://github.com/localthought/reflector-rs.git
git -C reflector-rs checkout 4aef40d6eb76be0cf23c5994c7b2c764255db37e
export REFLECTOR_ROOT="$PWD/reflector-rs"
export PUBLIC_URL="http://localhost:9883"
export API_CONSTANTS="owner=localthought,repo=test-repo-1"
export DRIVE_OWNER="did:ad:agent:YOUR_PUBLIC_KEY"
# Set API_TOKEN in your environment if the source API requires authentication.

# Stop AtomicServer before importing into its database.
atomic-server --domain localhost --port 9883 import-oad
# Restart with the same server configuration after the command exits.
atomic-server --domain localhost --port 9883
```

Use your AtomicServer agent's **subject**, not its secret, for `DRIVE_OWNER`.
The default example imports issues (open and closed) and comments into a separate
drive. Open
`http://localhost:9883/reflector-drives/localthought%2Ftest-repo-1` afterwards.
New drives grant read/write access to `DRIVE_OWNER`; without it, Reflector adds
no user access grants. Repeated imports update existing resources using their
stored Loro state and retain existing drive permissions.

## Configuration

Pass the same `--data-dir`, `--config-dir`, `--domain`, `--port`, and `--https`
options as your normal server, **before** `import-oad`. The command uses
AtomicServer's database and uploads paths. Reflector's `STORE_DIR` is ignored.
`PUBLIC_URL` is required and must equal the origin selected by the server flags,
so the imported ontology's URLs resolve on this server.

Reflector reads these environment variables (AtomicServer also loads `.env`):

| Variable | Purpose / default |
| --- | --- |
| `REFLECTOR_ROOT` | Root for relative document/overlay paths; current directory by default. |
| `OPENAPI_DOCUMENT` | Defaults to `spec/github-issues.openapi.yaml` under the root. |
| `OPENAPI_OVERLAYS` | Comma-separated paths, applied in order; defaults to Reflector's GitHub auth, pagination, and CRUD-causality overlays. Use `,` for no overlays (an empty value selects defaults). |
| `API_CONSTANTS` | Comma-separated `key=value` bindings; defaults to `owner=localthought,repo=test-repo-1`. Use `,` for no constants. |
| `API_TOKEN` / `GITHUB_TOKEN` | Bearer token; anonymous requests if neither is set. |
| `DRIVE_OWNER` | Agent subject granted access when a drive is first created. |
| `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET` | Configure both to enable Reflector's interactive GitHub OAuth fallback. `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` are aliases. |
| `OAUTH_REDIRECT_ADDR`, `OAUTH_SCOPE` | GitHub OAuth callback address and scope; defaults to `127.0.0.1:8901` and `repo`. |

The document and overlay files are external configuration, not bundled into the
server binary. See [Reflector's documentation](https://github.com/localthought/reflector-rs/tree/4aef40d6eb76be0cf23c5994c7b2c764255db37e)
for the overlay format, OAuth setup, and data mapping.

## Storage and failures

Stop the server before importing: redb requires exclusive access to its database.
This command writes directly to local storage and does not contact AtomicServer
over HTTP. Back up an existing store before the first import.

Imports persist progress as they go; a failure does not roll back earlier writes.
The command rebuilds the search index after syncing, including partial results,
and exits unsuccessfully if the sync reports errors. Correct the configuration
or API error and rerun the command. Restart the server after it finishes.

For maintainers: the workspace patches Reflector's pinned `atomic_lib` dependency
to the local crate so both sides share the same `Storelike` and database types.
Reflector and syncables are pinned Git dependencies until upstream publishes
compatible crates; publishing this server version to crates.io requires replacing
those Git dependencies with published versions first.
