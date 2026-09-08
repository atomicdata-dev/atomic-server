# Importing an API with OpenAPI and overlays

`atomic-server import-oad` runs one import from an API into your local server's
store. [Reflector](https://github.com/localthought/reflector-rs) renders the
records and derived ontology as Atomic Data;
[syncables](https://github.com/localthought/syncables-rs) interprets the OpenAPI
document and ordered overlays to discover resources and follow pagination.
Adding an API means providing a document and overlays, without generating
API-specific Rust or JavaScript.

This initial integration uses Reflector revision
`a299b200bf06d2c1e5902da90ecd643fa9a7a2ae`. It supports a full read into
local storage, including Reflector's bearer-token authentication and
optional GitHub OAuth fallback. It does not run continuously or send local
changes back to the source API. The Sync page also supports interactive
OAuth imports while the server is running.

## Connect from the Sync page

Start the server with `REFLECTOR_ROOT` pointing to a checkout of Reflector at the
revision above, with `REFLECTOR_ROOT/spec` populated — Reflector's own
`scripts/fetch-oad.sh` fetches the GitHub and Google Calendar OAD documents
and overlays from [`localthought/openapi-directory`](https://github.com/localthought/openapi-directory)
and [`localthought/overlays`](https://github.com/localthought/overlays) into
`spec/<id>/`; they aren't vendored in Reflector's own repo any more. Set
`OAD_INTEGRATIONS` to the comma-separated list of `spec/<id>` folders to
offer, e.g. `OAD_INTEGRATIONS=github,google-calendar` for both. `/app/sync`
then has an **Integrations** section with one button per listed id:
currently **GitHub** (`github`) and **Google** (`google-calendar`). No server
restart is needed between imports.

Register OAuth applications with GitHub and Google. Use this callback URL for a
local server on the default port:

```text
http://localhost:9883/integrations/callback
```

For other deployments, replace the origin with the server's configured public
origin (the same `--domain`, `--port`, and `--https` settings it normally uses).
Keep the callback path `/integrations/callback`.

Set these variables **in the environment that starts AtomicServer**, or in its
`.env` file. Do not commit filled credentials:

```sh
export REFLECTOR_ROOT="/absolute/path/to/reflector-rs"
export OAD_INTEGRATIONS="github,google-calendar"
export GITHUB_CLIENT_ID="your GitHub OAuth app client ID"
export GITHUB_CLIENT_SECRET="your GitHub OAuth app client secret"
export GOOGLE_CLIENT_ID="your Google OAuth web client ID"
export GOOGLE_CLIENT_SECRET="your Google OAuth web client secret"
export GITHUB_API_CONSTANTS="owner=localthought,repo=test-repo-1"
export GOOGLE_CALENDAR_API_CONSTANTS="calendarId=primary"
atomic-server --domain localhost --port 9883
```

Enable the Calendar API for the Google project and configure its consent screen
and test users as appropriate. GitHub requests the `repo` scope; Google requests
`calendar.readonly` with offline access. The buttons show **OAuth setup needed**
until their client credentials are configured. See the
[GitHub OAuth guide](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
and [Google web-server OAuth guide](https://developers.google.com/identity/protocols/oauth2/web-server).

Click a button, authorize with the provider, and return to Sync. The server starts
importing immediately using its existing open database; the page displays progress,
completion or failure, and a link to the imported drive. Each signed-in agent has
a separate import namespace and owns its imported drive. `DRIVE_OWNER`, `API_TOKEN`,
`STORE_DIR`, `PUBLIC_URL`, and `PLATFORMS` are not used by this browser workflow.
Use the platform-specific constants above to select the repository or calendar.

Access and refresh tokens stay in server memory for the duration of the import.
The importer refreshes an expiring token or retries a rejected token once when a
refresh token is available. Providers do not always return refresh tokens. Tokens
are discarded after the import; reconnecting starts OAuth again. There is no
scheduled sync or credential persistence in this version. Pending authorization
expires after ten minutes and an import is bounded to thirty minutes. Individual
provider requests time out after sixty seconds. Database work runs separately
from HTTP workers. The Sync page saves completed imports into the signed-in
user’s private-drive list, making them available under **My drives**. Partial
writes remain if an import fails or times out. Restarting the server clears jobs
and pending authorization.

### Declarative integration configuration

The catalog reads one `*.openapi.yaml` / `*.openapi.json` document in each folder,
then applies its `overlays/` YAML/JSON files in filename order. Its
`components.securitySchemes` must declare an OAuth2 `authorizationCode` flow with
`authorizationUrl`, `tokenUrl`, and `scopes`. Optional `x-authorization-params` on
that flow supplies provider parameters such as Google's `access_type=offline`.

The document or an overlay also supplies `x-atomic-integration` metadata:

```json
{
  "label": "Example",
  "clientIdEnv": "EXAMPLE_CLIENT_ID",
  "clientSecretEnv": "EXAMPLE_CLIENT_SECRET",
  "constants": {"account": "primary"}
}
```

`<FOLDER_NAME>_API_CONSTANTS` overrides those defaults (uppercase, hyphens become
underscores). Only administrators configuring files on the server can change
OAuth endpoints and API documents; the browser submits just the integration ID.

Reflector's current GitHub and Google Calendar overlays declare pre-obtained
bearer tokens. This PR supplies supplemental **declarative** OAuth overlays in
`server/integrations/` for those two folders. A folder's own OAuth flow and metadata
take precedence, so the declarations can move upstream without changing the host.
The generic server OAuth host handles state, PKCE, callback cookies and refresh;
Reflector/syncables still handle resource discovery, pagination, ontology and data
conversion. The supplemental declarations do not change the CLI's existing token
configuration.

## Try the GitHub Issues CLI example

Build `atomic-server` from this branch, then obtain Reflector's example document
and overlays:

```sh
git clone https://github.com/localthought/reflector-rs.git
git -C reflector-rs checkout a299b200bf06d2c1e5902da90ecd643fa9a7a2ae
./reflector-rs/scripts/fetch-oad.sh   # populates reflector-rs/spec/ — not vendored any more
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
| `OPENAPI_DOCUMENT` | Defaults to `spec/github/github-issues.openapi.yaml` under the root. |
| `OPENAPI_OVERLAYS` | Comma-separated paths, applied in order; defaults to Reflector's GitHub auth, pagination, and CRUD-causality overlays. Use `,` for no overlays (an empty value selects defaults). |
| `API_CONSTANTS` | Comma-separated `key=value` bindings; defaults to `owner=localthought,repo=test-repo-1`. Use `,` for no constants. |
| `API_TOKEN` / `GITHUB_TOKEN` | Bearer token; anonymous requests if neither is set. |
| `DRIVE_OWNER` | Agent subject granted access when a drive is first created. |
| `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET` | Configure both to enable Reflector's interactive GitHub OAuth fallback. `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` are aliases. |
| `OAUTH_REDIRECT_ADDR`, `OAUTH_SCOPE` | GitHub OAuth callback address and scope; defaults to `127.0.0.1:8901` and `repo`. |

The document and overlay files are external configuration, not bundled into the
server binary. See [Reflector's documentation](https://github.com/localthought/reflector-rs/tree/a299b200bf06d2c1e5902da90ecd643fa9a7a2ae)
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

When embedding `atomic-server` from another workspace, repeat this patch in that
workspace's root `Cargo.toml` (Cargo does not inherit dependency workspace patches):

```toml
[patch."https://github.com/ontola/atomic-server"]
atomic_lib = { path = "../atomic-server/lib" }
```

Adjust the path to the same library checkout used by your server dependency.
