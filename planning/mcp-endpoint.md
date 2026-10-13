# Atomic as an MCP server

> **Status:** One implementation. The node serves the tools at `POST /mcp`
> (`server/src/mcp/`): OAuth 2.1 authorization server plus Streamable HTTP
> resource server, reads and, if the person allowed editing, writes. A write is
> a commit the node signs as the *issued agent* behind the token (its key is
> derived again from the token's claims, never stored, never the person's), sent
> through the normal commit pipeline, so the ACLs the person granted that agent
> are the limit and Connected apps shows it by name and revokes it. The local
> `@tomic/mcp` (`browser/mcp`) is only a stdio bridge to that endpoint with a
> token from `atomic-mcp connect` (OAuth with a loopback redirect). The in-app
> assistant keeps its own tool list (`useAtomicTools`, `assistant-tools.ts` in
> `@tomic/lib`), which is the one place the verbs are still implemented twice;
> `atomic-cli connect` and `ad-generate connect` still use a key of their own
> (`/app/connect-agent`). Not done: `semantic_search` on `/mcp`, `format=compact`
> short refs, refresh-token rotation, a per-process-independent one-time code
> store.
> Companion to [`actions.md`](./actions.md) (one verb list, many surfaces),
> [`json-ad-compact.md`](./json-ad-compact.md) (the wire dialect),
> [`atomic-lib-runtime.md`](./atomic-lib-runtime.md) (`AtomicNode`),
> [`plugins.md`](./plugins.md) (issued agents, unattended writes),
> [`SDK-API-design.md`](./SDK-API-design.md) (agent DX), and
> [`planning/oidc-oauth.md`](https://github.com/ontola/atomic-server/blob/cursor/oidc-oauth-reconsider-1cb5/planning/oidc-oauth.md)
> (PR #1310; not on `develop` yet).
>
> **Decision:** Ship Atomic as an MCP *server*. Reads may live on the node.
> Writes stay signed commits from a key the caller holds — locally that is
> the user's Agent; remotely that is an **issued agent**, never the user's
> root and never an OAuth Bearer on `/commit`. Do not grow a fifth tool
> list. Do not wrap the Tauri DOM bridge and call it a data API.

## Why

The in-app assistant already *consumes* MCP (`McpServersContext`, Exa as a
default). Cursor, Claude Desktop, Claude Code, and ChatGPT cannot *talk to
Atomic*. That is the missing half of
[`SDK-API-design.md`](./SDK-API-design.md): an LLM agent should read and
edit a drive the same way a human does, from any client that speaks MCP.

The tool surface already exists. `useAtomicTools.ts` is a React hook around
get / query / search / schema / create / edit, speaking compact JSON-AD.
[`actions.md`](./actions.md) already lists "MCP server (future)" as a
projection of the same registry and warns that a new server would otherwise
become a fifth enumeration. [`json-ad-compact.md`](./json-ad-compact.md)
phase 4 is explicitly "server-side `format=compact` so MCP server & other
clients share it". The product intent is not new; the endpoint is.

## What this is not

| Existing thing | Why it is not this |
| --- | --- |
| Atomic Assistant + user-added MCP servers | We are a client of other people's tools. This plan is Atomic *as* the server. |
| Desktop `tauri-plugin-mcp-bridge` (`127.0.0.1:9223`) | DOM automation for e2e. Unauthenticated loopback, page JS, not the graph. Keep it; do not extend it. |
| `/app/token` Bearer AUTH | Signed Authentication Resource. MCP HTTP clients speak OAuth 2.1, not Ed25519 AUTH. |
| OpenAI-compatible chat endpoint (#1259) | Model inference. Orthogonal. A hosted proxy still must not sign user commits. |

## The write problem

Atomic writes are Ed25519 commits with a Loro update. The private key is
the identity (`did:ad:agent:{pubkey}`). MCP HTTP clients (Cursor, etc.)
are generic JSON-RPC callers: they present a Bearer token and invoke a
tool. They will not mint a Loro delta or sign a commit.

So a *remote* MCP handler that "just writes" has only two honest options,
and one of them is forbidden:

1. **The node signs as the user.** Forbidden. [#1310](https://github.com/ontola/atomic-server/pull/1310)
   D1: `POST /commit`, resource AUTH, WS `AUTH`, and Iroh `AUTH` never
   accept an OIDC/OAuth token. "The node signing content commits as the
   user" is on that PR's forbidden list. A Bearer on `/mcp` must not
   become a commit whose `signer` is the human's root DID.
2. **A different Agent signs, and the node may hold that key.** This is
   already how unattended plugins work (`plugins.md` B4): an app is issued
   its own Agent, the key lives on the node wrapped by the node key, writes
   are attributable to that DID, revoking is taking it off `write`. MCP is
   the same shape with a different caller.

A *local* MCP process sits next to a key the user already has. It signs
the way the data-browser does (`resource.save()` → `exportLoroDelta` →
commit). That is the "writes happen client-side" path, and it needs no
new identity primitive.

Two deployments, one tool list:

```text
Local (stdio / loopback HTTP)
  key = the user's Agent (env, desktop keychain, OPFS)
  signs commits itself
  MCP spec: stdio does not do OAuth

Remote (Streamable HTTP on the node)
  OAuth 2.1 resource server  (MCP spec 2025-06-18+)
  reads  = existing check_read, as the consented Agent
  writes = issued agent the node holds, scoped at consent
           never the user's root, never Bearer-on-/commit
```

v1 is local, with writes. Remote starts **read-only**. Hosted writes wait
on issued agents landing for plugins (#1307 / the #1275 shape) so MCP does
not invent a third signing identity.

## OAuth: which PR is actually relevant

MCP's HTTP transport is OAuth 2.1 with PKCE. The MCP *server* is a
**resource server** (RFC 9728 protected-resource metadata, `401` +
`WWW-Authenticate: resource_metadata=...`). The **authorization server**
is a separate role. Stdio is exempt.

Two open/closed PRs look similar and are not:

| PR | Role | What MCP needs from it |
| --- | --- | --- |
| **#1310** OIDC/OAuth retarget | Atomic as *relying party* ("Sign in with Google") | Helps a *human* reach the data-browser with nothing to memorize. An MCP client will not complete that browser flow just to get an `atomic_session` cookie. Useful later as *an* AS if the operator's IdP is advertised as the MCP authorization server — optional, not v1. |
| **#1275** (closed) issued agents / "Sign in with Atomic" | Atomic as *authorization server* | This is the load-bearing one. Consent page, app-shaped client, issued Agent, redirect with no secret in the URL. Remote MCP is that product with a standardized token instead of a one-off query string. Reopen the AS slice when remote MCP is scheduled; do not rebuild it inside `/mcp`. |

#1310 D1 still applies verbatim: an OIDC access token is not an Atomic
principal. Token-exchange into a SessionCert or an issued Agent; then
Ed25519 as today. The MCP Bearer is proof *to the MCP handler*, not to
`/commit`.

#1310's "use my OIDC token to call the API from a script → No, by design
(D1); issued app keys, PR #1275 shape" is the same sentence as this plan.

Do not implement a bespoke MCP auth that skips RFC 9728. Cursor and Claude
will not speak it.

## Tool surface

Do not copy `TOOL_NAMES`. Extract the **headless** verbs from
`useAtomicTools.ts` so the assistant, a CLI, and MCP are one implementation.

In MCP:

- **Tools** — `get_atomic_resource`, `query`, `semantic_search`,
  `get_schema`, `get_user_classes`, `describe_table`, `describe_dashboard`,
  `create_resource`, `edit_atomic_resource`, and the table/dashboard
  builders that already go through compact. Same compact JSON-AD as the
  assistant (`toCompact` / `fromCompact`). Short `#xxxxxxxx` refs at the
  tool boundary.
- **Schema tools** (hosted, built) — `find_schema({query, limit?})` and, on
  write connections only, `ensure_ontology({drive, schema, shortname?})`,
  twins of the assistant's tools (`schemaTools.ts`). Both run on the Rust
  JSON Schema import/export (`lib/src/schema/json_schema.rs`, shared fixture
  with `@tomic/lib`). `ensure_ontology` signs every commit as the issued
  agent and sends it through the commit pipeline (`CommitSink` in
  `EnsureTarget`), so rights apply as for `create_resource`.
  `get_user_classes` stays as a deprecated alias of `find_schema` with an empty
  query; `get_schema` stays. The descriptions tell the model to search first,
  reuse classes, put constraints in the schema, and that renaming a shortname
  or changing a type makes a new property.
- **Resources** — `atomic://{subject}` (or the subject URL itself).
  `resources/read` is GET; `resources/list` is a drive/query listing.
  This mapping is almost free and is how clients that prefer resources
  over tools will find data.
- **Not MCP** — `navigate_to_resource`, `change_theme`, anything that
  needs a React `navigate` or a toast. Those stay assistant-only.

[`actions.md`](./actions.md) step 4 (AI-tool / MCP derivation) is the
simple verbs (delete, favorite, …). The data tools above are richer and
already written; extract them first, derive the simple ones from the
registry second.

Wire dialect stays compact, never stored. Phase 4 of
[`json-ad-compact.md`](./json-ad-compact.md) (`format=compact` on the
server) is what lets a *Rust* MCP handler skip reimplementing resolution.
A TypeScript local MCP can ship before that, importing the existing
module. Long-term the graph verbs belong on `AtomicNode`; UI verbs do not.

## Sequencing

1. [x] **Extract headless tools** from `useAtomicTools.ts` (and
   `jsonAdCompact.ts`) so they take a `Store`, not a hook. Assistant keeps
   working; this is the shared library MCP will call. Cheap, unblocks
   everything, and is the
   [`actions.md`](./actions.md) "fifth enumeration" fix even if MCP slips.
2. [x] **Local stdio MCP.** Node script or small binary. Its own key,
   approved in the app (the agent secret still works for scripts). Read +
   write. This is the
   Cursor/Claude Desktop config people actually add. Highest ROI; no AS.
3. [ ] **Server `format=compact`.** json-ad-compact phase 4. Needed before a
   Rust remote handler is worth writing.
4. [x] **Remote Streamable HTTP, read-only.** RFC 9728 metadata, OAuth 2.1
   against Atomic-as-AS (#1275 reopened) *or* the operator IdP if #1310
   has already advertised one. Writes return a clear "use local MCP /
   issued agent not yet" error, not a silent server-side save.
5. [ ] **Remote writes as issued agent.** Same key-on-node pattern as plugin
   unattended runs. Consent scopes: at least drive + read/write. `signer`
   is the issued DID. The user's root never touches the commit.

## Hosted endpoint (step 4, built)

`server/src/mcp/`. No state to store: client ids, authorization codes and
tokens are signed with a key derived from the node key for this purpose
(`Db::derive_node_key`), so nothing here can open a stored secret.

```text
POST /mcp                  401 + WWW-Authenticate: resource_metadata=…
GET  /.well-known/oauth-protected-resource      (RFC 9728) names this node
GET  /.well-known/oauth-authorization-server    (RFC 8414)
POST /oauth/register       dynamic client registration; client_id = signed registration
GET  /oauth/authorize      validates client + redirect_uri, redirects to <app>/app/authorize-mcp
POST /oauth/agent          (signed by the person) a fresh issued agent for this client
     …the app grants that agent `read` on the drives picked, as the person…
POST /oauth/approve        (signed by the person) returns the redirect_url carrying the code
POST /oauth/token          code + PKCE verifier -> access (1 h) + refresh (90 d) tokens
```

- **The issued agent** is an Ed25519 identity derived from the node key, the
  approving person, the client and a nonce. Reads need no private key, so
  nobody holds it; the node can re-derive it if hosted writes (step 5) come,
  without storing a key. The node names its Agent resource after the client,
  so Connected apps shows a name rather than a key.
- **Rights are the ACLs**, as for the local MCP. A token is only "who am I":
  what it can read is what the agent is listed on. Revoking (Connected apps)
  removes the agent from the drives; the token keeps working and sees nothing.
- **Nothing signs as the person.** `/oauth/agent` and `/oauth/approve` are
  ordinary signed requests (version 2, method and body covered). A bearer
  token is accepted on `/mcp` only, never on `/commit` or the WebSocket.
- **Redirects** are exact-match against the registered URIs (https, http on
  localhost, or an app scheme), and an unregistered one is answered, never
  redirected to.
- Known limits: codes are single-use per process (a restart forgets spent
  codes, which are valid for two minutes and PKCE-bound); refresh tokens are
  not rotated server-side; the compact `#ref` form is not in the hosted tool
  list yet (step 3 makes it cheap).

## Allowed and forbidden

Allowed: local MCP that signs as the user; remote MCP that reads under
`check_read`; remote writes as a consented issued agent; compact JSON-AD
on the tool wire; MCP resources keyed by subject; extracting tools from
the assistant so MCP is a projection.

Forbidden: OAuth/OIDC Bearer on `/commit` or WS `AUTH`; the node signing
as the user's root because an MCP tool was called; a second tool list in
Rust that drifts from `useAtomicTools`; extending `tauri-plugin-mcp-bridge`
into a data API; storing compact JSON-AD; stdio OAuth.

## Open questions

- **Dogfood.** Should the in-app assistant call the same MCP server once
  it exists, or keep a direct `Store` path? Direct is faster and works
  offline; MCP-only is one surface. Recommend: keep the extracted library
  as the in-process path; MCP is the out-of-process projection.
- **Scope granularity.** Drive-level read/write is enough for v1 remote.
  Resource-level scopes wait until they have a UI that is not a lie.
- **Where compact lives.** TS module now; `format=compact` on the node
  next; do not twin the resolver. Runtime-boundary C: Rust-authoritative
  for ingest, TS may keep the first MCP binary.
- **Flutter / mobile.** Out of v1. Local MCP is a desktop/CLI concern.

## Consequences for open PRs

- **#1310** (OIDC retarget) — merge-as-is for human login. Do not stretch
  it into MCP auth. If remote MCP later uses the operator IdP as AS, that
  is an adapter on top of D2's advertised issuer, not a change to D1.
- **#1275** (issued agents, closed) — the AS + issued-agent slice is what
  remote MCP writes wait on. Reopen or fold into #1307 rather than
  designing a parallel "MCP user".
- **#1307** (plugin model) — issued-agent-on-the-node is the write
  identity remote MCP should reuse. MCP must not mint a second wrapped-key
  tree.
- **#1259** (OpenAI-compatible inference) — unrelated. Keep BYOK
  browser→provider; an MCP server is not a chat completions proxy.
- **#1258** — superseded by #1259; ignore.
- json-ad-compact phase 3 (`create_table.rows` on `fromCompact`) is
  independent and should land before a table-creating MCP tool is
  advertised as stable.
)
