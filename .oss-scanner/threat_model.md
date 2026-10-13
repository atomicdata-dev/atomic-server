# Threat model for atomic-server

Scope of this document: the self-hostable AtomicServer (`server/`), the core
library it is built on (`lib/`, crate `atomic_lib`), the plugin runtime
(`plugin-runtime/` and `server/src/plugins/`), and the WASM build of the library
(`wasm/`). It is written from the code; file paths below point at where each
claim can be checked.

## What the software is

AtomicServer is a graph database with real-time sync, served over HTTP and
WebSocket. Data is stored as *resources* (property-value maps identified by a
subject URL or `did:ad:` identifier), each backed by a Loro CRDT document.
Every change is a *commit*: a Loro update signed by an *agent* (an Ed25519
keypair, identified as `did:ad:agent:{publicKey}`). Resources live in *drives*,
and rights are granted through a parent hierarchy (`lib/src/hierarchy.rs`).

## Trust boundaries and untrusted input

Everything that arrives over a network, or from a file or URL the operator did
not author, is untrusted. The server has no notion of a trusted network
position: the operator is the only trusted party.

| Entry point | Where | Notes |
| --- | --- | --- |
| HTTP resource requests (GET/content negotiation, `/query`, `/search`, `/export`, `/download/...`, `/blob/{hash}`) | `server/src/routes.rs`, `server/src/handlers/` | Reads must be filtered by the caller's rights. `/search` over-fetches and filters per agent (`handlers/search.rs`). |
| Auth headers / cookies / bearer tokens | `lib/src/authentication.rs`, `server/src/helpers.rs` | Signature over `"{subject} {timestamp}"` (v1) or method and body hash (v2). Timestamps must be fresh. |
| `POST /commit` and `POST` of resources | `handlers/commit.rs`, `handlers/post_resource.rs`, `lib/src/commit.rs` | Commits come from **any** agent, including anonymous callers. Signature, timestamp, subject shape and rights must all be checked before anything is applied. |
| Loro updates inside commits | `lib/src/commit.rs` (`apply_changes`), `lib/src/loro.rs` | Attacker-controlled binary imported into a CRDT doc; parsing, memory growth and materialisation into typed values are all in scope. |
| WebSocket `/ws` (v2 binary protocol) | `handlers/web_sockets.rs`, `handlers/ws_v2.rs`, `lib/src/sync/protocol.rs`, `lib/src/sync/engine.rs` | Frames: AUTH, SUB, COMMIT, SYNC family, EPHEMERAL. Pre-auth and post-auth frame handling, size limits (`SYNC_PUSH_MAX_*`, `EPHEMERAL_MAX_PAYLOAD`, `LIVE_DOC_MAX_PAYLOAD`), AUTH binding to the requested origin. |
| File upload and download | `handlers/upload.rs`, `handlers/download.rs`, `handlers/image.rs`, `blob_storage.rs` | Upload body is capped by `PAYLOAD_MAX` (`serve.rs`). Content-addressed blobs. Uploaded bytes are decoded by the `image` crate for resizing/re-encoding (feature `img`). MIME handling, filenames and SVG/HTML served back to browsers are in scope. |
| Subjects and URLs the server fetches | `lib/src/client/helpers.rs` (`ssrf_guard`) | `fetch_body_untrusted`, used by `/bookmark` and `/import`, blocks private, loopback and link-local targets on the resolved address, including redirects. `ATOMIC_ALLOW_PRIVATE_FETCH=1` disables that guard (operator choice). Signers are never fetched over the network to learn a key (`lib/src/commit.rs`, `check_signature`). |
| Plugins (WASM components and JS drafts) | `server/src/plugins/`, `plugin-runtime/`, `handlers/plugin_*.rs`, `handlers/integration_action.rs` | Plugin code and manifests are untrusted. See below. |
| MCP endpoint and OAuth | `server/src/mcp/`, `/mcp`, `/oauth/*` | OAuth 2.1 with PKCE issues tokens tied to an issued agent; what a token reaches is what ACLs give that agent. |
| Iroh P2P sync | `lib/src/sync/peer.rs`, `POST /iroh-sync`, `handlers/forget_peer.rs` | QUIC peers authenticate with AUTH frames; per-drive admission checks (`may_accept_drive_write`). Pre-auth frames are capped at `IROH_PREAUTH_FRAME_MAX_BYTES`. Peers learn each other through a NodeID (`did:ad:node:...`) shared out of band. |
| Imported JSON-AD / document content | `lib/src/parse.rs`, `/import` | Parser input from clients and from fetched URLs. |
| Command-line flags and env (`ATOMIC_*`) | `server/src/config.rs` | Trusted (operator-controlled). |

### Authentication and authorization model (what to hold the code to)

- A commit is valid only if its signature verifies against the signer's public
  key. For `did:ad:agent:` signers the key is the identifier itself
  (`check_signature` in `lib/src/commit.rs`). Legacy HTTP agent URLs are bound
  to the key in their path, not to whatever a resource at that URL claims.
- Commit timestamps are checked against `ACCEPTABLE_TIME_DIFFERENCE`;
  `AUTH` proofs expire after `AUTH_MAX_AGE_MS`.
- Authorization is by hierarchy: read/write/append rights are resolved up the
  parent chain from the resource to its drive (`check_read`, `check_write`,
  `check_append` in `lib/src/hierarchy.rs`). A commit that changes rights or
  parents is classified (`AuthImpact`) because it can widen access.
- Anonymous requests map to `ForAgent::Public` and may read only what public
  rights allow, with a stricter write rate limit.
- `--public-mode` (`ATOMIC_PUBLIC_MODE`) intentionally makes all data publicly
  readable. Reports that only show behaviour under that flag are not
  vulnerabilities.
- The legacy `set`/`push`/`remove` commit fields are rejected; Loro is the only
  state path.

### Plugins

Plugins are WASM components (`wasm-plugins` feature, wasmtime) or JS drafts run
in a QuickJS-based WASM component (`plugin-runtime/`). The host treats them as
hostile:

- Execution is bounded by fuel and memory limits (`plugins/host_core.rs`,
  `plugins/wasm.rs`), widened only by manifest capabilities
  (`extended-fuel`, `extended-memory`).
- Network access from a plugin is checked on the resolved address and refuses
  loopback, private, link-local, CGNAT, multicast and IPv6 unique-local ranges
  (`plugins/egress.rs`), with a fetch timeout and a response size cap.
- Plugin reads and writes go through host functions that apply the calling
  agent's rights and the plugin's granted resources (`ResourceGrants`).
- Zip packages and manifests are parsed by the server (`zip`, `plugins/manifest.rs`,
  `handlers/plugin_release.rs`) and are untrusted input.

A plugin escaping its sandbox, exceeding its granted resources or capabilities,
reaching internal network ranges, or reading data its caller could not read is
in scope.

## In scope

- `server/` (HTTP, WebSocket, MCP/OAuth, upload/download, image processing,
  plugin hosting, rate limiting, CORS and cookie handling).
- `lib/` (`atomic_lib`): commits and signature validation, Loro import and
  materialisation, parsing, hierarchy and rights, search indexing, sync engine
  and protocol, Iroh transport, the SSRF guard, the storage layer.
- `plugin-runtime/` and `server/src/plugins/`.
- `wasm/` and `cli/` where they handle untrusted data (e.g. signature checks
  and parsing shared with `lib/`).
- The embedded web assets only when a flaw lets one drive's data run script in
  another origin (stored XSS via served content, missing `nosniff`/CSP on
  user-supplied files, and similar).

## Out of scope

- Frontend development tooling and tests: `browser/` build scripts, vite and
  vitest config, `browser/e2e/`, lint/format config, `browser/create-template`.
  (Vulnerabilities in the shipped app that run in a visitor's browser are
  covered above.)
- `planning/`, `docs/` source, `brand/`, `testdata/`, fixtures and the
  `*_test*.rs` / `tests` modules, `plugin-examples/`.
- `flutter/` and `desktop/` shells.
- Operator-controlled configuration: someone who can set flags, env vars or
  edit the data directory already controls the server (including
  `ATOMIC_PUBLIC_MODE` and `ATOMIC_ALLOW_PRIVATE_FETCH`).
- Denial of service that requires a trusted operator action, local filesystem
  access, or a build-time dependency compromise.
- Third-party dependencies, unless the repository calls them in a way that
  makes a vulnerability reachable (then report the call site).
- Anything that lives outside this repository, including separately hosted
  services.

## Severity guidance

Critical:
- Unauthenticated read or write of data the caller has no rights to.
- Cross-drive access: an agent reading or changing resources in a drive it has
  no rights in, or a commit applied to a resource outside the rights it holds.
- Commit signature bypass, signer impersonation (forging a commit as another
  agent, including via legacy agent URLs or DID parsing), or authentication
  bypass (replaying or forging `AUTH`, signature versions, cookies, bearer or
  OAuth tokens beyond their scope).
- Privilege escalation through the rights hierarchy (granting oneself rights,
  re-parenting into a drive).
- Remote code execution on the host, or a plugin sandbox escape.

High:
- SSRF reaching internal ranges despite the guards; plugin egress bypass.
- Stored XSS that executes in the server's origin from uploaded or imported
  content; path traversal in upload, download or plugin packages.
- Memory-safety bugs reachable from the network.
- Leaking secrets (plugin secrets, OAuth material, private keys) to other
  agents.

Medium:
- Information leaks of metadata (existence of private resources, titles in
  search results, history) beyond the caller's rights.
- Unauthenticated denial of service through unbounded memory, CPU or disk
  growth from a single request or frame.

Low:
- Denial of service that needs an authenticated agent with write rights, or
  that stays within that agent's own drive quota.
- Weaknesses that only manifest with non-default, explicitly insecure flags.
- Missing hardening headers without a demonstrated exploit.
