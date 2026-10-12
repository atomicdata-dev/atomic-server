# Changelog

List of changes for this repo, including `atomic-cli`, `atomic-server` and `atomic-lib`.
By far most changes relate to `atomic-server`, so if not specified, assume the changes are relevant only for the server.
**Changes to JS assets (including the front-end and JS libraries) are not shown here**, but in [`/browser/CHANGELOG`](/browser/CHANGELOG.md).
See [STATUS.md](server/STATUS.md) to learn more about which features will remain stable.

## UNRELEASED

- Loro documents: strings that start with `[`, `{`, `atomic:`, `did:ad:` or `http(s)://` are tagged as `string` in the `datatypes` map so they are no longer read back as nested resources or URLs, and JSON `null` is kept inside nested maps and lists.

## [v0.41.0-beta.8] - 2026-10-10

- Discovery (#2198): a drive's pkarr record also lists the public https origins of the servers hosting it (`_atomic_http`), published at boot and every hour, so the app can find a drive's server from the secret alone. New anonymous `GET /genesis?subject=<did>` returns only a drive's genesis certificate, which the app verifies against the drive DID before connecting. Drives minted before genesis certificates existed answer 404 and are not found this way.
- Schemas (#2151): properties get content-addressed subjects, `atomic:prop:{blake3}` of their ontology, shortname and datatype (`docs/src/schema/property-identity.md`). The server verifies the hash on genesis, accepts the same property from two devices, and refuses changes to its `parent`, `shortname` or `datatype`. Existing properties keep their subjects and stay editable.
- Class constraints (#2151): a Class's `constraints` map holds JSON Schema keywords per property (`enum`, `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `minLength`, `maxLength`, `minItems`, `maxItems`, `pattern`, `class`), enforced on commit; peer commits and sync skip it. An empty `allowsOnly` on a Property now restricts nothing.
- Lenses (#2151): `atomic:lens:` resources map one property onto another (`rename`, `wrap`, `head`, `map`, `convert`); the derived values appear in reads and indexes without changing signed data (`docs/src/schema/lenses.md`).
- `atomic-cli schema push | lock | check`: turn a JSON Schema or ontology file into an ontology and a lockfile that pins its property IDs (#2151). `atomic_lib::schema::json_schema` imports JSON Schema and `ensure_ontology` creates the result.
- Forms: field options use JSON Schema keyword names (`minItems`, `maxItems`, `minimum`, `maximum`; the old names are still read) and may only tighten the column's class constraints; `describe_form` returns the form's JSON Schema (#2151).

- `--served-domain-suffix` / `ATOMIC_SERVED_DOMAIN_SUFFIX` takes a comma-separated list (`atomicserver.eu,atomic.place`), so a node can answer under two domains while it moves from one to the other.

- MCP endpoint: `POST /mcp` (Streamable HTTP) is the one implementation of the
  MCP tools, for clients that cannot run a local process, such as claude.ai, and
  for the local `@tomic/mcp`, which now only bridges to it. It is an OAuth 2.1
  resource server (RFC 9728 metadata at `/.well-known/oauth-protected-resource`)
  with the node as authorization server (`/oauth/register`, `/oauth/authorize`,
  `/oauth/token`, PKCE S256, dynamic client registration, `resource` checked).
  The person approves in the app (`/app/authorize-mcp`): which drives, and read
  only or read and edit. Reading is as an issued agent under the normal rights
  checks. If editing was allowed, `edit_resource`, `create_resource` (documents
  take Markdown as `_documentText`) and `delete_resource` exist, and the node
  signs those commits as that issued agent, never as the person. Revoking is
  removing it under Connected apps. `list_drives`, `get_resource`, `search`,
  `query`, `get_user_classes` and `get_schema` are the read tools.
  `--app-url` / `ATOMIC_APP_URL` says where the approval page lives when the app
  is not served by this node.
- The approval page only works with a node the person is already using: a link
  naming another server is refused, and the redirect back to the client must be
  exactly the one registered, so a crafted link cannot grant access to someone
  else's key or run script in the app.

- `atomic-cli connect`: connect the CLI with a key made on this machine,
  approved in the app (`/app/connect-agent`), instead of pasting your agent
  secret. Without a config file, the CLI now points you to it rather than
  asking for the secret.

- Forms (beta): guests can fill in a form without an account, and each answer
  becomes a row in a Table. New default ontology `forms`
  (`lib/defaults/forms.json`: `Form`, `FormPage`, `FormField`, `FormHeading`,
  `FormParagraph`, `FormInfoBox`, `FormCondition`, `FormInviteCode` and their
  properties). New public endpoints: `GET /form/{id}` (the form page),
  `GET /form/{id}/definition`, `GET /form/{id}/challenge` (a self-hosted
  proof-of-work captcha, ALTCHA), `GET /form/{id}/image` and
  `POST /form/{id}/submit`. `{id}` is a short publish slug or the form's
  identifier. Only published forms inside their open/close window answer
  (others get `410`); invite-only forms need a single-use code. Submissions
  are validated against the form's questions and branching conditions
  (answers to hidden questions are dropped), rate-limited per client address,
  and written by the server's agent; a form can only write into, and show
  visitors resources from, its own drive. A class extender adds
  `form-submission-summary` to a Form for readers who may see it.
  `server/build.rs` embeds the `browser/form-app` bundle.
  [#875](https://github.com/ontola/atomic-server/issues/875)
- Collection `/query`: the rights walk no longer full-decodes ancestors (memoize by subject + `get_resource_shallow`). Denied members still do not consume `page_size`, so a readable row after a private streak is returned.
- Commits whose Loro update depends on ops the server does not have are now
  refused ("parked as pending") instead of being accepted without effect; the
  browser resends a self-contained update.
- `/download/files/{hash}` and blob URLs serve the File's stored mimetype.

- A plain `GET /ws` that is not a WebSocket upgrade (a crawler, a pasted URL) now answers 400 instead of 500, so it no longer shows up as an incident in error reporting.
- A commit is also sent to WebSocket subscribers of the resource's parent. A
  resource shared out of a drive the recipient can't read (a chatroom) can only
  be subscribed to on its own, and a new child is a new subject, so its new
  messages reached neither that subscription nor a drive subscription the
  recipient could hold. Read rights are checked per subscriber against the
  resource when it is sent, and a connection already reached through the
  resource or its drive doesn't get it twice.
- End-to-end encrypted conversations. `atomic_lib::conversation` derives an
  agent's X25519 `encryptionKey`, keeps a conversation's keys in a keyring
  wrapped to each member, and seals and opens messages; the WASM build exports
  it. New default ontology `conversations` (`lib/defaults/conversations.json`)
  with the `Conversation` and `SealedMessage` classes. New endpoint
  `/conversations` lists the conversations on the server the requesting agent
  is a member of. See `planning/encrypted-conversations.md`.

- New default ontology `notifications` (`lib/defaults/notifications.json`):
  the `Inbox` and `Notification` classes, and an `inbox` property the private
  drive points to its Inbox with.

- Removed range-based set reconciliation (RBSR, `lib/src/sync/rbsr.rs`). The
  server rebuilt a drive's whole inventory for every `RBSR_FP` round trip, so
  the descent cost more than the one full version-vector `SYNC` it replaced.
  `RBSR_FP` is now answered with `{"drive","unsupported":true}` and no
  fingerprints, which makes an older browser fall back to the full `SYNC`
  immediately. `RBSR_ITEMS` stays as the drive inventory, and a `SYNC` with
  `subjects` is still honoured. The `rbsr` capability is no longer advertised.

- The server raises its own file-descriptor soft limit to its hard limit at
  startup. It already budgeted HTTP connections against the soft limit and kept
  a reserve, but HTTP is not the only tenant of that pool: the database, Iroh's
  QUIC sockets and every open websocket draw on it too, so on a stock soft limit
  of 1024 the process can run out while the HTTP budget still looks healthy.
  Staging did, for twenty-three minutes, with 2,655 `error accepting connection:
  No file descriptors available`, Iroh unable to bind its hairpin probe, and a
  panic at the tail. A process may raise its own soft limit as far as the hard
  limit without privileges, and the connection budget is computed from whatever
  is in force afterwards, so a refused raise is logged and not fatal.

- Publishing a plugin release that is already recorded on the server (the
  same zip, uploaded by someone else) now grants the new publisher read on
  the `Release` and its package File. Before, their Installation could not
  resolve the release and activation failed with a 401.

- Version 2 request signatures (ontola/atomic-plugins#54). A request sent
  with `x-atomic-signature-version: 2` is checked against
  `atomic-request-v2\n{METHOD}\n{full URL}\n{timestamp ms}\n{sha-256 hex of
  the body}` instead of v1's `"{url} {timestamp}"`, so a captured proof can
  no longer be replayed with a different method or body within its five
  minutes. v2 is opt-in: a request without the header is checked as v1
  exactly as before, and a v2 request that fails is refused, never retried as
  v1. `/app-agent` and `/plugin-view-token` accept v2 (they do not require it
  yet); every other endpoint refuses a v2 signature with a 401 that says to
  sign with v1, as do an unknown version and a v2 header without the
  `x-atomic-*` headers. Cookies and WebSocket `AUTH` stay v1. `atomic_lib`
  exports `request_signature_message_v2`, `RequestBinding` and
  `client::get_authentication_headers_v2`; shared test vectors live in
  `lib/src/authentication_v2_vectors.json`.
- Identifiers are now emitted as `atomic:` (`atomic:{genesis}`,
  `atomic:agent:`, `atomic:commit:`, `atomic:blob:`, `atomic:node:`). The
  previous `did:ad:` spelling is accepted forever and names the same
  resource. New genesis certificates still encode the v1 header byte
  (`0x01`) so `GenesisCert` literals in downstream crates keep compiling;
  `GenesisCert::new_v2` canonicalizes parent/drive strings to `atomic:`.
  Decode accepts a `0x02` header. Existing v1 certificates and the
  personal-drive singleton stay v1. Pairing is
  `atomic:node:{id}?v=1&drives=*`; `/resource?subject=` is the HTTP
  endpoint (`/atomic` and `/did` remain aliases). The store canonicalizes
  subjects and identifier-shaped values on write and on query filters.
  Opening a pre-rename database rewrites leftover `did:ad:` keys in every
  subject-keyed tree (resources, snapshots, DID mapping keys and hint
  values, envelopes, tombstones, the outbox), streaming each tree, and
  rebuilds indexes. A v2 certificate that carries a `did:ad:` string is
  refused on decode; a v1 certificate's parent and drive are compared with
  the resource in one spelling. Sync advertises `canonical-scheme` and
  emits `did:ad:` to peers that do not list it on every frame that names a
  subject, over WebSocket and Iroh alike; a client canonicalizes what an
  old server echoes back. The in-memory store keys resources canonically
  (#1584).

- The causality guard no longer refuses a commit whose writes lost an honest
  race. It asked whether the merge kept what the commit sent, which an unseeded
  client and a client that simply lost to a newer peer both answer no, so a
  client with a perfectly good doc was told to refetch and retry, and could only
  resend the same bytes. It now asks what it means to ask: whether the incoming
  update's version vector carries any peer the stored state also has. A doc
  seeded from the server does, however far behind it has fallen, and losing
  last-writer-wins from there is accepted. A doc built from scratch does not,
  and its vanished writes are still refused, as before. The version comes from
  the blob header via `update_range`, so the check costs a parse and not a
  second document build.

- A causality rejection now names the writes it dropped. The error a client
  gets when its Loro update lost every write to LWW reports each mismatching
  property as `sent <x>, stored <y>`, in place of the full list of values sent
  and the bare list of stored keys. Which write lost, and to what, previously
  lived only in the server's own `[causality-guard] rejecting` log line. The
  `Commit's Loro update produced no state changes` prefix that
  `classify_commit_error` and the client outbox match on is unchanged, and so
  is the condition for accepting or rejecting a commit.

- Fix: a stale authentication proof no longer fails a request that needed no
  authentication. A browser keeps its proof in the `atomic_session` cookie, and
  until `AUTH_MAX_AGE_MS` arrived in 0.41 a proof never expired, so a stale one
  is the ordinary state of any tab left open. Every request such a tab made was
  answered 401, public ones included: on staging one tab polling the public
  `GET /server` endpoint produced 4,215 rejections, all carrying the same
  `signed at` timestamp. An HTTP request, and the headers a socket is opened
  with, now treat a proof that has aged out as no proof at all and continue as
  the public agent, leaving the rights check to decide whether that matters for
  what was asked. A signature that does not verify is still refused outright,
  and so is a stale proof in an `AUTH` frame or a peer handshake, where the
  caller asked to be authenticated and is owed the answer
  (`get_agent_from_auth_values_or_public` beside the existing
  `get_agent_from_auth_values_and_check`).

- Sentry no longer records every server error twice. `sentry_actix` captures a
  handler's 5xx with the request attached, and `tracing_actix_web` separately
  logs "Error encountered while processing the incoming HTTP request" at
  `error!`, which the Sentry tracing layer turned into a second event; the two
  staging floods of September arrived as paired issue groups of 6313 and 6312
  events for the same incidents. The tracing layer now ignores the
  `tracing_actix_web` target and delegates every other target to
  `default_event_filter`, so background work reports as before and the stdout
  log line is unchanged (`server/src/trace.rs`).

- Plugin install path, three fixes after the runtime convergence (#1571):
  - A publish refused for claiming the wrong `world` used to have already
    stored the package bytes and cached the release record. The claim is now
    checked before the first write, so a refusal leaves nothing behind
    (`POST /plugin-release-package`).
  - A JS plugin whose Installation could not be read, or whose `grants` could
    not be, ran with everything its own manifest declared. Only a legacy draft
    with no Installation still reads the manifest; anything else grants nothing
    and logs why. Reading which classes a resource has also went through
    `Value::to_subjects`, which errors on the scalar `isA` encodings, so an
    encoding alone could widen a plugin's grants. `Resource::class_subjects`
    and `Resource::has_class` are the one encoding-tolerant reader, shared
    with `ClassExtender`.
  - An Installation's `release` is declared an `atomicURL` and now holds one.
    The browser's two zip paths dropped the `Release` subject the publish
    response carries and stored the bare `blake3:` id, which meant writing the
    property with datatype validation switched off. `release::resolve` still
    accepts a bare id, for Installations written before this.
- `atomic_lib`: a signed destroy commit now removes the resource (and its
  cascade-deleted children, Loro snapshot, index and search rows) in the same
  redb transaction that stores its envelope and commit row. `Db::apply_commit`
  used to call `remove_resource`, which applied a transaction of its own, so a
  crash between the two left a deleted resource with no signed destroy for
  `SYNC_DIFF.removeCommits` to carry; tombstones are now recorded once that
  single transaction has landed. The destroy branch also returns an error on a
  malformed commit instead of panicking the request.
- Security hygiene, from the September 2026 audit (`planning/security-audit-2026-09.md`
  D, C16, F):
  - CORS: any origin may still read (Atomic is a headless CMS), but
    `Access-Control-Allow-Credentials` is now sent only to origins this
    server answers for — the configured domain, a subdomain of the base
    domain, loopback, and the desktop webview origins (`tauri://localhost`,
    `http://tauri.localhost`) — by the same rule `RequestContext` uses for
    trusting `Host`. Before, every origin was told it could attach the
    session cookie; `SameSite=Lax` was the only thing stopping it
    (`server/src/cors.rs`).
  - Client errors are answered as client errors instead of 500: a request
    body that does not parse is 400 (`AtomicErrorType::ParseError` maps to
    `BadRequest`; malformed commits are parse errors), a signature that does
    not verify, an unknown signer, or authentication headers that do not
    parse are 401 (`Commit::validate_signature` and
    `get_agent_from_auth_values_and_check` type every failure as
    unauthorized, and `get_client_agent` no longer flattens the type into a
    string). These no longer reach Sentry as crashes.
  - `/upload` returns 400 when the multipart body cannot be read (no
    boundary, truncated part) instead of ending its loop quietly and
    answering 200 for the files that made it through.
  - `atomic_lib`: the "importing from a peer" flag and the import source are
    a tokio task-local scope (`sync::ws_apply::import_scope`) instead of
    process-wide statics, so two peer connections importing at once no
    longer clear each other's flag or stamp each other's peer id on their
    writes (audit C16). The live push loop no longer consults a global mute;
    it skips the one peer a change came from, via the `source_id` the scope
    stamps on the `DbEvent`, which now also covers `COMMIT` frames applied
    for a live peer. `CommitIngestOpts::suppress_live_echo` is gone: a peer
    commit is attributed to the connection's import scope instead.
    `sync::peer::is_importing()` is now per task; a listener on another
    task should read the event's `source_id` (the Flutter binding does).
  - `collections::sort_resources` is a total order (missing values last in
    both directions, numbers compared numerically with `NaN` in a fixed
    place, numbers before strings), so a collection sorted through the
    `sort_by` query parameter can no longer panic `sort_by` on Rust 1.81+.
  - `sync::peer`: the live peer map recovers from a poisoned lock instead of
    unwrapping it, so one panic no longer stops live broadcast for the rest
    of the process.
- `atomic_lib`: `DbEvent::Destroyed` for a cascade-deleted child is sent only
  after the removal has been applied. `Db::recursive_remove` announced each
  child while it was still queueing the deletes into a transaction the caller
  had yet to apply, so a listener (`atomic-server`'s `CommitMonitor`, which
  fans removals out to WebSocket subscribers; a peer transport) heard of a
  deletion that could still fail or roll back, and heard of the children
  before their parent. The callers (`remove_resource`, the destroy branch of
  `apply_commit`) now announce every removed subject once the transaction has
  landed; the destroyed subject itself is still announced exactly once, wrapped
  in its signed destroy commit. `remove_resource` now also announces the
  subject it was called for, which it never did. Follow-up to #1544.

- `classify_commit_error` classifies "Commits cannot be edited." (a write whose
  subject is itself a Commit) as the new `IMMUTABLE_COMMIT` (10) error code, on
  the WS `ERROR` frame and the HTTP `/commit` error body's `errorCode` alike.
  It was going out as `UNKNOWN`, leaving clients to match the message text to
  know the refusal is terminal. The Rust outbox drops such entries as terminal.
- Query index: a drive-scoped, sorted, class-filtered collection could list
  and count fewer rows than the store held, with nothing to show for it
  (`planning/silent-failures.md`). Rows whose `isA` read back as a plain
  `String` were in the index and then hidden, because the built-in
  collection class extender could not parse the value and
  `Db::resolve_query_member` dropped any row an extender check errored on;
  an extender that cannot decide is now skipped with a warning and the row
  is listed. Rows whose `isA` was a `String` holding the JSON array were
  never indexed under their class and never matched it; the index keys and
  the matcher now read the array's elements from one helper
  (`Value::to_reference_index_strings`, `Value::contains_value`). New
  `Db::check_query_index(&Query)` compares a query's member index with a
  scan of the store and reports the missing and stale subjects; the first
  build of a filter cross-checks the equality constraints the planner did
  not scan (bounded by its 512-entry scan cap), warns with the filter and
  the subjects, and files them. DID resources stamped into another drive no
  longer enter a drive's watched query on commit or build: the `Db` resolves
  each watched filter's `drive` subject to its drive root and compares
  stamps (security audit C17; the filter's identity is unchanged).
- Startup store-size diagnostics and automatic redb compaction. Opening the
  store now logs the file's size and open duration (a warning above 1 GiB,
  naming `atomic-server compact`) and, from redb's `DatabaseStats`, how much
  of the file is live, fragmented and reclaimable (bytes on disk minus pages
  in use; redb's sparse growth headroom does not count). When the file is at
  least 256 MiB on disk and at least 30% of that is dead, `Db::init_redb_file`
  compacts it before the server listens and logs the before/after sizes and
  duration; the outcome is kept in the store and readable through
  `Db::last_compaction`. A compaction failure is a warning, never a refused
  start. New options `--auto-compact` (`ATOMIC_AUTO_COMPACT`, default
  `true`), `--auto-compact-min-mb` (`ATOMIC_AUTO_COMPACT_MIN_MB`, `256`) and
  `--auto-compact-min-reclaimable-percent`
  (`ATOMIC_AUTO_COMPACT_MIN_RECLAIMABLE_PERCENT`, `30`); `atomic_lib` callers
  pass a `db::compaction::CompactionPolicy` to
  `Db::init_redb_file_with_policy`. Not applied to the OPFS (browser) or sled
  backends. See `planning/disk-storage-and-persistence-optimization.md`.

- CI: the `:develop` docker image is published by its own job instead of a
  step tacked onto the end of the CI job. As a step it inherited whatever the
  CI step had already spent (a wedged Dagger engine on the runner burned the
  ten minute connect timeout and the publish was skipped without trying), and
  it could not be re-run on its own, so recovering a missed image meant
  re-running a pipeline that takes hours. `develop` went 2026-09-15 to
  2026-09-18 without an image that way. The gate is unchanged: `needs: ci`,
  so a red pipeline still publishes nothing. A new manual
  "Publish :develop image" workflow covers the case where the pipeline cannot
  go green for reasons unrelated to whether the binary builds; it refuses
  `latest` and `v*` tags, which release.yml owns.

- Error-handling hygiene on the commit and read paths. The legacy
  `set`/`push`/`remove` rejection in `sync::engine::ingest_commit` now checks
  the parsed commit's properties instead of substring-matching the raw body,
  so a commit whose subject is one of those Property resources (or whose
  values quote their URLs) is no longer refused. `Db::get_resource` warns
  (with the subject and error) when a stored Loro snapshot cannot be read or
  applied instead of silently serving the stale propvals. The sled
  `Db::init` wraps a migration failure in its error message (`.map_err`, not
  `.map`). `AppState::init` drops its own core-models bootstrap branch: its
  "store did not exist" check ran after the store directory had been
  created, and `Db::init_redb_file` already seeds a fresh store on open.

- `atomic_lib`: host-to-Drive mappings are reconcilable, so a control plane can
  install hosted vanity subdomains without an agent that can sign on the
  Drive's behalf. `Db::sync_drive_mappings` adds, repoints and removes a
  desired set idempotently and scopes removal to the hosts it installed
  itself (so `/bind-drive` bindings and the `localhost` entries from setup
  survive); `Db::list_drive_mappings` and `Db::managed_alias_hosts` read the
  table, which had no read path beyond a single-host lookup. Mapping keys are
  now normalized, so a mixed-case `Host` header resolves the Drive it was
  bound to instead of falling through to the store root.
- A host bound to a Drive now serves that Drive or answers 404. It used to
  fall through to the store root when the bound Drive was missing — not synced
  yet, or moved to another node — which on a multi-tenant server answers one
  tenant's hostname with another namespace's content.
- New `--served-domain-suffix` / `ATOMIC_SERVED_DOMAIN_SUFFIX`: answer for
  `*.<suffix>` so the request origin follows the hostname the visitor used,
  without `--base-domain`'s other effect of also becoming the store's base
  domain (which changes how subjects are normalized and migrated, and is not
  something to switch on for a server that already holds data).

- The `/version` and `/all-versions` endpoints are removed. Resource history
  is read from the Loro oplog on the client now (`resource.getLoroHistory()`,
  with signers from `/history-attribution`), which is what the History route
  has used for a while; these endpoints were the older server-side path to the
  same data, reachable only from a single "All versions" link. `atomic_lib`
  loses `history::encode_version_id` and `history::decode_version_id` with
  them -- they existed to carry an opaque `VersionID` through an HTTP query
  parameter. `history::versions`, `history::at_version`,
  `Resource::get_history` and `Resource::view_at` are unaffected.
- The outbox drains over a live Iroh link too (`sync::peer::LivePeerCommitTransport`):
  a device with no hub in reach delivers its queued writes to a paired peer as
  signed `COMMIT` frames, which the peer validates and applies like a hub
  would, and a freshly registered live link drains on connect. The Flutter
  binding falls back to it when no WebSocket session is open. This is the
  sending half of serverless sync (`planning/serverless-p2p.md` P4).
- `atomic_lib` has a durable outbox (`sync::outbox`, `Tree::Outbox`): local
  commits mark their subject dirty per signing agent, a drain exports the
  Loro delta since the version the hub holds, signs one commit per subject
  in parent-before-child order and sends it as a `COMMIT` frame over any
  `CommitTransport` (the WebSocket client implements it). Refusals back off
  exponentially, park the entry after repeated authorization failures, and
  drop it only when the hub says it can never apply. The Flutter binding
  records every local save in it and drains on save and on session open, so
  an edit made offline on Android now survives an app kill and reaches the
  hub on the next connection (`planning/unified-sync.md`, Outbox
  modernization item 6).
- Desktop: the app window now runs under a Content Security Policy
  (`desktop/tauri.conf.json`; security audit B7). Scripts only from the
  bundle plus WebAssembly, connections to the embedded and remote servers
  over HTTP and WebSocket, Google Fonts, no plugins or objects. Tauri hashes
  the bundle's inline scripts itself, so `dangerousDisableAssetCspModification`
  is off. A script injected through synced content can no longer reach the
  IPC surface.
- CI: a `v*` tag now publishes `@tomic/*` to npm through Trusted Publishing
  (`release.yml` `npm` job). Tags only published crates.io and GitHub assets
  before, which is why npm `latest` stayed on 0.40.0 and `beta` on
  0.41.0-beta.0 through v0.41.0-beta.7. Pre-releases get the `beta` (or
  `rc`, …) dist-tag, not `latest`; `@tomic/plugin` and `@tomic/edit-mode`
  are marked public for their first publication.
- Signed history now replicates. `SYNC_PUSH` carries the retained envelopes
  of the subjects it pushes (flag `0x02 ENVELOPES`, a trailer old decoders
  never read) over WebSocket, Iroh and browser peer links, and Cloud Vault
  packs carry them per entry. Receivers verify each envelope's signature and
  subject before keeping it, honouring their own `--envelope-retention`. A
  restored or newly invited device therefore shows who signed each change
  instead of "Unattributed" (`planning/auditability-loro-history.md`).
- Security: `POST /commit` charged the per-agent write budget to the signer
  the body *named* before verifying the signature, so anyone who knew an
  agent's public DID could flood the endpoint with forged commits naming that
  agent and lock them out of writing with `429`s. The signature is now
  verified first and the budget is charged to the signer it proves; a body
  that proves no signer spends the peer address's anonymous budget, like any
  other unsigned write. GHSA-f9rw-g3gr-3jw5, reported by
  [hackchang](https://github.com/hackchang).
- Rate-limit the write endpoints. `POST /commit` (HTTP and the WebSocket
  `COMMIT` frame), `/upload`, `PUT /blob`, `/iroh-sync`, `/forget-peer` and
  resource posts spend a per-agent token (`--write-rate-limit`, default 6000
  per minute, `ATOMIC_WRITE_RATE_LIMIT`); requests without a signed agent
  share a per-peer-address budget (`--anonymous-write-rate-limit`, default
  60 per minute). Over budget answers `429 Too Many Requests` with a
  `Retry-After`; `0` disables either limit.
- Fix: writes made through a directly opened file store (the Flutter/Android
  binding) were never made durable. Every redb commit skips the fsync and
  relies on a periodic flush that only the server, desktop and WASM hosts
  ran, so on Android an app kill rolled back every edit since the last drive
  switch. `Db::init_redb_file` now owns the 100ms durable-flush tick for every
  binding, and an idle tick no longer writes anything.
- Fix remaining `clippy` warnings in `wasm/src/lib.rs` blocking `develop`'s pre-commit hook ([#1508](https://github.com/ontola/atomic-server/issues/1508)).

## [v0.41.0-beta.7] - 2026-09-12

- Store hosted files in S3 without silently falling back to node-local storage.
- Fix stale collection queries bringing deleted sidebar resources back.
- Improve browser database durability and resource save-state handling.
- Isolate E2E shard state and simplify local test tooling; full develop CI passes on the release base.

- Add drive-scoped authenticated browser peer sessions; subscription-independent signaling and optional temporary TURN credentials are provided by the managed signaling service ([#1396](https://github.com/ontola/atomic-server/issues/1396)).

## [v0.41.0-beta.6] - 2026-09-09

- Desktop restore discovers reachable workspace sources and supports an explicit server address when automatic discovery does not find one.

- **Security audit fixes** (`planning/security-audit-2026-09.md`, #1384).
  `POST /iroh-sync` requires a signed agent with write on the drive and only
  answers POST; `SYNC_PUSH` entries are checked against the admitted drive;
  `https://host/agents/{key}` subjects bind the path key to the signing key
  and are never fetched from other hosts; a genesis can no longer append to
  a parent through its own `write` array, squat another agent's
  `did:ad:agent:` resource, or reserve top-level server paths; the request
  origin used for token binding honours `Host`/`X-Forwarded-*` only for the
  configured domain, its tenants and loopback; Iroh `AUTH` proofs name the
  responder node (`drive#nodeId`, unbound proofs accepted only from paired
  peers); `/forget-peer` needs write on a drive the peer was paired for;
  path-only auth signatures are refused; plugin zips and bookmark bodies go
  through the SSRF guard with size caps; blob responses are hash-checked;
  ephemeral relays require a subscriber; ACME errors instead of panicking
  and certificates are renewed daily on disk (restart to serve); the
  desktop and Android builds bind `127.0.0.1`; `config.toml` is written
  0600; wasmtime 47. API change: `/plugin-list` and the plugin UI files are
  read as the calling agent, so clients must sign that request (the
  data-browser does) or carry the session cookie.
- Fix: live collaboration stopped for the author of a document after a peer
  edited it. The server stamps `lastCommit` under its own Loro peer after
  applying a commit; the fan-out only forwarded the author's own bytes and
  never echoed to the author, so an edit built on the stored snapshot could
  not apply there. The `UPDATE` now carries everything the apply added and
  reaches the author too (`CommitResponse::fanout_delta`).
- Commits are signed envelopes, not a queryable event log. Ordinary content
  commits are not stored as resources after apply (genesis and
  rights/parent/destroy stay). Loro binaries are not KV-index keys. The
  `/commits` collection is not created. UI reads author/dates from the
  resource, not by fetching `did:ad:commit:` rows. A creation commit is
  retained whether or not the client flagged `isGenesis`. Clients no longer chain
  `previousCommit`; apply no longer has a previous-commit validation gate.
  History no longer offers a "Show Commit" link at a discarded envelope.
- **Signed envelopes live on the resource (`Tree::Envelopes`).** Every
  signed commit's JSON-AD is kept per resource, keyed by createdAt and
  signature, in the same transaction as the state it signs. Not a
  resource, not indexed. `--envelope-retention` / `ATOMIC_ENVELOPE_RETENTION`
  is `latest` (the envelope that produced the current state; default) or
  `all` (every envelope: a signed audit log). `GET /history-attribution?subject=`
  (read-gated) answers who signed which Loro change, verified with the
  apply code, plus whether every change is covered. Rust builder commits
  and `create_did` now tag their Loro change like the browser does, so
  History maps versions to signers. The destroy envelope on the tombstone
  (added for `SYNC_DIFF.removeCommits`) is now the subject's latest row
  in this tree. Envelopes do not yet travel in bulk sync or the vault.

- **Missing-drive bootstrap is no longer a free pass (OQ5).** A
  `SYNC_PUSH` or live write for a drive this node has never stored goes
  through `admit_unknown_drive`: `Public` never creates one (even on
  `OpenPolicy`); Owner mode enrolls only the owner; an authenticated
  first-sync on an open node still works. AUTH-before-`SYNC_PUSH` already
  closed the unauthenticated wire; this closes the library path.
- **`SUB` / `UNSUB` are engine-owned.** Parse and `check_read` live in
  `handle_frame_full`; the WebSocket handler registers the connection
  with the commit monitor only when the engine admits the subscription.
  The `0x20` / `0x21` wire is unchanged (anonymous `SUB` on a public
  share link still works).
- **One subscription actor.** `LoroSyncBroadcaster` is gone; Loro
  ephemera and drive presence fan out from `CommitMonitor` (one mailbox,
  one `UnsubscribeAll` on socket close). Wire and behaviour unchanged.
- **Bulk `SYNC_DIFF.remove` can carry a signed destroy.** When the sender
  still holds the destroy commit on the tombstone, `removeCommits` maps
  that subject to the JSON-AD envelope and the receiver applies it as a
  peer `COMMIT`. A bad signature does not fall back to the unsigned
  tombstone path. Senders without the envelope still send a subject-only
  `remove[]` entry (admission-gated). The envelope is only handed to a
  session that may read the drive; a signed destroy that is already
  stored here, or that predates the current resource's genesis, is
  refused as a replay. The browser applies the envelope as a local-cache
  write and removes the resource either way. Requiring an envelope on
  every delete still waits on `Tree::Envelopes`.
- **`AtomicTransport` / `SyncSession` first slice.** The engine loop is
  callable over any byte-pipe (`lib/src/sync/transport.rs`,
  `SyncSession::serve`). Iroh and WebSocket still have their own
  lifecycles; the outbox port and FRB `open_sync_session` are not this
  change.


## [v0.41.0-beta.5] - 2026-09-04

- **Local full-text search** in `atomic_lib` (`lib/src/search/`): a KV inverted
  index on the existing redb / sled / BTreeMap (OPFS) store. Indexes title,
  description, and Loro document body on every commit; queries AND tokens,
  rank with BM25, and match 1-edit prefix-fuzzy (`avacado` finds `avocado`).
  Exact `property:"value"` filters reuse the PropValSub index (empty `q` +
  `isA` is the file picker); there is no query language and no key escaping.
  `Db` / `AtomicNode` / WASM `ClientDb.search` expose it. Hosted `/search`
  is the same engine — Tantivy is removed.
  The browser uses this index (MiniSearch is gone) and merges with `/search`
  when online. Scale benches:
  `cargo bench -p atomic_lib --bench search_bench --features db-redb`.
  See `planning/local-search.md`.
- **Live collaboration is one binary frame on both transports.** Edits in
  progress, cursors and drive presence cross the WebSocket as
  `EPHEMERAL (0x40)`, the frame the Iroh link already used, in both
  directions; the text frames `LORO_SYNC_UPDATE`, `LORO_EPHEMERAL_UPDATE`
  and `PRESENCE_UPDATE` (base64 in JSON) are removed, the four subscribe /
  unsubscribe text frames stay. The server ignores the agent a client puts
  in the frame and stamps the connection's authenticated identity on every
  copy it fans out. Between nodes the payload is now the raw bytes rather
  than their base64 text, so cursors from a pre-2026-09-04 peer do not
  decode on this build (and vice versa); nothing persistent is affected.
  `WsClient::send_loro_sync_update` / `send_loro_ephemeral_update` /
  `send_presence_update` send the binary frame. Capability `ephemeral`.

- **Drive sync is one binary frame on both transports.** The browser's
  hash-first probe and its reduced reconcile now arrive as `SYNC (0x30)`
  with `"probe": true` or `"subjects": [...]` in the JSON tail
  (`encode_sync_probe`, `encode_sync_filtered`), handled by the shared sync
  engine; a stale probe is answered with the new `SYNC_RESEND (0x38)`.
  The text `SYNC_VV` request, its text `SYNC_RESEND <drive>` answer and the
  server handler's private copy of the reconcile are removed. Capability
  `sync-probe`. `WsClient` reports `WsMessage::SyncResend`.

- **One WebSocket subscription frame.** `SUB <subject>` registers a
  drive-wide subscription when the subject is a drive and a per-resource one
  otherwise; the per-resource text frame `SUBSCRIBE <subject>` (which also
  registered a spurious drive fan-out entry that delivered URL subjects'
  commits twice) and the filter subscription `SUBSCRIBE_QUERY` (sent by
  nothing outside the Rust integration tests) are removed, along with the
  commit monitor's third subscription map, the `MembershipNotification`
  fan-out and `WsClient::subscribe_query`. `WsClient::subscribe_resource`
  sends `SUB`. The lib's watched-query index (`QueryFilter::watch`,
  `DbEvent::QueryMembershipChanged`) is unchanged; the Flutter event stream
  still consumes it.

- **`atomic_lib::runtime::AtomicNode` is cut down to what binds to it.** The
  WASM `ClientDb` is the only adapter on the node and uses `from_db`, `db`,
  `query` and `apply_commit`; those, plus the agent accessors and
  `IngestPolicy::{Hub, Peer, LocalCache}`, are what remains. `open` /
  `NodeConfig` / `NodeStorage`, `get`, `mutate` / `ResourceEdit`, `subscribe`
  and `sync_with_peer` are removed (each was one line over `Db`, with no
  consumer three days after landing). The seam stays and grows again from
  what the next binding actually calls (`planning/atomic-lib-runtime.md`).

- **Sync stack cleanup.** No wire changes. `WsMessage` lost its `Commit` and
  `Resource` variants and the client no longer parses the pre-v2 `COMMIT `,
  `RESOURCE `, `AUTHENTICATED` and `ERROR ` text frames (nothing has sent
  them since the binary protocol); `IngestPolicy::Replica` went with them.
  `CommitIngestOpts::hub` / `::peer` are the two validation presets that were
  copied in three places; `ws_apply::apply_destroy_checked` (a byte-identical
  twin of `apply_destroy`) is merged into it; the server's three copies of
  "encode an `UPDATE`/`DESTROY` for a change" are one `encode_change_frame`.
  Iroh: the dead `sync_drive_with_peer` wrapper and the private `_forced`
  indirection are gone, the live-peer registry is a `LazyLock<Mutex<HashMap>>`
  holding the pinned QUIC connection alongside the stream (a peer registered
  before the registry was initialised used to be dropped silently), and the
  sync-event debounce map is pruned instead of growing for the life of the
  process. Test-only helpers `engine::drive_items` / `drive_sync_hash` and
  `OwnerPolicy::{owner_agent, hosted_drive_subjects}` are removed.

- **Sync protocol follow-ups** (see `docs/src/websockets.md`, "Changed in
  2026-09"):
  - Challenge-bound `AUTH` over WebSocket: the server's first frame is
    `CHALLENGE (0x42)` with a per-connection nonce; a client signs
    `requestedSubject = "{origin}#{nonce}"` and the proof is good on that
    socket only, so a captured frame can no longer be replayed elsewhere
    inside the five-minute window. Nonce-less proofs are still accepted
    (`engine::AuthChallenge::Issued`); `AuthChallenge::Required` is the
    strict mode, not yet wired to an option. Capability `auth-nonce`.
  - The WebSocket handler reads a client `HELLO` (capability `client-hello`)
    and answers `COMMIT` with a slim `COMMIT_OK` of `[request_id] [commit_id]`
    for a client that listed `commit-ok-slim` (the browser and the Rust
    `WsClient` both do). `protocol::decode_commit_ok` reads both forms.
  - Subscriptions follow the connection's identity: when an `AUTH` changes
    it, the commit monitor re-runs `check_read` for every subject, drive and
    filter subscription the connection holds and drops the unreadable ones
    (`RebindAgent`, capability `rebind-on-auth`). Until now a `SUB` accepted
    as the owner kept delivering after the socket re-authenticated as a
    stranger.
  - `WsMessage::Error` is a struct (`request_id`, `code`, `message`);
    `WsClient::post_commit` settles only on its own `request_id` and returns
    the commit id, so several commits can be in flight on one connection.
    Unknown text frames surface as `WsMessage::Unrecognized` instead of an
    error. `WsClient` sends a `HELLO` on connect and answers the server's
    challenge automatically (`WsClient::auth_subject`).
  - New error code `INVALID_SIGNATURE (9)` for a `COMMIT` whose signature
    does not verify; it went out as `UNKNOWN` before.
  - Iroh: `LIVE_CONNECTIONS` is keyed by peer and pruned when the peer is
    removed. It was an append-only list that pinned every QUIC connection
    ever dialed for the life of the process.
  - `ws_apply::apply_commit_json` (the replica applier that skips rights
    checks, audit finding F6) is gone: its only route was the pre-v2 `COMMIT`
    text frame, which no server sends. The server's rights-checked
    `handlers::commit::apply_commit_json` is the only function of that name.
  - New integration tests: `ws_errors` (ERROR format, `request_id` echo and
    codes), the nonce, the identity re-bind, and the slim ack.

- **Sync protocol hardening** (WebSocket and Iroh; wire reference rewritten in
  `docs/src/websockets.md`, see its "Changed in 2026-09" section):
  - `AUTH` proofs expire: a signed authentication older than five minutes
    (`atomic_lib::authentication::AUTH_MAX_AGE_MS`) is refused, on WebSocket,
    Iroh and the HTTP auth headers alike. Until now only future-dated
    timestamps were rejected, so a captured proof never expired.
  - Over WebSocket, `AUTH.requestedSubject` must name the server: either the
    origin the socket was opened on or the configured server URL
    (`AuthBinding::Origins`, the same tolerance the HTTP auth headers have); a
    proof signed for another server, or for the agent's own subject, no
    longer opens a session. A refused `AUTH` answers
    with the new error code `AUTH_FAILED (8)`. The Rust `WsClient` now signs
    the server origin (it signed the agent subject before). The Iroh
    initiator only accepts an auth-back signed for its own node id.
  - The hash-first `SYNC_VV` probe and the `RBSR_FP` / `RBSR_ITEMS` frames
    are gated by `check_read` per subject, like the full `SYNC_VV` exchange.
    Previously any socket could enumerate every subject and version vector of
    any drive it could name.
  - On the Iroh live link, destroys travel as the signed destroy `COMMIT`
    (`DbEvent::Destroyed` now carries `commit_json`); a naked `DESTROY` frame
    from a peer is ignored instead of applied on the connection's drive-level
    write verdict.
  - Capability advertisement: `AUTH_OK` carries a JSON array of capability
    names (`atomic_lib::sync::protocol::CAPABILITIES`), `HELLO` carries the
    same list after the device name. Both are optional trailing bytes.
  - `UNSUB (0x21)` now actually cancels a drive subscription (it previously
    edited a set nothing read). `KEEPALIVE (0x41)` is echoed over WebSocket so
    browsers can detect a dead socket.
  - Shared golden wire vectors (`lib/src/sync/protocol_vectors.json`, mirrored
    at `browser/lib/src/protocol_vectors.json`) pin the Rust and TypeScript
    codecs byte-for-byte.
  - Integration tests bind the test server to `127.0.0.1` and fall back to an
    OS-assigned port when `portpicker` finds none (hosts without IPv6).
- Tauri Android: ship `arm64-v8a` only. The sideloadable universal APK was ~369 MB because it bundled four copies of `libatomic_server_tauri.so` (armeabi-v7a / x86 / x86_64 as well). Phones and tablets we install on are arm64; override with `cargo tauri android build --target …` for an Intel emulator.
- CI: tag releases publish `@tomic/*` to npm. They previously only published
  crates.io and GitHub assets, which is why npm `latest` stayed on 0.40.0 and
  `beta` on 0.41.0-beta.0 through v0.41.0-beta.4. Pre-releases use the `beta`
  (or `rc`, …) dist-tag, not `latest`.

- Docs / planning: Atomic as an MCP server — local stdio signs writes as the
  user's Agent; remote Streamable HTTP is read-only until issued-agent
  writes. OAuth Bearer never hits `/commit`. See
  [`planning/mcp-endpoint.md`](planning/mcp-endpoint.md).

## [v0.41.0-beta.4] - 2026-09-03

- Fix: with `ATOMIC_HOME_DRIVE` set, `GET /server` answered 500 for plain JSON and JSON-LD (`Accept: application/json`): the `homeDrive` property the endpoint sets was never defined in the default store, so rendering tried to fetch it from atomicdata.dev. JSON-AD (what the data-browser asks for) was unaffected. The property is now part of the defaults.

## [v0.41.0-beta.3] - 2026-09-01

- Git / CI: one integration branch (`develop`) plus stable `v*` tags. Staging
  follows `develop`; production and live docs follow a tagged release. `master`
  is no longer a deploy or docs trigger, and `main` is not introduced as a
  copy of the latest tag.
- Fix: Atomic Canvas no longer returns to the gallery when the screen rotates.
  Android was treating the rotation as a back press.
- Fix: built-in defaults (`lib/defaults/*.json` + base models) now reach
  existing stores. The store records a fingerprint of the embedded defaults;
  every open (server and browser/OPFS) re-seeds add-only when the fingerprint
  changed, so a Property or Class added in a new release no longer 404s against
  a store seeded by an older one. Existing values, including user edits to
  default resources, are never overwritten. `--repopulate-defaults` remains as
  a forced re-run with the same add-only semantics.
- `atomic_lib`: `atomic_lib::runtime::AtomicNode` — a named node surface over
  `Db` (`open`, `get`, `query`, `apply_commit(json, IngestPolicy)`, `mutate`,
  `subscribe`, `sync_with_peer`). Thin delegation, no behaviour change; the
  WASM `ClientDb` is the first adapter on it. `IngestPolicy::{Hub, Peer,
  Replica, LocalCache}` names the four commit-validation profiles.
  `sync::engine::ingest_commit` returns the `CommitResponse` that
  `ingest_commit_json` serializes; `sync::ws_apply::apply_commit_json` now
  returns the `CommitResponse` instead of `()`. See
  `planning/runtime-boundary-decision.md`.

## [v0.41.0-beta.2] - 2026-08-01

**This is the local-first release.** Atomic Data no longer needs a server to exist.

It is also the first release with new features since **v0.40.0 in October 2024** — v0.40.2 and v0.40.3 were security-only patches. That is 1,222 commits and ~334,000 lines. The highlights below cover the whole 0.41 line; per-release detail continues in the v0.41.0-beta.1 and v0.41.0-beta.0 sections of [the changelog](https://github.com/atomicdata-dev/atomic-server/blob/develop/CHANGELOG.md), and everything front-end is in [the browser changelog](https://github.com/atomicdata-dev/atomic-server/blob/develop/browser/CHANGELOG.md).

### Highlights

**Your data works without us.** Create a drive, write to it, and read it back with no server in reach. Every write is a signed CRDT commit against a local database, so the app is fully usable offline and syncs when it can. This is not a cache in front of a server — the browser runs the same Rust storage and query engine through WASM, which is why an offline table computes the same totals as an online one.

**`did:ad` — identifiers that don't belong to a hostname.** Resources are addressed by a decentralized identifier rather than a URL on someone's domain, and resolved peer-to-peer over the Mainline DHT. No DNS, no certificate authority, no hosting company in the trust path. Combined with self-verifying genesis certificates, a resource proves who created it on its own terms. Your agent is now just a private key: no account on any server, nothing to be locked out of.

**Peers, not clients.** A sync protocol (#1178) and Iroh/Mainline peer sync let two devices converge directly. Pair a phone by scanning a QR code, mount a drive, and edits flow between them. A server, when you use one, is now described as just another device you sync with — it is a convenience, not the source of truth.

**Live everything.** Live queries (#1174) mean a collection updates as the data does, rather than when you reload. On top of that sits a full presence layer (#1229): see who else is here as avatars, follow someone through the app, watch "typing…" appear in chats and comments, and see live cursors while co-editing a document. Presence rides a drive-scoped ephemeral relay, so it never touches your stored data.

**A new document editor.** A ground-up rich text editor backed by a Loro CRDT, so two people can edit the same document at once without a lock or a merge conflict — with slash commands, resource mentions, tables, math and a collaborative canvas alongside it. And peer-to-peer **video and audio calls** in the meeting panel, where media never passes through a server at all.

**Tables became apps.** A **Kanban board** (#1198) with drag-and-drop and custom card ordering, plus **calendar** and **timer** views — all the same grid underneath, so cells stay editable and columns sortable whichever way you look at them. Then: **dashboards** that compose numbers, charts and embedded tables over your data; **computed columns** (a live duration, days-since, quantity × price); **totals** computed by the store across every matching row rather than the page on screen; **row actions** and **one-tap create** buttons that turn a table into something you press rather than something you fill in; and **thirteen ready-made templates** — issue tracker, CRM, expenses, grocery list, plant care, workout log and more. None of it ships a custom renderer: a mini-app is configuration, so the built-in assistant can build and reshape one for you.

**Private by default.** The browser's local database is now one encrypted store per agent (XChaCha20-Poly1305 at rest), so switching accounts or signing out genuinely closes the door. Account backup is passkey-first — one prompt, no secret to write down — and a device lock can seal the keypair after inactivity or when the browser closes.

**And it got much faster.** A query and indexing rework cut a 1000-member collection query by ~88% at the Rust level and ~70% over HTTP.

Also in this line: content localization with a `LocalizedText` datatype and locale-routed site templates, a desktop app that mounts your drives as a real **virtual drive** in Finder or your file manager, emoji and cover images on any resource, favorites, stateless invites, and the removal of `SERVER_URL` so a server can answer on several domains at once.

Beta, and honest about it: the storage format changed, so your database migrates on first run — **take a backup first**. See [STATUS.md](https://github.com/atomicdata-dev/atomic-server/blob/develop/server/STATUS.md) for what is expected to stay stable.

### Security

All four fixes documented under [v0.40.3](#v0403---2026-07-06) are present here — they reached this line through the `develop` merge, not through that tag. One deliberate divergence:

- The commit-level `check_server_managed_properties` guard that accompanied the `/download` arbitrary-file-read fix is **not** part of this line. It rejected any commit writing `internalId`, which breaks local-first uploads — here the client legitimately assigns that content hash at genesis. `/download` resolves `internalId` as an opaque content-addressed blob key rather than a filesystem path, so the path-traversal primitive the guard defended against does not exist. The `download.rs` hardening itself is retained.

### Added

- `Dashboard` and `Block` classes in the default store, with `dashboard-blocks` / `dashboard-layout` and `block-kind` / `block-source` / `block-view` / `block-query` / `block-aggregate` / `block-chart-spec`. One `Block` class carrying a kind string, the way `View` does, so a new block kind needs no ontology change. This is the schema behind the browser's new dashboards; the numbers themselves come from the aggregation engine already in `Query`.
- A `view-row-actions` property in the default store: the buttons a view puts on each row, as a JSON array of `{ id, label, kind, property, value }`. `kind` is a closed vocabulary of patches (`setNow` / `setValue` / `toggle` / `increment`) rather than code, so a person can edit one in a dialog and an assistant can write one, and each press stays an ordinary commit.
- A `view-quick-add` property in the default store: the button a view offers for creating a row, as a JSON object `{ label, field?, placeholder?, presets? }`. Each preset is `{ kind, property, value? }` using the same closed patch vocabulary as `view-row-actions`, applied to the row being created — so a button can stamp the current time and create in one press.
- `dashboard-layout` holds `{ subject, w, h }` — sizes only. It previously also carried `x`/`y`, which no renderer read.
- A `block-quick-add` property and a `'create'` block kind, so a Dashboard can carry a create button. It holds the same JSON shape as `view-quick-add`, which is what lets the table and the dashboard describe one button identically.
- Aggregate queries: a `Query` can carry an `aggregation`, and the store answers it by walking its own index instead of returning rows for the caller to add up. Sum, count, average, min and max over every row a query matches — filters included, paging excluded — plus an optional breakdown giving one subtotal per distinct value of a column, with day and month buckets resolved in the caller's timezone. Results arrive on the Collection's new `collection/aggregates` property. Because the browser's local database runs this same code through wasm, a table shows identical totals with no server in reach. Note that `count` counts the rows the asking agent may actually read, which can be lower than `totalMembers` — that one counts raw index hits, before rights are applied.
- Argon2id key derivation in `atomic-lib` as `vault::keys` (`argon2id_derive_key`), exposed to the browser as `argon2idDeriveKey`. This backs the passkey-wrapped ("envelope v2") backup of the agent secret: AES-GCM runs natively in WebCrypto, and Argon2id is the one primitive the Web platform's crypto API is missing. Defaults to ~64 MiB / 3 iterations / 1 lane.
- `EncryptedBackend` wraps any redb `StorageBackend` and encrypts data at rest with XChaCha20-Poly1305 (4 KiB blocks, a fresh random nonce per write, block-index AAD, key-check header), so resources, Loro snapshots, blobs and derived indexes are all ciphertext. Backs the browser's per-agent OPFS databases.
- A `coverImage` property in the default store — an image File shown as a decorative banner at the top of a resource's page — and a `coverImageFocus` float (0-1) holding that banner's vertical focal point, since a wide crop of a photo rarely has its subject in the middle.

### Changed

- Vector search is now opt-in (pass `--enable-vector-index` / `ATOMIC_ENABLE_VECTOR_INDEX`) instead of on by default. Loading embedding models and indexing every write on a plain create/edit had a real, measured performance cost that most deployments don't need.
- BREAKING (build): `vector-search` is no longer a default cargo feature — build with `--features vector-search` for semantic search. It was already opt-in at runtime and already absent from every released binary, but `cargo install atomic-server` still compiled the whole fastembed/lancedb/arrow/ort stack for a feature that stays switched off unless asked for: a very large build, requiring `protoc`, and failing outright on musl where `ort` has no prebuilt ONNX Runtime binary. Default now matches both the runtime default and what actually ships. Passing `--enable-vector-index` to a build without the feature warns instead of silently doing nothing.
- Query/index performance rework (`atomic-lib`): collection queries now read materialized rows instead of decoding a Loro CRDT snapshot per member, permission checks are memoized per request, and the query-members index uses compact query ids with typed, order-preserving sort keys. Verified paired before/after: a 1000-member collection query dropped ~88% at the Rust level (52ms → 6–7ms) and ~70% over HTTP in a single round trip (~104ms → ~30ms). See `planning/index-performance.md`.
- Live-query index updates are routed by `(drive, property)`, and multi-constraint (AND) queries pick their starting index by estimated selectivity — commits and first-time index builds touch far fewer filters/resources.
- Sorted collections now include members that lack the sort property (they sort first). Previously such members were silently dropped from sorted listings.

### Fixed

- A row edited until it no longer satisfies a filter now leaves that filter's results. Filtered queries are answered from a cached member list per watched query, and the whole-resource write path (`add_resource`, used by the browser's local database for every write it makes, and by imports) evicted the previous values' entries **against the new resource** — so it asked whether the new value still matched the filter, and a row edited out of the view answered no, skipping the one deletion that mattered. The row then stayed listed until the index was rebuilt, a reload included. The same mistake also listed a row **twice** when an edit kept it in the view but changed its sort value: the entry was filed under the old key and deleted under the new one, so the stale entry survived alongside the fresh one. It now evicts against the resource being replaced, the way commit application and recursive deletes already did. Commits were never affected, which is why this only ever showed up in the browser.
- [#287](https://github.com/atomicdata-dev/atomic-server/issues/287) Sorting collections by numeric properties (integers, floats, timestamps) now orders numerically instead of lexicographically ("2" no longer sorts after "10").
- `/search?filters=` actually filters again. Tantivy only scopes a JSON-field query to a path when the clause carries the field's own name, so the documented bare `<property-uri>:<value>` syntax silently matched nothing (no parse error) — `filters=isA:File`, used by the file picker, never found anything. Each AND/OR clause is now rewritten with the `propvals.` prefix before parsing, so the documented syntax works without any client change.
- Fixed a deadlock in `Db::apply_commit`: the per-subject lock was held across the after-commit handler loop, so a plugin's `after_commit` issuing its own follow-up commit to the same subject re-entered `apply_commit` and waited forever on a lock only it could release. The lock is now released before handlers run.
- `ATOMIC_REPOPULATE_DEFAULTS` now repopulates the base models (genesis, drive, the Commit class and the other fixed base-model properties/classes) as well as the JSON ontologies. Previously a store seeded before a base model was added could never receive it short of wiping the database.
- `_new:` placeholder resources no longer loop stuck-commit drops. If anything cleared `Resource.new` before a client-only `_new:<random>` subject completed its genesis save, the next local edit reached the outbox's incremental-commit path with an unresolved subject, which the server rejects.
- `atomic-cli` compiles again: the interactive `new` prompt's exhaustive `DataType` match had no arm for `LocalizedText` (added for #1069). Like the existing `LoroDoc` arm it now returns `Ok(None)`, since a per-language map isn't something a CLI prompt can collect as one string.

### Dependencies

- Bumped wasmtime/wasmtime-wasi/wasmtime-wasi-http (45.0.0 → 45.0.3, RUSTSEC-2026-0182 and -0188, the WASM plugin sandbox), quinn-proto (0.11.14 → 0.11.16, RUSTSEC-2026-0185), crossbeam-epoch (0.9.18 → 0.9.20, RUSTSEC-2026-0204) and plist (1.9.0 → 1.10.0, RUSTSEC-2026-0194 and -0195). The remaining cargo-audit findings (hickory-proto, rustls-webpki) trace to the deferred iroh 0.35 transport migration — see `planning/rust-dependency-upgrade-audit.md`.

## [v0.41.0-beta.1] - 2026-07-22

- [#1069](https://github.com/atomicdata-dev/atomic-server/issues/1069) Internationalization / content localization: new `LocalizedText` datatype storing per-language values as a native Loro map, with a fallback-chain resolver (exact locale → primary subtag → configured default language → first available).
- [#1069](https://github.com/atomicdata-dev/atomic-server/issues/1069) Fixed a DID-import bug where any string value equal to a reserved local ID was rewritten, not just values in reference positions — this could silently corrupt content (e.g. the website template ontology's own `shortname`, which equals its own local ID). Values now only resolve local IDs in reference positions; keys are still rewritten.
- Add `GET /drive-usage?subject=<drive>` — per-drive resource and byte usage (from `per_drive_usage`), signed by the requesting agent and gated on read access to the drive. Generic node metadata, available to self-hosted nodes too (not just managed ones).
- Add a `favorites` property to the default store, so clients can keep a per-user favorites list (alongside `drives` / `sharedWithMe`) on the user's private drive.

## [v0.41.0-beta.0] - 2026-06-22

- [#1139](https://github.com/ontola/atomic-server/issues/1139) AtomicServer can now create data without being dependent on a server! AtomicServer is now Local-First, using the new `did:ad` schema. Instead of relying on HTTP, Atomic can resolve resources over DHT Mainline. It combines true decentralization, cryptographic proof of ownership and high performance. User's agents are now also truly decentralized, relying solely on a private key.
- #584 Replace ureq with reqwest (async HTTP calls)
- #481 Drive scoped queries
- #1178 Sync protocol
- #1174 Live queries / real-time queries
- #1164 #1166 New Agents get private drives, shared resources through invites listed there
- #420 Fix OTLP / OpenTelemetry, update docs from Jaeger to SigNoz, add metrics
- Added self-verifying genesis certificates, including server-minted genesis support and dual-acceptance of the new certificates during migration.
- Stamp drives at resource creation and check write rights drive-first. This fixes resources being assigned the wrong drive and prevents drive-scoped commit fan-out from leaking cross-tenant updates.
- Added drive-scoped commit log diffing by accumulating Loro state before computing deltas, so history diffs reflect the actual resource state.
- Preserve cosmetic datatypes through the Loro round-trip and migrate away from stringified JSON datatype metadata in Loro properties.
- Reworked signed local commits so the outbox owns signed-but-not-acknowledged commits and drains them with per-agent scoping, retry backoff, and unrecoverable-commit parking.
- Added and hardened Iroh/Mainline peer sync, including smaller sync frames, faster version-vector decoding, and better websocket drop handling.
- Added vector search and made the vector-search stack optional. The server now uses rustls-backed FastEmbed/ORT features and disables the heavy vector stack for ARM64 musl builds.
- Relaxed redb durability with periodic flushes for better write performance.
- Speed up server development builds by skipping asset pre-compression in debug builds and parallelizing release asset work.
- Fixed WS/HTTP auth for agents whose key uses a different base64 alphabet.
- Fixed the default Commit class/genesis property population.
- [#590](https://github.com/ontola/atomic-server/issues/590) Get rid of the `SERVER_URL` env var, which makes moving & setup easier. All resources are now relative to the hosted domain, and AtomicServer can be available from multiple domains at once.
- [#544](https://github.com/ontola/atomicdata-dev/atomic-server/issues/544) Stateless invites, using JWTs. Server setup now requires you to check the logs for the invite token.
- We changed the binary format in which resources are stored. This means your data will be migrated the first time you run the server. This could take some time depending on the size of your database.
- [#1048](https://github.com/ontola/atomic-server/issues/1048) Fix search index not removing old versions of resources.
- [#1056](https://github.com/ontola/atomic-server/issues/1056) Switched from Earthly to Dagger for CI. Also made improvements to E2E test publishing, cross-target builds, and multi-architecture Docker images.
- Fixed Dagger CI workspace mounting after adding the `tools/cargo-bin` workspace member.
- [#979](https://github.com/ontola/atomic-server/issues/979) Fix nested resource deletion, use transactions
- [#1057](https://github.com/ontola/atomic-server/issues/1057) Fix double slashes in search bar
- [#986](https://github.com/ontola/atomic-server/issues/986) CLI should use Agent in requests - get
- [#1047](https://github.com/ontola/atomic-server/issues/1047) Search endpoint throws error for websocket requests
- [#958](https://github.com/ontola/atomic-server/issues/958) Fix search in CLI / atomic_lib
- [#658](https://github.com/ontola/atomic-server/issues/658) Added JSON datatype.
- [#1024](https://github.com/ontola/atomic-server/issues/1024) Added URI datatype.
- [#998](https://github.com/ontola/atomic-server/issues/998) Added YJS datatype.
- [#851](https://github.com/ontola/atomic-server/issues/851) Deleting file resources now also deletes the file from the filesystem.
  BREAKING: [#1107](https://github.com/ontola/atomic-server/issues/1107) Named nested resources are no longer supported. Value::Resource and SubResource::Resource have been removed. If you need to include multiple resources in a response use an array.
  BREAKING: `store.get_resource_extended()` now returns a `ResourceResponse` instead of a `Resource` due to the removal of named nested resources. Use `.into()` or `.to_single()` to convert to a `Resource`.
- [#415](https://github.com/ontola/atomic-server/issues/415) Mutli-filter queries.
- fix property sort order when importing + add tests #980
- auto-run `initialize` if server URL has changed #273

## [v0.40.3] - 2026-07-06

Security patch release, tagged from `develop` — so it carries the 0.41 development line's code, not v0.40.0's, despite the version number. All four fixes below are included, and all four are also present in the 0.41 line (see UNRELEASED for the one deliberate divergence).

- Guard outbound fetches (`/bookmark`, `/import`) against SSRF: reject loopback, RFC1918/CGNAT, and link-local (incl. cloud metadata) targets on every connection and redirect hop, plus a scheme check. Escape hatch: `ATOMIC_ALLOW_PRIVATE_FETCH=1`. Reported by Ray Sabee / Whitehat Security (@raysabee).
- Close two bugs undermining the single-use guarantee of the bootstrap `/setup` invite: an inverted expiry check that rejected valid invites and let expired ones through, and a TOCTOU race on `usagesLeft` that let concurrent requests both redeem what's meant to be a single-use invite. Reported by luuhung1217.
- Block arbitrary file read via `internalId`: a signed Commit could set this server-managed property directly, and `/download` trusted it verbatim as a filesystem path (traversal / absolute path). `internalId` is now denied in externally-submitted commits, and `/download` independently sanitizes and confines the resolved path to the uploads directory. GHSA-8vc4-8hjq-988p, reported by luuhung1217.
- Prevent stored XSS via uploaded files: `/download` now forces `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, so an uploaded HTML/SVG file can no longer render inline in the app's own origin. GHSA-x277-3wcg-g9r2, reported by luuhung1217.

## [v0.40.2] - 2026-07-03

Security patch release on the **v0.40.0 stable line** (tagged from the v0.40.0 commit), superseded three days later by v0.40.3. Note that v0.40.3 is *not* a descendant of this tag — the two were cut from divergent lines, so v0.40.2 contains none of the 0.41 development work that v0.40.3 does.

- Guard outbound fetches (`/bookmark`, `/import`) against SSRF. Reported by Ray Sabee / Whitehat Security (@raysabee). Superseded by v0.40.3, which carries this fix plus three more.

## [v0.40.0] - 2024-10-07

- Speed up Commits by bundling DB transactions #297
- Introduce `Db::apply_transaction` and `Storelike::apply_commit`
- Deprecate `add_atom_to_index` and `remove_atom_from_index` as public methods.

## [v0.39.0] - 2024-08-21

- The download endpoint can now optimize images on the fly. This is controlled via query parameters. #257
- Added export endpoint for exporting resources to other formats. Currently only supports exporting tables to csv. [#925](https://github.com/atomicdata-dev/atomic-server/issues/925)

## [v0.38.0] - 2024-06-08

- Remove `process-management` feature #324 #334
- Add `atomic_lib::client::search` for building queries #778
- Add `atomic-cli search` command #778
- Migrate atomic_cli to use the derive API #890

## [v0.37.0] - 2024-02-01

- Refactor `atomic_lib::Resource` propval methods (e.g. `set_propval` => `set`), make them chainable. #822
- Make `set_propval` and `set_propval_shortname` chainable #785
- Deterministic serialization JSON AD #794
- Use `musl` + `alpine` builds for docker images, way smaller images #620
- Support multi-platform docker builds #731
- Remove deprecated ENV vars #732
- Fix no Agent as drive
- Add `clear` option to error component (resets all front-end state)
- Add `Agent::from_secret` #785
- Don't use default agent when fetching with Db #787
- Fix HTTPS / TLS setup #768

## [v0.36.1] - 2023-12-06

- Fix locally searching for atomicdata.dev resources in external servers #706
- Use Earthly for CI: building, testing, pushing Docker images #576
- Host @tomic NPM docs [on Netlify](https://atomic-lib.netlify.app/) #707
- Deprecate Tauri Desktop build #718
- Merge Docs repository into this one #719

## [v0.36.0] - 2023-11-02

- **Requires `--rebuild-index`**
- Switch to monorepo. Include `atomic-data-browser` in this repo #216
- Add Tables (edit, keyboard support, sorting, more) #638
- The `parent` query param in `/search` has changed to `parents` and accepts an array of Subjects #677
- Improve query performance, less index storage #678

## [v0.34.3] - 2023-06-27

- Remove `tpf` queries from `atomic-cli` #610
- Fix `pageSize` property in Collections not using persistence
- Add Table Ontology #25
- Fix Post endpoints not including search params in returned `@id` field.
- Rebuilding indexes done on separate thread, only once #616 #615
- Don't require building index for populate commands
- Refactor `for_agent` arguments to use the new `ForAgent` enum #623
- Add support for Bearer token authentication, find in `/app/token` #632
- Add a `query` endpoint that allows performing collection queries via an endpoint instead of repurposing the collections collection.
- `resource.destroy` now recursively destroys its children.
- Update JS assets, add History view

## [v0.34.2] - 2023-03-04

- **Requires `--rebuild-index`**
- Improve full-text search, use JSON fields #335
- Rename `setup-env` to `generate-dotenv` and build it from clap #599
- Remove `remove_previous_search` and `asset_url` options
- Parse multiple auth cookies #525
- Fix `--script` flag
- Add `Storelike::post_resource`, which allows plugins to parse HTTP POST requests #592
- Move Server-Timing header to crate `simple-server-timing-header`
- Add `POST` + `body` support for Endpoints #592
- Refactor `Endpoint` handlers, uses a Context now #592
- Re-build store + invite when adjusting server url #607
- Use local atomic-server for properties and classes, improves atomic-server #604

## [v0.34.1] - 2023-02-11

- Improve query performance, refactor indexes. The `.tpf` API is deprecated in favor of the more powerful `.query`. #529
- Replace `acme_lib` with `instant-acme`, drop OpenSSL dependency, add DNS verification for TLS option with `--https-dns` #192
- Improved error handling for HTTPS initialization #530
- Add `--force` to `atomic-server import` #536
- Fix index issue happening when deleting a single property in a sorted collection #545
- Update JS assets & playwright
- Fix initial indexing bug #560
- Fix errors on succesful export / import #565
- Fix envs for store path, change `ATOMIC_STORE_DIR` to `ATOMIC_DATA_DIR` #567
- Refactor static file asset hosting #578
- Meta tags server side #577
- Include JSON-AD in initial response, speed up first render #511
- Remove feature to index external RDF files and search them #579
- Add staging environment #588
- Add systemd instructions to readme #271

## [v0.34.0] - 2022-10-31

- Add parent parameter to search endpoint which scopes a search to only the descendants of the given resource. #226
- Bookmark endpoint now also retrieves `og:image` and `og:description` #510
- Give server agent rights to edit all resources, fix issue with accepting invites in private drives #521
- Add cookie based authentication #512
- `Store::all_resources` returns `Iterator` instead of `Vec` #522 #487
- Change authentication order #525
- Fix cookie subject check #525

## [v0.33.1] - 2022-09-25

- Change how the sidebar resources are created
- Update JS assets

## [v0.33.0] - 2022-09-03

- Use WebSockets for fetching resources and authentication. Faster than HTTP! #485
- Added JSON-AD Importer
- Add HTML Bookmarks features
- Update Atomic-Data-Browser
- Improve CLI errors for Atomic-Server #465
- Fix default config directory, set it again to `~/.config/atomic`. This accidentally was `~` since v0.32.0.
- Fix flaky query test #468
- Don't subscribe to external resources #470
- Improve frequency search indexing #473
- Add HTML importer / bookmarks endpoint #432
- Allow new `Drive` resources without a parent
- Refactor end-to-end tests

## [v0.32.2] - 2022-06-20

- Upgrade to stable tauri #451
- Improve performance of invites #450
- Update JS bundle:
  - Fix Dropdown input bug
  - Fix autogrow textarea bug

## [v0.32.1] - 2022-06-15

- Fix issue when creating invite for chatroom #413
- Add OpenTelemetry suport #416
- Fix `remove` Commit command #417 (thanks @rasendubi!)
- Make tests less flaky by removing the `Store` in `Agent:to_resource` #430
- Update JS bundle

## [v0.32.0] - 2022-05-22

- **Warning**: Various default directories have moved (see #331). Most notably the `data` directory. The location depends on your OS. Run `show-config` to see where it will be stored now. If you have data in `~/.config/atomic/db`, move it to this new directory. Also, the search index will have to be rebuilt. Start with `--rebuild-index`.
- Updated various dependencies, and made `cargo.toml` less restrictive.
- Handle `previousCommit`. This means that Commits should contain a reference to the latest Commit.
- Remove `async-std` calls from `upload.rs`
- Added `reset` and `show-config` commands to `atomic-server`.
- Added `data-dir` flag
- Replaced `awc` with `ureq` #374
- Get rid of `.unwrap` calls in `commit_monitor` #345
- Make process management optional #324 #334
- Auto-update desktop distributions using Tauri #158
- Internal migration logic for inter-version compatibility of the database. Makes upgrading trivial. #102
- Use commits in populate and init
- Fix bug when opening the same invite twice with the same agent
- Update atomic-data-browser, deal with new commits, add chatrooms
- Add `Store::set_handle_commit`. Changes how Commits are internally processed. Now, users of `atomic_lib` can pass a custom handler function. This can be used to listen to events. #380 #253
- Added ChatRoom functionality. #373
- Add `push` option to Commits, which allows for efficient manipulation of ResourceArrays. Remove `Resource::append_subjects` method in favor of `push_propvals` #289.
- Add `append` right, only allows creating children #381.
- Fix logic for updating indexes. Sometimes atoms were ignored. #392 #395

## [v0.31.1] - 2022-03-29

- Host the data-browser assets / JS bundles from `atomic-server`'s binary #185
- Allow reading Commits #307
- Upgrade `actix`, `clap` and `tauri` dependencies #301
- No `Mutex` for `Appstate` in server #303
- Removed system tray from `atomic-server`, since I only want to maintain the Tauri version
- Rename `src-tauri` to `desktop` and make the tauri code part of the cargo workspace
- In Queries, respect a `limit` of `None` and `include_external` #317
- Run end-to-end tests from `atomic-data-browser` in `atomic-server` CI #204
- Use `nextest` for testing #338
- Improve and monitor test coverage #337
- Fix commit indexing #345

## [v0.31.0] - 2022-01-25

- Huge performance increase for queries! Added sortable index, big refactor #114
- Added `store.query()` function with better query options, such as `starts_at` and `limit`. Under the hood, this powers `Collection`s,
- `Resource.save` returns a `CommitResponse`.
- Refactor `Commit.apply_opts`, structure options.
- Remove the potentially confusing `commit.apply` method.
- `store.tpf` now takes a `Value` instead of `String`.
- Improved sorting logic. Still has some problems.

## [v0.30.4] - 2022-01-15

Run with `--rebuild-index` the first time, if you use an existing database.
Note that due to an issue in actix, I'm unable to publish the `atomic-server` crate at this moment.
You can still build from source by cloning the repo.

- Improve performance for applying commits and updating index (from ca. 50ms to <1ms), refactor value index #282
- More tracing / logging insights
- More search results for authorized resources #279
- Fix panic on unwrapping multipart upload
- Improve tauri dev UX

## [v0.30.3] - 2021-12-31

- Fix HTTPS initialization
- Add `--server-url` option
- Improved logs (better fitting level options, less verbose by default)
- rename `base_url` to `server_url`

## [v0.30.2] - 2021-12-30

- Update to actix v4, get Tauri to work again #246

## [v0.30.1] - 2021-12-28

- Replace `log` with `tracing` for structured logging and add tracing to `atomic-lib`, enables better (performance) diagnostics #261
- Add `--log-level` option #261
- Add `--trace-chrome` option #261
- Correct 404 status code
- Server-Timings header #256
- Added various endpoints as resources #259
- Show version, author and description in cli tool
- Fix indented welcome message in generated Drive

## [v0.30.0] - 2021-12-22

- Add file uploading and downloading #72
- Reverted to earlier Actix build, which unfortunately also means you have to wait longer for the Tauri desktop version of Atomic-Server #246
- Stricter authorization checks for Invites #182
- Add expires at check to Invites #182
- Add github CI action for Tauri Builds #221
- Add `append_subjects` method to Resource, helps dealing with arrays
- Running `--initialize` is non-destructive - rights to the Drive are only added, not removed.
- Stricter collection authorization #247
- Improved `check_rights` API #247
- Make Agents public by default, required for authentication process #247

## [v0.29.2] - 2021-12-10

- Desktop build (using Tauri) with system tray, icon, installers, menu items. #215
- Upgraded Actix to latest (needed for Tauri due to usage of Tokio runtime) #215
- Allow Agents to write and edit themselves #220
- Less collections for first-time users #224
- Sort collections by subject by default
- Set default port to 9883 instead of 80 #229

## [v0.29.0]

- Add authentication to restrict read access. Works by signing requests with Private Keys. #13
- Refactor internal error model, Use correct HTTP status codes #11
- Add `public-mode` to server, to keep performance maximum if you don't want authentication.

## [v0.28.2]

- Full-text search endpoint, powered by Tantify #40
- Add RDF-Search usecase (enables re-use of this server as search service for Solid pods)
- Add `enum` support using the `allows-only` Property. #206

## [v0.28.1]

- Fix docker env issue #202
- Fix docker image by switching `heim` with `sysinfo` #203
- Fix path ENV variables
- Fix logging while terminating existing process

## [v0.28.0]

- **IMPORANT**: before upgrading to this version, export your database using your previous version: `atomic-server export`. The database could become corrupted when running the new version.
- Refactor internal `Value` model and add Nested Resource parsing #195
- Added tests, improved some documentation
- Fix indexing commits #194
- Add more control over adding resources with `Store.add_resource_opts()`

## [v0.27.2]

- Make HTTPS optional #192
- Fix parsing .env file

## [v0.27.1]

- Fix bootstrapping issue #193

## [v0.27.0]

- **IMPORANT**: before upgrading to this version, export your database using your previous version: `atomic-server export`. The database could become corrupted when running the new version.
- Include Resources in Collection responses, improving performance dramatically for collections #62
- Introduce `incomplete` resources
- Update `get_resource_extended`, allow specify whether to calculate nested resources.
- Sort `children` in hierarchies.
- Sort `export` output - first export Properties, fixing #163
- Add `only-internal` to `export` CLI command in `atomic-server`.

## [v0.26.3]

- Many `atomic-server` CLI improvements. Add options as flags, without needing environment variables. #154

## [v0.26.2]

- Add `setup-env` command to `atomic-server` for creating a `.env` file #154 #187
- Remove analytics in server
- Make `asset-url` and `script` in HTML template customizable. #189

## [v0.26.1]

- Improved error message for hierarchy authorization check #178
- Fix Property `recommends` #177
- Refuse commits with query parameters in their subjects #179
- Add `resource.destroy()` method, which uses commits
- Improve killing existing processes - wait until other process has stopped #167
- Make `atomic-cli` smaller (don't use `db` feature from `atomic-lib`)

## [v0.26.0]

- Added WebSockets support for live synchronization / real-time updates with the front-end #171
- Update index after `destroy`ing a resource #173

## [v0.25.7]

- Improve process ID functionality #167
- Improve invite URL

## [v0.25.6]

- Fix domain .env #169
- Fix HTTPS port bug

## [v0.25.5]

- Check and terminate running instances of `atomic-server` when running instance #167

## [v0.25.4]

- Add flags for `reindex` and `init`
- Improve CI for automated tests & builds #165

## [v0.25.3]

- Improve ease of initial setup with initial invite on `/setup` #159 and welcoming descriptions for first Drive and Invite.

## [v0.25.2]

- Fixes caching bugs for collections introduced by #14
- Fix external resources in Collections #161

## [v0.25.1]

- Add Value indexing, which speeds up TPF queries / collections tremendously #14
- Add models for Document editor
- Improve commit authorization checks - allow new resources with existing parents

## [v0.24.2]

- Fix `/path` endpoint return values #143
- Add ASCI logo in terminal on boot
- Fix getting resources from server's `/commit` path #144
- Fix cache-control header issue when opening a closed tab #137
- Add collection properties `name`, `sortBy` and `sortDesc` #145
- Extract `apply_changes` from `apply_commit`, make versioning safer and more reliable #146
- Remove AD3 remnants, clean up code #148
- TPF endpoint supports JSON-AD #150
- Custom serializations in `atomic-cli tpf`

## [v0.24.1]

- Add write rights to Agent itself on accepting Invite
- Fix RDF serialization for dynamic resources #141
- Update and check Usages for Invites #134
- Make names for agents optional
- Move shortname property always to first one

## [v0.24.0]

- [Hierarchy](https://docs.atomicdata.dev/hierarchy.html) with breadcrumbs and easy to use navigation #134
- Authorization using Hierarchy, which means you can add write & read permissions anywhere in a hierarchy.
- Invites to invite new and existing users to read / edit a bunch of resources. Test it [here](https://atomicdata.dev/invites/1).

## [v0.23.5]

- Build using esbuild instead of webpack #31
- Some documentation improvements
- Remove `createdAt` from Agent model required fields
- Fix `n-triples` content type negotiation

## [v0.23.4]

- Fix deadlock in `cli new` command #124
- Added boolean, timestamp and unsupported fallback to `cli new` command #30
- Fix CLI input `server` - no subcommand required for running

## [v0.23.3]

- Added import / export to server and lib #121
- Added basic cli functionality with Clap to server #125
- Added multi-resource JSON-AD array parsing #123
- Use JSON-LD as default store #79

## [v0.23.2]

- Removed all HTML rendering from `atomic-server` (since we're using `atomic-data-browser`).
- Changed how config paths are calculated and shared.
- Remove the need for having the `./static` folder #118 when running `atomic-server`, moved to config dir.
- Add `open config` to tray icon
- Updated `atomic-cli` path, no longer requires quotes

## [v0.23.0]

- Added versioning #42
- Added endpoints #110 #73
- Moved `/path` logic to `atomic-lib` as endpoint #110
- `get_extended_resource` is now DB only #110
- Correct response codes (404) #105
- Improved .html page (+PWA support and Matomo tracking)
- Upgraded various dependencies

## [v0.22.4]

- Reject commits if they are editing a non-owned resource #106
- Correct response codes (404) #105

## [v0.22.3]

- Use atomic-data-browser js frontent by default #103

## [v0.22.2]

Warning: existing databases will _not_ work with this version.

- Fix deleting items #101
- Add a datatype for floats #93.

## [v0.22.1]

- Switch to JSON-AD parsing & serialization for Commits #100

## [v0.22.0]

Warning: existing Agents and Commits will no longer work. Be sure to create new ones.

- Change Commit serialization to [match atomic-data-browser](https://github.com/atomicdata-dev/atomic-data-browser/issues/3) implementation #98.

## [v0.21.1]

- Permissive CORS #92

## [v0.21.0]

- Add JSON-AD serialization #79, use it in Commits
- Servers are aware of their own URL #51
- Improved CLI edit feature, more flexible (create new resources if none exist, fix newlines)
- Add `resource.save_locally()`

## [v0.20.4]

- Fix array length bug in paths
- Add docker link to homepage
- Add system tray icon #75
- Removed `ResourceString`
- Improved WASM compliance #76
- Add ARM Docker compatibility #80
- Remove dead dependency #82
- CLI commit commands shortname fix #83
- rename `set_propval_by_shortname` to `set_propval_shortname`

## [v0.20.3]

- Added persistence to server docker image #70
- Improved default Agent setup for server

## [v0.20.1]

- Improved error handling in cli
- Added tests for cli #67
- Fixed generated addresses `localhost/collection` vs `localhostcollection`
- Added dockerfile for server #69

## [v0.20.0]

- Huge refactor of internals. Got rid of all string representations for Atoms, so store should only contain valid data. All Resources have all required props, and data is of the correct datatype.
- `Resource.save()` can be called! Easy way to store changes, both locally and externally.
- Added collection sorting #63

## [v0.19.0]

- Added table view for `atomic-server` #53
- Changed many methods from the `Resource` API to fix some ownership / trait object issues #45. `Resource` no longer has an internal reference to `Store`, so it needs an explicit store in most methods.

## [v0.18.0]

- Atomic-cli 0.18.0 allows for instantiating new Resources, whilst creating commits! It also re-introduces the TPF query.

## [v0.17.1]

- Atomic-server 0.17.1 now automatically renews HTTPS certificates on boot, if needed.

## [v0.17.0]

- `atomic-cli` can now edit data securely on an `atomic-server` #41 #13
- Root agent is automatically generated #38
- Convenient Collections (such as a list of all Commits, Classes, Agents, etc.) are generated for every store on `populate()`. #43
- Fixed some props for Collections and Commits

## [v0.15.0]

- Add dynamic collections with pagination #36 #17
- Refactor Db to use native values, for allowing nested resources #16
- Atomic Commits using deterministic serialization and cryptographic signatures #26 #24 #27 #31
- Recognize filetypes in URL #33

## [v0.13.0]

- Save reference to Store inside Resource #19
- No more &muts #18 #15

## [v0.12.1]

- Adds HTTPS auto certificate support
