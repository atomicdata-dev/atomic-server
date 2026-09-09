# Security and code-quality audit, September 2026 (atomic-server)

Scope: the whole `atomic-server` tree at commit `1e5e130` (server, lib, browser, desktop, cli, CI, scripts). The companion report for the control plane lives in `atomic-saas/planning/security-audit-2026-09.md`.

Method: seven parallel code-reading passes over disjoint areas, followed by hand verification of every Critical and High finding and most Mediums against the source. Nothing was executed against a running server, so "Verified" below means "the code path was read end to end", not "exploited in a test".

Confidence labels: **Verified** (read end to end by the reviewer), **Confirmed** (read end to end in the area pass), **Likely** (depends on a runtime detail not checked), **Needs-verification**.

---

## 0. Act today

1. **Revoke two live API keys** committed in `desktop/zed backup settings.json` (Context7 and Brave). See A1.
2. **Take `POST /iroh-sync` off the public surface** or gate it on write rights. See A2.
3. **Fix `SYNC_PUSH` per-entry authorization.** See A3.
4. **Stop trusting `/agents/{key}` URLs on arbitrary hosts as agent identity.** See A4.

---

## A. Critical

### A1. Live third-party API keys committed to the repo. Verified
`desktop/zed backup settings.json:46,52`. Tracked since commit `91b31ef` (#1350). It is a personal Zed editor config containing a `context7_api_key` and a `brave_api_key` in vendor format, plus `trust_all_worktrees: true` and agent `tool_permissions.default: allow`. The repo is public. Revoke both keys, delete the file, consider a history rewrite. Also tracked and unrelated to source: `.pnpm-store/v11/index.db`, `.pnpm-store/v11/.pnpm-needs-build-marker`, `node_modules/.vite/vitest/.../results.json`.

### A2. Unauthenticated `POST /iroh-sync` makes the server dial an attacker's node with owner trust. Verified
`server/src/routes.rs:99-143,219`. The handler takes `nodeId` and `drive` from an unauthenticated JSON body, has no `get_client_agent` call and is registered with `.to()` so any HTTP method reaches it. It calls `sync_drive_with_peer_outcome`, whose dial path applies `SYNC_DIFF.remove[]` and `SYNC_PUSH` with `trust_owned=true` (`lib/src/sync/peer.rs:1677,1733`). `may_accept_drive_write` (`lib/src/sync/engine.rs:1264-1288`) then accepts writes from any peer identity as long as the server's own default agent can write the drive. The HELLO handler also records the attacker's node as a known peer with auto-reconnect.

Trigger: `POST /iroh-sync {"nodeId":"did:ad:node:<attacker>","drive":"<victim drive>"}`. The attacker's node answers AUTH_OK and pushes overwrites or removals for every drive the server agent owns. Also a dial-spam and SSRF-to-iroh primitive.

Fix: require a signed agent with write on `drive` (owner in Owner mode), guard on `Method::POST`, and do not persist the peer as known without consent.

### A3. `SYNC_PUSH` entries are never checked against the drive they claim. Verified
`lib/src/sync/engine.rs:1374-1535`. Admission happens once for `push.drive`. The entry loop then loads or creates a Loro snapshot for every `entry.subject` in the frame, merges the attacker's delta and calls `add_resource_opts` (which does no authorization). Nothing verifies that `entry.subject` belongs to `push.drive`, and nothing checks write rights per subject. Loro merge is last-writer-wins, so `write`/`read` arrays and any other property on any resource can be overwritten.

Trigger: any DID agent authenticates with only its own keypair (`lib/src/authentication.rs:139-153`, no stored agent needed). Under the default `OpenPolicy`, `admit_unknown_drive` admits any authenticated agent naming a brand-new drive DID (`policy.rs:122-124`). So: `AUTH` with a fresh key, then `SYNC_PUSH {drive:"did:ad:<fresh>", entries:[{subject:<victim root>, loro_bytes:<write=[me]>}]}` over WS (`web_sockets.rs:294-296` only requires non-Public) or over Iroh. The live `UPDATE` path in `ws_apply.rs:114-132` resolves the drive from the existing resource; bulk sync does not.

Fix: for each entry, resolve the existing resource's `drive` stamp (or, for new subjects, require the stamp to equal `push.drive`) and reject mismatches; run `check_write` per subject for non-owner pushes.

### A4. Any `http(s)://<anyhost>/agents/{key}` is treated as `did:ad:agent:{key}` for rights, but authenticated by the key found in the fetched resource. Verified
`lib/src/agents.rs:332-341` (`migrate_legacy_agent_subject` accepts any host), `lib/src/authentication.rs:161-171`, `lib/src/commit.rs:371-396`, `lib/src/hierarchy.rs:238-252`, `lib/src/db.rs:3466-3517`, `lib/src/client/helpers.rs:198-230`.

For a non-DID agent subject, authentication fetches the agent resource (an external subject goes over the network via `fetch_body`, which has no SSRF guard, and is stored with `add_resource_opts`), then only compares the header public key with the fetched resource's `publicKey`. The `{key}` in the path is never compared to the signing key. Rights checks then normalize the agent string through `migrate_legacy_agent_subject`, yielding `did:ad:agent:{key}`, and compare that to the server's default agent (`did:ad:agent:<serverkey>`, public information).

Trigger: attacker hosts JSON-AD at `https://attacker.example/agents/<SERVER_PUBKEY>` with `publicKey = <attacker key>`, sends `x-atomic-agent` pointing at it with a signature from the attacker key. Auth passes; every rights check treats the caller as the server root agent. The same applies to the commit `signer` field. Any other user's key can be impersonated the same way.

Fix: for `/agents/{key}` subjects, require the key in the path to equal the authenticated key (or refuse non-DID agent subjects from other hosts entirely). Do not fetch external agent resources during authentication.

---

## B. High

### B1. Genesis commits can create children under any resource using their own `write` array. Verified
`lib/src/hierarchy.rs:180-192`, called from `commit.rs:823` with `applied.resource_new`. If the agent lacks `append` on the parent, `check_append` falls back to `check_rights(resource_new, Write)`. `resource_new` is built from the attacker's Loro update, so its `write` list contains the attacker. The comment at `commit.rs:854` shows the update path knows the new resource is untrusted; the create path does not. Result: arbitrary children in a victim drive, stamped with the victim's `drive`, listed in their collections and fanned out to subscribers. The `TODO` at `hierarchy.rs:502-504` describes exactly the missing test.

### B2. Parentless creation for any `did:` subject or anything claiming `isA: Drive`. Verified
`hierarchy.rs:193-206`, `commit.rs:436-439,571-590`. A genesis for `did:ad:agent:<victim>` is exempt from the cert check and treated as new when the victim has no stored agent yet, so an attacker can squat a victim's agent resource with `write=[attacker]`; the victim's later genesis is refused. A genesis with `isA:[Drive]` under `https://server/anything` creates `internal:/anything` without a parent, which is the local delivery vehicle for A4 and lets anyone reserve server paths.

### B3. `X-Forwarded-Host` and `X-Forwarded-Proto` trusted from any client, defeating the origin binding of session tokens. Verified
`server/src/context.rs:16-30`, `server/src/helpers.rs:136-137`, `web_sockets.rs:68-71`. Cookie and Bearer tokens are bound to the request only by a string compare of `requestedSubject` against the computed origin. A token captured on server B (or issued by a malicious operator of B) replays on server A for 5 minutes with `X-Forwarded-Host: B`. Fix: honour forwarded headers only behind a configured trusted proxy.

### B4. `POST /forget-peer` accepts any self-minted key. Verified
`server/src/handlers/forget_peer.rs:41-52`. The only gate is `!matches!(for_agent, ForAgent::Public)`; any `did:ad:agent:` whose embedded key matches the header key passes authentication without a store lookup. The handler then unconditionally drops the live link and known-peer entry for any node id. Anyone can disconnect the operator's paired devices.

### B5. Iroh `AUTH` proofs are replayable across responders. Confirmed
`lib/src/sync/peer.rs:1502`, `engine.rs:218-225`. The dialer signs `"{drive} {timestamp}"` and the accept side verifies with `AuthBinding::Unbound, AuthChallenge::None`. A peer you dial can forward your AUTH frame to any other node hosting that drive within 5 minutes and be served as you. The reverse direction and the WS path are bound correctly.

### B6. Desktop and mobile embedded server binds `::` (all interfaces). Verified
`server/src/config.rs:59` defaults `--ip` to `::`; `desktop/src/lib.rs:621-629,641` never overrides it. Every desktop and phone install exposes the user's node on the LAN. The comments at `lib.rs:141,193` claim it listens on localhost. Pass `--ip 127.0.0.1` from the launcher.

### B7. Desktop app: CSP disabled, devtools in release, broad IPC. Confirmed
`desktop/tauri.conf.json:22-25` (`csp: null`, `dangerousDisableAssetCspModification`), `desktop/Cargo.toml:26` (`devtools` feature unconditional), `capabilities/default.json`. IPC exposes `adopt_agent(secret)` and `vault_import/export`. Any XSS in synced content becomes full IPC access with no CSP backstop. Also makes C3 below unmitigated on desktop.

### B8. Data-browser trusts a remote server's `portalUrl` for where to send the managed-account bearer token. Verified
`browser/data-browser/src/helpers/managedServer.ts:132-143` stores whatever `portalUrl` a node returns from `GET /server`; `helpers/managed/api.ts:90-98,148-166` uses it as the API base in Tauri builds and attaches `Authorization: Bearer <device token>` from localStorage to every request. Connecting the desktop or Android app to a hostile server leaks the control-plane session and the recovery envelope. The same value feeds `window.open` and `location.assign` for "Sign in" and "Create account" (phishing). Allowlist the portal origin or bind it to the provider the device was linked to.

---

## C. Medium

- **C1. `BLOB_RESPONSE` stores bytes under a hash without hashing them.** Confirmed. `engine.rs:430-438`; pending-request map is store-global, so any authenticated session can poison a content-addressed blob.
- **C2. Dial-side owner trust is not scoped to the drive being synced.** Confirmed. `peer.rs:1677,1733`; a peer dialed for shared drive X can push and remove in every drive we own. Overlaps A2.
- **C3. URI-typed values and `downloadUrl` rendered as raw `href` / `window.open` without scheme check.** Verified. `browser/lib/src/datatypes.ts` has no `Datatype.URI` validation case; `ValueComp.tsx:69`, `URICell.tsx:36`, `AtomicLink.tsx:88-145`, `useFile.ts:42`. Web builds are mitigated by the nonce CSP; desktop (B7) is not.
- **C4. Stored HTML injection into the SPA shell via unescaped `downloadUrl` in meta tags.** Verified. `single_page_app.rs:113-116,144-156`. Meta-refresh redirects and injected forms work on every public visit; the `evil_meta_tags` test only covers `description`.
- **C5. Reflected HTML injection in `/plugin-ui?format=html`.** Confirmed. `plugin_ui.rs:372-410` interpolates the raw query string into `src`/`href`.
- **C6. Any drive writer can run server-side WASM with self-declared network access; plugin zip download has no SSRF guard, timeout or size cap.** Confirmed. `plugins/plugin.rs:234` (`reqwest::get`), `wasm.rs:611-617` (`inherit_network`). Fuel and memory limits exist. Plus **wasmtime 45.0.3 carries RUSTSEC-2026-0269** (filesystem sandbox escape via trailing slashes) and the host does preopen a per-plugin directory (`wasm.rs:637`); upgrade to 46.0.3+ or 47.0.4+.
- **C7. `ingest_commit` persists an agent resource for any signer before verifying the signature.** Confirmed. `engine.rs:700-718`; unauthenticated store pollution.
- **C8. `EPHEMERAL` Loro payloads relayed with no admission check.** Confirmed. `web_sockets.rs:510-541`, `commit_monitor.rs:933-968`; contrast `PresenceUpdate` and `LoroSyncUpdate`.
- **C9. Unbounded on-disk growth of image renditions.** Confirmed. `download.rs:382-444`; `q` is an `f32` in the cache key, nothing evicts, public files need no auth.
- **C10. `/upload` buffers each multipart part in memory with no limit.** Verified. `upload.rs:79-87`; `PayloadConfig` does not cover `Multipart`.
- **C11. No upper bound on `limit` in `/search` and `/vector_search`; multiply can overflow.** Confirmed. `search.rs:42-55`, `vector_search.rs:211-225,290`. Panics under the `e2e` profile.
- **C12. LanceDB filter injection in `/vector_search` `parents`/`is_a`.** Confirmed. `vector_search.rs:246-267`. Not an ACL bypass (results are re-fetched with the caller's agent) but defeats scoping.
- **C13. Panic-on-`unwrap` in the auth path with attacker-controlled input.** Verified. `helpers.rs:60-71` `origin()` unwraps `Uri` parse, scheme and authority; reachable via `/ws` Bearer tokens and via `X-Forwarded-Host: a b`.
- **C14. Auth signature fallback accepts a path-only message.** Verified. `authentication.rs:51-87`; a signature over `"/ <ts>"` is valid on every host and tenant for 5 minutes and bypasses the WS challenge binding for clients that sign that way.
- **C15. TLS certificates only checked at startup; ACME code panics (`todo!()`, `unwrap`).** Confirmed. `serve.rs:474-479`, `https.rs:64-86,249,269`.
- **C16. Process-global import flags race across connections.** Confirmed. `ws_apply.rs:10,30`, `peer.rs:1186-1195`.
- **C17. DID resources leak into other drives' watched queries.** Likely. `query_index.rs:479-482,382-445`. Read rights still apply at query time.
- **C18. Every commit is written with `Durability::None`.** Confirmed. `redb_store.rs:477,567` (`// EXPERIMENT`). Acknowledged writes are lost on crash until the next flush.
- **C19. Unbounded response body on the bookmark fetch.** Confirmed. `client/helpers.rs:355-366`, `bookmark.rs:47`; SSRF guard is present, size cap is not.
- **C20. Client-stamped `drive` trusted when the parent is not materialized.** Needs-verification. `commit.rs:242-256,876-893`; with B2 this may allow cross-drive fan-out injection.
- **C21. Agent private key written with default file mode.** Confirmed. `lib/src/config.rs:62-74` (`config.toml` with `agent_secret` lands 0644).
- **C22. CI: `permissions: write-all` on `release.yml` with unpinned third-party actions; PAT persisted in `.git/config` on the self-hosted runner (`main.yml:230-237`, no `persist-credentials: false`, `clean: false`); deploy SSH uses `ssh-keyscan` TOFU every run (`.dagger/src/index.ts:1816-1821`, `deployment.yml:114-116`); secrets expanded inline into `run:` (`tauri-release.yml:305-309`).** Confirmed.
- **C23. Flutter bridge deletes the database on any open error.** Confirmed. `flutter/rust/src/api/simple.rs:143-151`.
- **C24. Virtual drive is an unauthenticated read-write NFS server on loopback.** Likely. `desktop/src/vfs.rs:51,1307,1479`.

## D. Low and Info (selected)

- `Cors::permissive()` with credentials (`serve.rs:390`); currently saved by `SameSite=Lax` on the client cookie.
- `atomic_session` cookie set without `Secure` (`browser/lib/src/authentication.ts:118-121`).
- Unauthenticated WS `SUBSCRIBE_INDEX_STATUS` inserts per-connection state for arbitrary drive strings; `RBSR_FP` ranges unbounded (`web_sockets.rs:566-579,638-682`). No rate limiting on `/commit`, `/upload`, `/iroh-sync`.
- Auth failures and most client errors return HTTP 500 (`helpers.rs:183`, `errors.rs:119-137`), filling Sentry; `default_service` logs `error!` on every unmatched request (`serve.rs:405-408`).
- `/plugin-ui` and `/plugin-list` unauthenticated, read with `ForAgent::Sudo`, echo filesystem paths (`plugin_ui.rs:443-521`).
- `Agent` and `Config` derive `Debug` including the private key (`agents.rs:57-69`, `config.rs:129-142`).
- Agent identity strings not base64-canonicalized: one key, several identities (`authentication.rs:139-171`, `hierarchy.rs:310-313`).
- Genesis cert `parent`/`drive` never compared with the document (`commit.rs:451-460`).
- Plugin RPC client accepts `message` events from any source (`browser/plugin/src/rpc.ts:21-53`).
- Secrets in `localStorage`: edit-mode guest secret, OpenRouter key, managed device token.
- Docker image runs as root on `alpine:latest`; `docker-compose.yml` image untagged; `curl | sh` for rustup/pnpm/nextest inside CI containers.
- Signing scripts pass passwords on the command line despite claiming otherwise (`scripts/setup-android-signing.sh:69-77,123`, `setup-apple-signing.sh:154-185`).
- Blob bytes readable by hash without ACL (`download.rs:211-234,339-355`); by design, but should be stated in the threat model.
- Client never verifies incoming commits or genesis certs (`verifyGenesisCert` unused); design choice, document it.

---

## E. Dependency advisories (cargo audit, pnpm audit)

Rust (`cargo audit`, workspace root):

| Advisory | Crate | Version | Issue | Fix |
|---|---|---|---|---|
| RUSTSEC-2026-0269 | wasmtime | 45.0.3 | filesystem sandbox escape (trailing slash) | ≥46.0.3 or ≥47.0.4 |
| RUSTSEC-2026-0222 | wasmtime | 45.0.3 | type index confusion between engines | same |
| RUSTSEC-2026-0258 | h2 | 0.3.27, 0.4.14 | unbounded empty DATA frames | ≥0.4.16 |
| RUSTSEC-2026-0098/0099/0104/0049 | rustls-webpki | 0.102.8 | name-constraint bypasses, CRL panic | ≥0.103.13 |
| RUSTSEC-2026-0118/0119 | hickory-proto | 0.25.2 | CPU exhaustion, unbounded NSEC3 loop | ≥0.26.1 (0118 unpatched) |

Plus unmaintained `dotenv`, `bincode 1`, `rustls-pemfile`, `paste`, `instant`, gtk3 bindings, and unsound `lru`, `im`, `memmap2`, `rand 0.7`. Yanked: `aes 0.9.0`, `chacha20 0.10.0`.

JavaScript (`pnpm audit --prod` in `browser/`): 21 advisories, 11 high. Runtime-relevant: `@tiptap/core 3.23.6` (GHSA-cp6q-959q-f8rh, `mergeAttributes` prototype key becomes DOM attributes, fix ≥3.30.4) and the `@modelcontextprotocol/sdk` transitive set (`hono`, `qs`, `ip-address`, `express`) used by `data-browser/src/components/AI/MCP/*`. The rest (`fast-uri` via ajv, `browserslist`, `brace-expansion`, `nanoid`, `postcss`) are build-time.

---

## F. Sloppy code (grouped)

**Tests that assert nothing or hide bugs**
- `lib/src/hierarchy.rs:576-596` `authorization` test is empty (`TODO: FINISH THIS`); `:502-504` TODO names the missing "malicious commit grants itself write" test (B1).
- `lib/src/agents.rs:483-500` tautological assertion.
- `lib/src/validate.rs:173-266` dead code with `u8` counters, `println!`, `break` where `continue` is meant, empty `validate_populated` test.
- `lib/src/db/test.rs:2212` `#[ignore]` documents an open bug in `query_sorted_indexed`.
- `browser/lib/tests/upload-offline-reconnect.integration.test.ts:72` `it.skip` on a test the comment calls "a genuine, newly-surfaced bug".
- `e2e/tests/drafts.spec.ts:22`, `resource-context-menu.spec.ts:150` `test.fixme`.

**Panics on untrusted or user input**
- `lib/src/collections.rs:257-281` `sort_resources` comparator is not a total order; reachable via `sort_by` query param, may panic on Rust ≥1.81.
- `lib/src/agents.rs:212-215` `unwrap`/`expect` in `generate_public_key` on user-supplied secrets.
- `lib/src/parse.rs:880,871,925` `unwrap` on `importer`/`resource_new`.
- `lib/src/storelike.rs:513-521` `to_single()` panics on `Redirect`; reachable from `/path` for `did:ad:blob:` subjects (needs-verification).
- `lib/src/subject.rs:119,121,145` `Url::parse().unwrap()` on Host-derived strings.
- `server/src/handlers/web_sockets.rs:719` and `lib/src/discovery.rs:126-140` byte-slice `&str` at a fixed index (panics on multibyte, only when debug logging is on).
- `server/src/plugins/bookmark.rs:238` `self.url.join(url).unwrap()` inside the HTML rewriter.
- `server/src/errors.rs:79` `unwrap` inside `error_response`.
- `server/src/serve.rs:44-53` `expect` inside a detached `rt::spawn` (failure swallowed, startup continues).
- `cli/src/new.rs:23,169,178,203-355`, `cli/src/main.rs:162-164,310` `unwrap` on argv, interactive input and `config.toml`.
- `lib/src/db.rs:1997,3711`, `db/migrations.rs:105-200` deliberate crash-on-corruption during full scans; `db.rs:3196-3201` production asserts.

**Ignored results and swallowed errors**
- `server/src/handlers/upload.rs:47` `while let Ok(Some(field))` ends the loop silently on a multipart error and returns 200.
- `lib/src/envelopes.rs:181-189`, `lib/src/sync/engine.rs:1529` `let _ =` on store writes.
- `lib/src/sync/peer.rs:501,820,2079` `LIVE_PEERS.lock().unwrap()`: one panic kills live broadcast permanently.

**Dead, duplicated or misleading code**
- `lib/src/commit.rs:1165-1167,1191-1194` `SIGNER` set twice.
- `lib/src/sync/engine.rs:633-635` deprecated-field check is a substring match on raw JSON (any value containing the URL is refused).
- `lib/src/sync/engine.rs:1657` reads `LoroSnapshots` by raw subject while all writers key by `pure_id()`.
- `lib/src/sync/peer.rs:2387` counts entries as imports.
- `lib/src/utils.rs:23-38` `check_valid_url` accepts anything starting with `http` or `/`.
- `lib/src/discovery.rs:649-667` parses DNS rdata by string-searching `{:?}` output.
- `server/src/appstate.rs:142` condition evaluated after the path was created (always false).
- `server/src/serve.rs:184` `PAYLOAD_MAX = 50_242_880` is neither 50 MB nor 50 MiB; `:129-181` `Result` that can only be `Ok`; `config.rs:486` bitwise `&` on bools; `config.rs:311-312` "Unused" field still computed.
- `server/src/handlers/export.rs:77` `println!` in a request path; `:314` regex recompiled per CSV cell.
- `server/src/handlers/vector_search.rs:352-394` reranker indices can misalign with `resources`.
- `server/src/handlers/get_resource.rs:57-62` uses `Host` for tenant mapping while `context.rs` uses `X-Forwarded-Host`.
- `server/src/lib.rs:24,30` stale commented-out cfg and "Force rebuild for blake3".
- `browser/data-browser/src/components/ValueComp.tsx:54` `case (Datatype.DATE, Datatype.TIMESTAMP):` comma operator; DATE values never reach `<DateTime>`.
- Unawaited `resource.save()` at `react/src/hooks.ts:478`, `EditPropertyDialog.tsx:31`, `useAddToOntology.ts:32`, `FilePicker.tsx:62`, `usePreview.ts:73`, `TableRangeInput.tsx:40`.
- `browser/cli/src/store.ts:47-51` agent installed by an unawaited module-level promise; `:18` index 0 treated as missing.
- Duplicated and diverged `EventManager.ts` and `stringToSlug.ts` between `lib/` and `data-browser/`.
- Six "RECOVERY-RECONSTRUCTED" modules in `data-browser/src/helpers/managed/` with banners saying nobody has re-verified them; these decide where bearer tokens go (B8).
- `useAtomicTools.ts:808-857` fifty lines of commented-out tool definition.
- `browser/tsconfig.build.json` not `strict`; `useUnknownInCatchVariables: false`.
- `desktop/latest-version.json` stale 2020 updater manifest with an empty signature; `Cross.toml`, `.earthlyignore`, `cli/wapm.toml` reference removed tooling; `.vscode/tasks.json` and `.zed/tasks.json` reference a non-existent `server/e2e_tests/`.
- `flutter/.mise.toml:3` pins `flutter = "2.5.3-stable"` while CI uses `flutter:3.44.0`; `scripts/dev-all.sh:46` vs `tauri-release.yml:390` disagree on the NDK version.
- `scripts/bump-version.mjs:179` recommends the exact command its own header says must not be used.
- `main.yml:44-73,188-191` dead `pull_request_target` guard on a workflow that only runs on `push`.
- `.dagger/src/index.ts:1114-1140` production binary built with `--features light` as an "explicitly-approved stopgap" with no tracking issue.
- TODOs on known-incorrect behaviour: `lib/src/store.rs:197`, `values.rs:125,291,360`, `resources.rs:1037`, `storelike.rs:639`, `db.rs:3625,3786`, `single_page_app.rs:84,114,119`.

---

## G. Checked and found fine

Ed25519 only, strict key lengths, JCS-canonical commit payloads; genesis cert binary format with cross-language vectors; auth timestamp window (10 s skew, 5 min max age); CSPRNG everywhere keys and nonces are made; vault crypto (XChaCha20-Poly1305, random 24-byte nonces, Argon2id 64 MiB, BLAKE3 subkeys, header as AAD); SSRF guard on bookmark and import fetches (IP-literal preflight, public-only resolver, per-redirect check); `/blob/{hash}` PUT admission; `/upload` write check before body read; `/download` served with `attachment` and `nosniff`; commit fan-out drive-scoped and read-checked on subscribe; WS AUTH bound to origin plus per-connection nonce; invite tokens re-check the issuer's current write right; protocol decoders bounds-checked with frame caps; WASM host fuel, memory limiter, no stdio, zip path-traversal guards; SPA CSP nonce from `SystemRandom` with `</script>` escaping tested; `prunetests` behind `debug_assertions`; agent secret never logged; Android cleartext off in release; Flutter secret in secure storage; deep-link handler JSON-escapes before eval; MCP bridge debug-only on loopback; deploy workflows gate on green CI for the exact SHA; signing material scrubbed with `if: always()`; host mode refuses to boot misconfigured; react-markdown without `rehype-raw`; plugin host-side `postMessage` checks `event.source`; non-extractable keypair in IDB; OPFS DB encrypted per agent; no `eval`/`new Function`/prototype-pollution helpers; no empty `catch` blocks.

---

## H. Status (same branch)

Fixed on `claude/security-code-quality-audit-ahi0jo`:

- **A1**: `desktop/zed backup settings.json`, the `.pnpm-store` cache and the vitest result file are removed from the tree and ignored. The two API keys are still valid until revoked at the vendors; that is not something a commit can do.
- **A2**: `POST /iroh-sync` requires a signed agent: write on the drive when this node already holds it, or the sync policy's leave to bring a new drive here (any signed-in agent on an open node, the owner in Owner mode). Only answers `POST`. The two client calls sign the request. On the dial side, owner trust is now confined to the drive that was dialed for: pushes claiming another drive and removals outside it are judged on the peer's own rights (this also covers C2).
- **A3**: `import_sync_push` checks every entry: an existing resource must carry the admitted drive as its stored `drive` stamp (or be the drive itself); a new one must resolve, via its stored parent or its own stamp, to that drive. Mismatches are skipped with a warning.
- **A4**: for `/agents/{key}` subjects the key in the path is bound to the signing key in both header authentication and commit signature validation. Agent subjects on other hosts are refused instead of fetched. `legacy_agent_pubkey` in `agents.rs` is the single place that maps a legacy subject to its key.
- **B1**: `check_append` no longer falls back to the new resource's own `write` array; `Append` on the parent already honours the parent's `write`. Regression test `genesis_cannot_grant_itself_append_via_its_own_write_array`.
- **B2** (agent squatting): a parentless `did:ad:agent:{key}` genesis is accepted only from that key, the node's own agent, or Sudo. Regression test `agent_resource_can_only_be_created_by_its_own_key`. The `isA: Drive` parentless path is unchanged; see below.
- **B3**: `RequestContext` takes the origin from `Host`/`X-Forwarded-*` only when the host is the configured domain, a subdomain of the base domain, or loopback; otherwise the configured origin is used. A server left on the default domain `localhost` keeps trusting the header. The WebSocket handler uses the same origin. Unit tests in `context.rs`.
- **B4**: known peers now record the drives they were paired for; `/forget-peer` requires write on one of them, or the node's own agent (or the Owner-mode owner). Integration test covers both the refused stranger and the accepted drive writer.
- **B6**: the desktop launcher and the Android options bind `127.0.0.1` unless `--ip`/`ATOMIC_IP` is given.
- **B8**: a node-reported `portalUrl` is accepted only as an absolute `https:` URL (or `http:` on localhost); once a device token exists, the portal it was issued by is pinned and later nodes cannot move it; every navigation to a portal goes through `safePortalUrl`. Unit tests in `managed/api.test.ts`.
- **B5**: the dialer now signs `drive#<responder node id>` (`auth_subject_for`), and the accept side verifies the node id as the connection's challenge, so a proof captured by one responder does not open another. A proof without a node id (a pre-binding dialer) is honoured only from a peer this node's owner paired with, until that peer upgrades; a proof for another node is refused. Test `iroh_auth_must_name_this_node`.
- **C1**: `BLOB_RESPONSE` bytes must hash to the requested key.
- **C3**: `Datatype.URI` rejects `javascript:`, `data:` and `vbscript:`; `isSafeHref` guards `AtomicLink`, `ValueComp`, `URICell` and file downloads.
- **C4, C5**: `downloadUrl` is escaped in the meta tags; the `/plugin-ui` query string is attribute-escaped.
- **C9**: rendition quality is rounded to whole numbers and width to a multiple of 64 (max 4096) before encoding and caching.
- **C10**: multipart uploads are bounded by `PAYLOAD_MAX`.
- **C11**: `limit` is capped at 500 in `/search` and `/vector_search`.
- **C12**: LanceDB filter literals are quoted.
- **C13**: `origin()` in `helpers.rs` no longer panics on unparsable input.
- **C21**: `config.toml` (agent secret) is written with mode 0600.
- **D**: plugin RPC ignores messages not from `window.parent`; the session cookie gets `Secure` on https.
- **F**: `ValueComp` comma-case, unawaited `resource.save()` calls, CLI agent readiness, the commented-out tool block, the duplicate `EventManager`, `SIGNER` set twice, bitwise `&` on bools, the empty `authorization` test.

Fixed in the second round on the same branch:

- **B2** (parentless creation): `check_append` now allows a parentless non-agent DID only when it has no `parent` at all, or when its `drive` stamp names a drive the agent may append to (the race-free parent-before-child path, which an attacker cannot pass on a victim's drive); a non-DID `isA: Drive` genesis needs the node's own agent or Sudo. Tests in `commit.rs`.
- **C6, C19**: plugin zips and bookmark bodies are fetched through `fetch_bytes_untrusted` / a bounded `fetch_body_untrusted` (SSRF guard, 50 MiB and 10 MiB caps, `Content-Length` checked up front).
- **C7**: the signer's Agent resource is created only after the commit is accepted.
- **C8**: `EPHEMERAL` Loro payloads are relayed and fanned out only from a subscriber of that subject.
- **C14**: path-only auth signatures are no longer accepted; the full-URL-without-query fallback stays.
- **C15**: the ACME flow returns errors instead of panicking, and a daily task renews the certificate on disk and warns that a restart is needed.
- **C23**: the Flutter bridge deletes the database only on a corruption error.
- **C22**: the atomic-saas checkout no longer persists its PAT; `release.yml` has per-job minimal permissions; Apple notarization secrets go through `env:`.
- **D**: `Agent` and `SharedConfig` redact secrets in `Debug`; genesis certs with a `parent`/`drive` must match the document; `/plugin-list` and the plugin UI files are read as the calling agent (the data-browser signs that request) and the `plugin` parameter is validated; `default_service` logs at debug; the desktop `devtools` feature is opt-in.
- **Dependencies**: `wasmtime` 47.0.4 (sandbox escape), `h2` 0.4.19, `quinn-proto`, `rustls-webpki` 0.103.13; `@tiptap/*` 3.30, `@modelcontextprotocol/sdk` 1.30 and the transitive build tools, after which `pnpm audit --prod` reports nothing. Still open: `h2 0.3` (via actix-http 3, no patched 0.3 line) and `rustls-webpki 0.102` / `hickory-proto 0.25` (via iroh 0.35; an iroh upgrade is the only route).

Not fixed here:

- **C17** (DID resources in other drives' watched queries): a first version compared a resource's `drive` stamp with the query's `drive`, but for a `did:` query `QueryFilter.drive` is `drive_prefix_from_subject` of the queried subject, which is that subject itself rather than the drive root, so legitimate rows were excluded and the `query_aggregates` tests failed. Reverted. A correct fix has to carry the drive root in the filter (resolve the queried subject's `drive` stamp when the filter is registered) and only then compare stamps, or keep the constraint check as the scope and rely on read rights at query time, which still apply.
- **B7** (desktop CSP disabled): enabling a CSP for the data-browser under Tauri needs the app tested under it (inline theme script, styled-components, wasm workers, server origins); the `devtools` feature is now opt-in.
- **C16** (process-global import flags), **C18** (`Durability::None`), **C24** (loopback NFS): structural changes with performance or design trade-offs, listed above with the fix direction.
- The `stringToSlug` duplicate stays: the data-browser copy fixes a case (`Meat & fish`) the lib copy gets wrong; port the fix into lib first.
