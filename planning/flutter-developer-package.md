# Flutter developer package

Goal: a third-party app (or an AI agent) adds one Flutter package and has a
working `Store` on the Rust `atomic_lib` node, with no Rust or
`flutter_rust_bridge` knowledge.

Result: `packages/atomic_store_flutter` (entry point `AtomicFlutter.init()` /
`AtomicFlutter.open(...)`), example in `packages/atomic_store_flutter/example`.

- [x] Move the Rust crate (`flutter/rust`), the cargokit FFI plugin
      (`flutter/rust_builder`), the generated Dart (`flutter/lib/bridge`),
      `flutter_rust_bridge.yaml` and `BridgeStoreBackend` into the package (git mv)
- [x] Plugin and package renamed `atomic_store_flutter` (podspecs, gradle,
      CMake); crate and native library keep the name `atomic_flutter_rust`
- [x] `AtomicFlutter` / `AtomicNode` entry point; public generated bridge in `lib/bridge/`
- [x] App depends on the package; imports switched to
      `package:atomic_store_flutter/...`; `rust_init*` removed (unused)
- [x] Root `Cargo.toml` exclude, dagger `flutterTest`, workflows, docs updated
- [x] Regenerate with codegen 2.12.0; `git diff` clean after a second run
- [x] `example/` (hello_atomic) passes `flutter analyze`; CI job `example`
- [ ] Linux build of the example (needs > 3 GB free; not tried in the sandbox)
- [ ] Typed Dart wrappers for files and history (raw bridge only today)
- [ ] Publish to pub.dev / prebuilt native binaries (cargokit precompiled
      binaries) so a first build does not compile `atomic_lib` for ~10 minutes
- [x] Iroh peer sync usable from a node other than the default store: the peer
      serves the first store that starts it (`start_peer_for`, `PEER_STORE`),
      other stores are refused with a clear error. One endpoint per process stays.

## Peers, server sync, drives, identity, sharing in the package

Owner's rule: this logic comes from our lib, not reimplemented per app.

### Inventory (what exists where)

| Area | `atomic_lib` (Rust) | Bridge (before) | `flutter/lib` (app) |
| --- | --- | --- | --- |
| Peers | `lib/src/sync/peer.rs`: `start`, `get_node_id`, `get_known_peers`/`add_known_peer`/`remove_known_peer` (store-bound, `PluginMeta`), live peers, `sync_drive_with_peer_*`, `SyncEvent`s, `get/set_device_name`; `dial_gate`; `host::peer_search` | free fns in `simple/peers.rs`/`sync.rs` on the **default** store (`db()`), `PEER_SEARCH` process-wide | `AtomicClient` wrappers; `pair_screen.dart` parses QR (`PeerInfo`, `formatQrValue`), `sync_screen.dart` |
| Server sync | `sync::session`, `ws_apply`, `outbox` | `AtomicStore::open_ws_sync`/`close_ws_sync`/`is_syncing`/`connected_server`/`push_pending` (per handle); free `connect_home_server`, `resume_app_session`, `resolve_drive_origins`, `genesis_answer_verifies` (default store) | `AtomicClient.resumeSession`, `discoverHomeServer` (http + genesis probe), `verifiedDriveOrigins`, `connectKnownServer`, `account_store.dart`, `server_info.dart` (atomic.place specifics stay there) |
| Drives | `Db::create_drive`/`list_drives`/`set_active_drive`, `host::lists::order_drives_by_use` | `AtomicStore::new_drive`/`set_drive` (pinned, not remembered); free `list_drives_with_names` (default) | `AtomicClient.listDrivesWithNames`/`createDrive`/`setActiveDrive` |
| Identity | `Agent`, `Db::setup`/`load_agent_from_secret`, `host::own_profile` | `AtomicStore::setup`/`load_agent`/`agent_subject`; free `get_own_profile`, `set_agent_profile`, `clear_agent` (default) | `login_screen.dart` (new agent, secret, server sign-in), `own_profile.dart`, `session.dart` (secret persistence) |
| Sharing | rights are plain `read`/`write`/`append` props (`urls.rs`, `hierarchy::check_*`); invites: `Invite` class, `/invites` endpoint + `InviteToken` live in the **server** crate (`server/src/invite_token.rs`, `plugins/invite.rs`) | nothing | nothing |
| `@tomic/lib` naming | `core.properties.read/write` (`useShareRights`), `generateInviteToken(target, agent, write, expiresAt, description, browserPeer, maxUsages)` -> `<server>/app/invite?token=` | | |

Findings: nothing in `atomic_lib` creates an invite; only TypeScript signs
tokens (the server verifies them and keeps acceptances in `PluginMeta`).
Rights need no new lib code: they are ordinary properties, checked by
`hierarchy`. So the bridge got `create_invite_token` (same signable bytes as the
server's `InviteToken::signable_json`: sorted keys, no whitespace) and the Dart
`Sharing` edits the two lists.

### Done

- [x] Bridge per-handle methods (`rust/src/api/node.rs`): `start_peer`,
      `known_peers`/`add_known_peer`/`remove_known_peer`, `live_unpaired_peers`,
      `device_name`/`set_device_name`, `sync_with_peer`, `sync_with_peers`,
      `list_drives_info`, `switch_drive` (remembered), `profile`, `set_profile`,
      `sign_out`, `create_invite_token`; Rust tests (`api::node::tests`)
- [x] `PairingCode` (format/parse of QR text, moved out of the app's pair screen)
- [x] `node.peers` (`Peers`), `node.sync` (`ServerSync`, `HomeServerDiscovery`),
      `node.drives`, `node.identity`, `node.sharing` (`Sharing`)
- [x] Fakes: `package:atomic_store_flutter/testing.dart`
- [x] `atomic_store`: `Store.drive` assignable (a drive switch is followed),
      `Props.read/write/append/publicAgent`
- [x] App swap: `PairScreen.parsePeerInfo`/`formatQrValue` -> `PairingCode`;
      `AtomicClient.discoverHomeServer`/`verifiedDriveOrigins` -> `HomeServerDiscovery`
- [x] README sections with examples

### Follow-ups

- [ ] App still on the default-store free functions (`AtomicClient` ->
      `bridge/api/simple/*`): known peers, `peer_sync`, `list_drives_with_names`,
      `resume_app_session`, `load_agent`. Moving it onto `AtomicFlutter.open` +
      `node.*` is a larger change (the app opens the default store with
      `open_db`; the handle would have to be the default store's file, which is
      shared, so peers keep serving it). Do it screen by screen:
      pair_screen (`node.peers.pair`), sync_screen (`peers.syncNow`,
      `sync.discover`), drive switcher (`node.drives`), login (`node.identity`).
- [ ] `resume_app_session`'s pkarr/known-peer fallback and `follow_listed_drives`
      (fetching the person's other drives after connect) run only on the default
      store; a handle `open_ws_sync` does it for the default handle only.
- [ ] `peers.sync_with_peers` skips the pkarr lookup `sync_connectivity_now`
      does (the background search loop covers it); unify when the app moves.
- [ ] Accepting an invite from Dart (`GET /invites?token=` + POST) and a
      lib-level invite creation in `atomic_lib` (so the server tests and the
      bridge share one signer instead of the server crate's test-only one)
- [ ] Peer/server sync status stream is polled (1 s); a lib event would be better
- [ ] Integration test of two nodes pairing in one process is impossible
      (one Iroh endpoint per process); `cross_process_sync` in atomic_lib covers it
