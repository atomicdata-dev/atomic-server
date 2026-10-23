# atomic_store_flutter

Build a Flutter app on Atomic Data in a few lines. This package gives you a
working [`Store`](../atomic_store/README.md) backed by the Rust `atomic_lib`
node: a local database, signed commits, full-text search and optional sync with
an Atomic Server. It builds the native library for you (cargokit), so you
never touch Rust or `flutter_rust_bridge`.

```dart
await AtomicFlutter.init();                         // once, in main()
final node = await AtomicFlutter.open(path: dir, agentName: 'Alice');

final note = node.store.newResource(
    isA: [Classes.folder], props: {Props.name: 'Hello'});
await note.save();                                  // one signed commit

await for (final r in node.store.watch(note.subject)) { print(r.name); }
```

`Store`, `Resource`, `Props`, `Classes` and `Value` come from
`package:atomic_store`; read its README for the API (`getResource`, `set`,
`save`, `destroy`, `search`, `children`, `watch`, `watchChildren`, errors, how
to model your own data, testing with `InMemoryBackend`).

## Add it to your app

Not published to pub.dev yet; use a path or git dependency:

```yaml
dependencies:
  atomic_store_flutter:
    git:
      url: https://github.com/atomicdata-dev/atomic-server
      path: packages/atomic_store_flutter
  atomic_store:
    git:
      url: https://github.com/atomicdata-dev/atomic-server
      path: packages/atomic_store
  path_provider: ^2.1.5
```

or, in a checkout, `path: ../atomic-server/packages/atomic_store_flutter`.

The Rust crate reaches `atomic_lib` at `../../../lib` of this repository, so
the dependency must come from a full checkout of it (a git dependency clones
the whole repository, so that holds). The first build compiles `atomic_lib` and
its dependencies, about 10 minutes cold.

### Prerequisites

- Flutter 3.24+ (CI uses 3.44.7).
- A Rust toolchain via [rustup](https://rustup.rs). The repository's
  `rust-toolchain.toml` pins the version and rustup installs it (and the
  Android/iOS targets cargokit asks for) on first build.
- Linux desktop: `clang cmake ninja-build pkg-config libgtk-3-dev`.
- Android: the NDK (Android Studio SDK Manager). iOS/macOS: Xcode.
- Web is not supported: there is no native node in a browser. Use a
  different `StoreBackend` there.

## What you get

- `AtomicFlutter.init()` loads the native library (call it once).
- `AtomicFlutter.open(path:, agentSecret:, agentName:, drive:)` opens the
  database in `path`, and returns an `AtomicNode`:
  - `node.store`: the `Store`, working in `node.drive`;
  - `node.agentSecret`: **the identity**. First run creates a new agent and a
    private drive; persist the secret (e.g. `flutter_secure_storage`) and pass
    it back as `agentSecret` on the next start;
  - `node.connect(serverOrigin)` / `disconnect()`: sync with an Atomic Server
    over WebSocket;
  - `node.handle`: the raw bridge handle for everything else.
- `BridgeStoreBackend`: the `StoreBackend` itself, for building a `Store` on a
  raw handle yourself.

Open a database path **once per process**; a second open of a redb file in the
same process is not safe. Keep the `AtomicNode`.

## Identity, restart and sync

**Identity is the agent secret.** The first `open` (no `agentSecret`) creates an
Ed25519 agent and a private drive, both on this device only; nothing is sent
anywhere. Keep what `node` tells you:

```dart
// First run
final node = await AtomicFlutter.open(path: dir, agentName: 'Alice');
await secureStorage.write(key: 'agent', value: node.agentSecret);
await secureStorage.write(key: 'drive', value: node.drive!); // a second device needs it

// Every later run, same `dir`
final node = await AtomicFlutter.open(
    path: dir, agentSecret: await secureStorage.read(key: 'agent'));
print(node.drive);   // the same drive subject as the first run
```

With the saved `agentSecret` and the same `path`, the node signs as the same
agent and `node.drive` is the drive it was last working in (the database
remembers it), so everything written before is still there. Without the secret
a new agent and a new empty drive are made: the old data stays in the file but
is not yours to write to. Pass `drive:` to open on a specific drive. Open a
path once per process.

**`node.connect(serverOrigin)`** (for example `https://example.com`, no path)
opens a WebSocket to that Atomic Server, **authenticates as the node's agent**
(a signed challenge with the same secret; no password or account), subscribes
to `node.drive`, fetches the drive from the server if this device lacks it, then
applies the server's changes to the local store (so `watch` and `watchChildren`
see them) and sends every local write that is waiting, in order. Later writes
go out as they are made. Without a drive it authenticates and sends the waiting
writes but subscribes to nothing. Writes always succeed locally first; offline,
they wait on disk until the next `connect`. `disconnect()` stops the session.
If the server refuses the agent or the drive, the drive fetch fails quietly
(logged) and the node stays local-only for it; check by watching for the data.
It does not retry or reconnect on its own: call `connect` again after a drop.

**A second device**, same person: open there with the same `agentSecret` and a
new `path`, and give it the drive, `drive: savedDriveSubject` (store it with the
secret, as above), then `connect` to the server both use. The drive is fetched
from the server and from then on both devices see each other's writes through
it. This needs a server that holds the drive; two devices with no server can
only pair over Iroh, which the app (`flutter/`) wires up but a node from
`AtomicFlutter.open` does not take part in.

**Sharing** with other people (inviting another agent, setting who may read or
write) is not supported by this package; a drive belongs to its agent. The
rights and invite resources exist in Atomic Data and are reachable through the
raw bridge or the server, but there is no typed API here.

## Still on you

- Where to keep the agent secret, and sign-in / account UI. This package has no
  login screen; the atomic.place app (`flutter/`) has one.
- Pointing at a server: `connect` takes an origin you choose. Discovering a
  user's servers and drives is app code (`flutter/lib/atomic/`).
- Peer-to-peer sync (Iroh pairing, QR codes) is process-wide and only wired to
  the app's default store (`flutter/lib/atomic/atomic_client.dart`, the raw
  `bridge/api/simple/peers.dart`). A node you open with `AtomicFlutter.open`
  does not take part in it.
- Files/blobs, history and the assistant/chat calls exist in the raw bridge
  (`package:atomic_store_flutter/bridge/api/...`, generated and unstable; `node.handle` is the
  `AtomicStore` of `bridge/api/resources.dart`) but
  have no typed Dart wrapper here yet.
- Releases: not on pub.dev; pin a git ref.

## Layout and maintenance

```
lib/atomic_store_flutter.dart   AtomicFlutter, AtomicNode, BridgeStoreBackend
lib/bridge/                     GENERATED Dart bindings (do not edit); public
                                as package:atomic_store_flutter/bridge/api/*.dart
rust/                           the Rust crate atomic_flutter_rust (workspace-excluded)
rust/src/frb_generated.rs       GENERATED glue (do not edit)
cargokit/, android/, ios/,      the native build glue (an FFI plugin)
macos/, linux/, windows/
flutter_rust_bridge.yaml        codegen config
example/                        hello_atomic, a ~100 line app
```

Regenerate the bindings after changing `rust/src/api` (codegen 2.12.0, the
version of `flutter_rust_bridge` in `pubspec.yaml` and `rust/Cargo.toml`):

```bash
cargo install flutter_rust_bridge_codegen --version 2.12.0 --locked
cd packages/atomic_store_flutter && flutter_rust_bridge_codegen generate
```

CI regenerates and fails on any diff. Rust tests:
`cargo test --lib --manifest-path packages/atomic_store_flutter/rust/Cargo.toml`.
