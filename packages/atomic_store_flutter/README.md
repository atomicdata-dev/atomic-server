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
      url: https://github.com/ontola/atomic-server
      path: packages/atomic_store_flutter
  atomic_store:
    git:
      url: https://github.com/ontola/atomic-server
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
    over WebSocket (same as `node.sync.connect`);
  - `node.identity`, `node.drives`, `node.sync`, `node.peers`, `node.sharing`:
    the typed parts, below;
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
new `path`, and **no `drive:`**. The secret carries the agent's private drive,
so the node works in it (`node.drive`) and `node.driveNeedsSync` is `true`: the
drive is not on this device yet, so the store is empty until you `connect` to
the server both devices use. The drive is fetched from the server and from then
on both devices see each other's writes through it. (Pass `drive:` to work in
another drive instead; a file that already remembers a drive keeps it, so you
do not need to store the drive subject next to the secret.) This needs a server that holds the drive, or a paired device: two devices
with no server pair over Iroh (`node.peers`).

## Identity, drives, sync, peers, sharing

Everything below lives in Rust (`atomic_lib`) and is reached through the node,
so an app writes screens, not sync logic. Each part is an interface
(`Identity`, `Drives`, `ServerSync`, `Peers`, `Sharing`) with a fake in
`package:atomic_store_flutter/testing.dart`; take the interface in your
widgets and pass `node.peers` etc. in production.

### Identity (`node.identity`)

```dart
final made = await node.identity.create('Alice');    // new agent + private drive
await secureStorage.write(key: 'agent', value: made.secret);

final found = await node.identity.signIn(secret);    // an existing agent
if (found.needsSync) { /* drive is not here yet: node.sync or node.peers */ }
await node.identity.updateProfile(name: 'Alice B');
final me = await node.identity.profile();
await node.identity.signOut();                       // forget the agent here
```

**Keeping the secret is your job**: the package never writes it anywhere.
Whoever has it is the agent. `signIn` makes the store work in the drive the
secret names (`node.drive`, `node.store.drive`).

Signing in as a *different* agent brings the old one's work along: the old agent
adds the new one to `write` on every drive it can write (its private drive only
if it holds something), and they are listed for the new agent. `SignIn.broughtAlong`
has those drive subjects (show "your notes are in your account now"), and
`SignIn.previousSecret` is the old agent's secret, which the package does not
keep: archive it. Nothing is copied; a second sign-in brings nothing.

### Drives (`node.drives`)

```dart
final list = await node.drives.list();               // names, icons, current first
final work = await node.drives.create('Work');       // and switches to it
await node.drives.switchTo(list.first.subject);      // remembered for next start
node.drives.watchCurrent().listen(...);              // node.store.drive follows
```

### Server (`node.sync`)

```dart
final status = await node.sync.resume(savedOrigin);  // on app start, 10 s at most
// ResumeStatus.ready | offline | needsSync
node.sync.watchStatus().listen((s) => print(s.connected));

// A drive that is not here and no server is saved: look it up. Its public
// record (pkarr) names servers; each must prove it hosts the drive.
final origin = await node.sync.discover(drive);      // connects to the first that proves it
```

`resume` never throws for an unreachable server (`offline`: writes wait on
disk). `connect(origin)`, `disconnect()`, `pushPending()` and
`verifiedOrigins(drive)` are there too. Which server to use, and remembering
it, is the app's.

### Devices (`node.peers`)

Sync between devices over Iroh (QUIC), no server: pair with a QR code and the
devices keep each other's drive up to date while both are online.

```dart
await node.peers.start();                            // once; own node id
showQr(node.peers.pairingCode);                      // 'atomic:node:<id>:<device name>'
await node.peers.pair(scannedText);                  // device B: parse, sync, remember
node.peers.watchKnown().listen(...);                 // paired devices, live flag
node.peers.watchLive().listen(...);                  // connected right now
await node.peers.syncNow();                          // all paired + connected
node.peers.rename(id, 'Kitchen tablet'); node.peers.remove(id);
```

`PairingCode.parse(text)` reads what a scanner returns (it also reads the
`atomic://pair?…` codes the web and desktop apps show) and returns `null` for
anything else. A code is routing only: the device dialed proves it holds the
same agent key before anything crosses. Call `node.peers.setForeground(bool)`
from the app lifecycle so the background search stops.

**Peers belong to the process.** Iroh runs one endpoint per process and it
serves the store of the first node that calls `peers.start()`; another node
in the same process gets an error from it. With one node per app (the only
supported use) there is nothing to do. The node's database must be the
`path` you opened (a path is opened once per process).

### Sharing (`node.sharing`)

Sharing in Atomic Data is two things, both mirrored from `@tomic/lib` and the
web app's Share dialog:

- **Rights** are the `read` and `write` properties of a resource: lists of
  agent subjects, inherited down `parent`. `sharing.grant`, `revoke`,
  `setPublic` and `rights` edit and read them, as an ordinary signed write.
- **Invites** are stateless tokens the inviting agent signs for a target
  resource; the server that hosts it grants the right when someone accepts.

```dart
await node.sharing.grant(folder, friendAgentSubject, ShareRole.write);
await node.sharing.setPublic(folder, ShareRole.read);    // anyone with the link may read
final link = node.sharing.inviteLink('https://my.server', folder,
    role: ShareRole.read, maxUsages: 5);               // <server>/app/invite?token=…
```

Accepting an invite happens in the server's web app (`/app/invite`) or its
`/invites` endpoint; the package only creates invites. An invite needs a
resource on a server, so connect the node first, and the inviter must be
allowed to write the target (the server checks).

## Testing without the native library

```dart
final store = Store(backend: InMemoryBackend());              // atomic_store/testing.dart
final peers = FakePeers(deviceName: 'Test phone')..reachable.add(otherId);
final sync = FakeServerSync()..servers.add('https://s.example');
final drives = FakeDrives(store);
final identity = FakeIdentity(store);
final sharing = Sharing(store, (t, w, e, m) => 'token');      // real rights logic
```

`FakePeers.connect(id)` / `disconnect(id)` simulate a device coming and going;
`HomeServerDiscovery` takes an `http.Client` (use `MockClient`).

## Still on you

- Where to keep the agent secret, and the sign-in / account screens. The
  package gives you `identity`, not UI; the atomic.place app (`flutter/`) has
  screens you can read.
- Which server to use and remembering it: `sync.connect` takes an origin you
  choose, `sync.discover(drive)` finds one for a drive.
- Accepting an invite (opening the invite link on the receiving side).
- Files/blobs, history and the assistant/chat calls exist in the raw bridge
  (`package:atomic_store_flutter/bridge/api/...`, generated and unstable; `node.handle` is the
  `AtomicStore` of `bridge/api/resources.dart`) but
  have no typed Dart wrapper here yet.
- Releases: not on pub.dev; pin a git ref.

## Layout and maintenance

```
lib/atomic_store_flutter.dart   AtomicFlutter, AtomicNode, BridgeStoreBackend,
                                Peers, ServerSync, Drives, Identity, Sharing
lib/testing.dart                fakes of the above (no native library)
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
