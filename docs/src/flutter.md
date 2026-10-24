{{#title Flutter and Dart: native Atomic Data apps}}
# Flutter / Dart: native apps with `atomic_lib`

The Rust library that powers AtomicServer, [`atomic_lib`](rust-lib.md), also compiles into Flutter apps.
A phone or tablet running your app gets the same local store, the same signing, the same CRDT merging and the same [peer sync](sync.md) as the desktop and the browser.
It is not a REST wrapper around a server: the app works with no server at all, and syncs to one, or to another phone, when you ask it to.

The bridge is [`flutter_rust_bridge`](https://github.com/fzyzcjy/flutter_rust_bridge).
On Android, iOS, macOS and Linux it goes through `dart:ffi`. Flutter web is not supported: a browser has no native node, so use [`@tomic/lib`](js.md) there.

## Status

The SDK is two Dart packages in the repository:

- [`atomic_store`](https://github.com/ontola/atomic-server/tree/develop/packages/atomic_store) is pure Dart, with no Flutter and no native code.
  It has a `Store` and `Resource` API that mirrors `@tomic/lib` (`getResource`, `newResource`, `search`, `watch`, `resource.set`, `save`), over a `StoreBackend` you can swap.
- [`atomic_store_flutter`](https://github.com/ontola/atomic-server/tree/develop/packages/atomic_store_flutter) is an FFI plugin that builds `atomic_lib` for you and gives you a working `Store` through `AtomicFlutter.open`.
  You never touch Rust or `flutter_rust_bridge`.

Neither is on pub.dev yet.
Depend on a git ref or a path, and pin the ref.
The first native build compiles `atomic_lib` and takes about 10 minutes.
Web is not supported by `atomic_store_flutter`, because a browser has no native node; use a different `StoreBackend` there.

## Add it to your app

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

The Rust crate reaches `atomic_lib` through a relative path, so the dependency must come from a full checkout of this repository.
A git dependency clones all of it, so that holds.
The [package README](https://github.com/ontola/atomic-server/tree/develop/packages/atomic_store_flutter) lists the prerequisites (Flutter version, Rust via rustup, Android NDK or Xcode, Linux build packages).

## What the node gives you

`AtomicFlutter.open` returns an `AtomicNode`.
Everything up to sync is purely local: nothing touches the network until you call a sync method.

| Part | What it does |
| --- | --- |
| `node.store` | The `Store`: read, write, search and watch resources in `node.drive` |
| `node.identity` | Create an agent, sign in with a secret, profile, sign out |
| `node.drives` | List, create and switch Drives (workspaces) |
| `node.sync` | Sync with a server over WebSocket: `connect`, `resume`, `discover`, `watchStatus` |
| `node.peers` | Device to device over Iroh: start, pairing code, `pair`, known and live devices |
| `node.sharing` | Rights (`grant`, `revoke`, `setPublic`, `rights`) and invite links |
| `AtomicAccountButton` | An app bar button that opens the shared user panel (`AtomicNodeSettings` over the node) for name, workspaces, sign in, secret, invite link, adding a device and sign out |
| `node.handle` | The raw bridge handle, for everything not wrapped yet |

Connecting to a server *fetches* a Drive this device lacks and sends the writes that are waiting.
Writes always succeed locally first; offline, they wait on disk until the next `connect`.
The node does not reconnect on its own: call `connect` or `resume` again after a drop.

## A minimal flow

```dart
import 'package:atomic_store/atomic_store.dart';
import 'package:atomic_store_flutter/atomic_store_flutter.dart';

await AtomicFlutter.init(); // once, in main()

// 1. Local node: database, signing agent and a private Drive.
//    Nothing here needs a network.
final node = await AtomicFlutter.open(path: appDir, agentName: 'Alice');
await secureStorage.write(key: 'agent', value: node.agentSecret); // the secret is the account

// 2. Read and write. The write is signed and lands locally immediately.
final note = node.store.newResource(
  isA: [Classes.folder],
  props: {Props.name: 'Written on a train'},
);
await note.save(); // one signed commit

// 3. Later, with a network: sync with a server...
await node.sync.connect('https://example.com');

// ...or with another device, no server needed.
await node.peers.start();               // this device becomes dialable
showQr(node.peers.pairingCode);         // render as a QR code
await node.peers.pair(scannedText);     // on the other device, after scanning

// 4. Share.
await node.sharing.grant(note.subject, friendAgentSubject, ShareRole.write);
```

On the next launch, pass the saved secret and the same path: `AtomicFlutter.open(path: appDir, agentSecret: saved)`.
The node signs as the same agent, works in the Drive it was last in, and the local store already holds the data.
Open a database path once per process and keep the `AtomicNode`.

For a second device of the same person, open with the same secret and a new path.
`node.driveNeedsSync` is then `true`: the Drive arrives when you `connect` to a server that holds it, or `pair` with a device that has it.
`node.sync.discover(drive)` looks up servers for a Drive through its public record, and each must prove it hosts the Drive.

The package also has a runnable [example app](https://github.com/ontola/atomic-server/tree/develop/packages/atomic_store_flutter/example) of about 100 lines.

## Reacting to changes

Sync applies remote commits to the local store in the background.
The `Store` turns the node's event stream into Dart streams, so you do not poll:

```dart
// One resource: emits now, then once per change, and ends when it is destroyed.
node.store.watch(subject).listen((r) => print(r.name));

// A live list: the children of a parent, again whenever they change.
node.store.watchChildren(folder.subject).listen((List<Resource> notes) { /* ... */ });
```

Both fit a `StreamBuilder`.
There is also `store.subscribe(subject, callback)` with a cancelable subscription, like `@tomic/lib`.
Local and synced writes are both seen.
`node.drives.watchCurrent()`, `node.sync.watchStatus()` and `node.peers.watchKnown()` / `watchLive()` do the same for Drives, connection state and paired devices.

## Testing without the native library

`atomic_store` has `InMemoryBackend` in `package:atomic_store/testing.dart`, and `atomic_store_flutter` has fakes of each node part in `package:atomic_store_flutter/testing.dart`.
Take the interface (`Peers`, `ServerSync`, `Drives`, `Identity`, `Sharing`) in your widgets and pass `node.peers` and friends in production.

```dart
final store = Store(backend: InMemoryBackend());
final peers = FakePeers(deviceName: 'Test phone');
final sync = FakeServerSync();
```

`backend.touch(subject)` and `backend.destroy(subject)` simulate someone else's edit or delete.
The package READMEs have recipes for testing streams and widgets.

## What is not wrapped yet

- Accepting an invite on the receiving side.
  The node creates invite links; accepting happens in the server's web app (`/app/invite`) or its `/invites` endpoint.
- Files and blobs, and history (time travel over a Resource's Loro oplog).
  They exist in the raw bridge (`package:atomic_store_flutter/bridge/api/...`, generated and unstable) but have no typed Dart wrapper.
- Which server to use and remembering it.
  `open` remembers the agent secret in the OS keychain; `AtomicAccountButton` opens the account panel.
  Signing in through the atomic.place website is not in the package.

## Signing HTTP requests from Dart

Some endpoints on an always-on device, such as file download, check who is asking.
The reference app signs those requests in pure Dart (`flutter/lib/atomic/atomic_auth.dart`) using the same scheme as `@tomic/lib` and `atomic_lib`: sign `"<url> <timestamp>"` with the Agent key and send the signature, public key, timestamp and Agent identifier as headers.
See [Authentication](authentication.md#per-request-signing).

## The reference app

The app in [`flutter/`](https://github.com/ontola/atomic-server/tree/develop/flutter) is a full Android, iOS and web client built on these packages.
Its [`README.md`](https://github.com/ontola/atomic-server/blob/develop/flutter/README.md) has the dev loop (`make phone`, `make tablet`, `make web`, hot reload from any terminal) and the pairing walkthrough: open Settings, show a code on one device, scan it on the other, and both devices exchange data regardless of who started.

## Compared to the other clients

| | Flutter (`atomic_lib`) | Browser (`@tomic/lib` + WASM) | Rust (`atomic_lib`) |
| --- | --- | --- | --- |
| Local store | redb on disk | OPFS, encrypted per Agent | redb |
| Can be dialed by a peer | Yes (Iroh) | No; reaches peers through a server or a WebRTC room | Yes (Iroh) |
| Talks to a server | WebSocket, HTTP fallback | WebSocket, HTTP fallback | WebSocket, HTTP |
| Same sync engine | Yes | Yes (WASM build) | Yes |

## Where the vocabulary comes from

The words on screen (workspace, device, pairing code, sync) are shared across the Flutter app, the web app and the desktop app on purpose, so a person meeting more than one of them does not have to learn each.
If you build your own UI on the SDK, borrowing them will make your app feel like part of the same system.
