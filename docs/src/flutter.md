{{#title Flutter and Dart: native Atomic Data apps}}
# Flutter / Dart: native apps with `atomic_lib`

The Rust library that powers AtomicServer, [`atomic_lib`](rust-lib.md), also compiles into Flutter apps.
A phone or tablet running your app gets the same local store, the same signing, the same CRDT merging and the same [peer sync](sync.md) as the desktop and the browser.
It is not a REST wrapper around a server: the app works with no server at all, and syncs to one, or to another phone, when you ask it to.

The bridge is [`flutter_rust_bridge`](https://github.com/fzyzcjy/flutter_rust_bridge).
On Android and iOS it goes through `dart:ffi`; on the web the same Rust is compiled to WASM.

## Status

The Dart SDK lives in the repository under [`flutter/lib/atomic`](https://github.com/ontola/atomic-server/tree/develop/flutter/lib/atomic), inside **Atomic Canvas**, a collaborative infinite drawing canvas that ships as the reference app.
It is not yet published on pub.dev.
The API is still moving, so expect to vendor it or depend on the git path for now; the extraction into a package is planned in `planning/dart-sdk-package.md`.
The canvas-specific calls (strokes, folders, thumbnails) sit next to the general ones; only the general ones are described here.

## What the SDK gives you

The client is grouped by concern, and everything up to the last group is purely local: nothing touches the network until you call a sync method.

| Group | Calls | What it does |
| --- | --- | --- |
| Database | `openDb(path)` | Open (or create) the local store on disk |
| Agent | `setup(name)`, `loadAgent(secret)`, `getActiveAgent()` | Create a keypair and a personal Drive, or restore one from a secret. Pure local. |
| Drive | `createDrive(name)`, `listDrives()`, `setActiveDrive(subject)` | Workspaces, addressed by `atomic:` identifiers |
| Resource | `getProperty(subject, property)`, `setProperty(subject, property, value)` | Read and write; a write is signed and applied locally at once |
| History | `getResourceHistory(subject)`, `getResourceAtVersion(subject, version)` | Time travel over the Resource's Loro oplog, no network needed |
| Peer sync | `startPeer()`, `getPeerId()`, `peerSync(nodeId)`, `peerAnnounce(drive)`, `peerDiscoverSync(drive)` | Device-to-device over Iroh: pair by scanning a code, or discover a Drive through the pkarr relay |
| Server sync | `openWsSync(serverUrl)`, `syncDriveToServer(serverUrl)` | Talk to an always-on device over WebSocket: subscribe to live updates, or push a Drive that was created on this phone so a browser can reach it |

The distinction in the last two rows matters.
Connecting to a server *fetches* a Drive this device lacks and pushes commits made from then on.
A Drive created on the phone before it ever connected anywhere has to be offered explicitly with `syncDriveToServer`; that is the only way it reaches a browser tab, which cannot be paired with.

## A minimal flow

```dart
import 'package:your_app/atomic/atomic_client.dart';

// 1. Local store. Nothing here needs a network.
await AtomicClient.openDb('$appDir/atomic.redb');

// 2. Identity. Keep the secret; it is the account.
final setup = await AtomicClient.setup('Alice');
// setup.agentSubject  -> atomic:agent:...
// setup.driveSubject  -> atomic:...   (Alice's personal Drive)
// setup.agentSecret   -> store this in secure storage

// 3. Read and write. The write is signed and lands locally immediately.
await AtomicClient.setProperty(
  setup.driveSubject,
  'https://atomicdata.dev/properties/description',
  'Written on a train',
);
final desc = await AtomicClient.getProperty(
  setup.driveSubject,
  'https://atomicdata.dev/properties/description',
);

// 4. Later, with a network: sync.
await AtomicClient.startPeer();            // this device becomes dialable
final myCode = await AtomicClient.getPeerId(); // show as a QR code
// ...or, on the other device, after scanning:
await AtomicClient.peerSync(scannedNodeId);
```

On the next launch, `loadAgent(secret)` restores the identity and the local store already holds the data.

## Reacting to changes

Sync applies remote commits to the local store in the background.
The app learns about them by polling the store's event stream:

```dart
while (mounted) {
  final event = await AtomicClient.pollDbEvent(timeoutMs: 60000);
  if (event == null) continue; // timeout, nothing changed
  // event['subject'] changed, was destroyed, or entered / left a watched query
  refresh(event['subject'] as String);
}
```

`AtomicStore`, a `ChangeNotifier` in the same folder, wraps this into `watch(subject)` streams for widgets.

## Signing HTTP requests from Dart

Some endpoints on an always-on device, such as file download, check who is asking.
`atomic_auth.dart` signs those requests in pure Dart using the same scheme as `@tomic/lib` and `atomic_lib`: sign `"<url> <timestamp>"` with the Agent key and send the signature, public key, timestamp and Agent identifier as headers.
See [Authentication](authentication.md#per-request-signing).

## Running the reference app

Atomic Canvas targets Android, iOS and web from one codebase.
The [`flutter/README.md`](https://github.com/ontola/atomic-server/blob/develop/flutter/README.md) has the dev loop (`make phone`, `make tablet`, `make web`, hot reload from any terminal) and the pairing walkthrough: open Settings, show a code on one device, scan it on the other, and both devices exchange data regardless of who started.

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
