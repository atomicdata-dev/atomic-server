# Step 5: the same Drive on a phone

A browser tab cannot be dialed by another device, so in step 4 the server was the meeting point.
A phone running `atomic_lib` is different: it is a full peer.
It holds its own copy, can be dialed directly, and can serve the Drive to yet another device.

This step uses the [Flutter SDK](../flutter.md).
Building a Flutter UI on it is the same sequence of calls.

## Restore the identity

On the phone, sign in with the secret from step 1.
In the SDK that is one call:

```dart
await AtomicFlutter.init();
final node = await AtomicFlutter.open(path: appDir, agentName: 'Phone');
await node.identity.signIn(secret); // the string from Agent.buildSecret
```

This restores *who you are*.
The phone's store is still empty: a secret carries no data.

## Get the data across

Two routes, and they can both be on:

**Through the server.** Give the phone the server's address. It opens a WebSocket as your Agent and fetches the Drives it lacks, including the reading list, then subscribes to live updates.

```dart
await node.sync.connect('http://your-server:9883');
// on later launches: await node.sync.resume(savedOrigin);
```

**Directly from the laptop**, if the laptop runs the desktop app or a local AtomicServer rather than only a browser tab.
Show the pairing code on one side and scan it on the other.
Both devices prove their Agent over the link, compare version vectors, and exchange only what differs.

```dart
await node.peers.start();
final code = node.peers.pairingCode; // render as a QR code
// on the scanning side:
await node.peers.pair(scannedText);
```

The code carries the *route* to the device and nothing else.
What crosses the link is decided by the rights on each Resource, the same check the server ran in step 4.

## Edit anywhere

Add a Book on the phone in a tunnel.
It is signed, saved locally, and queued.
When the phone next sees the server or the laptop, the commit travels, the browser's `store.subscribe` callback fires, and the list updates.
Edit the same Book on both devices while apart and the two edits merge; nobody is asked to pick a winner.

## What you have

The reading list on a laptop, a server and a phone.
Each copy is complete, each edit is signed, and any one of the three can go away without the other two losing anything.
That is the whole local-first story, in one small app.

## Where to go from here

- Model your own data with the [ontology editor](../atomicserver/gui.md) and generate types with [`@tomic/cli`](../js-cli.md).
- Use [`@tomic/react`](../usecases/react.md) or [`@tomic/svelte`](../svelte.md) instead of raw `store.subscribe` calls.
- Read [Atomic Sync](../sync.md) for what the engine does under the hood, and [URLs and identifiers](../urls.md) for every identifier you met along the way.
