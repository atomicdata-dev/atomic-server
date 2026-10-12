{{#title Atomic Sync: keeping devices in agreement without a central server}}
# Atomic Sync

Atomic Sync is how two copies of a Drive end up holding the same data.
It is one protocol with one set of rules, spoken over whichever transport connects the two devices: a WebSocket to an always-on device, an Iroh QUIC stream between two phones, or a WebRTC data channel between two browser tabs.
The transport changes; what crosses it, and who is allowed to send it, does not.

This page explains the model. The [wire protocol reference](websockets.md) has every frame and byte; [browser peer sync](browser-peer-sync.md) covers the WebRTC path and its operator settings.

## Why sync instead of request and response

In the HTTP era a client asked a server for the current state, and the server was the only place that state lived.
Every edit was a round trip, and no connection meant no work.

In the [local-first](local-first.md) model each device keeps a full copy of the Drives it uses.
Edits are applied to that local copy first, immediately, and are signed by the Agent making them.
Sync is what happens afterwards: the device tells its peers what it changed and asks what it missed.
Because every Resource is a [Loro CRDT](https://loro.dev) document, two devices that edited the same Resource while apart merge without conflicts and without a coordinator.

The pieces:

- **A signed [Commit](commits/intro.md)** is the unit of authority. It carries a Loro delta and an Ed25519 signature. Any device that receives one verifies the signature and the signer's rights before applying it. That check is the same code on a server, a phone and a browser tab.
- **A version vector** per Resource lets two devices find out what the other lacks by comparing summaries, not by re-sending everything.
- **An outbox** holds edits made while offline. It drains to the first reachable peer, in order, and survives a restart.
- **Rights decide, on every transport.** A device serves a peer only the Resources that peer's Agent may read, and accepts only writes that Agent may make. Pairing two devices introduces them; it grants nothing.

## Transports

| Transport | Between | When it is used | Live updates |
| --- | --- | --- | --- |
| WebSocket | A browser, phone or CLI and an always-on device (an AtomicServer) | Whenever the client knows the server's address. The default for the web app. | Yes: subscriptions push each applied commit |
| Iroh (QUIC, peer to peer) | Two devices running `atomic_lib`: phones, desktops, home servers | After scanning a pairing code. Works through NAT via a relay, direct when possible. | Yes, once both sides are in live mode |
| WebRTC | Up to eight browser tabs, with no server holding the data | From the Sync page in the web app. A signaling service introduces the tabs; data flows tab to tab. | Yes, plus presence and cursors |
| HTTP `POST /commit` | Any client and an AtomicServer | Fallback when no socket is open, and for scripts | No |

A browser tab is the odd one out: it cannot accept incoming connections, so it is never a peer another device can dial.
It reaches other devices through an always-on device, or through the WebRTC room.
A phone or desktop running `atomic_lib` *is* a peer: it can be dialed, and it can serve.

Discovery, the step of finding an address for a Drive you only know by its `atomic:` identifier, is separate from transport.
A device announces that it holds a Drive through the pkarr relay network, and a client looks that up to find an Iroh node to dial; see [resolution](identifiers.md#resolution).
A mesh transport over [Reticulum](https://reticulum.network/) is planned but not built.

## What crosses the link

Not everything a device holds travels, and not everything that travels is kept.

- **Persisted state**: signed commits, and on trusted links the Loro snapshots they produce. This is what a peer stores, indexes and serves onward.
- **Ephemeral state**: edits in progress on a rich-text document, cursor positions, who is present in a Drive. Broadcast to whoever is connected right now, never written to disk, gone when the tab closes.
- **Blobs**: the bytes behind a [File](files.md), fetched by hash on demand rather than pushed with the Drive.
- **Deletes**: a signed destroy commit, so a peer can check that whoever deleted was allowed to. A bare "delete this" frame from a peer is ignored.

## A day in the life of an edit

1. You change a cell in a table on your laptop, on a train, with no connection.
2. The change is written to the laptop's local store and shows up in the UI at once. The laptop signs a commit for it and puts it in the outbox.
3. Back online, the laptop opens a WebSocket to your always-on device, proves who it is, and drains the outbox. The server verifies the signature and your write right, applies the Loro delta, and pushes the update to every other subscribed client.
4. Your phone, paired to the laptop directly, dials it over Iroh the next time both are awake. They compare version vectors, exchange only what differs, and end up identical.
5. Meanwhile a colleague edited the same table from a browser tab. Their commit and yours merge in the CRDT. Nobody sees a conflict dialog.

## Where the code lives

The sync engine is transport-agnostic and lives in `atomic_lib` (`lib/src/sync/`).
The server, the Flutter app and the WASM build in the browser all run that same engine, which is why a phone can act as a hub for another phone.
The TypeScript client in `@tomic/lib` mirrors the frame encoding for the WebSocket and WebRTC paths.

## Up next

- The full frame-by-frame [wire protocol](websockets.md), if you are implementing a client or a peer.
- [Browser peer sync](browser-peer-sync.md), for the WebRTC room and how to run the signaling endpoint yourself.
- [Decentralized Identifiers](did.md), for how a device finds a Drive it has never seen.
