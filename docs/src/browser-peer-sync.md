# Browser peer sync

The Sync page can pair two browsers without an Atomic Cloud Server subscription.
Create a peer link in the source drive's Sync page, share it with the other person,
and connect from that link. Give a different agent access through Share first;
a peer link introduces devices but does not grant read or write permission.
Local browser storage is enabled when connecting so edits survive reloads.

Both browsers must be open to exchange changes. Signed edits, presence, document
updates and attachment blobs use an encrypted WebRTC data channel. Offline edits
remain in local storage and reconcile when the browsers meet again. Closing every
replica makes the data unavailable to other people until a replica returns. A
Cloud Server can provide an always-online replica independently of peer pairing.

## Discovery and transport

A random 256-bit room secret in the invitation identifies a rendezvous room at
`/webrtc-signal`. The secret is sent in the WebSocket join message, not its URL.
The signaling server exchanges offers and answers and keeps no drive data. There
is no Pkarr lookup. Each room currently supports two browsers; the app remembers
one link per drive and agent. Disconnect removes that browser's saved link.

Peers authenticate using Atomic agent signatures over a fresh challenge bound to
the drive and both WebRTC certificate fingerprints. The local Rust node validates
permissions, drive scope and signed commits before persisting received data.
Snapshot reconciliation uses the existing authenticated-writer trust policy;
snapshots are not independently signed state certificates. Deletions require
signed evidence. Pair only with agents you intend to trust with the drive.

WebRTC attempts a direct connection using ICE/STUN. The UI reports whether the
selected path is direct or relayed. TURN, when configured, relays encrypted data
when direct connections fail. Neither signaling nor TURN is an always-online
storage replica. Browser execution can be suspended in background tabs.

## Operator configuration

Serve the signaling endpoint over HTTPS/WSS. The app defaults to its configured
AtomicServer's `/webrtc-signal`; set `VITE_ATOMIC_SIGNALING_URL` at frontend build
time to use a separate shared service. No subscription check is made by this
endpoint. Local development permits unencrypted WebSocket signaling on loopback.

The endpoint supplies Cloudflare's public STUN address. For coturn REST
credentials, configure the signaling process with:

- `ATOMICSERVER_WEBRTC_TURN_URLS`: comma-separated `turn:` / `turns:` URLs.
- `ATOMICSERVER_WEBRTC_TURN_SECRET`: coturn's shared authentication secret.

Only one-hour credentials are sent to clients. Never put the shared secret in a
frontend environment variable. `VITE_ATOMIC_ICE_SERVERS` can override the supplied
ICE configuration for development. TURN bandwidth and public service operation
remain the operator's responsibility; subscription-free access is a deployment
policy, not a guarantee of free infrastructure.

Signaling limits rooms to two peers, 512 concurrent rooms and 2048 sockets. It
limits message sizes and message rates, removes empty rooms and renews sockets
after 30 minutes. Public operators should also apply network-level abuse limits.

## Current limits and verification

Frames are limited to 16 MiB. This bounds a single snapshot or blob transfer;
larger attachments need additional application-level chunking. Sync sends the
resources available in the browser's local database. A partial cache of a hosted
drive is not proof that the browser holds the entire drive.

Local acceptance uses separate Chromium contexts, real WebRTC and OPFS, distinct
agents, and no AtomicServer data requests. It exercises initial replication,
concurrent edits, presence, attachments, offline reconciliation, reload and
signed deletion. The Sync page controls are separately exercised in Chromium.
The lower-level transport also runs in Firefox. Two physical devices, full
Firefox drive sync, forced TURN, and a deployed public service remain unverified.
