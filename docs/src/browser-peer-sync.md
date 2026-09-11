# Browser peer sync

The Sync page can connect up to eight browsers without an Atomic Cloud Server subscription.
Create a peer link in the source drive's Sync page, share it with the other person,
and connect from that link. Give a different agent access through Share first;
a peer link introduces devices but does not grant read or write permission.
Local browser storage is enabled when connecting so edits survive reloads.

Browsers must be open to exchange changes. Signed edits, presence, document
updates and attachment blobs use an encrypted WebRTC data channel. Offline edits
remain in local storage and reconcile when the browsers meet again. Closing every
replica makes the data unavailable to other people until a replica returns. A
Cloud Server can provide an always-online replica independently of peer pairing.

## Discovery and transport

A random 256-bit room secret in the invitation identifies a rendezvous room at
Atomic SaaS's `/webrtc-signal`. The secret is sent in the WebSocket join message, not its URL.
The signaling server exchanges offers and answers and keeps no drive data. There
is no Pkarr lookup. Each room supports up to eight browsers in a full mesh; the app remembers
one link per drive and agent. Disconnect removes that browser's saved link.
Each browser maintains up to seven independent authenticated connections. Local
edits and presence go directly to each connected peer; incoming frames are not
rebroadcast. Reconciliation carries persisted state across reconnects. A failed
connection only retries that peer, and the group continues when the invitation
creator leaves. Larger groups and rotating connections are not implemented.

For a device with no local drive state, the invitation creator must be reachable
for the initial trusted download. Once initialized, the drive's stored permissions
authorize other peers independently. Any initialized member can create an invite
for the existing room, naming themselves as that initial trusted peer; this does
not create a separate group or change anyone's permissions.

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

The signaling endpoint is served by **Atomic SaaS**, not an AtomicServer data
node. It requires no SaaS login, drive enrollment or Cloud Server subscription.
The browser uses `VITE_MANAGED_PORTAL_URL` for its SaaS environment, defaulting to
`https://atomicserver.eu` (or the staging SaaS origin for the staging app). Users
do not select a data node to discover peers.

`VITE_ATOMIC_SIGNALING_URL` overrides discovery for self-hosted/community
services. Use WSS outside loopback development. Local portal Vite proxies
`/webrtc-signal` to `ATOMIC_SAAS_API_ORIGIN` with WebSocket support.

Invitations preserve their chosen endpoint. Experimental links from earlier
versions of this PR that point at a data node must be disconnected and recreated
against SaaS; explicit custom endpoints are not silently rewritten.

The endpoint supplies Cloudflare's public STUN address. For coturn REST
credentials, configure the signaling process with:

- `ATOMIC_SAAS_WEBRTC_TURN_URLS`: comma-separated `turn:` / `turns:` URLs.
- `ATOMIC_SAAS_WEBRTC_TURN_SECRET`: coturn's shared authentication secret.

Only one-hour credentials are sent to clients. Never put the shared secret in a
frontend environment variable. `VITE_ATOMIC_ICE_SERVERS` can override the supplied
ICE configuration for development. TURN bandwidth and public service operation
remain the operator's responsibility; subscription-free access is a deployment
policy, not a guarantee of free infrastructure.

Signaling limits rooms to eight peers, 512 concurrent rooms and 2048 sockets. It
limits message sizes and message rates, removes empty rooms and renews sockets
after 30 minutes. Public operators should also apply network-level abuse limits.

## Current limits and verification

Frames are limited to 16 MiB. This bounds a single snapshot or blob transfer;
larger attachments need additional application-level chunking. Sync sends the
resources available in the browser's local database. A partial cache of a hosted
drive is not proof that the browser holds the entire drive.

Group acceptance uses eight separate Chromium contexts, real WebRTC and OPFS, distinct
agents, and no AtomicServer data requests. It exercises initial replication,
concurrent creations, group presence, attachments, creator departure, offline
reconciliation and signed deletion. A ninth room member is rejected. The separate
two-browser acceptance also checks reload persistence. The Sync page controls are separately exercised in Chromium.
The lower-level transport also runs in Firefox. Two physical devices, full
Firefox drive sync, forced TURN, and a deployed public service remain unverified.

## Local acceptance without a data server

In the matching `atomic-saas` checkout:

```sh
cargo run --example peer_signaling
```

This fixture runs the same SaaS handler on loopback port 6791 without account,
billing or node provisioning dependencies. In `atomic-server`:

```sh
ATOMIC_PEER_SIGNALING_URL=ws://127.0.0.1:6791/webrtc-signal node browser/e2e/scripts/verify-peer-mesh.mjs
ATOMIC_PEER_SIGNALING_URL=ws://127.0.0.1:6791/webrtc-signal node browser/e2e/scripts/verify-peer-sync.mjs
```

Neither script starts an AtomicServer process. They use real WASM/OPFS and reject
HTTP data requests. Public SaaS deployment and forced-TURN verification remain
separate release checks.
