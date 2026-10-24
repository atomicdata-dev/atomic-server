{{#title The Atomic sync protocol: WebSocket and Iroh peer streams}}

# The Atomic sync protocol (WebSocket and Iroh peer streams)

One binary frame format, spoken over two transports: a browser-facing
WebSocket and a node-to-node Iroh QUIC stream. This page is the canonical
wire-format reference; for the model behind it (what syncs, why, and which
transport is used when) read [Atomic Sync](sync.md) first. It describes what the code on this branch actually
sends and accepts, including which side sends each frame and which
responders have an arm for it.

Encoders and decoders live in `lib/src/sync/protocol.rs` (Rust, source of
truth for tag bytes and layouts) and `browser/lib/src/ws-v2.ts`
(TypeScript). A golden-vector file pins the two together; see
[Conformance](#conformance).

## Overview and transports

A frame is `[tag: u8] [payload...]`. There is no envelope, no version
prefix, and no base64: Loro bytes travel raw.

**WebSocket.** The browser connects to the responder's `/ws` endpoint and
requests the subprotocol `atomicdata-ws.v2`; the server offers exactly that
one. WebSocket supplies its own framing, so a frame is one binary message and
`binaryType` is `arraybuffer`. Some low-volume registration and inventory
messages are still UTF-8 text frames with a keyword prefix, listed under
[Text frames](#text-frames).

The Rust `WsClient` (`lib/src/client/ws.rs`, used by the CLI, the Flutter FRB
bridge and tests) connects with `connect_async(url)` and does **not** request
the subprotocol. The server accepts it anyway, since nothing branches on the
negotiated name. Only the browser reads `ws.protocol` back, to record a
server version hint.

**Iroh QUIC peer streams.** Peers dial each other on the ALPN `atomic/1`
and open one bidirectional stream. QUIC streams are byte streams, not
message streams, so every frame is wrapped in a length envelope:

```
[len: u32 big-endian] [tag: u8] [payload...]      // len covers tag + payload
```

Both directions use it, for every frame including `KEEPALIVE`. A reader that
sees `len == 0`, or a `len` over the applicable cap (see
[Size limits](#size-limits)), drops the connection.

A peer stream has two phases. During the **handshake** the accept side runs
`peer::handle_stream`, which is `AUTH`-gated and delegates everything it does
not intercept to `sync::engine::handle_frame`. Once the bulk exchange
completes both sides move to **live mode** (`peer::register_live_peer`): a
read loop plus a write loop that handle `UPDATE`, `EPHEMERAL`, `KEEPALIVE`
and `COMMIT`, and delegate the rest back to the engine.

## Versioning and capabilities

There is no version number on the wire. A responder advertises named
capabilities and a client adapts to them. Anything not advertised is assumed
absent, which is the pre-2026-09 baseline.

`AUTH_OK (0x02)`'s payload is a JSON array of capability names, UTF-8, with
no length prefix. A responder with nothing to advertise sends a bare
`[0x02]`, which is what every pre-2026-09 build sends; decoders match on the
tag alone, so the payload was additive. `HELLO (0x37)` carries the same array
after the name field, so peers on an Iroh stream learn each other's
capabilities too.

The current list (`protocol::CAPABILITIES`):

| Name | Meaning |
| --- | --- |
| `auth-max-age` | `AUTH` proofs older than `AUTH_MAX_AGE_MS` are refused, and a failed `AUTH` answers with `AUTH_FAILED (8)`. |
| `keepalive` | Understands `KEEPALIVE (0x41)`, and echoes it over WebSocket. |
| `rbsr` | *Retired 2026-09, no longer advertised; never reuse.* Answered the `RBSR_FP` range-fingerprint frames. |
| `pull-from` | `SYNC_DIFF` carries a `pullFrom` map of per-subject version vectors. |
| `signed-destroy` | On a peer stream, destroys travel as signed `COMMIT` frames; a naked `DESTROY` from a peer is ignored. |
| `unsub` | `UNSUB (0x21)` actually cancels a drive subscription. |
| `auth-nonce` | Sends `CHALLENGE (0x42)` as its first frame on a WebSocket and verifies an `AUTH.requestedSubject` of the form `{origin}#{nonce}` against it. |
| `commit-ok-slim` | Answers `COMMIT` with the slim `COMMIT_OK` (`[request_id] [commit_id]`) for a client whose `HELLO` lists `commit-ok-slim`. |
| `client-hello` | Reads a `HELLO (0x37)` from a WebSocket client and records the capabilities it lists. |
| `rebind-on-auth` | Re-evaluates the connection's subscriptions against the new identity when an `AUTH` lands, dropping the ones it may no longer read. |
| `sync-probe` | Reads the `probe` and `subjects` keys of a `SYNC (0x30)` JSON tail and answers a stale probe with `SYNC_RESEND (0x38)`. |
| `ephemeral` | Reads and writes `EPHEMERAL (0x40)` over WebSocket for edits in progress, cursors and drive presence, in place of the `LORO_SYNC_UPDATE` / `LORO_EPHEMERAL_UPDATE` / `PRESENCE_UPDATE` text frames. |
| `commit-pace` | Appends the node's write-load hint (`pace_ms`) to the slim `COMMIT_OK` of a client whose `HELLO` lists `commit-pace`, and may refuse a `COMMIT` with `BUSY (12)` when overloaded. See [Write load and pacing](#write-load-and-pacing). |
| `get-many` | Answers `GET_MANY (0x15)`, a list of subjects, with one `GET_MANY_RESULT (0x16)` holding an `UPDATE` or `ERROR` entry per subject, so a client fetches a whole list in one round trip. |

The list is **additive only**: a name is never renamed or reused once
shipped. Treat an absent name as "not supported" and fall back, never as an
error. The browser stores the list per origin; the Rust client exposes it as
`WsClient::server_capabilities()`.

**Client capabilities.** Since 2026-09 a WebSocket client introduces itself
too: the browser and `WsClient` send a `HELLO` on open, listing what they
speak (`protocol::CLIENT_CAPABILITIES`, `CLIENT_CAPABILITIES` in `ws-v2.ts`).
The server answers nothing (its own list rides on `AUTH_OK`); the list steers
what that connection is sent from then on. The one name a responder acts on
today are `commit-ok-slim` and `commit-pace`. A server that predates `client-hello` drops the
frame unread, and the client gets the pre-2026-09 behaviour.


## Binary tag table

"Sender" is who actually emits the frame in this codebase. "Handled by" says
which responder has an arm for it. A tag with no arm on a transport is
logged and dropped, not answered.

| Tag | Name | Sender | Handled by |
| --- | --- | --- | --- |
| `0x01` | `AUTH` | initiator; also the Iroh accept side, as auth-back | WS handler (binds origin), engine, Iroh handshake and live loop |
| `0x02` | `AUTH_OK` | responder | client / initiator only |
| `0x03` | `ERROR` | either | client / initiator; the Iroh live loop logs and keeps the link |
| `0x10` | `GET` | client, peer | engine (both transports) |
| `0x11` | `UPDATE` | responder, and Iroh peers in live mode | client; Iroh live loop. **No WS server arm**: an `UPDATE` from a browser is dropped. |
| `0x12` | `DESTROY` | responder | client. **No WS server arm.** The Iroh live loop explicitly ignores it (see [Deletes](#deletes)). |
| `0x13` | `COMMIT` | client; Iroh live push loop, for destroys | WS handler (hub semantics), engine (peer semantics) |
| `0x14` | `COMMIT_OK` | responder | client / initiator only. Payload is the full commit JSON-AD, or the bare commit id for a client whose `HELLO` listed `commit-ok-slim`. |
| `0x15` | `GET_MANY` | client | engine (both transports). Sent only to a responder advertising `get-many`. |
| `0x16` | `GET_MANY_RESULT` | responder | client only. |
| `0x20` | `SUB` | client | WS handler only. **No engine arm**, so an Iroh peer cannot subscribe. |
| `0x21` | `UNSUB` | client | WS handler only. **No engine arm.** |
| `0x30` | `SYNC` | Iroh initiator; the browser, as a hash-only probe and then filtered to the differing subjects | engine (both transports) |
| `0x31` | `SYNC_OK` | responder | client / initiator only |
| `0x32` | `SYNC_DIFF` | responder | client / initiator only |
| `0x33` | `SYNC_PUSH` | either | engine (both transports) |
| `0x34` | `BLOB_REQUEST` | either | engine (both transports); the browser also answers from its local blob store |
| `0x35` | `BLOB_RESPONSE` | either | engine (both transports) |
| `0x36` | *reserved* | nobody | nobody. Previously `QUERY_UPDATE`; retired, never reuse. |
| `0x37` | `HELLO` | both peers on an Iroh stream; a WebSocket client on open | Iroh handshake and live loop; the WS handler records the client's capabilities. The WS server never sends one (its capabilities ride on `AUTH_OK`). |
| `0x38` | `SYNC_RESEND` | responder, answering a `SYNC` probe whose hash is stale | client only. Tells the client to send its full version-vector `SYNC`. |
| `0x40` | `EPHEMERAL` | Iroh peers; WS client and server, both ways | Iroh live loop; WS handler (`require_auth`, then the broadcaster). The server relays between the two transports. |
| `0x41` | `KEEPALIVE` | both sides, on their own schedule | WS server **echoes** it; Iroh **never** echoes it. |
| `0x42` | `CHALLENGE` | WS server, as its first frame | client only. Never sent on an Iroh stream. |
| `0x50` | `CALL` | Iroh dialer, after `AUTH` | `atomic_lib::sync::call`, answered by the server's host ABI. Iroh only; the WS server answers it with an `ERROR`. |
| `0x51` | `CALL_RESULT` | Iroh responder | the dialer of the `CALL`. |
| `0x52` | `INVITE` | Iroh dialer, after `AUTH` | `atomic_lib::sync::invite`. Iroh only; the WS server answers it with an `ERROR`. |
| `0x53` | `INVITE_OK` | Iroh responder | the dialer of the `INVITE`. A refusal is an `ERROR` with code 13 (`INVITE_REFUSED`). |

## Frame layouts

All integers are big-endian. A trailing field with no length prefix runs to
the end of the frame.

### Small frames

```
[0x01] [auth_json_utf8]                          // AUTH, see Authentication
[0x02] [capabilities_json_utf8]?                 // AUTH_OK, JSON array, may be absent
[0x03] [request_id: u16] [code: u16] [message_utf8]      // ERROR
[0x10] [request_id: u16] [subject_utf8]                  // GET
[0x15] [request_id: u16] [count: u16] ([subject_len: u16] [subject_utf8])*   // GET_MANY
[0x16] [request_id: u16] [count: u16] ([frame_len: u32] [frame])*             // GET_MANY_RESULT
[0x12] [request_id: u16] [subject_utf8]                  // DESTROY
[0x13] [request_id: u16] [signed_commit_json_ad_utf8]    // COMMIT
[0x14] [request_id: u16] [created_commit_json_ad_utf8]   // COMMIT_OK, full form
[0x14] [request_id: u16] [commit_id_utf8]                 // COMMIT_OK, slim form (client HELLO lists commit-ok-slim)
[0x14] [request_id: u16] [commit_id_utf8] 0x00 [pace_ms: decimal ascii]   // COMMIT_OK, paced slim form (client HELLO lists commit-ok-slim and commit-pace)
[0x20] [drive_subject_utf8]                              // SUB
[0x21] [drive_subject_utf8]                              // UNSUB
[0x31] [drive_len: u16] [drive_utf8]                     // SYNC_OK
[0x38] [drive_len: u16] [drive_utf8]                     // SYNC_RESEND, hash-first probe missed
[0x34] [hash: 32 bytes]                                  // BLOB_REQUEST
[0x35] [hash: 32 bytes] [blob_bytes...]                  // BLOB_RESPONSE
[0x41]                                                   // KEEPALIVE, no payload
[0x42] [nonce_utf8]                                      // CHALLENGE, 64 hex chars today
```

A `COMMIT_OK` decoder tells the two forms apart by the first payload byte: a
`{` is the full JSON (its `@id` is the commit id), anything else is the id
itself (`decode_commit_ok`, `decodeCommitOk`). A full form without an `@id`
is malformed.

An `ERROR`'s `request_id` is `0` for connection-level errors, meaning
everything that does not answer a specific request; see
[Error codes](#error-codes). `hash` is the raw 32-byte BLAKE3 hash of the
blob. A `COMMIT` payload is the same signed JSON-AD body HTTP `POST /commit`
accepts.

### UPDATE (0x11)

```
[0x11] [flags: u8] [request_id: u16] [subject_len: u16] [subject_utf8]
       [commit_id_len: u16] [commit_id_utf8]        // only if HAS_COMMIT_ID
       [loro_bytes...]
```

Flags: `0x01` `SNAPSHOT` (`loro_bytes` is a full Loro snapshot; clear means a
delta), `0x02` `HAS_COMMIT_ID` (the two commit-id fields are present),
`0x04` `PUSH` (a subscription-driven push, not a `GET` response).

`commit_id` is the full `atomic:commit:<signature>` DID, which the receiver
stores as `lastCommit` and uses as `previousCommit` on its next write.

### SYNC (0x30)

```
[0x30] [drive_len: u16] [drive_utf8] [hash_len: u16] [hash_hex_utf8]
       [json_utf8]
```

`hash_hex_utf8` is the drive hash as a lower-case hex **string**, not raw
bytes. `json_utf8` is:

```json
{ "peers": ["<peer id>", "..."],
  "resources": { "<subject>": [<counter>, <counter>, ...] } }
```

Each `resources` entry is a version vector compacted against the `peers`
array: position *i* is that subject's counter for `peers[i]`. Zero counters
are dropped on decode. Two optional keys shape the exchange (`sync-probe`):
`"probe": true` asks for a hash comparison only (the `peers` and `resources`
are empty and ignored), answered with `SYNC_OK` or `SYNC_RESEND (0x38)`;
`"subjects": [...]` restricts the reconcile to that set, so the responder
builds version vectors for those subjects only and both comparison loops
skip everything else. A decoder that predates the capability ignores both
keys and runs the full reconcile. The drive hash is SHA-256 over
`"{subject}:{c0},{c1}|{subject}:{c0},{c1}|…"` with subjects sorted and
counters ordered by the sorted peer set (`engine::compute_drive_hash`; the
browser builds the byte-identical string and hashes it with
`crypto.subtle`).

### SYNC_DIFF (0x32)

```
[0x32] [drive_len: u16] [drive_utf8] [json_utf8]
```

```json
{
  "pull":   ["<subject>", "..."],
  "push":   ["<subject>", "..."],
  "remove": ["<subject>", "..."],
  "pullFrom": { "<subject>": { "<peer id>": <counter> } }
}
```

- `pull`: subjects the **receiver** should send back as `SYNC_PUSH`.
- `push`: subjects the sender is about to push, in the `SYNC_PUSH` frames
  that follow immediately in the same response batch.
- `remove`: subjects the receiver should delete locally. The sender holds a
  tombstone for them and they are absent from its version vectors. Without
  this, a bulk reconcile resurrects deleted resources.
- `pullFrom`: for each `pull` subject, the sender's own version vector, so
  the receiver exports updates *since* that vector rather than a full
  snapshot. A subject absent from `pullFrom`, or mapped to `{}`, means "send
  everything".

The encoder always emits all four keys; decoders default `remove` and
`pullFrom` to empty, so a pre-`pull-from` responder still parses.

### SYNC_PUSH (0x33)

```
[0x33] [drive_len: u16] [drive_utf8] [flags: u8] [count: u16] [entry × count]

entry := [subject_len: u16] [subject_utf8] [bytes_len: u32] [loro_bytes...]

# only when flag 0x02 ENVELOPES is set, after the last entry:
[env_count: u16] [envelope × env_count]
envelope := [subject_len: u16] [subject_utf8] [json_len: u32] [commit_json_ad_utf8]
```

Flags: `0x01` `LAST` marks the final chunk of a run. See
[Chunking](#sync_push-chunking-and-acknowledgement). `0x02` `ENVELOPES`
says the frame ends with the retained signed envelopes of the subjects it
pushes (the commit JSON-AD exactly as `/commit` accepted it; one per subject
on a `latest` node, every one on `all`), so the receiver can attribute the
history it imports. The receiver verifies each envelope's signature and that
it names a subject imported from the same frame before keeping it; a bad
envelope is dropped, never the push. A decoder that predates the flag stops
after `count` entries and does not see the section.

### HELLO (0x37)

```
[0x37] [name_len: u16] [name_utf8] [capabilities_json_utf8]?
```

A self-reported display name, capped at 64 Unicode scalar values; a longer
name is **rejected**, not truncated. Control characters are stripped on
decode so a peer cannot smuggle line breaks into logs. Display only:
authorization uses the authenticated agent and the Iroh NodeId, never this. A
decoder that predates capabilities ignores the trailing bytes.

### CALL (0x50) and CALL_RESULT (0x51)

```
[0x50] [request_id: u16] [json]     // CALL
[0x51] [request_id: u16] [json]     // CALL_RESULT
```

Run an app export (`atomic:host/calls`, see `docs/src/plugins/host-abi.md`) on
the responding node. Iroh only. `CALL` is accepted after `AUTH` and only for
the drive the `AUTH` was signed for, like `SYNC`; any other drive is answered
as a `SYNC` for the wrong drive is.

```json
// CALL
{ "drive": "did:ad:…", "interface": "atomic:example/counter@1",
  "function": "increment", "args": "{\"subject\":\"…\"}",
  "caller": "did:ad:agent:…", "depth": 1,
  "budget": { "calls": 60, "fuel": 15000000000,
              "effects": ["read"], "secrets": false } }
// CALL_RESULT: exactly one of result and error
{ "result": "{\"count\":1}", "callsLeft": 55, "fuelLeft": 14000000000 }
{ "error": { "code": "forbidden", "message": "…" }, "callsLeft": 0, "fuelLeft": 0 }
```

`args` and `result` are JSON text, as in `calls.call`. `error.code` is one of
the host ABI's stable codes. `budget` is what the whole call chain may still
spend; `effects: null` is any effect. The responder never widens it: counts are
capped at its own limits, an effect it does not know is dropped, and
`secrets: false` stays false. `callsLeft` and `fuelLeft` hand back what was not
spent. `depth` is the number of hops so far, this one included. A node answering
a `CALL` does not forward it again.

The `AUTH` on the stream is the dialing *node's* agent, as for a sync. `caller`
is the agent the call is for: the node vouches for it, because the caller's own
key never reaches it. The responder runs the call for `caller` (all the usual
checks), and in addition needs the node's agent to be able to read the drive,
and to write it wherever a hop writes. A `caller` of `sudo` or the public agent
is refused.

### INVITE (0x52) and INVITE_OK (0x53)

```
[0x52] [json {"token": "<base64 invite token>"}]              // INVITE
[0x53] [json {"drive": "did:ad:…", "write": false}]           // INVITE_OK
```

Redeem an invite token (`generateInviteToken` of `@tomic/lib`, signed by the
inviter) at a device of the inviter, without a server. Iroh only. The dialer
finds the device the way it finds any device of a drive: the pkarr record of
the token's target lists the Iroh node ids (`_atomic_nodes`). It sends `AUTH`
for the token's target (`drive#nodeId`, as for a sync), which proves who the
invitee is, and then `INVITE`. The frame is accepted from any authenticated
agent, paired or not: the token is the authority, and `INVITE` for a drive other
than the `AUTH`'s is refused like a `SYNC` for the wrong drive.

The responder grants only when all of these hold, and otherwise answers
`ERROR` with code 13 and a plain sentence as message (nothing is granted):

- the token has not expired ("This invite has expired. Ask for a new one.");
- the token's signer is the responder's **own** agent and the signature
  verifies, because only then can this node sign the change as the inviter
  ("This device did not make this invite, so it cannot accept it.");
- that agent may still write the target in the responder's store.

It then adds the invitee to the target's `read` list (and `write` for a write
invite) in a commit signed by its agent, queues that commit for the inviter's
servers and lets live peers carry it to the inviter's other devices, and
answers `INVITE_OK`. The invitee then syncs the drive from the same device with
an ordinary `SYNC`, which the sync policy admits because the invitee can now
read. `max_usages` of the token is not counted: that needs state shared by all
the inviter's devices. In the link form of the Flutter package this is
`atomic:invite?token=<token>`; the web app does not parse that form yet.

### EPHEMERAL (0x40)

```
[0x40] [kind: u8] [drive_len: u16] [drive_utf8] [agent_len: u16] [agent_utf8]
       [payload...]
```

The agent travels with the frame because a peer link is node-to-node while
presence is per-agent: one node may relay several agents' cursors. The same
frame is the WebSocket form since 2026-09-04: a client sends it with an
empty `agent` (the server attributes it to the connection's authenticated
identity and stamps that on every copy it fans out), and receives it with
the agent filled in. `drive` holds the resource for `LORO` and `DOC` and the
drive for `PRESENCE`.

| `kind` | Name | Browser channel | Gate on receipt from a peer | Max payload |
| --- | --- | --- | --- | --- |
| `0` | `LORO` | `subscribeLoroEphemeral` (cursors) | `check_read` on the scope subject | 64 KiB |
| `1` | `PRESENCE` | `subscribePresenceUpdates` | `check_read` on the scope subject | 64 KiB |
| `2` | `DOC` | `subscribeLoroSync` (an edit in progress) | drive-level **write** verdict | 1 MiB |

`DOC` carries the ops of an edit in progress, so it is content rather than a
cursor: it gets the stricter gate and the looser size cap. Nothing on this
channel is ever persisted. A frame over its cap fails to decode and is
dropped whole. Over WebSocket the gate is the subscription: `require_auth`
first, then the broadcaster relays a frame only from a connection that
subscribed to its subject (`LORO_SYNC_SUBSCRIBE` / `PRESENCE_SUBSCRIBE`,
where `check_read` runs) and, for `DOC`, that may write it.

## Authentication

An `AUTH` payload is a JSON object with these five fields, all required (the
deserializer has no defaults):

```json
{
  "https://atomicdata.dev/properties/auth/agent": "atomic:agent:<pubkey>",
  "https://atomicdata.dev/properties/auth/requestedSubject": "<subject>",
  "https://atomicdata.dev/properties/auth/publicKey": "<base64 ed25519>",
  "https://atomicdata.dev/properties/auth/timestamp": 1756900000000,
  "https://atomicdata.dev/properties/auth/signature": "<base64 ed25519>"
}
```

The signed message is exactly `"{requestedSubject} {timestamp}"`, where
`timestamp` is milliseconds since the epoch. Base64 is accepted in both the
url-safe and the legacy standard alphabet, and keys are compared by decoded
bytes. (The verifier also retries the signature against the path and the
query-stripped URL of `requestedSubject`, a multi-tenant carve-out from the
HTTP auth headers that share this code.)

**Freshness.** A proof is refused if its timestamp is more than 10 000 ms in
the future, or older than `AUTH_MAX_AGE_MS` (5 minutes,
`lib/src/authentication.rs`). Clients sign immediately before sending, so
this window is clock-skew slack, not a session lifetime.

**Challenge nonce (WebSocket).** The server's first frame on every socket,
before the client has said anything, is `CHALLENGE (0x42)` carrying a fresh
nonce (32 random bytes, hex). A client that saw it signs
`requestedSubject = "{origin}#{nonce}"`: the nonce rides in the URL fragment,
so the signed string keeps its `"{requestedSubject} {timestamp}"` shape and
the HTTP auth headers, which never carry a fragment, are untouched. The
responder (`engine::AuthChallenge`) strips the fragment before the origin
comparison below and compares the nonce with the one it issued on *this*
connection; a mismatch is `AUTH_FAILED`. A proof that carries no fragment is
still accepted on its timestamp, so a client that predates the frame keeps
working; `AuthChallenge::Required` refuses those too, and is the strict mode
a deployment can turn on once every client it serves speaks `auth-nonce`
(not wired to a server option yet). The browser waits up to 300 ms for the
challenge before signing a timestamp-only proof; `WsClient` does the same
(`WsClient::auth_subject`). Peer (Iroh) streams have no challenge: the
initiator speaks first, and the QUIC handshake already binds the link to a
node key.

**Binding.** `requestedSubject` is inside the signature, so it is what stops
a proof signed for one place from opening another. Each transport binds it
differently (`engine::AuthBinding`):

| Responder | What the client signs | How the responder binds it |
| --- | --- | --- |
| WebSocket server | the server origin (`new URL(ws.url).origin` in the browser, `http(s)://host[:port]` in `WsClient`), with the challenge nonce in the fragment | `AuthBinding::Origins([request_origin, server_url])`, after the fragment is stripped. The proof's `requestedSubject` must have the same `scheme://host[:port]` as either the origin the upgrade request arrived on (scheme and `Host`, forwarded headers honoured) or the responder's configured server URL, so a full resource URL under one of those is accepted too. Two names because a server is often dialled under a name other than its configured URL (a proxy, a container network) and the browser signs the one it used; the HTTP auth headers have the same tolerance. A responder that knows neither as an absolute http(s) URL cannot bind, and falls through to unbound. |
| Iroh accept side | the drive the initiator is about to sync | `AuthBinding::Unbound` at verification time. The accepted `requestedSubject` is recorded as `bound_drive`, and every subsequent handshake `SYNC` / `SYNC_PUSH` must name that same drive, or the stream is closed with `AUTH_REQUIRED` and the message `AUTH was for <x>, not <y>`. |
| Iroh initiator, receiving the accept side's auth-back | the initiator's node key | The initiator accepts the auth-back only when its `requestedSubject` normalises to the initiator's own node id (`normalize_node_id`); a proof signed for anything else is logged and ignored, and the remote stays `Public` for that connection. |

**Failure.** A refused `AUTH` answers with `ERROR`, `request_id = 0`, code
`AUTH_FAILED (8)`: bad signature, unknown agent, a timestamp outside the
window, or a `requestedSubject` that does not name this responder. Resending
the same frame changes nothing. Over WebSocket the socket stays open and the
client may retry. On an Iroh stream the responder writes the error, finishes
its half, and closes.

**Late AUTH.** `AUTH` is not restricted to the start of a connection. The
WebSocket handler writes the proven identity back onto the connection actor
and, when the identity changed, has the commit monitor re-evaluate every
subscription the connection holds against it (see
[Subscriptions](#subscriptions)). The Iroh live read loop holds a mutable
agent that a mid-session `AUTH` upgrades, invalidating the per-connection
drive-verdict cache so a `Public` verdict cached before the upgrade does not
stick.

**Iroh mutual auth.** After a successful `AUTH` the accept side writes, in
order: `AUTH_OK`, its own `HELLO`, then an `AUTH` of its own back to the
initiator, signed for the remote node key. Best effort: a node with no
default agent does not send it and stays unidentified, with `Public`
semantics. The initiator's own order is `AUTH`, wait for `AUTH_OK`, `HELLO`,
`SYNC`.

## What is refused before AUTH

Until an `AUTH` succeeds the session's agent is `Public`. Anything refused
for that reason answers with `ERROR`, `request_id = 0`, code
`AUTH_REQUIRED (5)`, and the frame is not processed.

**Iroh streams: everything except `AUTH`.** The accept-side dispatch loop
refuses any other tag, including `HELLO` and `SYNC`, and closes the stream.
"Public semantics" was never nothing here: an unauthenticated `SYNC` still
served every publicly readable subject of the drive, and an unauthenticated
`SYNC_PUSH` could bootstrap a new drive onto an open node. The live read loop
restates the same rule for connections dialled into us.

**WebSocket: an anonymous session may read.** This is what a public share
link relies on for live updates. The `require_auth` gate covers exactly:

- binary `SYNC_PUSH (0x33)`, `BLOB_RESPONSE (0x35)` and `EPHEMERAL (0x40)`,
  whatever its kind;
- the identity-bearing text frames `LORO_SYNC_SUBSCRIBE` and
  `PRESENCE_SUBSCRIBE`.

Everything else is open to an anonymous socket and gated per subject by
`check_read` instead:

- `GET`, `SUB`, `SYNC` (including the hash-first probe), and `RBSR_ITEMS`.
  The probe and the inventory answer over `drive_items_for`, which requires
  the drive resource itself to be readable and drops every subject the agent
  cannot read. Filtering also makes the probe hash agree: a client only ever
  holds what it may read.
- `COMMIT (0x13)` is **not** gated. A commit is a self-authorizing
  certificate: its signature, its signer's rights and its schema are all
  validated on application, so the connection's own identity is not the
  authority.
- `BLOB_REQUEST (0x34)` is **not** gated, on either transport, and runs no
  rights check. Knowing the 32-byte content hash is the capability. A
  deliberate, accepted decision: the hash is only learnable from a resource
  the requester was already served.
- Unsubscribing (`UNSUB`, `LORO_SYNC_UNSUBSCRIBE`, `PRESENCE_UNSUBSCRIBE`,
  `UNSUBSCRIBE_INDEX_STATUS`) is never gated.

## Error codes

`ERROR` carries a `u16` code from one registry, shared with the HTTP
`/commit` error body.

| Code | Name | Meaning |
| --- | --- | --- |
| `0` | `UNKNOWN` | No structured classification. Only the message text is meaningful. |
| `1` | `GENESIS_COLLISION` | The commit's subject already exists. Terminal: this write can never succeed. |
| `2` | `MISSING_REQUIRED_PROPERTY` | The result is missing a property its class requires. Terminal. |
| `3` | `UNAUTHORIZED_WRITE` | The signer has no write right on the target or its parents. Blocking, not terminal. |
| `4` | `MISSING_CLASS` | The commit names a class this node does not hold, so validation cannot run. Blocking, not terminal: the class may still arrive. |
| `5` | `AUTH_REQUIRED` | The frame needs an authenticated session. `request_id = 0`. |
| `6` | `SYNC_REJECTED` | A commit was refused by node enrollment/quota policy, or a `SYNC_PUSH` was refused as a whole. Keep local edits; stop unbounded retries. Commits carry their request ID; `SYNC_PUSH` uses `request_id = 0` and message `SYNC_PUSH rejected for drive <drive>: <reason>`. |
| `7` | `UNAUTHORIZED_READ` | A subscription or a read-side reconcile frame was refused. `request_id = 0`. Message: `<FRAME> refused for <subject>: <reason>`. |
| `8` | `AUTH_FAILED` | An `AUTH` frame was refused. `request_id = 0`. |
| `9` | `INVALID_SIGNATURE` | A `COMMIT` whose signature does not verify against its signer's key, or that has none. Terminal for that envelope: sign again. |
| `10` | `IMMUTABLE_COMMIT` | The commit's subject is itself a Commit, which can never be edited. Terminal: drop the entry; nothing is lost. |
| `11` | `CAUSALITY_CONFLICT` | A new Loro write lost against stored state. Keep the local edit; stop sending the same stale update until it is rebased. |
| `12` | `BUSY` | The node is overloaded with writes, or the agent spent its write rate budget. Refused **before** any work; nothing landed. The message carries `retry_after_ms=<n>`. Not a failure: keep the edit, wait, send one merged delta, and do not retry over another transport. See [Write load and pacing](#write-load-and-pacing). |

Codes `1` to `4` and `9` to `12` come from `classify_commit_error`, which pattern-matches the
underlying error text where the frame is built. Many other engine failures
are **not** classified and go out as `UNKNOWN` with a descriptive message: an
invalid frame of any kind, `No state`, a failed `GET` lookup,
`Blob not found`, `Unsolicited blob response`, `Drive not admitted for sync`.
Treat an unrecognized code the same as `UNKNOWN` and fall back to the
message.

## Write load and pacing

The cost of a commit on the node is per commit, not per edit: it rebuilds the
resource's Loro document, rewrites the full snapshot and takes one write
transaction on the single writer. Clients are local first (the edit is already
saved on the device, peers see typing live over `EPHEMERAL`), so when the node
is busy they can send fewer, fatter commits. The node tells them when.

`POST /commit` and the WebSocket `COMMIT` frame share one counter of commits
in flight (taken before the signature check, released when the commit is
answered). Two limits, `--commit-soft-limit` (`ATOMIC_COMMIT_SOFT_LIMIT`,
default 32) and `--commit-hard-limit` (`ATOMIC_COMMIT_HARD_LIMIT`, default 256,
`0` switches the whole mechanism off):

- **Soft signal, `pace_ms`.** With `n` commits in flight, `pace_ms` is `0`
  for `n <= soft` and rises linearly to 10 000 at `n = hard`:
  `10000 * (n - soft) / (hard - soft)`. It is the least time a client should
  leave between two commits of one resource. A client that lists both
  `commit-ok-slim` and `commit-pace` in its `HELLO` gets it on every
  `COMMIT_OK`, appended to the commit id after a NUL byte as decimal ASCII
  (`0` when there is no pressure, so the client can relax). Any other client
  gets the existing `COMMIT_OK` forms, byte for byte. Over HTTP a successful
  `POST /commit` carries the same number in the `X-Atomic-Pace-Ms` response
  header.
- **Hard signal, `BUSY`.** With more than `hard` commits in flight a new
  `COMMIT` is refused up front with `ERROR` code `BUSY (12)` and the message
  `Server busy; retry_after_ms=<n>`. Over HTTP the answer is `503` with
  `Retry-After` (whole seconds, rounded up) and `X-Atomic-Retry-After-Ms`.
  `n` is the time the node needs to drain its queue (in-flight commits times
  a moving average of the commit service time), clamped to 250 ms to 10 s and
  jittered by +-50% so refused clients do not return in one wave. An old
  client sees an unknown code and retries generically.
- **Rate limit.** The write rate limiter (`--write-rate-limit`) answers a
  `COMMIT` with the same `BUSY`; the message is
  `Too many writes; retry after <s> seconds (retry_after_ms=<s * 1000>)`.
  Over HTTP it stays `429` with `Retry-After`. Before 2026-10 the WebSocket
  frame carried code `UNKNOWN (0)` and the delay only in the text.

A client that honours the hints keeps every edit and never drops one: it
sends a resource at most once per `max(debounce, pace_ms)`, lets edits pile
up into the next delta, and on `BUSY` waits `retry_after_ms` (plus its own
jitter), counts no failure and does not fall back to HTTP.

## Resource fetching

```
-> GET (0x10) [request_id] [subject]
<- UPDATE (0x11) [flags=SNAPSHOT|HAS_COMMIT_ID] [request_id] ... [snapshot]
```

The responder materializes the resource's Loro state, resolves any
`internal:/…` subject against its own origin (an `internal:` subject must
never cross the wire, since the receiver keys its cache on whatever subject
arrives), and sets `HAS_COMMIT_ID` with the resource's `lastCommit` when
there is one. Without that field a client whose only source of state is the
socket cannot know which commit produced it, and marks its next save as a
genesis commit, which the responder rejects. A resource with no state answers
`ERROR` `UNKNOWN` `No state`; an unreadable or missing subject answers
`ERROR` `UNKNOWN` with the lookup error, on the same `request_id`.
That `lastCommit` id is a receipt for genesis detection, not a refetchable
resource. It is derived when the state is sent (the id of the newest kept
envelope) and is not stored in the resource's Loro document.

A client that needs many subjects at once (a chat and every part of every
message, say) sends one `GET_MANY` instead of one `GET` per subject, when
the responder advertises `get-many`:

```
-> GET_MANY (0x15) [request_id] [count] [subject]*
<- GET_MANY_RESULT (0x16) [request_id] [count] [frame]*
```

Each entry is exactly the frame a single `GET` for that subject would have
been answered with, a complete `UPDATE` or `ERROR` frame with its tag byte,
in request order, all carrying the batch's `request_id`. Order is what
pairs an `ERROR` (which names no subject) with the subject it answers. The
responder evaluates every subject with the connection's identity, exactly as
for `GET`, so a batch never reveals more than the same single fetches would.
The browser chunks a request at 200 subjects and falls back to single `GET`s
when the capability is absent.

## Persisted commits

```
-> COMMIT (0x13) [request_id] [signed_commit_json_ad]
<- COMMIT_OK (0x14) [request_id] [created_commit_json_ad]   # or [commit_id], see below
<- UPDATE (0x11) ...        # to OTHER subscribers, not the origin connection
```

**Pipelining.** The server applies each `COMMIT` on its own spawned future,
so several may be in flight on one connection and their acks come back in
completion order; every `COMMIT_OK` and every `ERROR` for a commit carries
the `request_id` the client chose, and clients match on it (the browser's
`pendingCommits` map, `WsClient::post_commit`). The browser's outbox drain
uses this: subjects of one ordering tier (agents, then the drive, then
children by depth) are drained up to eight at a time, with a barrier between
tiers so a child's genesis never races ahead of its parent's.

**Slim acknowledgement.** The full form returns the created commit's JSON-AD,
which since 2026-09 no client in this tree reads beyond its `@id`. A client
that lists `commit-ok-slim` in its `HELLO` is answered with the bare commit
id instead, and resolves its caller with the commit it signed plus that id.

The payload is the same signed JSON-AD body HTTP `POST /commit` accepts, so
deterministic signing and commit parsing are unaffected by the transport.
`created_commit_json_ad` is the created commit resource
(`atomic:commit:<sig>`) that `/commit` also returns. On failure the responder
answers `ERROR` with the matching `request_id` and a classified code. HTTP
`POST /commit` remains the fallback path.

**The echo carries the server's own ops.** The `UPDATE` a commit fans out is
not the commit's own bytes: it is every op the stored doc gained during the
apply, which is the author's ops plus whatever the server writes afterwards
under its own peer (`createdAt` at genesis, a derived `drive`). Older servers
also wrote a `lastCommit` stamp there on every commit; it is now derived and
no longer part of the document. Anyone who loads the stored snapshot builds
their next edit on top of those ops, so a subscriber without them parks that
edit as pending and every later delta parks behind it. For the same
reason the author's own connection receives the echo too; the client dedups
it by commit id and imports it without notifying.

**Echo suppression** applies to non-commit changes only. Each WebSocket
connection has a per-process id (`ws-<n>`). The server threads it through as
the change's `source_id`, stamps it on the emitted database events, and the
commit monitor skips subscribers registered under the same id for external
changes (sync imports, internal writes). An HTTP commit has no source id.

**The peer `COMMIT` arm differs deliberately** (`engine::handle_frame`, via
`apply_peer_commit`):

| | WS server (hub) | Engine (peer) |
| --- | --- | --- |
| Signature, schema, signer rights | validated | validated |
| Timestamp | validated | validated (bounds replay of a captured signed destroy) |
| `validate_loro_causality` | on | **off**: concurrent writes between peers are expected |
| Subject ownership | enforced | **off**: hosting subjects it does not own is what a replica is |
| `previousCommit` | not validated | not validated |
| `source_id` echo suppression | non-commit changes only; a commit's `UPDATE` reaches its author with the server's stamp | none: peers do not fan out through the commit monitor |
| Live-echo suppression | no | yes, so the live push loop does not bounce the commit back |

Both roles auto-create the signer's agent resource when it is absent and the
signer is an agent DID.

## Subscriptions

All subscriptions deliver through the same two frames: `UPDATE (0x11)` and
`DESTROY (0x12)`. All of them are registered on the WebSocket transport
only.

**`SUB (0x20) <subject>`** is the one registration frame. What it registers
depends on the subject:

- a **drive** (`isA` includes `Drive`): a drive-wide subscription, so every
  commit on a resource under that drive is fanned out to the connection, plus
  a per-resource subscription on the drive resource itself, so renames and
  ACL edits arrive even though a DID drive subject would never prefix-match
  a commit subject;
- **any other resource**: a per-resource subscription on that one subject.

No `AUTH` needed; gated on `check_read` of the subject. Until 2026-09-04 the
per-resource case was a separate text frame (`SUBSCRIBE <subject>`, `AUTH`
required, no unsubscribe), and a filter subscription (`SUBSCRIBE_QUERY`)
existed that no client outside the Rust integration tests ever sent; both
are gone.

**`UNSUB (0x21) <subject>`** cancels it, under the same raw string `SUB`
registered with, so the fan-out entry is actually found. It removes the
per-resource entry too. Nothing is sent in reply.

**Refusal frame.** A subscription refused for rights, or naming a subject the
responder does not hold, is not registered and answers with:

```
ERROR (0x03) request_id=0 code=UNAUTHORIZED_READ(7)
             "<FRAME> refused for <subject>: <reason>"
```

`<FRAME>` is one of `SUB`, `LORO_SYNC_SUBSCRIBE`, `PRESENCE_SUBSCRIBE`. A
missing subject and an unreadable one give the same reason (`not readable`):
which of the two it is is not something an agent without read rights gets to
learn. One frame gets one answer. An accepted subscription is silent.

**Identity follows the connection.** Each registration remembers the agent
it was admitted under. When an `AUTH` changes the connection's identity, the
WebSocket handler sends the commit monitor a `RebindAgent` and every
subscription the connection holds (per-resource, drive-wide and filter) is
re-checked with `check_read` as the new agent: the ones it may read are
re-bound to it, the rest are dropped silently. A client that switched agents
re-subscribes on its own (the browser's `reSubscribeAll`), and is refused
out loud then if it must be. The Loro sync and presence channels are not
re-evaluated. Before 2026-09 the agent was checked once and forgotten, so a
`SUB` accepted as the owner kept delivering after the socket
re-authenticated as a stranger.

**What a fan-out `UPDATE` carries.** This differs by trigger, and it matters:

| Trigger | Flags | Payload |
| --- | --- | --- |
| A commit under a subscribed drive or subject | `HAS_COMMIT_ID \| PUSH` | the commit's Loro **delta**, not a snapshot |
| A commit with `destroy` | (a `DESTROY` frame) | subject only |
| An external change, meaning a write with no commit behind it, such as a peer sync writing straight to the store | `SNAPSHOT \| PUSH`, plus `HAS_COMMIT_ID` when a `lastCommit` exists | the full stored snapshot |
| An external destroy | (a `DESTROY` frame) | subject only |

The `SNAPSHOT` flag on the external-change path is load-bearing. Labelling
full state as a delta makes the client merge it into a document it does not
have, producing a class-less partial resource.

## Drive synchronization over WebSocket

This is the sequence the browser runs on connect, after draining its outbox.

**1. Hash-first probe.** The client computes its drive state but sends only
the hash:

```
-> SYNC (0x30) <drive> <hash> {"peers":[],"probe":true,"resources":{}}
```

The server recomputes the hash over the subjects this session's agent may
read and answers `SYNC_OK (0x31)` (in sync, nothing more is exchanged) or
`SYNC_RESEND (0x38)`. A drive the agent cannot read answers `ERROR`
`UNAUTHORIZED_READ`.

**2. Full state.** On `SYNC_RESEND` the client sends the version vectors of
every subject it holds in the drive, computed for the probe:

```
-> SYNC (0x30) <drive> <hash> {"peers":[...],"resources":{...}}
```

The server walks the drive once, compares, and answers with the diff.

A `SYNC` may also carry `"subjects": [...]`, which limits the reconcile to
that set: the server builds version vectors for just those subjects and
skips anything outside it. The browser no longer sends it (it came from the
range-based set reconciliation descent, removed 2026-09), but the server
still honours it. *Limitation:* the full path also pulls a subject whose
version vector **matches** but whose blob the server lacks, the backstop
for metadata that arrived over HTTP `POST /commit` while the bytes stayed on
the client. That backstop does not run for subjects left out of `subjects`.

**3. RBSR (removed 2026-09).** Clients from before this answered
`SYNC_RESEND` with a range descent over the `RBSR_FP` / `RBSR_ITEMS` text
frames, then a `SYNC` with `subjects`. The server rebuilt the whole drive
inventory for every one of those round trips, so it cost more than the one
full `SYNC` it was meant to avoid. A current server answers `RBSR_FP` at once
with `{"drive","unsupported":true}` and no `fps`: an old client's descent
fails on its first range and it sends the full `SYNC`, as it did on any RBSR
failure. `RBSR_ITEMS` is still answered, as the drive inventory (see
[Text frames](#text-frames)).

**4. Diff and transfer.** The server answers `SYNC_DIFF (0x32)`, followed
immediately by the `SYNC_PUSH (0x33)` chunks for everything in its `push`
list. The client applies the removals, then sends its own `SYNC_PUSH` chunks
for the `pull` list, exporting updates since the matching `pullFrom` vector
where one is given.

## Drive synchronization over Iroh

Same engine, binary handshake, no text frames:

```
-> AUTH (0x01)                 signed for the drive
<- AUTH_OK (0x02) [caps]
<- HELLO (0x37)                accept side introduces itself
<- AUTH (0x01)                 accept side's auth-back (best effort)
-> HELLO (0x37)
-> SYNC (0x30)                 drive + hash + full compacted VVs
<- SYNC_OK (0x31)              fast path, hashes match, done
   or
<- SYNC_DIFF (0x32)
<- SYNC_PUSH (0x33) × n        last chunk flagged LAST
-> SYNC_PUSH (0x33) × n        the initiator's answer to `pull`
```

The initiator sends the full `SYNC` state; there is no probe on this
transport. If the `SYNC_DIFF` has an empty `push` list the initiator
sends its pushback immediately and stops reading, rather than waiting for
`SYNC_PUSH` frames that will not come.

Both sides then transition to live mode. On the accept side that happens once
the bulk exchange completes, including the case of a `SYNC_DIFF` whose `pull`
list is empty: without that check the accept side stays in handshake mode and
later live `UPDATE` frames go to the sync engine, which has no arm for them.

Serving a peer's `pull` list is gated per subject on `check_read` for the
identity the peer proved, exactly as the accept side's `SYNC_DIFF` is. Dialing
a peer never establishes that peer's rights. A peer the local user
deliberately paired with is additionally served whatever *this node* may
read, never more.

A stream authenticated for a drive may also carry `CALL` frames instead of (or
after) the sync; see [CALL](#call-0x50-and-call_result-0x51).

## SYNC_PUSH chunking and acknowledgement

A push run is one or more `SYNC_PUSH` frames; only the last has `LAST` set. A
receiver **must** loop until it sees `LAST`, or it will terminate early or
hang. An empty push still emits one `LAST`-flagged frame so the receiver does
not wait forever. Sender-side chunk caps are a local choice, not a protocol
rule: both senders close a chunk at 100 entries, the Rust sender also at
1 MiB and the browser at 48 KiB so a slow uplink shows progress per chunk. A
single entry larger than the byte budget is still sent alone, and receivers
accept either.

An admitted chunk is answered with `SYNC_OK (0x31)` for the drive, followed
by any `BLOB_REQUEST` frames the chunk gave rise to. `SYNC_OK` acknowledges
the **chunk, not its contents**: individual entries may still be skipped
(tombstoned locally, unreadable, a failed Loro import). A sender that needs
proof re-probes.

The Rust drive-replication client counts all chunk acknowledgements before
re-probing. On a WebSocket peer advertising `keepalive`, it then sends a
`KEEPALIVE` and reads through the echo to drain blob requests queued after
those acknowledgements. If no blob was requested, it can re-probe immediately
instead of waiting for 30 seconds of silence. The echo does not acknowledge
asynchronous blob storage: transfers with blob requests, and peers without
`keepalive`, retain the idle wait. Only the independent matching-hash response
sets the replication result's `in_sync` flag.

A push refused **as a whole** is answered with `ERROR`, `request_id = 0`,
code `SYNC_REJECTED (6)`, message
`SYNC_PUSH rejected for drive <drive>: <reason>`, and **no `SYNC_OK`**.
Nothing from it landed. The two reasons are that the sending agent has no
write right on the drive, or that the node's sync policy does not admit it
(not enrolled, or over quota). A drive that does not exist locally yet may be
enrolled on the spot if the policy allows it, which is what keeps ordinary
first sync working on an open node.

On an accept-side connection the sender must hold write rights itself. On a
connection the node **dialled**, a relayed push to a drive this node's own
agent may write is accepted even though the relaying peer authenticates as a
different agent: a server holding your drive is not you, and gating on its
identity is what made a phone stop receiving a browser's edits.

## Deletes

There are three separate paths and they do not share a mechanism.

**Live, over WebSocket.** The client sends a signed destroy `COMMIT (0x13)`.
The server validates and applies it, then fans a `DESTROY (0x12)` out to
every subscriber of that subject and to every drive-wide subscriber of the
drive it lived under, skipping the originating connection.

**Live, over an Iroh peer link.** A destroy crosses as the signed
`COMMIT (0x13)` that caused it, so the peer validates signature, rights and
timestamp exactly as for any other commit. A **naked `DESTROY (0x12)` from a
peer is ignored**, logged and never applied, whoever sent it: it carries no
signature and no signer, so the only thing it could be checked against is the
connection's drive-level write verdict, which is not what authorizes a
delete. A removal no commit authorized (a cascade-deleted child, a local
eviction) is not propagated live at all; the peer's own apply of the parent
commit cascades there too.

**Bulk, during reconcile.** `SYNC_DIFF.remove` lists subjects the sender
holds a tombstone for. When the sender still has the signed destroy
commit on that tombstone, `removeCommits` is a `{ subject: commitJson }`
map of those envelopes; the receiver applies each as a peer `COMMIT`
(signature + the signer's rights). The sender attaches envelopes only
when the session may read the drive, and a receiver refuses a destroy
it already holds, or one older than the resource's genesis, as a
replay. Entries without an envelope stay on
the unsigned path: the receiver applies them only if the sending identity
is admitted for that subject's drive, the same drive-level write verdict,
with the dial-side "trust owned" relaxation. A subject whose drive cannot
be resolved locally is destroyed without that check. Full envelope-on-resource
storage (`Tree::Envelopes`) is still the commit-retention floor; this is
destroy-only evidence on the existing tombstone key.

## Blobs

```
-> BLOB_REQUEST (0x34) [blake3_hash: 32 bytes]
<- BLOB_RESPONSE (0x35) [blake3_hash: 32 bytes] [bytes...]
```

`BLOB_REQUEST` is ungated on both transports and runs no rights check: the
hash is the capability. A miss answers `ERROR` `UNKNOWN` `Blob not found`.
`BLOB_RESPONSE` is accepted **only for a hash this node actually requested**.
Importing a `SYNC_PUSH` entry whose `File` resource names a blob the node
lacks records the hash against the (already admitted) drive and emits the
request. The response handler consumes that record and re-checks the drive
against the sync policy, since enrollment or quota can change in between. A
response with no matching record answers `ERROR` `UNKNOWN`
`Unsolicited blob response`; one for a no-longer-admitted drive answers
`Drive not admitted for sync`. A pending request expires after 5 minutes.

Over WebSocket, `BLOB_RESPONSE` additionally requires `AUTH`.

## Liveness

**WebSocket.** The server pings every 5 s and drops a connection that has
sent nothing at all for 60 s. That budget is deliberately generous: a
saturated renderer can stall pong delivery for seconds.

A browser cannot observe protocol-level pings, so it has its own probe. When
the server advertised `keepalive`, the client checks every 5 s: after 20 s
with no inbound frame it sends one `KEEPALIVE (0x41)`; if that probe is still
unanswered 25 s after it was sent, it closes the socket and lets the reconnect
loop take over. Any inbound frame resets both. Silence alone never closes the
socket: a hidden tab's timers can fire a minute apart, and the first check
after such a gap must ask the server rather than give up on it. The server **echoes** `KEEPALIVE` verbatim, which
is the whole point of it. Against a server that did not advertise
`keepalive` the client does not probe, since an unanswered probe would make
every idle socket look dead.

**Iroh.** Each side's write loop sends a `KEEPALIVE` whenever it has had
nothing else to send for 10 s (`KEEPALIVE_INTERVAL`). It is **never echoed**:
both sides send on their own schedule, so each read loop always has something
arriving. A read loop that hears nothing for 35 s (`LIVENESS_TIMEOUT`) treats
the link as dead and tears it down, but **only once that peer has sent at
least one `KEEPALIVE`**. Silence from a peer that has never sent one carries
no information, and treating it as death turned every idle connection to an
older build into a 35-second reconnect loop.

This exists because a half-open connection is otherwise invisible: one side's
stream dies, the other keeps queueing writes into it and the reconnect loop
skips it as "connected". Observed gap before this was added: 15 minutes, with
every local change silently dropped.

## Size limits

| Limit | Value | Where |
| --- | --- | --- |
| WebSocket frame | 16 MiB | actix `frame_size`. A frame over the limit makes actix drop the TCP socket with no close frame, which the browser sees as `code=1006`. |
| Iroh frame, authenticated | 50 000 000 bytes | `IROH_FRAME_MAX_BYTES` |
| Iroh frame, before AUTH | 10 000 000 bytes | `IROH_PREAUTH_FRAME_MAX_BYTES`, so an unauthenticated dialer cannot force a 50 MB allocation |
| `EPHEMERAL` payload, `LORO` / `PRESENCE` | 64 KiB | `EPHEMERAL_MAX_PAYLOAD` |
| `EPHEMERAL` payload, `DOC` | 1 MiB | `LIVE_DOC_MAX_PAYLOAD` |
| `HELLO` name | 64 Unicode scalar values | `HELLO_MAX_CHARS`; over-long is rejected, not truncated |
| `SYNC_PUSH` chunk, Rust sender | 100 entries or 1 MiB | sender-side only |
| `SYNC_PUSH` chunk, browser sender | 100 entries or 48 KiB | sender-side only |

The Iroh frame cap is chosen per frame from the connection's *current*
identity, in both loops, so a connection that authenticates mid-stream moves
up to the larger budget and one that never does never leaves the tight one.

## Text frames

WebSocket only. Format is `PREFIX ` followed by the payload; the prefix
includes its trailing space. Payloads are JSON except where noted.

Client to server:

| Frame | Payload | Needs AUTH |
| --- | --- | --- |
| `LORO_SYNC_SUBSCRIBE` | `{"subject"}` | yes |
| `LORO_SYNC_UNSUBSCRIBE` | `{"subject"}` | no |
| `PRESENCE_SUBSCRIBE` | `{"subject":"<drive>"}` | yes |
| `PRESENCE_UNSUBSCRIBE` | `{"subject":"<drive>"}` | no |
| `SUBSCRIBE_INDEX_STATUS` | `{"drive"}` | no |
| `UNSUBSCRIBE_INDEX_STATUS` | `{"drive"}` | no |
| `RBSR_FP` | `{"drive","ranges":[["<lo>","<hi>"\|null], ...]}` (retired, see below) | no |
| `RBSR_ITEMS` | `{"drive","lo","hi"\|null}` | no |

Server to client:

| Frame | Payload |
| --- | --- |
| `RBSR_FP` | `{"drive","unsupported":true}` (no `fps`) |
| `RBSR_ITEMS` | `{"drive","items":[["<subject>",[["<peer>",<counter>], ...]], ...]}` |
| `INDEX_STATUS` | `{"drive","indexing"}` |

The subscriptions register an interest; the updates themselves travel as
`EPHEMERAL (0x40)`. `SUBSCRIBE_INDEX_STATUS` is answered immediately with
one `INDEX_STATUS`. `RBSR_ITEMS` returns the drive inventory: every subject
in `[lo, hi)` (`hi = null` is unbounded) the agent may read, with its version
vector; the browser uses it to check it holds a complete copy before making
a drive local-only. The name is left over from the removed range
reconciliation, as is `RBSR_FP`, which is only answered so old clients fall
back without waiting for a timeout. Prefixes are matched longest-conflicting first; an
unrecognized text frame is logged and ignored.

## Session flows

**Browser over WebSocket**

```
-> upgrade, Sec-WebSocket-Protocol: atomicdata-ws.v2
<- CHALLENGE (0x42) <nonce>                      (server's first frame)
-> HELLO (0x37) name + ["commit-ok-slim"]        (client's first frame)
-> AUTH (0x01) signed for "<origin>#<nonce>"
<- AUTH_OK (0x02) ["auth-max-age", "keepalive", "auth-nonce", ...]
-> SUB (0x20) <drive>
-> SYNC (0x30) drive + hash, probe:true
<- SYNC_RESEND (0x38) drive
-> SYNC (0x30) drive + hash + full version vectors
<- SYNC_DIFF (0x32)
<- SYNC_PUSH (0x33) x n, last one flagged LAST
-> SYNC_PUSH (0x33) x n, last one flagged LAST
-> COMMIT (0x13) request_id 1
-> COMMIT (0x13) request_id 2                    (pipelined, same tier)
<- COMMIT_OK (0x14) 2 [commit_id]                (slim; acks in completion order)
<- COMMIT_OK (0x14) 1 [commit_id]
<- UPDATE (0x11) delta | HAS_COMMIT_ID | PUSH    (own commit echoed with the server's stamp; deduped by id)
<- UPDATE (0x11) delta | HAS_COMMIT_ID | PUSH    (someone else's commit)
-> GET (0x10)
<- UPDATE (0x11) SNAPSHOT | HAS_COMMIT_ID
-> PRESENCE_SUBSCRIBE {"subject": <drive>}       (text)
-> EPHEMERAL (0x40) kind=PRESENCE, agent ""      (this tab's cursor)
<- EPHEMERAL (0x40) kind=PRESENCE, agent <bob>   (a collaborator's)
-> KEEPALIVE (0x41)                              (after 20 s idle)
<- KEEPALIVE (0x41)                              (echo)
```

**Iroh peer.** Every line is length-prefixed; `->` is the initiator.

```
-> QUIC connect, ALPN atomic/1, open_bi
-> AUTH (0x01) signed for <drive>
<- AUTH_OK (0x02) [caps]
<- HELLO (0x37) name + caps
<- AUTH (0x01) auth-back, signed for the initiator's node key
-> HELLO (0x37)
-> SYNC (0x30) drive + hash + version vectors
<- SYNC_DIFF (0x32)
<- SYNC_PUSH (0x33) x n ... LAST
-> SYNC_PUSH (0x33) x n ... LAST
-> BLOB_REQUEST (0x34)
<- BLOB_RESPONSE (0x35)
   === both sides enter live mode ===
<- UPDATE (0x11) delta
-> COMMIT (0x13) signed destroy
-> EPHEMERAL (0x40) kind=PRESENCE
-> KEEPALIVE (0x41)                (every 10 s idle, never echoed)
<- KEEPALIVE (0x41)
```

## Conformance

`lib/src/sync/protocol_vectors.json` holds one golden frame as hex per named
case, covering `AUTH_OK` with and without capabilities, `ERROR`, `GET`,
`UPDATE` as delta and as snapshot, `DESTROY`, `COMMIT`, `COMMIT_OK` in both
forms, `SUB`, `UNSUB`, `SYNC`, `SYNC_OK`, `SYNC_DIFF`, `SYNC_PUSH`,
`BLOB_REQUEST`, `BLOB_RESPONSE`, `HELLO` with and without capabilities,
`KEEPALIVE`, `CHALLENGE`, and `EPHEMERAL`.

The Rust test module `protocol::wire_vectors` asserts that every encoder
produces the recorded bytes and that the recorded bytes decode to the
recorded fields. `browser/lib/src/ws-v2.test.ts` asserts the same for the
TypeScript codec against `browser/lib/src/protocol_vectors.json`, a
byte-identical copy kept inside the browser package because CI runs the
TypeScript tests in a container that holds only `browser/`. The Rust test
`wire_vectors::browser_copy_is_identical` fails when the two copies drift.
Every frame both sides can encode must come out byte-identical.

After a deliberate wire change, regenerate with
`cargo test -p atomic_lib print_wire_vectors -- --ignored --nocapture`, paste
the printed JSON into both copies of `protocol_vectors.json`, and update this
page in the same commit.

## Implementation

Every file below links back here from its module header. Keep this page in
step when you touch any of them.

| File | Role |
| --- | --- |
| `lib/src/sync/protocol.rs` | Tags, flags, error codes, `CAPABILITIES`, encoders and decoders, size limits, golden vectors. |
| `lib/src/sync/engine.rs` | Transport-agnostic frame handling: `AUTH` verification and binding, `GET`, commit ingest, `SYNC` / `SYNC_DIFF` / `SYNC_PUSH`, blob bookkeeping. |
| `lib/src/sync/peer.rs` | Iroh QUIC transport: length envelope, handshake, live loops, keepalive, ephemeral relay. |
| `lib/src/authentication.rs` | `AuthValues`, signature check, freshness window. |
| `lib/src/client/ws.rs` | The Rust WebSocket client. |
| `server/src/handlers/web_sockets.rs` | The Actix WebSocket handler: binary arms, text frames, `require_auth`, heartbeat. |
| `server/src/commit_monitor.rs` | Subscription registries, commit fan-out, and `EPHEMERAL` / presence fan-out (folded from `LoroSyncBroadcaster`, 2026-09-05). |
| `server/src/actor_messages.rs` | Subscription messages and the refusal frame. |
| `server/src/serve.rs` | Relays Iroh `EPHEMERAL` into the commit monitor so local WebSocket subscribers see peer presence. |
| `browser/lib/src/ws-v2.ts` | Frame encode and decode. |
| `browser/lib/src/websockets.ts` | The browser client: auth, pending requests, subscriptions, commit over WS, liveness, drive reconcile. |
| `packages/atomic_store_flutter/rust/src/api/simple/ws_sync.rs` | The Flutter FRB bridge over `WsClient`. |

## Known gaps

Tracked in [`planning/unified-sync.md`](https://github.com/ontola/atomic-server/blob/master/planning/unified-sync.md),
"Remaining work".

- **`SUB` / `UNSUB` are engine-owned.** Parse and `check_read` live in
  `handle_frame_full`; a hub still registers the connection with the
  commit monitor because the engine has no actor mailbox.
- **No Layer-2 provenance on `SYNC_PUSH`.** Entries carry raw Loro bytes with
  no `lastCommit` and no signed envelope, so an import cannot verify or
  record who authored the state it merged.
- **The `CHALLENGE` nonce is optional, and WebSocket-only.** A proof without
  a nonce is still accepted on its timestamp (so pre-2026-09 clients keep
  working), which leaves a captured nonce-less frame replayable inside the
  five-minute window until a deployment turns on `AuthChallenge::Required`
  (no server option for it yet). Iroh streams have no challenge at all; the
  initiator's proof for a drive is timestamp-bounded only.
- **Loro sync and presence subscriptions are not re-bound on `AUTH`.** The
  commit monitor's resource and drive maps are; the Loro-ephemera and
  presence maps on the same actor still check identity once, at registration.

## Changed in 2026-10

- **`commit-pace` and `BUSY (12)`.** Write-load signalling, see
  [Write load and pacing](#write-load-and-pacing). The WebSocket rate-limit
  refusal is now `BUSY` instead of `UNKNOWN`; the message text is unchanged
  up to a `(retry_after_ms=...)` suffix.

## Changed in 2026-09

Wire-visible changes in this revision:

- **`AUTH` freshness and origin binding.** Proofs older than
  `AUTH_MAX_AGE_MS` (5 minutes) are refused, and the WebSocket responder
  requires `requestedSubject` to name its own origin. A refused `AUTH` now
  answers with the new code `AUTH_FAILED (8)`.
- **Capability payloads.** `AUTH_OK` carries a JSON array of capability
  names, `HELLO` the same array after the name. Both are optional trailing
  bytes, so older decoders are unaffected.
- **`UNSUB (0x21)` is implemented.** It previously edited a set nothing read;
  it now removes the drive fan-out entry and the companion per-resource
  entry.
- **`KEEPALIVE (0x41)` over WebSocket.** The server echoes it, and the
  browser uses it as a liveness probe once the server advertises `keepalive`.
- **`CHALLENGE (0x42)`.** The WebSocket server's first frame carries a
  per-connection nonce; a client signs `{origin}#{nonce}` and the proof is
  good on that socket only. Nonce-less proofs are still accepted
  (`auth-nonce`).
- **Client `HELLO` over WebSocket.** The browser and `WsClient` send one on
  open, listing `commit-ok-slim`; the server records it (`client-hello`).
- **Slim `COMMIT_OK`.** For such a client the ack is
  `[request_id] [commit_id]` instead of the full commit JSON
  (`commit-ok-slim`). The Rust and TypeScript decoders read both forms.
- **Pipelined `COMMIT`.** Acks were always matched by `request_id` on the
  server; the browser's outbox now drains an ordering tier concurrently, and
  the Rust `WsClient::post_commit` no longer fails on an unrelated `ERROR`.
  `WsMessage::Error` carries `request_id` and `code`.
- **Subscriptions re-bound on `AUTH`.** When a connection's identity changes,
  its subject and drive subscriptions are re-checked as the new agent and
  the unreadable ones dropped (`rebind-on-auth`).
- **`INVALID_SIGNATURE (9)`.** A `COMMIT` whose signature does not verify is
  classified instead of going out as `UNKNOWN`.
- **One subscription frame (2026-09-04).** `SUB <subject>` registers a
  drive-wide subscription for a drive and a per-resource one for anything
  else; the text `SUBSCRIBE <subject>` frame and the filter subscription
  `SUBSCRIBE_QUERY` are removed (the browser never sent either; the Rust
  client's `subscribe_resource` now sends `SUB`). The `MembershipNotification`
  fan-out and the commit monitor's filter map went with them; the lib's
  watched-query index stays for the Flutter event stream.
- **Live collaboration is one frame on both transports (2026-09-04).** The
  browser and the Rust client send and receive edits in progress, cursors
  and drive presence as `EPHEMERAL (0x40)`, raw bytes, the same frame the
  Iroh link already carried. The text frames `LORO_SYNC_UPDATE`,
  `LORO_EPHEMERAL_UPDATE` and `PRESENCE_UPDATE` (base64 in JSON, both
  directions) are removed; the four subscribe / unsubscribe text frames
  stay. Between nodes the payload is now the raw bytes rather than their
  base64 text, so a pre-2026-09-04 peer's cursors do not decode on this
  build and vice versa; nothing persistent is affected. Capability
  `ephemeral`.
- **Drive sync is one frame on both transports (2026-09-04).** The browser
  sends binary `SYNC (0x30)` for its hash-first probe (`"probe": true`) and
  its reduced reconcile (`"subjects": [...]`), and a stale probe is answered
  with the new `SYNC_RESEND (0x38)`. The text `SYNC_VV` request and the text
  `SYNC_RESEND <drive>` answer are removed; the RBSR descent stays text.
  Capability `sync-probe`.
- **Range-based set reconciliation removed.** A stale probe is answered by
  the client with its full version-vector `SYNC`. The server no longer
  computes range fingerprints: `RBSR_FP` gets `{"drive","unsupported":true}`,
  which makes an older client fall back to the full `SYNC` at once.
  `RBSR_ITEMS` stays, as the drive inventory. Capability `rbsr` is no longer
  advertised.
- **The hash-first probe and the RBSR frames are read-gated.** `SYNC` with
  `probe: true`, `RBSR_FP` and `RBSR_ITEMS` now answer only over the subjects
  the asking agent may `check_read`, and refuse an unreadable drive with
  `UNAUTHORIZED_READ`. Previously an anonymous socket could enumerate every
  subject and version vector of any drive it could name.
- **Iroh destroys travel as signed `COMMIT` frames.** A naked `DESTROY` from
  a peer is now ignored rather than applied on the connection's drive-level
  write verdict.
- **TypeScript `encodeSync` layout fix.** It wrote a raw 32-byte hash with no
  length prefix, which the Rust decoder misparsed; it now writes
  `[hash_len: u16] [hash_hex_utf8]`.

Corrections to what this page previously claimed:

- `SUB` was said to deliver a full snapshot per commit. A commit fan-out
  `UPDATE` carries the commit's **delta** with `HAS_COMMIT_ID | PUSH`;
  `SNAPSHOT` appears only on external-change pushes.
- `UNSUB` was said to work. It did not, until this revision.
- `SYNC_DIFF.remove` was said to be optional. The encoder always emits it;
  only decoders tolerate its absence.

### Browser invitation bootstrap over WebRTC

Browser-only drive invitations are signed JSON-AD invite tokens with
`https://atomicdata.dev/properties/invite/transport` set to `webrtc`. The
transport marker is included in the signature. These are not redeemed at a
data node's `/invites` endpoint.

The recipient pins the token issuer as its expected peer for the unknown drive.
After verifying that issuer's channel-bound AUTH, it sends its own channel-bound
AUTH with an optional `browserInvite` string carrying the signed token. This
field is sent only over the authenticated WebRTC connection, never signaling.
The issuer validates its own token, expiry, target and recipient proof, checks
its current write authority, and saves a normal signed ACL commit granting the
requested access. Ordinary peer AUTH/ACL checks then run before any sync data is
sent. Other peers cannot redeem an issuer's token. Reconnecting after a trusted
local snapshot exists uses normal ACL authentication without re-redeeming it.
