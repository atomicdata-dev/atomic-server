//! WebSocket Protocol v2: binary-first, unified messages.
//!
//! Frame format: `[type: u8] [payload...]`
//! All frames are binary WebSocket frames. No base64, no JSON for Loro bytes.
//!
//! **Canonical wire-format spec:** `docs/src/websockets.md`. This module is
//! the Rust source of truth for tag bytes, flag bits, and encode/decode of
//! every frame; when you change anything here, update that doc and the
//! TypeScript counterpart (`browser/lib/src/ws-v2.ts`) in the same change.
//!
//! Used by:
//! - `server/src/handlers/web_sockets.rs` — browser-facing WS handler
//! - `lib/src/sync/engine.rs` — transport-agnostic drive sync (SYNC*)
//! - `lib/src/sync/peer.rs` — Iroh QUIC peer transport (adds HELLO)
//! - `lib/src/client/ws.rs` — Rust WS client

/// Message type tags
#[allow(dead_code)]
pub mod tag {
    pub const AUTH: u8 = 0x01;
    pub const AUTH_OK: u8 = 0x02;
    pub const ERROR: u8 = 0x03;
    pub const GET: u8 = 0x10;
    pub const UPDATE: u8 = 0x11;
    pub const DESTROY: u8 = 0x12;
    pub const COMMIT: u8 = 0x13;
    pub const COMMIT_OK: u8 = 0x14;
    pub const SUB: u8 = 0x20;
    pub const UNSUB: u8 = 0x21;
    pub const SYNC: u8 = 0x30;
    pub const SYNC_OK: u8 = 0x31;
    pub const SYNC_DIFF: u8 = 0x32;
    pub const SYNC_PUSH: u8 = 0x33;
    pub const BLOB_REQUEST: u8 = 0x34;
    pub const BLOB_RESPONSE: u8 = 0x35;
    /// Reserved (do not reuse). Previously `QUERY_UPDATE` — retired (see
    /// `planning/sync.md`, "QUERY_UPDATE removed"). Drive-wide and
    /// resource-level commits now travel exclusively as `UPDATE` (0x11) and
    /// `DESTROY` (0x12) frames carrying the snapshot or delta + commit_id.
    pub const QUERY_UPDATE_RESERVED: u8 = 0x36;
    /// Self-reported display name (plus, optionally, a capability list) on
    /// peer-sync streams. Sent by both sides right after `AUTH_OK`, before
    /// the binary `SYNC` handshake. Display only; never used for
    /// authorization (the authenticated agent + Iroh NodeId are).
    pub const HELLO: u8 = 0x37;
    pub const EPHEMERAL: u8 = 0x40;
    /// Liveness probe. Payload-free. On a QUIC peer stream it is never
    /// answered — both sides send it on their own schedule, so each read loop
    /// has something to receive and silence can be treated as a dead link
    /// rather than an idle one. Over a browser WebSocket the responder echoes
    /// it back: a browser cannot observe protocol-level pings, so this is the
    /// only way it can tell a silently dead socket from an idle one.
    pub const KEEPALIVE: u8 = 0x41;
    /// Responder → client, first frame on a WebSocket, before the client has
    /// said anything: `[0x42] [nonce_utf8]`. A client that saw it signs
    /// `AUTH.requestedSubject` as `{origin}#{nonce}`, which ties the proof
    /// to this one connection: captured, it is worthless anywhere else, and
    /// the five-minute `AUTH_MAX_AGE_MS` window stops mattering. A client
    /// that ignores the frame (pre-2026-09) still authenticates with the
    /// timestamp-bounded form. Never sent on a peer (Iroh) stream, where the
    /// initiator speaks first and the QUIC handshake already binds the link
    /// to a node key.
    pub const CHALLENGE: u8 = 0x42;
    /// Responder → client, the negative answer to a `SYNC` probe:
    /// `[0x38] [drive_utf8]`. The drive hashes differ, so the client should
    /// reconcile (RBSR over the text frames, then a `SYNC` for the
    /// differing subjects). The positive answer is `SYNC_OK`. Until
    /// 2026-09-04 this was the text frame `SYNC_RESEND <drive>` and the
    /// probe itself was the text `SYNC_VV`; both transports now speak the
    /// binary form.
    pub const SYNC_RESEND: u8 = 0x38;
}

/// Feature names a responder advertises in the `AUTH_OK` payload and both
/// peers advertise in `HELLO`, so a client can adapt to what the other side
/// speaks instead of guessing from a version string. Additive only: never
/// rename or reuse a name once shipped. A peer that sends no list is treated
/// as advertising nothing (the pre-2026-09 baseline).
///
/// - `auth-max-age`: `AUTH` proofs older than `AUTH_MAX_AGE_MS` are refused
///   and a failed `AUTH` carries `error_code::AUTH_FAILED`.
/// - `keepalive`: understands `KEEPALIVE` (0x41); echoes it over WebSocket.
/// - `rbsr`: answers the `RBSR_FP` / `RBSR_ITEMS` text frames.
/// - `pull-from`: `SYNC_DIFF` carries `pullFrom` version vectors.
/// - `signed-destroy`: on a peer stream, destroys travel as signed `COMMIT`
///   frames and a naked `DESTROY` from a peer is ignored.
/// - `unsub`: `UNSUB` (0x21) actually cancels a drive subscription.
/// - `auth-nonce`: sends `CHALLENGE` (0x42) on connect and verifies an
///   `AUTH.requestedSubject` of the form `{origin}#{nonce}` against it.
/// - `commit-ok-slim`: honours a client `HELLO` that lists `commit-ok-slim`
///   by answering `COMMIT` with `[0x14] [request_id] [commit_id]` instead of
///   the full commit JSON (see [`encode_commit_ok_slim`]).
/// - `client-hello`: reads a `HELLO` (0x37) from a WebSocket client and
///   records the capabilities it lists.
/// - `rebind-on-auth`: re-evaluates this connection's subscriptions against
///   the new identity when an `AUTH` lands, dropping the ones it may no
///   longer read.
/// - `sync-probe`: the binary `SYNC` payload may carry `probe` and
///   `subjects`; a probe is answered with `SYNC_OK` or `SYNC_RESEND` (0x38).
/// - `ephemeral`: reads and writes `EPHEMERAL` (0x40) over WebSocket for
///   edits in progress, cursors and drive presence, in place of the text
///   frames `LORO_SYNC_UPDATE` / `LORO_EPHEMERAL_UPDATE` / `PRESENCE_UPDATE`.
pub const CAPABILITIES: &[&str] = &[
    "auth-max-age",
    "keepalive",
    "rbsr",
    "pull-from",
    "signed-destroy",
    "unsub",
    "auth-nonce",
    "commit-ok-slim",
    "client-hello",
    "rebind-on-auth",
    "sync-probe",
    "ephemeral",
];

/// Capability names a *client* may list in the `HELLO` it sends a responder
/// (WebSocket clients since 2026-09; peers always sent one). The only one a
/// responder acts on today:
///
/// - `commit-ok-slim`: the client decodes a `COMMIT_OK` whose payload is a
///   bare commit id, so the responder need not ship the full commit JSON
///   back to the agent that just signed it.
pub const CLIENT_CAPABILITIES: &[&str] = &["commit-ok-slim"];

/// The name of the client capability a responder consults before sending a
/// slim `COMMIT_OK`.
pub const CAP_COMMIT_OK_SLIM: &str = "commit-ok-slim";

/// How often an otherwise-idle live connection sends a `KEEPALIVE`.
pub const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a live connection may hear nothing at all before it is considered
/// dead. Comfortably more than [`KEEPALIVE_INTERVAL`], so a couple of dropped
/// probes do not tear down a working link.
///
/// This exists because a half-open connection is invisible: one side's stream
/// dies and the other keeps queueing writes into it, believing it is live —
/// which also stops the reconnect loop, since that skips peers it thinks are
/// connected. Observed gap between the two sides noticing: 15 minutes, during
/// which every local change was silently dropped.
pub const LIVENESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(35);

/// Which live-collaboration channel a frame belongs to.
///
/// They are not interchangeable: each fans out to a different subscriber set on
/// the far side, so the frame has to say which. [`DOC`] additionally differs in
/// what it is *allowed* to do — see its own note.
pub mod ephemeral_kind {
    /// Cursors and selections: ephemeral state for one subject (the
    /// browser's `subscribeLoroEphemeral` channel).
    pub const LORO: u8 = 0;
    /// Drive-scoped presence, who is where in a drive.
    pub const PRESENCE: u8 = 1;
    /// The ops of an edit in progress, before anyone has saved (the
    /// browser's `subscribeLoroSync` channel).
    ///
    /// The odd one out, and the reason this frame is no longer only about
    /// presence: this is content, not a cursor. Committed state crosses the
    /// link as an `UPDATE` frame when the store is written, which happens on
    /// save — so without this, a peer sees nothing of an edit until it is
    /// finished, while cursors cross the instant they move. The result was
    /// carets pointing into text the receiving document had never heard of,
    /// which Loro rejects, so remote cursors never appeared at all.
    ///
    /// Because it is content it gets a stricter gate and a looser size limit
    /// than the other two: see [`max_payload_for_kind`] and the read loop in
    /// `peer.rs`, which admits it on *write* rights rather than read.
    pub const DOC: u8 = 2;
}

/// A single `KEEPALIVE` frame, length-prefixed and ready to send.
pub fn encode_keepalive_wire_msg() -> Vec<u8> {
    let frame = vec![tag::KEEPALIVE];
    let mut msg = Vec::with_capacity(4 + frame.len());
    msg.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    msg.extend_from_slice(&frame);
    msg
}

/// Structured error codes carried on `ERROR` frames (and the HTTP `/commit`
/// error body's `code` field — same registry, shared source of truth).
///
/// F5 (planning/unified-sync.md): the outbox previously pattern-matched exact
/// server error MESSAGE TEXT to decide whether a failed drain is terminal
/// (drop the entry), blocking (stop retrying but keep it visible), or
/// transient (keep retrying with backoff). A wording change on either side
/// silently converted a terminal error into an infinite-retry loop. These
/// codes are what the outbox should switch on now;
/// `browser/lib/src/local-outbox.ts`'s string matchers remain as a fallback
/// for a code of `UNKNOWN` (e.g. an older server that hasn't shipped this
/// yet, or a genuinely unclassified error).
#[allow(dead_code)]
pub mod error_code {
    /// No structured classification — client falls back to string matching.
    pub const UNKNOWN: u16 = 0;
    /// The commit's subject already exists server-side; this exact write can
    /// never succeed by retrying (see `is_genesis: true, but the resource
    /// already exists` in `commit.rs`). Terminal — drop the outbox entry.
    pub const GENESIS_COLLISION: u16 = 1;
    /// The resulting resource is missing a property its class requires;
    /// structurally invalid on every attempt. Terminal — drop the entry.
    pub const MISSING_REQUIRED_PROPERTY: u16 = 2;
    /// The signer has no write right on the target (or its parents).
    /// Retrying floods the server; only a rights change or a fresh edit
    /// helps. Blocking — stop retrying, keep the entry visible.
    pub const UNAUTHORIZED_WRITE: u16 = 3;
    /// The commit names a class this server does not hold, so validation
    /// cannot run. Seen in the field as a table whose rows were refused one at
    /// a time because the table's row class had never reached the server: every
    /// row looked saved locally and none of them were.
    ///
    /// Blocking, NOT terminal. The write itself is well-formed — the class may
    /// still arrive, at which point the same commit would apply — so dropping
    /// it would discard a good edit. Keep it, stop retrying, and say so.
    pub const MISSING_CLASS: u16 = 4;
    /// The frame needs an authenticated session and none has been
    /// established: no `AUTH` frame succeeded on this connection (and, on
    /// WebSocket, no auth headers came with the upgrade). Sent with
    /// `request_id = 0`. Iroh closes the stream right after; a WebSocket
    /// stays open so the client can still `AUTH` and retry. The client should
    /// authenticate first — retrying the same frame without an `AUTH`
    /// changes nothing.
    pub const AUTH_REQUIRED: u16 = 5;
    /// A `SYNC_PUSH` was refused as a whole — the agent may not write the
    /// drive, or this node's sync policy does not admit it — and **nothing**
    /// from it landed. Replaces the old behaviour of silently dropping the
    /// import and still answering `SYNC_OK`, which made the ack meaningless.
    /// The message names the drive. Blocking, not terminal: keep the local
    /// state, stop pushing, and surface it.
    pub const SYNC_REJECTED: u16 = 6;
    /// A subscription (`SUB`, `LORO_SYNC_SUBSCRIBE`, `PRESENCE_SUBSCRIBE`)
    /// was refused because the
    /// session's agent may not read the subject or drive it named. Nothing
    /// was registered; no frames will follow for it. Same verdict a `GET`
    /// would get, delivered instead of the old silent drop.
    pub const UNAUTHORIZED_READ: u16 = 7;
    /// An `AUTH` frame was refused: bad signature, unknown agent, a timestamp
    /// outside the accepted window (`AUTH_MAX_AGE_MS`), or a
    /// `requestedSubject` that does not name this responder. Sent with
    /// `request_id = 0`. The client must sign a fresh proof for the right
    /// subject; resending the same frame changes nothing.
    pub const AUTH_FAILED: u16 = 8;
    /// A `COMMIT` whose signature does not verify against its signer's key
    /// (or that carries none). Terminal for that envelope: re-sending the
    /// same bytes changes nothing; the client has to sign again.
    pub const INVALID_SIGNATURE: u16 = 9;
}

/// Decode the payload of an `ERROR` frame (slice *after* the tag byte):
/// `[request_id: u16] [code: u16] [message: utf8]`. One decoder for the four
/// places that used to hand-slice the offsets.
pub fn decode_error(data: &[u8]) -> Option<DecodedError> {
    if data.len() < 4 {
        return None;
    }
    let request_id = u16::from_be_bytes([data[0], data[1]]);
    let code = u16::from_be_bytes([data[2], data[3]]);
    let message = std::str::from_utf8(&data[4..]).ok()?.to_string();
    Some(DecodedError {
        request_id,
        code,
        message,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedError {
    pub request_id: u16,
    pub code: u16,
    pub message: String,
}

/// Classify a commit-application error message into a structured code for
/// [`error_code`]. Called at the point an `ERROR` frame or `/commit` error
/// response is built, so both wire paths share one classification. Mirrors
/// (and is now authoritative over) `local-outbox.ts`'s
/// `isTerminalCommitErrorMessage` / `isUnrecoverableCommitErrorMessage`
/// patterns — update both sides together if you add a case.
pub fn classify_commit_error(message: &str) -> u16 {
    if message.contains("is_genesis: true, but the resource already exists") {
        return error_code::GENESIS_COLLISION;
    }

    // `commit.rs` — the signature does not verify against the signer's key,
    // or there is none: a tampered or mis-attributed envelope.
    if message.contains("Incorrect signature for Commit") || message.contains("No signature set") {
        return error_code::INVALID_SIGNATURE;
    }

    if message.contains("missing. Is required in class") {
        return error_code::MISSING_REQUIRED_PROPERTY;
    }

    if message.contains("/properties/write right has been found") {
        return error_code::UNAUTHORIZED_WRITE;
    }

    // `storelike.rs` wraps the lookup failure as
    // "Failed getting class <subject>. <inner>", so the prefix is the stable
    // part regardless of why the class could not be read.
    if message.contains("Failed getting class") {
        return error_code::MISSING_CLASS;
    }

    error_code::UNKNOWN
}

/// HELLO display name cap. Counted in Unicode scalar values, not bytes, so
/// "🚀 prod-eu-3" doesn't get split mid-character on the wire. Anything
/// longer is rejected by `decode_hello` rather than silently truncated —
/// truncation hides config typos that would otherwise scream at the user.
pub const HELLO_MAX_CHARS: usize = 64;

/// UPDATE flags (bitfield)
pub mod flags {
    /// Loro snapshot (1) vs delta (0)
    pub const SNAPSHOT: u8 = 0b0001;
    /// A commit ID follows the subject
    pub const HAS_COMMIT_ID: u8 = 0b0010;
    /// Server→client subscription push (not a GET response)
    pub const PUSH: u8 = 0b0100;
}

/// SYNC_PUSH flags (bitfield)
pub mod sync_push_flags {
    /// This is the final chunk of a SYNC_PUSH run. Receivers loop reading
    /// SYNC_PUSH frames until they see one with this bit set.
    pub const LAST: u8 = 0b0001;
}

/// Chunking thresholds for `encode_sync_push_chunks`. A chunk closes when
/// either threshold is hit, whichever comes first.
pub const SYNC_PUSH_MAX_ENTRIES: usize = 100;
pub const SYNC_PUSH_MAX_BYTES: usize = 1_048_576; // 1 MB

/// Max length-prefixed frame `peer.rs` will read off an **authenticated**
/// Iroh QUIC stream before giving up on the connection — bounds the
/// `vec![0u8; len]` allocation against an attacker-controlled `u32` length
/// prefix. Shared by the live-sync loop and an initiator's own post-AUTH
/// `SYNC_*` response reads (cheap inconsistency sweep, planning/unified-sync.md
/// Phase 0b) — both run only after the peer has already proven its identity,
/// so a generous cap doesn't expand who can trigger the allocation.
pub const IROH_FRAME_MAX_BYTES: usize = 50_000_000;

/// Same purpose, but for frames read from a peer that has **not yet**
/// authenticated: the accept-side dispatch loop (`handle_stream`), whose
/// very first frame IS the AUTH attempt, and an initiator's wait for that
/// AUTH's `AUTH_OK`/`ERROR` reply (always tiny in practice). Kept well below
/// [`IROH_FRAME_MAX_BYTES`] so an unauthenticated peer — anyone who learns a
/// NodeID via pkarr discovery, same threat model as F9
/// (planning/unified-sync.md) — can't force a 50MB allocation before proving
/// who they are.
pub const IROH_PREAUTH_FRAME_MAX_BYTES: usize = 10_000_000;

// ---- Encoding ----

/// Encode an AUTH frame: [0x01] [json AuthValues]
/// The agent signs `requested_subject timestamp` with its private key.
pub fn encode_auth(
    agent: &crate::agents::Agent,
    requested_subject: &str,
) -> crate::errors::AtomicResult<Vec<u8>> {
    let timestamp = crate::utils::now();
    let message = format!("{} {}", requested_subject, timestamp);
    let signature = crate::agents::sign_message(
        message.as_bytes(),
        agent
            .private_key
            .as_ref()
            .ok_or("Agent has no private key")?,
    )?;

    let auth = serde_json::json!({
        "https://atomicdata.dev/properties/auth/publicKey": agent.public_key,
        "https://atomicdata.dev/properties/auth/timestamp": timestamp,
        "https://atomicdata.dev/properties/auth/signature": signature,
        "https://atomicdata.dev/properties/auth/requestedSubject": requested_subject,
        "https://atomicdata.dev/properties/auth/agent": agent.subject.to_string(),
    });

    let json_bytes =
        serde_json::to_vec(&auth).map_err(|e| format!("Failed to encode auth: {e}"))?;
    let mut buf = Vec::with_capacity(1 + json_bytes.len());
    buf.push(tag::AUTH);
    buf.extend_from_slice(&json_bytes);
    Ok(buf)
}

/// Encode an UPDATE message.
pub fn encode_update(
    flag_bits: u8,
    request_id: u16,
    subject: &str,
    commit_id: Option<&str>,
    loro_bytes: &[u8],
) -> Vec<u8> {
    let subject_bytes = subject.as_bytes();
    let commit_id_bytes = commit_id.map(|s| s.as_bytes());
    let commit_len = commit_id_bytes.map(|b| 2 + b.len()).unwrap_or(0);

    // Capacity layout:
    // - 1 byte for UPDATE type tag
    // - 1 byte for flag bits
    // - 2 bytes for request_id (u16)
    // - 2 bytes for subject_len (u16)
    // - subject_bytes.len()
    // - commit_len (optional 2 bytes len + commit_id bytes)
    // - loro_bytes.len()
    let mut buf =
        Vec::with_capacity(1 + 1 + 2 + 2 + subject_bytes.len() + commit_len + loro_bytes.len());

    buf.push(tag::UPDATE);
    buf.push(flag_bits);
    buf.extend_from_slice(&request_id.to_be_bytes());
    buf.extend_from_slice(&(subject_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(subject_bytes);

    if let Some(cid) = commit_id_bytes {
        buf.extend_from_slice(&(cid.len() as u16).to_be_bytes());
        buf.extend_from_slice(cid);
    }

    buf.extend_from_slice(loro_bytes);
    buf
}

/// Encode a GET message.
pub fn encode_get(request_id: u16, subject: &str) -> Vec<u8> {
    let subject_bytes = subject.as_bytes();
    let mut buf = Vec::with_capacity(3 + subject_bytes.len());
    buf.push(tag::GET);
    buf.extend_from_slice(&request_id.to_be_bytes());
    buf.extend_from_slice(subject_bytes);
    buf
}

/// Encode a DESTROY message.
pub fn encode_destroy(request_id: u16, subject: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(3 + subject.len());
    buf.push(tag::DESTROY);
    buf.extend_from_slice(&request_id.to_be_bytes());
    buf.extend_from_slice(subject.as_bytes());
    buf
}

/// Encode a COMMIT message.
///
/// Format: `[0x13] [request_id: u16] [commit_json_utf8]`.
pub fn encode_commit(request_id: u16, commit_json: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(3 + commit_json.len());
    buf.push(tag::COMMIT);
    buf.extend_from_slice(&request_id.to_be_bytes());
    buf.extend_from_slice(commit_json.as_bytes());
    buf
}

/// Encode a COMMIT_OK message.
/// Format: `[0x14] [request_id: u16] [server_commit_json_utf8]`.
///
/// The full-JSON form, for clients that did not list `commit-ok-slim` in a
/// `HELLO`. Since 2026-09 no client in this tree reads anything but the
/// commit's `@id` out of it; see [`encode_commit_ok_slim`].
pub fn encode_commit_ok(request_id: u16, commit_json: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(3 + commit_json.len());
    buf.push(tag::COMMIT_OK);
    buf.extend_from_slice(&request_id.to_be_bytes());
    buf.extend_from_slice(commit_json.as_bytes());
    buf
}

/// Encode a slim COMMIT_OK: `[0x14] [request_id: u16] [commit_id_utf8]`.
///
/// Same tag and same first three bytes as [`encode_commit_ok`]; the payload
/// after the request id is the server's commit id (`did:ad:commit:<sig>` or
/// `https://host/commits/<sig>`) instead of the whole commit resource. A
/// responder sends this only to a client that listed `commit-ok-slim` in
/// its `HELLO`. [`decode_commit_ok`] reads both forms.
pub fn encode_commit_ok_slim(request_id: u16, commit_id: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(3 + commit_id.len());
    buf.push(tag::COMMIT_OK);
    buf.extend_from_slice(&request_id.to_be_bytes());
    buf.extend_from_slice(commit_id.as_bytes());
    buf
}

/// A decoded COMMIT_OK, whichever form it came in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedCommitOk {
    pub request_id: u16,
    /// The server's id for the applied commit.
    pub commit_id: String,
    /// The full commit JSON-AD, present only for the legacy full form.
    pub commit_json: Option<String>,
}

/// Decode a COMMIT_OK payload (slice *after* the tag byte) in either form:
/// a full commit JSON-AD object (its `@id` is the commit id) or a bare
/// commit id. `None` for a truncated frame, an empty payload, JSON without
/// an `@id`, or an id that is not valid UTF-8.
pub fn decode_commit_ok(data: &[u8]) -> Option<DecodedCommitOk> {
    let decoded = decode_commit(data)?;
    let body = decoded.commit_json.trim();
    if body.is_empty() {
        return None;
    }
    if body.starts_with('{') {
        let json: serde_json::Value = serde_json::from_str(body).ok()?;
        let id = json.get("@id")?.as_str()?.to_string();
        return Some(DecodedCommitOk {
            request_id: decoded.request_id,
            commit_id: id,
            commit_json: Some(decoded.commit_json.to_string()),
        });
    }
    Some(DecodedCommitOk {
        request_id: decoded.request_id,
        commit_id: body.to_string(),
        commit_json: None,
    })
}

/// Encode a CHALLENGE frame: `[0x42] [nonce_utf8]`. See [`tag::CHALLENGE`].
pub fn encode_challenge(nonce: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + nonce.len());
    buf.push(tag::CHALLENGE);
    buf.extend_from_slice(nonce.as_bytes());
    buf
}

/// Decode a CHALLENGE payload (slice *after* the tag byte). `None` for an
/// empty or non-UTF-8 nonce.
pub fn decode_challenge(data: &[u8]) -> Option<&str> {
    let nonce = std::str::from_utf8(data).ok()?;
    if nonce.is_empty() {
        return None;
    }
    Some(nonce)
}

/// A fresh, unguessable nonce for a `CHALLENGE`: 32 random bytes, hex.
/// Hex keeps it safe inside the URL fragment the client signs it in.
pub fn new_challenge_nonce() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    hex::encode(bytes)
}

/// Split an `AUTH.requestedSubject` into the subject proper and the
/// challenge nonce riding in its fragment, `{subject}#{nonce}`. A subject
/// with no fragment carries no nonce.
pub fn split_challenge_fragment(requested_subject: &str) -> (&str, Option<&str>) {
    match requested_subject.split_once('#') {
        Some((subject, nonce)) if !nonce.is_empty() => (subject, Some(nonce)),
        Some((subject, _)) => (subject, None),
        None => (requested_subject, None),
    }
}

/// Encode an ERROR message.
/// Format: `[0x03] [request_id: u16] [code: u16] [message: utf8]` (F5:
/// `code` added 2026-07-02 — see [`error_code`]). Older clients parsing
/// this frame with the pre-F5 3-byte-header layout will see the 2 code
/// bytes as leading garbage in the message text; not a hard break, just a
/// cosmetically mangled error string until they upgrade.
pub fn encode_error(request_id: u16, code: u16, message: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + message.len());
    buf.push(tag::ERROR);
    buf.extend_from_slice(&request_id.to_be_bytes());
    buf.extend_from_slice(&code.to_be_bytes());
    buf.extend_from_slice(message.as_bytes());
    buf
}

/// Encode SUB: subscribe to drive-scoped updates (the responder pushes
/// `UPDATE` / `DESTROY` for every commit under the drive).
pub fn encode_sub(drive_subject: &str) -> Vec<u8> {
    let drive_bytes = drive_subject.as_bytes();
    let mut buf = Vec::with_capacity(1 + drive_bytes.len());
    buf.push(tag::SUB);
    buf.extend_from_slice(drive_bytes);
    buf
}

/// Encode UNSUB: cancel a drive subscription made with `SUB`. Same payload
/// shape as `SUB`: `[0x21] [drive_utf8]`.
pub fn encode_unsub(drive_subject: &str) -> Vec<u8> {
    let drive_bytes = drive_subject.as_bytes();
    let mut buf = Vec::with_capacity(1 + drive_bytes.len());
    buf.push(tag::UNSUB);
    buf.extend_from_slice(drive_bytes);
    buf
}

/// Encode AUTH_OK with this build's [`CAPABILITIES`] as its payload.
pub fn encode_auth_ok() -> Vec<u8> {
    encode_auth_ok_with_caps(CAPABILITIES)
}

/// Encode AUTH_OK: `[0x02] [caps_json_utf8]`, where the payload is a JSON
/// array of capability names. The payload is optional on the wire: a
/// pre-2026-09 responder sends a bare `[0x02]`, and every decoder in the
/// tree matches on the tag alone, so adding it broke nothing.
pub fn encode_auth_ok_with_caps(caps: &[&str]) -> Vec<u8> {
    let mut buf = vec![tag::AUTH_OK];
    if !caps.is_empty() {
        buf.extend_from_slice(&serde_json::to_vec(caps).unwrap_or_default());
    }
    buf
}

/// Decode the payload of an AUTH_OK frame (slice *after* the tag byte) into
/// the responder's capability names. Empty when the responder sent none.
pub fn decode_auth_ok(data: &[u8]) -> Vec<String> {
    if data.is_empty() {
        return Vec::new();
    }
    serde_json::from_slice::<Vec<String>>(data).unwrap_or_default()
}

/// A single unframed `KEEPALIVE` frame, for transports that frame
/// themselves (WebSocket). Peer streams use [`encode_keepalive_wire_msg`].
pub fn encode_keepalive() -> Vec<u8> {
    vec![tag::KEEPALIVE]
}

/// Encode SYNC_OK.
pub fn encode_sync_ok(drive: &str) -> Vec<u8> {
    let drive_bytes = drive.as_bytes();
    let mut buf = Vec::with_capacity(3 + drive_bytes.len());
    buf.push(tag::SYNC_OK);
    buf.extend_from_slice(&(drive_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(drive_bytes);
    buf
}

/// Encode SYNC_DIFF: [0x32] [drive_len: u16] [drive] [json{pull, push, remove?, removeCommits?}]
pub fn encode_sync_diff(
    drive: &str,
    pull: &[String],
    push: &[String],
    remove: &[String],
    pull_from: &std::collections::HashMap<String, std::collections::HashMap<String, i32>>,
    remove_commits: &std::collections::HashMap<String, String>,
) -> Vec<u8> {
    let drive_bytes = drive.as_bytes();
    let mut diff = serde_json::json!({
        "pull": pull,
        "push": push,
        "remove": remove,
        "pullFrom": pull_from,
    });
    // Keep the golden `sync_diff` vector byte-identical when there is no
    // signed destroy to attach; older decoders ignore unknown fields anyway.
    if !remove_commits.is_empty() {
        diff["removeCommits"] = serde_json::json!(remove_commits);
    }
    let diff_bytes = serde_json::to_vec(&diff).unwrap_or_default();

    let mut buf = Vec::with_capacity(3 + drive_bytes.len() + diff_bytes.len());
    buf.push(tag::SYNC_DIFF);
    buf.extend_from_slice(&(drive_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(drive_bytes);
    buf.extend_from_slice(&diff_bytes);
    buf
}

/// Encode a single SYNC_PUSH chunk:
/// `[0x33] [drive_len: u16] [drive] [flags: u8] [count: u16]
///  [subject_len: u16] [subject] [bytes_len: u32] [loro_bytes] ...`
///
/// Set `last = true` to signal the final chunk of a run; receivers loop
/// reading SYNC_PUSH until they see one with the LAST flag set. Use
/// `encode_sync_push_chunks` for the common case where you have a flat
/// `entries` list and want it split + flagged automatically.
pub fn encode_sync_push(drive: &str, entries: &[(&str, &[u8])], last: bool) -> Vec<u8> {
    let drive_bytes = drive.as_bytes();
    let total_entry_size: usize = entries.iter().map(|(s, b)| 2 + s.len() + 4 + b.len()).sum();

    let mut buf = Vec::with_capacity(1 + 2 + drive_bytes.len() + 1 + 2 + total_entry_size);
    buf.push(tag::SYNC_PUSH);
    buf.extend_from_slice(&(drive_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(drive_bytes);
    buf.push(if last { sync_push_flags::LAST } else { 0 });
    buf.extend_from_slice(&(entries.len() as u16).to_be_bytes());

    for (subject, loro_bytes) in entries {
        let s = subject.as_bytes();
        buf.extend_from_slice(&(s.len() as u16).to_be_bytes());
        buf.extend_from_slice(s);
        buf.extend_from_slice(&(loro_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(loro_bytes);
    }

    buf
}

/// Split `entries` into one or more SYNC_PUSH frames bounded by
/// [`SYNC_PUSH_MAX_ENTRIES`] and [`SYNC_PUSH_MAX_BYTES`]; the last frame
/// has the [`sync_push_flags::LAST`] bit set. Always returns at least one
/// frame, even when `entries` is empty (the empty terminator).
///
/// Receivers must loop reading SYNC_PUSH frames until the LAST bit fires
/// — otherwise they'll terminate the read early or hang waiting for data
/// that's not coming.
pub fn encode_sync_push_chunks(drive: &str, entries: &[(&str, &[u8])]) -> Vec<Vec<u8>> {
    if entries.is_empty() {
        return vec![encode_sync_push(drive, &[], true)];
    }

    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut start = 0;
    while start < entries.len() {
        let mut end = start;
        let mut bytes_acc: usize = 0;
        while end < entries.len() && end - start < SYNC_PUSH_MAX_ENTRIES {
            let (s, b) = entries[end];
            let entry_size = 2 + s.len() + 4 + b.len();
            // Always include at least one entry per chunk, even if it alone
            // exceeds the byte budget — chunking past a single oversized
            // entry isn't possible without subdividing the loro_bytes.
            if end > start && bytes_acc + entry_size > SYNC_PUSH_MAX_BYTES {
                break;
            }
            bytes_acc += entry_size;
            end += 1;
        }
        let last = end == entries.len();
        chunks.push(encode_sync_push(drive, &entries[start..end], last));
        start = end;
    }
    chunks
}

/// Encode a HELLO frame: `[0x37] [name_len: u16] [name_utf8]`.
///
/// `name` is the sender's self-reported display name. Pass an empty string
/// if you don't have one — the receiver still decodes it; the UI just shows
/// "Unknown device". This frame is purely informational; downstream auth
/// decisions must use the authenticated agent or Iroh NodeId.
pub fn encode_hello(name: &str) -> Vec<u8> {
    encode_hello_with_caps(name, CAPABILITIES)
}

/// Encode a HELLO frame with an explicit capability list:
/// `[0x37] [name_len: u16] [name_utf8] [caps_json_utf8]`.
///
/// The capability list is a trailing, optional JSON array. `decode_hello`
/// has always ignored bytes after the name, so a pre-2026-09 peer reads the
/// name and skips the list; a current peer reads both via
/// [`decode_hello_caps`].
pub fn encode_hello_with_caps(name: &str, caps: &[&str]) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    // u16 length prefix bounds the wire size at ~64 KB even if the caller
    // hands us a giant string. `decode_hello` enforces the real display cap.
    let len = name_bytes.len().min(u16::MAX as usize);
    let caps_bytes = if caps.is_empty() {
        Vec::new()
    } else {
        serde_json::to_vec(caps).unwrap_or_default()
    };
    let mut buf = Vec::with_capacity(3 + len + caps_bytes.len());
    buf.push(tag::HELLO);
    buf.extend_from_slice(&(len as u16).to_be_bytes());
    buf.extend_from_slice(&name_bytes[..len]);
    buf.extend_from_slice(&caps_bytes);
    buf
}

/// The capability names carried after the name in a HELLO payload (slice
/// *after* the tag byte). Empty for a malformed frame or a peer that sent
/// none.
pub fn decode_hello_caps(data: &[u8]) -> Vec<String> {
    if data.len() < 2 {
        return Vec::new();
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    match data.get(2 + len..) {
        Some(rest) if !rest.is_empty() => {
            serde_json::from_slice::<Vec<String>>(rest).unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

/// Largest ephemeral payload accepted from a peer. Presence is cursor
/// positions and selections, not documents — anything larger is a bug or an
/// attempt to push real data down a channel that skips every rights check a
/// write would face.
pub const EPHEMERAL_MAX_PAYLOAD: usize = 64 * 1024;

/// Largest [`ephemeral_kind::DOC`] payload accepted from a peer.
///
/// Roomier than [`EPHEMERAL_MAX_PAYLOAD`] because this kind carries content: a
/// keystroke is tens of bytes, but pasting a section of a document is a single
/// op and can be far larger. Still bounded — a whole document arrives as a
/// snapshot through the sync handshake, not through here.
pub const LIVE_DOC_MAX_PAYLOAD: usize = 1024 * 1024;

/// The payload ceiling for one [`ephemeral_kind`].
pub fn max_payload_for_kind(kind: u8) -> usize {
    if kind == ephemeral_kind::DOC {
        LIVE_DOC_MAX_PAYLOAD
    } else {
        EPHEMERAL_MAX_PAYLOAD
    }
}

/// Encode an EPHEMERAL frame: `drive`, the agent it originated from, and an
/// opaque payload (a Loro `EphemeralStore` update).
///
/// The agent travels with the frame because a peer link is node-to-node while
/// presence is per-agent: one node may relay several agents' cursors, and the
/// receiver needs to know whose it is — to attribute it, and to decide whether
/// it may be shown at all.
pub fn encode_ephemeral(kind: u8, drive: &str, agent: &str, payload: &[u8]) -> Vec<u8> {
    let drive_bytes = drive.as_bytes();
    let agent_bytes = agent.as_bytes();
    let drive_len = drive_bytes.len().min(u16::MAX as usize);
    let agent_len = agent_bytes.len().min(u16::MAX as usize);

    let mut buf = Vec::with_capacity(2 + 2 + drive_len + 2 + agent_len + payload.len());
    buf.push(tag::EPHEMERAL);
    buf.push(kind);
    buf.extend_from_slice(&(drive_len as u16).to_be_bytes());
    buf.extend_from_slice(&drive_bytes[..drive_len]);
    buf.extend_from_slice(&(agent_len as u16).to_be_bytes());
    buf.extend_from_slice(&agent_bytes[..agent_len]);
    buf.extend_from_slice(payload);
    buf
}

/// A decoded EPHEMERAL frame. Never persisted — see the read loop in `peer.rs`.
#[derive(Debug, Clone)]
pub struct DecodedEphemeral {
    /// See [`ephemeral_kind`].
    pub kind: u8,
    pub drive: String,
    pub agent: String,
    pub payload: Vec<u8>,
}

/// Decode the payload of an EPHEMERAL frame (slice *after* the tag byte).
///
/// Returns `None` on truncation, invalid UTF-8, or a payload beyond
/// [`max_payload_for_kind`]. Fail closed rather than attempt recovery — for
/// presence because it is the least important thing on the link, and for
/// [`ephemeral_kind::DOC`] because a half-read op is worse than a missing one:
/// the sender's next save pushes a full snapshot, so a dropped frame costs a
/// moment of divergence, not the edit.
pub fn decode_ephemeral(data: &[u8]) -> Option<DecodedEphemeral> {
    if data.len() < 3 {
        return None;
    }

    let kind = data[0];
    let drive_len = u16::from_be_bytes([data[1], data[2]]) as usize;
    let mut cursor = 3;

    if data.len() < cursor + drive_len {
        return None;
    }

    let drive = std::str::from_utf8(&data[cursor..cursor + drive_len])
        .ok()?
        .to_string();
    cursor += drive_len;

    if data.len() < cursor + 2 {
        return None;
    }

    let agent_len = u16::from_be_bytes([data[cursor], data[cursor + 1]]) as usize;
    cursor += 2;

    if data.len() < cursor + agent_len {
        return None;
    }

    let agent = std::str::from_utf8(&data[cursor..cursor + agent_len])
        .ok()?
        .to_string();
    cursor += agent_len;

    let payload = data[cursor..].to_vec();

    if payload.len() > max_payload_for_kind(kind) {
        return None;
    }

    Some(DecodedEphemeral {
        kind,
        drive,
        agent,
        payload,
    })
}

/// Decode the payload of a HELLO frame (slice *after* the tag byte).
///
/// Returns `None` if the frame is malformed (truncated, invalid UTF-8, or
/// the decoded name exceeds [`HELLO_MAX_CHARS`] scalar values). Control
/// characters are stripped so a hostile peer can't smuggle line breaks
/// into log output.
pub fn decode_hello(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + len {
        return None;
    }
    let raw = std::str::from_utf8(&data[2..2 + len]).ok()?;
    // Strip control chars; we display the name in HTML/logs as-is.
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).collect();
    if cleaned.chars().count() > HELLO_MAX_CHARS {
        return None;
    }
    Some(cleaned)
}

/// Encode a BLOB_REQUEST message: [0x34] [hash: [u8; 32]]
pub fn encode_blob_request(hash: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 32);
    buf.push(tag::BLOB_REQUEST);
    buf.extend_from_slice(hash);
    buf
}

/// Encode a BLOB_RESPONSE message: [0x35] [hash: [u8; 32]] [bytes...]
pub fn encode_blob_response(hash: &[u8; 32], bytes: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 32 + bytes.len());
    buf.push(tag::BLOB_RESPONSE);
    buf.extend_from_slice(hash);
    buf.extend_from_slice(bytes);
    buf
}

/// Decoded UPDATE message.
///
/// Authoritative source of truth for the wire format: [docs/src/websockets.md](file:///Users/joep/dev/atomic-server/docs/src/websockets.md)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedUpdate {
    pub flag_bits: u8,
    pub request_id: u16,
    pub subject: String,
    pub commit_id: Option<String>,
    pub loro_bytes: Vec<u8>,
}

/// Decode an UPDATE message (after the type tag).
///
/// Authoritative source of truth for the wire format: [docs/src/websockets.md](file:///Users/joep/dev/atomic-server/docs/src/websockets.md)
pub fn decode_update(payload: &[u8]) -> Option<DecodedUpdate> {
    if payload.len() < 5 {
        return None;
    }
    let flag_bits = payload[0];
    let request_id = u16::from_be_bytes([payload[1], payload[2]]);
    let subject_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let mut cursor = 5;
    if payload.len() < cursor + subject_len {
        return None;
    }
    let subject = std::str::from_utf8(&payload[cursor..cursor + subject_len])
        .ok()?
        .to_string();
    cursor += subject_len;

    let mut commit_id = None;
    if flag_bits & flags::HAS_COMMIT_ID != 0 {
        if payload.len() < cursor + 2 {
            return None;
        }
        let cid_len = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]) as usize;
        cursor += 2;
        if payload.len() < cursor + cid_len {
            return None;
        }
        commit_id = Some(
            std::str::from_utf8(&payload[cursor..cursor + cid_len])
                .ok()?
                .to_string(),
        );
        cursor += cid_len;
    }

    let loro_bytes = payload[cursor..].to_vec();

    Some(DecodedUpdate {
        flag_bits,
        request_id,
        subject,
        commit_id,
        loro_bytes,
    })
}

// ---- Decoding (used by binary frame handler) ----

/// Decoded GET message.
pub struct DecodedGet<'a> {
    pub request_id: u16,
    pub subject: &'a str,
}

/// Decoded COMMIT / COMMIT_OK message.
pub struct DecodedCommit<'a> {
    pub request_id: u16,
    pub commit_json: &'a str,
}

/// Decode a GET message (after the type tag).
pub fn decode_get(data: &[u8]) -> Option<DecodedGet<'_>> {
    if data.len() < 2 {
        return None;
    }

    let request_id = u16::from_be_bytes([data[0], data[1]]);
    let subject = std::str::from_utf8(&data[2..]).ok()?;
    Some(DecodedGet {
        request_id,
        subject,
    })
}

/// Decode a COMMIT or COMMIT_OK message (after the type tag).
pub fn decode_commit(data: &[u8]) -> Option<DecodedCommit<'_>> {
    if data.len() < 2 {
        return None;
    }

    let request_id = u16::from_be_bytes([data[0], data[1]]);
    let commit_json = std::str::from_utf8(&data[2..]).ok()?;
    Some(DecodedCommit {
        request_id,
        commit_json,
    })
}

/// Decode a BLOB_REQUEST message (after the type tag).
pub fn decode_blob_request(data: &[u8]) -> Option<[u8; 32]> {
    if data.len() < 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[0..32]);
    Some(hash)
}

/// Decoded BLOB_RESPONSE message.
pub struct DecodedBlobResponse {
    pub hash: [u8; 32],
    pub bytes: Vec<u8>,
}

/// Decode a BLOB_RESPONSE message (after the type tag).
pub fn decode_blob_response(data: &[u8]) -> Option<DecodedBlobResponse> {
    if data.len() < 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[0..32]);
    let bytes = data[32..].to_vec();
    Some(DecodedBlobResponse { hash, bytes })
}

/// Encode SYNC (client → server): [0x30] [drive_len: u16] [drive] [hash_len: u16] [hash] [json{peers, resources}]
pub fn encode_sync(
    drive: &str,
    drive_hash: &str,
    peers: &[String],
    resources: &std::collections::HashMap<String, Vec<i32>>,
) -> Vec<u8> {
    encode_sync_json(
        drive,
        drive_hash,
        serde_json::json!({ "peers": peers, "resources": resources }),
    )
}

/// A hash-first `SYNC` probe: the drive and its hash, no version vectors.
/// The responder answers `SYNC_OK` when its hash over what this session may
/// read matches, `SYNC_RESEND` when not, and `ERROR UNAUTHORIZED_READ` for
/// a drive the session may not read. Payload: `{"peers":[],"resources":{},"probe":true}`.
pub fn encode_sync_probe(drive: &str, drive_hash: &str) -> Vec<u8> {
    encode_sync_json(
        drive,
        drive_hash,
        serde_json::json!({ "peers": [], "resources": {}, "probe": true }),
    )
}

/// A `SYNC` over only `subjects` (the ones an RBSR descent found
/// differing): the responder builds version vectors for that set instead
/// of walking the drive, and both comparison loops skip anything outside it.
pub fn encode_sync_filtered(
    drive: &str,
    drive_hash: &str,
    peers: &[String],
    resources: &std::collections::HashMap<String, Vec<i32>>,
    subjects: &[String],
) -> Vec<u8> {
    encode_sync_json(
        drive,
        drive_hash,
        serde_json::json!({ "peers": peers, "resources": resources, "subjects": subjects }),
    )
}

fn encode_sync_json(drive: &str, drive_hash: &str, json: serde_json::Value) -> Vec<u8> {
    let drive_bytes = drive.as_bytes();
    let hash_bytes = drive_hash.as_bytes();
    let json_bytes = serde_json::to_vec(&json).unwrap_or_default();

    let mut buf =
        Vec::with_capacity(1 + 2 + drive_bytes.len() + 2 + hash_bytes.len() + json_bytes.len());
    buf.push(tag::SYNC);
    buf.extend_from_slice(&(drive_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(drive_bytes);
    buf.extend_from_slice(&(hash_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(hash_bytes);
    buf.extend_from_slice(&json_bytes);
    buf
}

/// Decoded SYNC message.
pub struct DecodedSync {
    pub drive: String,
    pub drive_hash: String,
    pub peers: Vec<String>,
    pub resources: std::collections::HashMap<String, Vec<i32>>,
    /// Hash-first probe: only `drive_hash` is meaningful; answer with
    /// `SYNC_OK` or `SYNC_RESEND` rather than a diff.
    pub probe: bool,
    /// When present, reconcile only these subjects (the RBSR-reduced set).
    pub subjects: Option<Vec<String>>,
}

/// Decode a SYNC message (after the type tag).
pub fn decode_sync(data: &[u8]) -> Option<DecodedSync> {
    if data.len() < 4 {
        return None;
    }
    let drive_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let drive = std::str::from_utf8(data.get(2..2 + drive_len)?).ok()?;
    let rest = data.get(2 + drive_len..)?;

    if rest.len() < 2 {
        return None;
    }
    let hash_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    let hash = std::str::from_utf8(rest.get(2..2 + hash_len)?).ok()?;
    let json_bytes = rest.get(2 + hash_len..)?;

    #[derive(serde::Deserialize)]
    struct SyncJson {
        #[serde(default)]
        peers: Vec<String>,
        #[serde(default)]
        resources: std::collections::HashMap<String, Vec<i32>>,
        #[serde(default)]
        probe: bool,
        #[serde(default)]
        subjects: Option<Vec<String>>,
    }

    let parsed: SyncJson = serde_json::from_slice(json_bytes).ok()?;

    Some(DecodedSync {
        drive: drive.to_string(),
        drive_hash: hash.to_string(),
        peers: parsed.peers,
        resources: parsed.resources,
        probe: parsed.probe,
        subjects: parsed.subjects,
    })
}

/// Encode SYNC_RESEND: `[0x38] [drive_utf8]`. See [`tag::SYNC_RESEND`].
pub fn encode_sync_resend(drive: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + drive.len());
    buf.push(tag::SYNC_RESEND);
    buf.extend_from_slice(drive.as_bytes());
    buf
}

/// Decode a SYNC_RESEND payload (slice *after* the tag byte): the drive.
pub fn decode_sync_resend(data: &[u8]) -> Option<&str> {
    let drive = std::str::from_utf8(data).ok()?;
    if drive.is_empty() {
        return None;
    }
    Some(drive)
}

/// Decoded SYNC_DIFF message.
pub struct DecodedSyncDiff {
    pub drive: String,
    pub pull: Vec<String>,
    pub push: Vec<String>,
    /// Subjects the client should delete (destroyed on the server).
    pub remove: Vec<String>,
    /// Signed destroy commit JSON-AD per `remove` subject, when the sender
    /// still holds the envelope on the tombstone. Missing entries are the
    /// unsigned tombstone path (admission-gated).
    pub remove_commits: std::collections::HashMap<String, String>,
    /// Server oplog VV per `pull` subject — client exports updates since this.
    pub pull_from: std::collections::HashMap<String, std::collections::HashMap<String, i32>>,
}

/// Decode a SYNC_DIFF message (after the type tag).
pub fn decode_sync_diff(data: &[u8]) -> Option<DecodedSyncDiff> {
    if data.len() < 2 {
        return None;
    }
    let drive_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let drive = std::str::from_utf8(data.get(2..2 + drive_len)?).ok()?;
    let json_bytes = data.get(2 + drive_len..)?;

    #[derive(serde::Deserialize)]
    struct DiffJson {
        pull: Vec<String>,
        push: Vec<String>,
        #[serde(default)]
        remove: Vec<String>,
        #[serde(default, rename = "removeCommits")]
        remove_commits: std::collections::HashMap<String, String>,
        #[serde(default, rename = "pullFrom")]
        pull_from: std::collections::HashMap<String, std::collections::HashMap<String, i32>>,
    }

    let parsed: DiffJson = serde_json::from_slice(json_bytes).ok()?;

    Some(DecodedSyncDiff {
        drive: drive.to_string(),
        pull: parsed.pull,
        push: parsed.push,
        remove: parsed.remove,
        remove_commits: parsed.remove_commits,
        pull_from: parsed.pull_from,
    })
}

/// A single entry in a SYNC_PUSH message.
pub struct SyncPushEntry {
    pub subject: String,
    pub loro_bytes: Vec<u8>,
}

/// Decoded SYNC_PUSH message.
pub struct DecodedSyncPush {
    pub drive: String,
    pub entries: Vec<SyncPushEntry>,
    /// True iff this is the final chunk of a SYNC_PUSH run. Receivers loop
    /// reading SYNC_PUSH frames until they see one with `last == true`.
    pub last: bool,
}

/// Decode a SYNC_PUSH message (after the type tag).
pub fn decode_sync_push(data: &[u8]) -> Option<DecodedSyncPush> {
    if data.len() < 4 {
        return None;
    }
    let drive_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let drive = std::str::from_utf8(data.get(2..2 + drive_len)?).ok()?;
    let rest = data.get(2 + drive_len..)?;

    // [flags: u8] [count: u16] [entries...]
    if rest.len() < 3 {
        return None;
    }
    let flag_bits = rest[0];
    let last = flag_bits & sync_push_flags::LAST != 0;
    let count = u16::from_be_bytes([rest[1], rest[2]]) as usize;
    let mut pos = 3;
    let mut entries = Vec::with_capacity(count);

    for _ in 0..count {
        if pos + 2 > rest.len() {
            break;
        }
        let subj_len = u16::from_be_bytes([rest[pos], rest[pos + 1]]) as usize;
        pos += 2;
        let subject = std::str::from_utf8(rest.get(pos..pos + subj_len)?).ok()?;
        pos += subj_len;

        if pos + 4 > rest.len() {
            break;
        }
        let bytes_len =
            u32::from_be_bytes([rest[pos], rest[pos + 1], rest[pos + 2], rest[pos + 3]]) as usize;
        pos += 4;
        let loro_bytes = rest.get(pos..pos + bytes_len)?.to_vec();
        pos += bytes_len;

        entries.push(SyncPushEntry {
            subject: subject.to_string(),
            loro_bytes,
        });
    }

    Some(DecodedSyncPush {
        drive: drive.to_string(),
        entries,
        last,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_round_trip() {
        let flag_bits = flags::SNAPSHOT | flags::HAS_COMMIT_ID | flags::PUSH;
        let encoded = encode_update(
            flag_bits,
            42,
            "did:ad:test",
            Some("did:ad:commit:abc"),
            b"loro-snapshot-bytes",
        );

        assert_eq!(encoded[0], tag::UPDATE);
        let decoded = decode_update(&encoded[1..]).expect("Should decode");
        assert_eq!(decoded.flag_bits, flag_bits);
        assert_eq!(decoded.request_id, 42);
        assert_eq!(decoded.subject, "did:ad:test");
        assert_eq!(decoded.commit_id.as_deref(), Some("did:ad:commit:abc"));
        assert_eq!(decoded.loro_bytes, b"loro-snapshot-bytes");
    }

    #[test]
    fn legacy_update_decoder_bug_regression() {
        let flag_bits = flags::HAS_COMMIT_ID;
        let original_loro = b"loro-payload";
        let commit_id = "did:ad:commit:123";
        let subject = "did:ad:test";

        let encoded = encode_update(flag_bits, 1, subject, Some(commit_id), original_loro);

        // Simulate legacy peer.rs slicing behavior:
        let payload = &encoded[1..];
        let subject_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
        let legacy_loro_bytes = &payload[5 + subject_len..];

        // The legacy parser slices starting at 5 + subject_len.
        // Since HAS_COMMIT_ID is set, the payload at 5 + subject_len contains
        // 2 bytes of commit_id length, then the commit_id, then the original loro bytes.
        // Therefore, legacy_loro_bytes starts with the commit ID data, not original_loro!
        assert_ne!(legacy_loro_bytes, original_loro);

        // The new unified decoder should parse it correctly.
        let decoded = decode_update(&encoded[1..]).unwrap();
        assert_eq!(decoded.loro_bytes, original_loro);
        assert_eq!(decoded.commit_id.as_deref(), Some(commit_id));
        assert_eq!(decoded.subject, subject);
        assert_eq!(decoded.flag_bits, flag_bits);
    }

    #[test]
    fn get_round_trip() {
        let encoded = encode_get(7, "did:ad:agent:alice");
        assert_eq!(encoded[0], tag::GET);
        let decoded = decode_get(&encoded[1..]).unwrap();
        assert_eq!(decoded.request_id, 7);
        assert_eq!(decoded.subject, "did:ad:agent:alice");
    }

    #[test]
    fn hello_round_trip() {
        let encoded = encode_hello("Joe's Laptop");
        assert_eq!(encoded[0], tag::HELLO);
        let decoded = decode_hello(&encoded[1..]).unwrap();
        assert_eq!(decoded, "Joe's Laptop");
    }

    #[test]
    fn hello_empty_name() {
        let encoded = encode_hello("");
        let decoded = decode_hello(&encoded[1..]).unwrap();
        assert_eq!(decoded, "");
    }

    #[test]
    fn hello_strips_control_chars() {
        // A peer trying to smuggle newlines into our logs gets them stripped.
        let encoded = encode_hello("OK\nFAKE-LINE");
        let decoded = decode_hello(&encoded[1..]).unwrap();
        assert_eq!(decoded, "OKFAKE-LINE");
    }

    #[test]
    fn hello_rejects_oversize_name() {
        // 65 ASCII chars > HELLO_MAX_CHARS (64) → reject.
        let name = "x".repeat(HELLO_MAX_CHARS + 1);
        let encoded = encode_hello(&name);
        assert!(decode_hello(&encoded[1..]).is_none());
    }

    #[test]
    fn hello_counts_unicode_scalars_not_bytes() {
        // 64 emoji = 64 chars (well under the byte limit). Must decode.
        let name = "🚀".repeat(HELLO_MAX_CHARS);
        let encoded = encode_hello(&name);
        assert_eq!(decode_hello(&encoded[1..]).unwrap(), name);
    }

    #[test]
    fn hello_truncated_payload_returns_none() {
        // Bare frame (no capability suffix), so truncating cuts the name.
        let mut encoded = encode_hello_with_caps("hello", &[]);
        encoded.truncate(encoded.len() - 2);
        assert!(decode_hello(&encoded[1..]).is_none());
    }

    #[test]
    fn commit_round_trip() {
        let json = r#"{"https://atomicdata.dev/properties/subject":"did:ad:test"}"#;
        let encoded = encode_commit(42, json);
        assert_eq!(encoded[0], tag::COMMIT);
        let decoded = decode_commit(&encoded[1..]).unwrap();
        assert_eq!(decoded.request_id, 42);
        assert_eq!(decoded.commit_json, json);
    }

    #[test]
    fn commit_ok_round_trip() {
        let json = r#"{"@id":"did:ad:commit:test"}"#;
        let encoded = encode_commit_ok(43, json);
        assert_eq!(encoded[0], tag::COMMIT_OK);
        let decoded = decode_commit(&encoded[1..]).unwrap();
        assert_eq!(decoded.request_id, 43);
        assert_eq!(decoded.commit_json, json);
    }

    #[test]
    fn sync_push_structure() {
        let entries: Vec<(&str, &[u8])> =
            vec![("did:ad:r1", b"snapshot1"), ("did:ad:r2", b"delta2")];
        let encoded = encode_sync_push("did:ad:drive", &entries, true);
        assert_eq!(encoded[0], tag::SYNC_PUSH);
        let decoded = decode_sync_push(&encoded[1..]).unwrap();
        assert_eq!(decoded.drive, "did:ad:drive");
        assert_eq!(decoded.entries.len(), 2);
        assert!(decoded.last, "single-frame push must set LAST");
    }

    #[test]
    fn sync_push_chunking() {
        // 250 entries of ~5 bytes each → at least 3 chunks at 100 entries
        // per chunk. Only the final chunk should be marked LAST.
        let small_blob = vec![0u8; 4];
        let owned: Vec<(String, Vec<u8>)> = (0..250)
            .map(|i| (format!("did:ad:r{i}"), small_blob.clone()))
            .collect();
        let entries: Vec<(&str, &[u8])> = owned
            .iter()
            .map(|(s, b)| (s.as_str(), b.as_slice()))
            .collect();

        let chunks = encode_sync_push_chunks("did:ad:drive", &entries);
        assert!(
            chunks.len() >= 3,
            "expected ≥3 chunks, got {}",
            chunks.len()
        );

        let mut total_entries = 0;
        for (i, chunk) in chunks.iter().enumerate() {
            let decoded = decode_sync_push(&chunk[1..]).expect("decode chunk");
            total_entries += decoded.entries.len();
            let is_last = i == chunks.len() - 1;
            assert_eq!(
                decoded.last, is_last,
                "chunk {} LAST flag wrong (is_last={})",
                i, is_last
            );
        }
        assert_eq!(total_entries, 250);
    }

    #[test]
    fn sync_push_empty_terminator() {
        // Empty entries still produces one frame with LAST set, so
        // receivers don't hang waiting for a terminator.
        let chunks = encode_sync_push_chunks("did:ad:drive", &[]);
        assert_eq!(chunks.len(), 1);
        let decoded = decode_sync_push(&chunks[0][1..]).unwrap();
        assert_eq!(decoded.entries.len(), 0);
        assert!(decoded.last);
    }

    #[test]
    fn error_encoding() {
        let encoded = encode_error(99, error_code::UNAUTHORIZED_WRITE, "Not found");
        assert_eq!(encoded[0], tag::ERROR);
        let request_id = u16::from_be_bytes([encoded[1], encoded[2]]);
        assert_eq!(request_id, 99);
        let code = u16::from_be_bytes([encoded[3], encoded[4]]);
        assert_eq!(code, error_code::UNAUTHORIZED_WRITE);
        assert_eq!(&encoded[5..], b"Not found");
    }

    #[test]
    fn classify_commit_error_matches_known_patterns() {
        assert_eq!(
            classify_commit_error("is_genesis: true, but the resource already exists"),
            error_code::GENESIS_COLLISION
        );
        assert_eq!(
            classify_commit_error("Property foo missing. Is required in class Bar"),
            error_code::MISSING_REQUIRED_PROPERTY
        );
        assert_eq!(
            classify_commit_error(
                "Unauthorized. No https://atomicdata.dev/properties/write right has been found for did:ad:agent:x"
            ),
            error_code::UNAUTHORIZED_WRITE
        );
        assert_eq!(
            classify_commit_error(
                "Incorrect signature for Commit. This could be due to an error during signing"
            ),
            error_code::INVALID_SIGNATURE
        );
        assert_eq!(
            classify_commit_error("some other error"),
            error_code::UNKNOWN
        );
    }

    /// The message a table row gets when its class never reached this server.
    /// Verbatim from the field, where every row of a shared table was refused
    /// with it and nothing surfaced that to either person.
    #[test]
    fn a_missing_class_is_classified_rather_than_left_unknown() {
        assert_eq!(
            classify_commit_error(
                "Failed getting class did:ad:ViKExaq3nm6tVE5UCaCzEQhe7lwOrd. \
                 Resource not found. DID Resource did:ad:ViKExaq3nm6tVE5UCaCzEQhe7lwOrd \
                 not found locally"
            ),
            error_code::MISSING_CLASS
        );
    }

    #[test]
    fn encode_sub_frame() {
        let encoded = encode_sub("did:ad:drive:abc");
        assert_eq!(encoded[0], tag::SUB);
        assert_eq!(&encoded[1..], b"did:ad:drive:abc");
    }
}

#[cfg(test)]
mod ephemeral_frame_tests {
    use super::*;

    #[test]
    fn an_ephemeral_frame_round_trips() {
        let payload = vec![0xAA, 0xBB, 0x00, 0xFF];
        let frame = encode_ephemeral(
            ephemeral_kind::PRESENCE,
            "did:ad:drive123",
            "did:ad:agent:abc",
            &payload,
        );

        assert_eq!(frame[0], tag::EPHEMERAL);

        let decoded = decode_ephemeral(&frame[1..]).expect("must decode");
        assert_eq!(decoded.kind, ephemeral_kind::PRESENCE);
        assert_eq!(decoded.drive, "did:ad:drive123");
        assert_eq!(decoded.agent, "did:ad:agent:abc");
        assert_eq!(decoded.payload, payload);
    }

    /// Presence skips every check a write faces, so an oversized payload is
    /// either a bug or an attempt to move real data down it. Drop, don't parse.
    #[test]
    fn an_oversized_payload_is_refused() {
        let payload = vec![0u8; EPHEMERAL_MAX_PAYLOAD + 1];
        let frame = encode_ephemeral(
            ephemeral_kind::PRESENCE,
            "did:ad:drive123",
            "did:ad:agent:abc",
            &payload,
        );

        assert!(decode_ephemeral(&frame[1..]).is_none());
    }

    /// Fail closed on anything malformed: presence is the least important
    /// thing on the link, so a truncated frame is dropped rather than guessed.
    #[test]
    fn a_truncated_frame_is_refused() {
        let frame = encode_ephemeral(
            ephemeral_kind::LORO,
            "did:ad:drive123",
            "did:ad:agent:abc",
            &[1, 2, 3],
        );

        for cut in 1..frame.len().min(24) {
            let _ = decode_ephemeral(&frame[1..cut]);
        }

        assert!(decode_ephemeral(&[]).is_none());
        assert!(decode_ephemeral(&[0xFF]).is_none());
    }

    /// An edit in progress is content, not a cursor: a paste is one op and can
    /// be far bigger than any selection. Holding it to the presence ceiling
    /// would drop exactly the edits most worth relaying.
    #[test]
    fn an_edit_may_carry_more_than_a_cursor() {
        let payload = vec![7u8; EPHEMERAL_MAX_PAYLOAD + 1];
        let frame = encode_ephemeral(
            ephemeral_kind::DOC,
            "did:ad:doc123",
            "did:ad:agent:abc",
            &payload,
        );

        let decoded = decode_ephemeral(&frame[1..]).expect("must decode");
        assert_eq!(decoded.kind, ephemeral_kind::DOC);
        assert_eq!(decoded.payload, payload);
    }

    /// Roomier is not unbounded — a whole document arrives as a snapshot
    /// through the sync handshake, never through this channel.
    #[test]
    fn an_edit_past_its_own_ceiling_is_refused() {
        let payload = vec![7u8; LIVE_DOC_MAX_PAYLOAD + 1];
        let frame = encode_ephemeral(
            ephemeral_kind::DOC,
            "did:ad:doc123",
            "did:ad:agent:abc",
            &payload,
        );

        assert!(decode_ephemeral(&frame[1..]).is_none());
    }

    #[test]
    fn sync_diff_remove_commits_roundtrip() {
        let mut pull_from = std::collections::HashMap::new();
        pull_from.insert(
            "did:ad:y".to_string(),
            [("p1".to_string(), 2)].into_iter().collect(),
        );
        let mut remove_commits = std::collections::HashMap::new();
        remove_commits.insert(
            "did:ad:z".to_string(),
            r#"{"https://atomicdata.dev/properties/destroy":true}"#.to_string(),
        );
        let frame = encode_sync_diff(
            "did:ad:d",
            &["did:ad:y".to_string()],
            &["did:ad:x".to_string()],
            &["did:ad:z".to_string()],
            &pull_from,
            &remove_commits,
        );
        let d = decode_sync_diff(&frame[1..]).unwrap();
        assert_eq!(d.remove, vec!["did:ad:z"]);
        assert_eq!(
            d.remove_commits.get("did:ad:z").map(String::as_str),
            Some(r#"{"https://atomicdata.dev/properties/destroy":true}"#)
        );
    }
}

/// Golden wire frames shared with the TypeScript codec
/// (`browser/lib/src/ws-v2.test.ts` reads the same file). Every frame both
/// sides can encode must come out byte-identical; every frame either side
/// decodes must decode to the recorded fields. Regenerate with
/// `cargo test -p atomic_lib print_wire_vectors -- --ignored --nocapture`
/// after a deliberate wire change, and update `docs/src/websockets.md` in
/// the same commit.
#[cfg(test)]
mod wire_vectors {
    use super::*;

    const VECTORS_JSON: &str = include_str!("protocol_vectors.json");

    fn build() -> Vec<(&'static str, Vec<u8>)> {
        let mut resources = std::collections::HashMap::new();
        resources.insert("did:ad:x".to_string(), vec![3, 0]);
        let mut pull_from = std::collections::HashMap::new();
        let mut from = std::collections::HashMap::new();
        from.insert("p1".to_string(), 2);
        pull_from.insert("did:ad:y".to_string(), from);
        vec![
            (
                "auth_ok_caps",
                encode_auth_ok_with_caps(&["keepalive", "unsub"]),
            ),
            ("auth_ok_bare", encode_auth_ok_with_caps(&[])),
            (
                "error",
                encode_error(
                    7,
                    error_code::UNAUTHORIZED_READ,
                    "SUB refused for did:ad:d: no",
                ),
            ),
            ("get", encode_get(1, "did:ad:x")),
            (
                "update_delta_push",
                encode_update(
                    flags::HAS_COMMIT_ID | flags::PUSH,
                    0,
                    "did:ad:x",
                    Some("did:ad:commit:abc"),
                    &[1, 2, 3],
                ),
            ),
            (
                "update_snapshot",
                encode_update(flags::SNAPSHOT, 5, "did:ad:x", None, &[0xff]),
            ),
            ("destroy", encode_destroy(0, "did:ad:x")),
            ("commit", encode_commit(9, "{\"a\":1}")),
            ("commit_ok", encode_commit_ok(9, "{\"a\":1}")),
            (
                "commit_ok_slim",
                encode_commit_ok_slim(9, "did:ad:commit:abc"),
            ),
            ("challenge", encode_challenge("0badf00d")),
            ("sub", encode_sub("did:ad:d")),
            ("unsub", encode_unsub("did:ad:d")),
            (
                "sync",
                encode_sync(
                    "did:ad:d",
                    "abc123",
                    &["p1".to_string(), "p2".to_string()],
                    &resources,
                ),
            ),
            ("sync_probe", encode_sync_probe("did:ad:d", "abc123")),
            (
                "sync_filtered",
                encode_sync_filtered(
                    "did:ad:d",
                    "abc123",
                    &["p1".to_string()],
                    &resources,
                    &["did:ad:x".to_string()],
                ),
            ),
            ("sync_resend", encode_sync_resend("did:ad:d")),
            ("sync_ok", encode_sync_ok("did:ad:d")),
            (
                "sync_diff",
                encode_sync_diff(
                    "did:ad:d",
                    &["did:ad:y".to_string()],
                    &["did:ad:x".to_string()],
                    &["did:ad:z".to_string()],
                    &pull_from,
                    &std::collections::HashMap::new(),
                ),
            ),
            (
                "sync_push_last",
                encode_sync_push("did:ad:d", &[("did:ad:x", &[1, 2])], true),
            ),
            ("blob_request", encode_blob_request(&[0xab; 32])),
            ("blob_response", encode_blob_response(&[0xab; 32], &[9, 9])),
            (
                "hello_caps",
                encode_hello_with_caps("Dev 🚀", &["keepalive"]),
            ),
            ("hello_bare", encode_hello_with_caps("Dev", &[])),
            ("keepalive", encode_keepalive()),
            (
                "ephemeral_presence",
                encode_ephemeral(ephemeral_kind::PRESENCE, "did:ad:d", "did:ad:agent:a", &[7]),
            ),
        ]
    }

    fn recorded() -> std::collections::BTreeMap<String, String> {
        let parsed: serde_json::Value = serde_json::from_str(VECTORS_JSON).unwrap();
        parsed["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                (
                    v["name"].as_str().unwrap().to_string(),
                    v["hex"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn rust_encoders_match_recorded_wire_vectors() {
        let recorded = recorded();
        let built = build();
        assert_eq!(
            recorded.len(),
            built.len(),
            "protocol_vectors.json and build() list different frames; regenerate"
        );
        for (name, frame) in built {
            let expected = recorded
                .get(name)
                .unwrap_or_else(|| panic!("no recorded vector named {name}; regenerate"));
            assert_eq!(
                &hex::encode(&frame),
                expected,
                "wire layout of `{name}` changed; if deliberate, regenerate the vectors and update docs/src/websockets.md"
            );
        }
    }

    #[test]
    fn recorded_vectors_decode() {
        let recorded = recorded();
        let hex_of = |name: &str| hex::decode(recorded.get(name).unwrap()).unwrap();

        let e = decode_error(&hex_of("error")[1..]).unwrap();
        assert_eq!((e.request_id, e.code), (7, error_code::UNAUTHORIZED_READ));
        assert_eq!(
            decode_auth_ok(&hex_of("auth_ok_caps")[1..]),
            vec!["keepalive", "unsub"]
        );
        assert!(decode_auth_ok(&hex_of("auth_ok_bare")[1..]).is_empty());
        let u = decode_update(&hex_of("update_delta_push")[1..]).unwrap();
        assert_eq!(u.commit_id.as_deref(), Some("did:ad:commit:abc"));
        assert_eq!(u.loro_bytes, &[1, 2, 3]);
        let s = decode_sync(&hex_of("sync")[1..]).unwrap();
        assert_eq!(s.drive_hash, "abc123");
        assert_eq!(s.peers, vec!["p1", "p2"]);
        assert!(!s.probe);
        assert!(s.subjects.is_none());
        let probe = decode_sync(&hex_of("sync_probe")[1..]).unwrap();
        assert!(probe.probe);
        assert!(probe.resources.is_empty());
        let filtered = decode_sync(&hex_of("sync_filtered")[1..]).unwrap();
        assert_eq!(
            filtered.subjects.as_deref(),
            Some(&["did:ad:x".to_string()][..])
        );
        assert_eq!(
            decode_sync_resend(&hex_of("sync_resend")[1..]),
            Some("did:ad:d")
        );
        let d = decode_sync_diff(&hex_of("sync_diff")[1..]).unwrap();
        assert_eq!(d.remove, vec!["did:ad:z"]);
        assert_eq!(d.pull_from["did:ad:y"]["p1"], 2);
        let p = decode_sync_push(&hex_of("sync_push_last")[1..]).unwrap();
        assert!(p.last);
        assert_eq!(p.entries.len(), 1);
        assert_eq!(decode_hello(&hex_of("hello_caps")[1..]).unwrap(), "Dev 🚀");
        assert_eq!(
            decode_hello_caps(&hex_of("hello_caps")[1..]),
            vec!["keepalive"]
        );
        assert!(decode_hello_caps(&hex_of("hello_bare")[1..]).is_empty());
        let eph = decode_ephemeral(&hex_of("ephemeral_presence")[1..]).unwrap();
        assert_eq!(eph.kind, ephemeral_kind::PRESENCE);
        let slim = decode_commit_ok(&hex_of("commit_ok_slim")[1..]).unwrap();
        assert_eq!(slim.request_id, 9);
        assert_eq!(slim.commit_id, "did:ad:commit:abc");
        assert!(slim.commit_json.is_none());
        assert_eq!(
            decode_challenge(&hex_of("challenge")[1..]),
            Some("0badf00d")
        );
    }

    /// The browser package keeps its own copy of the vectors
    /// (`browser/lib/src/protocol_vectors.json`) because CI runs the
    /// TypeScript tests in a container that holds only `browser/`. The two
    /// files must be byte-identical; this catches a regeneration that
    /// updated one and not the other. Skipped when the browser tree is not
    /// present (a published crate, a partial checkout).
    #[test]
    fn browser_copy_is_identical() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../browser/lib/src/protocol_vectors.json");
        let Ok(browser_copy) = std::fs::read_to_string(&path) else {
            eprintln!("skipping: {} not present", path.display());
            return;
        };
        assert_eq!(
            browser_copy, VECTORS_JSON,
            "browser/lib/src/protocol_vectors.json differs from lib/src/sync/protocol_vectors.json; copy the regenerated file to both places"
        );
    }

    /// Regenerator. Prints the JSON to paste into `protocol_vectors.json`
    /// (both copies, see `browser_copy_is_identical`).
    #[test]
    #[ignore]
    fn print_wire_vectors() {
        let vectors: Vec<serde_json::Value> = build()
            .into_iter()
            .map(|(name, frame)| serde_json::json!({ "name": name, "hex": hex::encode(frame) }))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "note": "Golden wire frames for lib/src/sync/protocol.rs and browser/lib/src/ws-v2.ts. Regenerate with `cargo test -p atomic_lib print_wire_vectors -- --ignored --nocapture`.",
                "vectors": vectors
            }))
            .unwrap()
        );
    }
}
