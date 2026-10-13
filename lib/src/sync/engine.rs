//! Transport-agnostic sync engine.
//!
//! Handles drive synchronization using Loro CRDT version vectors.
//! The engine processes v2 binary frames and produces response frames.
//! The transport (WebSocket, Iroh QUIC, etc.) is responsible for
//! sending/receiving the raw bytes.
//!
//! Wire format for `SYNC`, `SYNC_DIFF`, `SYNC_PUSH`, and the resource
//! `UPDATE` frames this engine emits is documented in
//! `docs/src/websockets.md` (canonical spec). Frame encoders/decoders live
//! in [`super::protocol`]; matching TypeScript helpers in
//! `browser/lib/src/ws-v2.ts`.

use crate::db::trees::Tree;
use crate::loro::AtomicLoroDoc;
use crate::{Db, Storelike};

use super::protocol;

/// What an `AUTH` frame's `requestedSubject` has to name for this session.
///
/// The signature covers `"{requestedSubject} {timestamp}"`, so the subject
/// is what stops a proof signed for one place from opening another. Every
/// transport binds it differently: the browser signs the server origin, the
/// Iroh initiator signs the drive it is about to sync (bound after AUTH by
/// the accept loop in `peer.rs`), the auth-back signs the remote node key.
/// A transport that knows what the subject must be passes it here and a
/// mismatch is refused with `AUTH_FAILED`; one that binds later (or has
/// nothing to bind to) passes `Unbound`.
#[derive(Debug, Clone, Copy)]
pub enum AuthBinding<'a> {
    /// Accept whatever subject the proof names. The caller binds it itself
    /// (Iroh) or the subject carries no meaning for this session.
    Unbound,
    /// The proof must name this origin (`scheme://host[:port]`), or a
    /// subject under it. What a WebSocket responder passes: the browser
    /// signs `new URL(ws.url).origin`, so a proof captured from a request to
    /// another server, or an HTTP auth header for some resource URL, is not
    /// a WebSocket session here.
    Origin(&'a str),
    /// Like [`AuthBinding::Origin`], but any of several origins is accepted.
    /// A server is commonly reachable under more than one name (its
    /// configured URL, the host a proxy or a test harness dials it on), and
    /// the client signs the one it used. The WebSocket responder passes the
    /// origin the upgrade request arrived on together with its configured
    /// server URL, which is the same tolerance the HTTP auth headers have
    /// always had (they compare against the request URL).
    Origins(&'a [&'a str]),
}

/// The connection-bound challenge an `AUTH` proof may answer; see
/// [`protocol::tag::CHALLENGE`]. The responder that issued a nonce passes it
/// here so a proof carrying one in its `requestedSubject` fragment is held
/// to it.
#[derive(Debug, Clone, Copy)]
pub enum AuthChallenge<'a> {
    /// No challenge was issued on this connection (peer streams). A
    /// fragment on the requested subject is left alone: nothing to compare
    /// it with, and on a peer stream the subject is a drive, not an origin.
    None,
    /// A nonce was issued. A proof that carries one must carry this one; a
    /// proof without one is still accepted on its timestamp (a client that
    /// predates `CHALLENGE`).
    Issued(&'a str),
    /// A nonce was issued and every proof must answer it. Not wired to a
    /// server option yet; the strict mode a deployment turns on once every
    /// client it serves speaks `auth-nonce`.
    Required(&'a str),
}

/// `scheme://host[:port]` of a URL, lower-cased, or `None` for anything that
/// is not an absolute http(s) URL (a DID, `internal:/`, garbage).
fn url_origin(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?.to_ascii_lowercase();
    Some(match parsed.port() {
        Some(p) => format!("{}://{}:{}", parsed.scheme(), host, p),
        None => format!("{}://{}", parsed.scheme(), host),
    })
}

/// Verify an `AUTH` frame payload (the JSON after the tag byte), and on
/// success assign the proven identity to `agent`. Returns the frames to send
/// back: `AUTH_OK` (carrying this build's capabilities) or one `ERROR` with
/// `AUTH_FAILED`. One implementation for every transport; see
/// [`AuthBinding`] for the one thing that differs between them.
pub async fn handle_auth_frame(
    payload: &[u8],
    store: &Db,
    agent: &mut crate::agents::ForAgent,
    binding: AuthBinding<'_>,
    challenge: AuthChallenge<'_>,
) -> Vec<Vec<u8>> {
    let refuse = |msg: String| {
        vec![protocol::encode_error(
            0,
            protocol::error_code::AUTH_FAILED,
            &msg,
        )]
    };

    let Ok(json) = std::str::from_utf8(payload) else {
        return refuse("Invalid UTF-8 in auth".into());
    };
    let auth = match serde_json::from_str::<crate::authentication::AuthValues>(json) {
        Ok(a) => a,
        Err(e) => return refuse(format!("Invalid auth JSON: {e}")),
    };

    // A nonce rides in the fragment of the requested subject so the signed
    // string (`"{requestedSubject} {timestamp}"`) did not have to change
    // shape for HTTP, which never sees it. Fragments are stripped before the
    // origin comparison below, so the binding check is unaffected.
    let (_, carried_nonce) = protocol::split_challenge_fragment(&auth.requested_subject);
    match (challenge, carried_nonce) {
        (AuthChallenge::None, _) => {}
        (AuthChallenge::Issued(_), None) => {}
        (AuthChallenge::Required(_), None) => {
            return refuse(
                "Auth failed: this server requires the CHALLENGE nonce in requestedSubject".into(),
            );
        }
        (AuthChallenge::Issued(issued) | AuthChallenge::Required(issued), Some(carried)) => {
            if carried != issued {
                return refuse(
                    "Auth failed: requestedSubject nonce does not answer this connection's CHALLENGE"
                        .into(),
                );
            }
        }
    }

    let expected: Vec<&str> = match binding {
        AuthBinding::Unbound => Vec::new(),
        AuthBinding::Origin(one) => vec![one],
        AuthBinding::Origins(many) => many.to_vec(),
    };
    // Only absolute http(s) URLs can bind. A responder that knows none of
    // its origins (no base domain configured) falls back to the unbound
    // behaviour; that is the localhost / test default, not a public host.
    let expected_origins: Vec<String> = expected.iter().filter_map(|o| url_origin(o)).collect();
    if !expected_origins.is_empty() {
        let signed_origin = url_origin(&auth.requested_subject);
        let named_this_server = signed_origin
            .as_deref()
            .is_some_and(|signed| expected_origins.iter().any(|e| e == signed));
        if !named_this_server {
            return refuse(format!(
                "Auth failed: requestedSubject {} does not name this server ({})",
                auth.requested_subject,
                expected_origins.join(" or ")
            ));
        }
    }

    match crate::authentication::get_agent_from_auth_values_and_check(Some(auth), store).await {
        Ok(a) => {
            *agent = a;
            vec![protocol::encode_auth_ok()]
        }
        Err(e) => refuse(format!("Auth failed: {e}")),
    }
}

/// Which identifier spelling a connection understands, from the capabilities
/// the other side listed (`HELLO` for a client or an Iroh dialer, `AUTH_OK`
/// for the responder). Every subject the engine puts on the wire goes
/// through [`WireScheme::subject`]; a peer that listed nothing predates the
/// rename and gets `did:ad:`, which it can parse. Signed material (commit
/// JSON, envelopes) is never rewritten: it verifies as stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireScheme {
    canonical: bool,
}

impl WireScheme {
    /// The peer listed [`crate::identifiers::CAP_CANONICAL_SCHEME`].
    pub const CANONICAL: Self = Self { canonical: true };
    /// The peer predates the rename.
    pub const LEGACY: Self = Self { canonical: false };

    pub fn from_caps(caps: &[impl AsRef<str>]) -> Self {
        Self {
            canonical: caps
                .iter()
                .any(|c| c.as_ref() == crate::identifiers::CAP_CANONICAL_SCHEME),
        }
    }

    pub fn is_canonical(self) -> bool {
        self.canonical
    }

    /// The spelling of `raw` this peer should receive.
    pub fn subject(self, raw: &str) -> String {
        if self.canonical {
            crate::identifiers::canonicalize_scheme(raw)
        } else {
            crate::identifiers::to_legacy_scheme(raw)
        }
    }

    pub fn subjects(self, raw: &[String]) -> Vec<String> {
        raw.iter().map(|s| self.subject(s)).collect()
    }
}

/// Side effects a transport must honour after [`handle_frame_full`].
///
/// Reply frames always go back on the wire. `subscribe` / `unsubscribe` are
/// how a hub registers the connection for commit fan-out — the engine owns
/// the `SUB`/`UNSUB` tags (parse + `check_read`) but has no actor mailbox,
/// so the server's WebSocket handler is the one that `do_send`s to the
/// commit monitor. A peer stream that is not a hub ignores them; Iroh live
/// mode does not speak `SUB`.
#[derive(Debug, Default, Clone)]
pub struct HandleOutput {
    pub frames: Vec<Vec<u8>>,
    pub subscribe: Option<String>,
    pub unsubscribe: Option<String>,
}

/// Process a single v2 binary frame. Returns response frames to send back.
/// This is the transport-agnostic entry point — used by WebSocket, Iroh, etc.
///
/// Transports that can register subscriptions should call
/// [`handle_frame_full`] instead so a validated `SUB`/`UNSUB` is not dropped.
pub async fn handle_frame(
    frame: &[u8],
    store: &Db,
    agent: &mut crate::agents::ForAgent,
) -> Vec<Vec<u8>> {
    handle_frame_full(frame, store, agent).await.frames
}

/// [`handle_frame`] for a connection whose identifier scheme is known.
pub async fn handle_frame_for_caps(
    frame: &[u8],
    store: &Db,
    agent: &mut crate::agents::ForAgent,
    wire: WireScheme,
) -> Vec<Vec<u8>> {
    handle_frame_full_for_caps(frame, store, agent, wire)
        .await
        .frames
}

/// The answer to one fetched subject: an `UPDATE` carrying the full snapshot,
/// or an `ERROR` when it is missing, unreadable or has no state. Shared by
/// `GET` (one subject) and `GET_MANY` (one entry per subject).
async fn answer_get(
    store: &Db,
    agent: &crate::agents::ForAgent,
    request_id: u16,
    raw_subject: &str,
    wire: WireScheme,
) -> Vec<u8> {
    let subject = crate::Subject::from_raw(raw_subject, store.get_base_domain().as_deref());

    match store.get_resource_extended(&subject, false, agent).await {
        Ok(r) => {
            let resource = r.to_single();
            let snapshot = resource.materialized_state().unwrap_or_else(|| {
                resource
                    .build_state_doc()
                    .map(|doc| doc.export_snapshot())
                    .unwrap_or_default()
            });

            if snapshot.is_empty() {
                protocol::encode_error(request_id, protocol::error_code::UNKNOWN, "No state")
            } else {
                // Resolve `internal:/…` to this node's origin —
                // `internal:` is a node-local concept and must not
                // cross the wire; the recipient keys its resource
                // cache on whatever subject we emit. A no-op for
                // normal (External/DID) subjects, so it's safe on
                // every transport, not just the server's origin.
                let origin = store
                    .get_base_domain()
                    .unwrap_or_else(|| "http://localhost".to_string());
                let subject_resolved = wire.subject(&resource.get_subject().resolve(&origin));
                // Include `lastCommit` so the recipient can stamp
                // `_lastCommit` and not mis-detect genesis on save.
                let last_commit = resource
                    .get(crate::urls::LAST_COMMIT)
                    .ok()
                    .map(|v| wire.subject(&v.to_string()))
                    .filter(|s| !s.is_empty());
                let mut flags = protocol::flags::SNAPSHOT;
                if last_commit.is_some() {
                    flags |= protocol::flags::HAS_COMMIT_ID;
                }
                protocol::encode_update(
                    flags,
                    request_id,
                    &subject_resolved,
                    last_commit.as_deref(),
                    &snapshot,
                )
            }
        }
        Err(e) => protocol::encode_error(request_id, protocol::error_code::UNKNOWN, &e.to_string()),
    }
}

/// Like [`handle_frame`], plus the `SUB`/`UNSUB` session commands a hub
/// applies to its commit monitor.
pub async fn handle_frame_full(
    frame: &[u8],
    store: &Db,
    agent: &mut crate::agents::ForAgent,
) -> HandleOutput {
    handle_frame_full_for_caps(frame, store, agent, WireScheme::CANONICAL).await
}

/// [`handle_frame_full`] for a connection whose identifier scheme is known:
/// the subjects in every answer follow `wire`.
pub async fn handle_frame_full_for_caps(
    frame: &[u8],
    store: &Db,
    agent: &mut crate::agents::ForAgent,
    wire: WireScheme,
) -> HandleOutput {
    if frame.is_empty() {
        return HandleOutput::default();
    }

    let tag = frame[0];
    let payload = &frame[1..];

    match tag {
        protocol::tag::SUB => return handle_sub(payload, store, agent).await,
        protocol::tag::UNSUB => return handle_unsub(payload),
        _ => {}
    }

    let frames = match tag {
        protocol::tag::AUTH => {
            handle_auth_frame(
                payload,
                store,
                agent,
                AuthBinding::Unbound,
                AuthChallenge::None,
            )
            .await
        }

        protocol::tag::GET => {
            if let Some(decoded) = protocol::decode_get(payload) {
                vec![answer_get(store, agent, decoded.request_id, decoded.subject, wire).await]
            } else {
                vec![protocol::encode_error(
                    0,
                    protocol::error_code::UNKNOWN,
                    "Invalid GET frame",
                )]
            }
        }

        protocol::tag::GET_MANY => {
            if let Some(decoded) = protocol::decode_get_many(payload) {
                // One answer per subject, in request order (join_all keeps it), so
                // the client can pair an `ERROR` (which names no subject) with what
                // it asked. Evaluated concurrently: the batch is only worth its
                // frame if it is not slower than the single GETs it replaces.
                let agent: &crate::agents::ForAgent = agent;
                let answers =
                    futures::future::join_all(decoded.subjects.iter().map(|subject| {
                        answer_get(store, agent, decoded.request_id, subject, wire)
                    }))
                    .await;
                vec![protocol::encode_get_many_result(
                    decoded.request_id,
                    &answers,
                )]
            } else {
                vec![protocol::encode_error(
                    0,
                    protocol::error_code::UNKNOWN,
                    "Invalid GET_MANY frame",
                )]
            }
        }

        protocol::tag::COMMIT => {
            // A signed commit is the unit of authority on every transport: it
            // carries its own signature and the signer's rights are checked
            // here, so a peer relaying it can only ever apply a change its
            // signer was already entitled to make — no escalation from "I
            // dialed you." This is what lets a serverless peer apply a `COMMIT`
            // exactly like atomic-server's HTTP path does; the connection's own
            // AUTH identity is not the gate (the commit's signature is).
            //
            // Differs from the server's WS `COMMIT` arm in two deliberate ways:
            // no `source_id` echo-suppression (peer transports don't fan out
            // through the commit monitor), and `validate_loro_causality` is
            // OFF because concurrent writes between peers are expected (see the
            // field's own docs in `commit.rs`).
            match protocol::decode_commit(payload) {
                Some(decoded) => {
                    let request_id = decoded.request_id;
                    match apply_peer_commit(store, decoded.commit_json).await {
                        Ok(commit_json) => {
                            vec![protocol::encode_commit_ok(request_id, &commit_json)]
                        }
                        Err(e) => {
                            let msg = e.to_string();
                            vec![protocol::encode_error(
                                request_id,
                                protocol::classify_commit_error(&msg),
                                &msg,
                            )]
                        }
                    }
                }
                None => vec![protocol::encode_error(
                    0,
                    protocol::error_code::UNKNOWN,
                    "Invalid COMMIT frame",
                )],
            }
        }

        protocol::tag::SYNC => match protocol::decode_sync(payload) {
            // Hash-first probe: compare the drive hash over what this
            // session may read, without either side exchanging the
            // O(drive) version vector. In sync → SYNC_OK; otherwise
            // SYNC_RESEND asks the client to reconcile. Hashed over the
            // readable subjects both so it can match the client's and so an
            // anonymous socket learns nothing about a drive it cannot read.
            Some(sync) if sync.probe => {
                // A first upload has no readable root here yet. Invite its
                // full reconcile only when the same admission gate used by
                // SYNC_PUSH allows bootstrapping it. Existing private drives
                // still go through the read check below; no inventory or
                // resource is created by this probe.
                let drive =
                    crate::Subject::from_raw(&sync.drive, store.get_base_domain().as_deref());
                if store.get_resource(&drive).await.is_err_and(|error| {
                    error.error_type == crate::errors::AtomicErrorType::NotFoundError
                }) && admit_unknown_drive(store, &sync.drive, agent)
                {
                    return HandleOutput {
                        frames: vec![protocol::encode_sync_resend(&wire.subject(&sync.drive))],
                        ..Default::default()
                    };
                }
                match drive_sync_hash_for_wire_version(
                    store,
                    &sync.drive,
                    agent,
                    wire,
                    sync.hash_version,
                )
                .await
                {
                    Ok(server_hash) if server_hash == sync.drive_hash => {
                        vec![protocol::encode_sync_ok(&wire.subject(&sync.drive))]
                    }
                    Ok(_) => vec![protocol::encode_sync_resend(&wire.subject(&sync.drive))],
                    Err(reason) => vec![protocol::encode_error(
                        0,
                        protocol::error_code::UNAUTHORIZED_READ,
                        &format!("SYNC refused for {}: {reason}", sync.drive),
                    )],
                }
            }
            Some(sync) => {
                // `subjects`, when present, limits the reconcile to that set:
                // build version vectors for just those instead of walking the
                // drive. The bundled browser client no longer sends it (it
                // came from the removed RBSR descent); kept for other clients.
                let filter = sync
                    .subjects
                    .as_ref()
                    .map(|s| s.iter().cloned().collect::<std::collections::HashSet<_>>());
                match sync.vvs.as_ref() {
                    // Sparse encoding (`sparse-sync`): the client's vectors
                    // arrive as they are, no peer table to expand.
                    Some(vvs) => {
                        handle_sync_vv_reconcile(
                            &sync.drive,
                            &sync.drive_hash,
                            sync.hash_version,
                            || {
                                let mut client_vvs: std::collections::HashMap<
                                    String,
                                    std::collections::HashMap<String, i32>,
                                > = std::collections::HashMap::new();

                                for (subject, vv) in vvs {
                                    let entry = client_vvs
                                        .entry(crate::Subject::from_raw(subject, None).pure_id())
                                        .or_default();

                                    for (peer, &counter) in vv {
                                        if counter != 0 {
                                            let current = entry.entry(peer.clone()).or_default();
                                            *current = (*current).max(counter);
                                        }
                                    }
                                }

                                client_vvs
                            },
                            filter.as_ref(),
                            store,
                            agent,
                            wire,
                            // Dialed into us: the same gate `SYNC_PUSH` applies below.
                            false,
                        )
                        .await
                    }
                    None => {
                        handle_sync_vv_filtered(
                            &sync.drive,
                            &sync.drive_hash,
                            &sync.peers,
                            &sync.resources,
                            filter.as_ref(),
                            store,
                            agent,
                            wire,
                            // Dialed into us: the same gate `SYNC_PUSH` applies below.
                            false,
                        )
                        .await
                    }
                }
            }
            None => vec![protocol::encode_error(
                0,
                protocol::error_code::UNKNOWN,
                "Invalid SYNC frame",
            )],
        },

        protocol::tag::SYNC_PUSH => {
            if let Some(push) = protocol::decode_sync_push(payload) {
                // handle_frame serves connections dialed *into* us (accept side,
                // WS): no owned-drive relaxation — the sender must itself hold
                // write rights. The dial side calls import_sync_push directly
                // with trust_owned=true.
                match import_sync_push(&push, store, agent, false).await {
                    Ok((_count, mut blob_requests)) => {
                        let mut responses =
                            vec![protocol::encode_sync_ok(&wire.subject(&push.drive))];
                        responses.append(&mut blob_requests);
                        responses
                    }
                    // A refused import used to be answered with `SYNC_OK` all
                    // the same, so a sender could never tell "landed" from
                    // "dropped" (`replicate.rs` re-probed with a second SYNC
                    // to find out). Say no when the answer is no.
                    Err(rejected) => vec![rejected.to_error_frame()],
                }
            } else {
                vec![protocol::encode_error(
                    0,
                    protocol::error_code::UNKNOWN,
                    "Invalid SYNC_PUSH frame",
                )]
            }
        }

        protocol::tag::BLOB_REQUEST => {
            if let Some(hash) = protocol::decode_blob_request(payload) {
                match store.get_blob(&hash).await {
                    Ok(Some(bytes)) => vec![protocol::encode_blob_response(&hash, &bytes)],
                    _ => vec![protocol::encode_error(
                        0,
                        protocol::error_code::UNKNOWN,
                        "Blob not found",
                    )],
                }
            } else {
                vec![protocol::encode_error(
                    0,
                    protocol::error_code::UNKNOWN,
                    "Invalid BLOB_REQUEST frame",
                )]
            }
        }

        protocol::tag::BLOB_RESPONSE => {
            if let Some(resp) = protocol::decode_blob_response(payload) {
                // F4 (planning/unified-sync.md): a `BLOB_RESPONSE` with no
                // matching `BLOB_REQUEST` we issued is unsolicited — reject
                // it rather than storing arbitrary bytes with no admission
                // check at all. A matching entry names the (already-
                // admitted at request time) drive; re-check admission here
                // too, since enrollment/quota state can change between the
                // request and this response.
                match store.take_pending_blob_request(&resp.hash) {
                    // Blobs are content-addressed: the bytes must hash to the
                    // key they are stored under, or any session that answers
                    // a pending request poisons what every later reader of
                    // that hash gets.
                    Some(_drive) if blake3::hash(&resp.bytes).as_bytes() != &resp.hash => {
                        tracing::warn!(
                            "BLOB_RESPONSE: bytes do not hash to {}, dropped",
                            hex::encode(resp.hash)
                        );
                        vec![]
                    }
                    Some(drive) if store.sync_policy().admit_drive_write(&drive) => {
                        match store.put_blob(&resp.hash, &resp.bytes).await {
                            Ok(()) => vec![],
                            Err(error) => {
                                tracing::warn!("BLOB_RESPONSE: storage failed: {error}");
                                vec![protocol::encode_error(
                                    0,
                                    protocol::error_code::UNKNOWN,
                                    "Blob storage failed",
                                )]
                            }
                        }
                    }
                    Some(drive) => {
                        tracing::warn!(
                            "BLOB_RESPONSE: drive {} not admitted by sync policy, dropping blob",
                            drive
                        );
                        vec![protocol::encode_error(
                            0,
                            protocol::error_code::UNKNOWN,
                            "Drive not admitted for sync",
                        )]
                    }
                    None => {
                        tracing::warn!(
                            "BLOB_RESPONSE: no matching pending BLOB_REQUEST, dropping blob"
                        );
                        vec![protocol::encode_error(
                            0,
                            protocol::error_code::UNKNOWN,
                            "Unsolicited blob response",
                        )]
                    }
                }
            } else {
                vec![protocol::encode_error(
                    0,
                    protocol::error_code::UNKNOWN,
                    "Invalid BLOB_RESPONSE frame",
                )]
            }
        }

        _ => {
            tracing::debug!("Unhandled frame tag: 0x{:02x}", tag);
            vec![]
        }
    };

    HandleOutput {
        frames,
        subscribe: None,
        unsubscribe: None,
    }
}

/// `SUB <subject>`: parse, `check_read`, and tell the transport to register.
/// The wire refusal matches `refuse_subscription` in the server so a client
/// cannot tell the engine path from the monitor's defence-in-depth re-check.
async fn handle_sub(payload: &[u8], store: &Db, agent: &crate::agents::ForAgent) -> HandleOutput {
    let Ok(subject_str) = std::str::from_utf8(payload) else {
        return HandleOutput {
            frames: vec![protocol::encode_error(
                0,
                protocol::error_code::UNKNOWN,
                "Invalid SUB frame",
            )],
            ..HandleOutput::default()
        };
    };

    let subject = crate::Subject::from_raw(subject_str, store.get_base_domain().as_deref());

    let refuse = |reason: &str| HandleOutput {
        frames: vec![protocol::encode_error(
            0,
            protocol::error_code::UNAUTHORIZED_READ,
            &format!("SUB refused for {subject}: {reason}"),
        )],
        ..HandleOutput::default()
    };

    if !subject.is_local() {
        tracing::warn!("can't subscribe to external resource: {subject}");
        return HandleOutput::default();
    }

    let resource = match store.get_resource(&subject).await {
        Ok(r) => r,
        Err(_) => return refuse("not readable"),
    };

    if let Err(e) = crate::hierarchy::check_read(store, &resource, agent).await {
        return refuse(&e.to_string());
    }

    HandleOutput {
        frames: vec![],
        subscribe: Some(subject_str.to_string()),
        unsubscribe: None,
    }
}

/// `UNSUB <subject>`: no rights check — cancelling a subscription you never
/// held is a no-op, and the monitor looks up by the raw key `SUB` registered.
fn handle_unsub(payload: &[u8]) -> HandleOutput {
    match std::str::from_utf8(payload) {
        Ok(subject) => HandleOutput {
            frames: vec![],
            subscribe: None,
            unsubscribe: Some(subject.to_string()),
        },
        Err(_) => HandleOutput::default(),
    }
}

/// Policy knobs distinguishing a hub ingesting a client's commit from a peer
/// replica ingesting another peer's commit. The validation *core* (signature,
/// schema, timestamp, signer rights) is identical in both roles.
pub struct CommitIngestOpts {
    /// Transport/source identity for echo suppression by the hub's commit
    /// monitor. Peers have no commit-monitor fanout, so `None` there.
    pub source_id: Option<String>,
    /// Hub semantics: reject commits whose Loro ops are concurrent with stored
    /// state (client doc wasn't seeded from this node). Off between peers,
    /// where concurrent writes are expected.
    pub validate_loro_causality: bool,
    /// Hub semantics: reject commits for subjects this node cannot own. Off
    /// for peer replicas — hosting subjects the node does not own is what
    /// replication is.
    pub enforce_subject_ownership: bool,
    /// Hub semantics: check values against class `constraints`. Off for peer
    /// replicas, which must keep what another node already accepted.
    pub validate_constraints: bool,
    /// Origin used to resolve `internal:/` subjects in the response JSON-AD.
    /// `None` falls back to the store's base domain.
    pub response_origin: Option<String>,
}

impl CommitIngestOpts {
    /// Hub semantics: this node owns the subject and is the authority (HTTP
    /// `/commit`, the WebSocket `COMMIT` frame). Every check on.
    pub fn hub(source_id: Option<String>, response_origin: Option<String>) -> Self {
        Self {
            source_id,
            validate_loro_causality: true,
            enforce_subject_ownership: true,
            validate_constraints: true,
            response_origin,
        }
    }

    /// Peer semantics: a signed commit from another full node over a peer
    /// transport. Signature, schema and rights still run; ownership and Loro
    /// causality do not (a replica hosts subjects it does not own, and
    /// concurrent writes are expected). No `source_id` of its own: the
    /// change is attributed to the peer whose [`ws_apply::import_scope`]
    /// the caller runs this in, so the live push loop skips exactly that
    /// peer and nothing else.
    ///
    /// [`ws_apply::import_scope`]: super::ws_apply::import_scope
    pub fn peer() -> Self {
        Self {
            source_id: None,
            validate_loro_causality: false,
            enforce_subject_ownership: false,
            validate_constraints: false,
            response_origin: None,
        }
    }
}

/// Parse a JSON-AD commit and verify its signature, returning the signer it
/// proves. This is the identity check alone: no schema, timestamp, rights,
/// ownership or Loro checks run, and nothing is stored.
///
/// Until the Ed25519 signature over the body checks out, the `signer` field
/// is just a string anyone can put there, so nothing keyed on the signer
/// (the per-agent write budget, for one) may trust it before this returns
/// `Ok`. A hub calls this before spending any budget on a `/commit` request;
/// [`ingest_commit`] verifies again when it applies the commit, which keeps
/// that path self-contained at the cost of one cheap re-check.
pub async fn verify_commit_signer(
    store: &impl crate::Storelike,
    commit_json: &str,
) -> crate::errors::AtomicResult<crate::Subject> {
    let resource = crate::parse::parse_json_ad_commit_resource(commit_json, store).await?;
    let commit = crate::commit::Commit::from_resource(resource)?;
    commit.validate_signature(store).await?;
    Ok(commit.signer)
}

/// Ingest a signed JSON-AD `COMMIT`, returning the server-created commit
/// resource as JSON-AD. This is the single implementation shared by the
/// server's HTTP/WS commit application and peer-transport `COMMIT` frames
/// (see [`CommitIngestOpts`] for what differs between the two roles).
///
/// Signature, schema, and signer-rights validation always run — the commit is
/// a self-authorizing certificate, so those checks (not a connection's AUTH
/// identity) are the authority. What varies is domain-ownership enforcement,
/// Loro-causality enforcement and source-id-based echo suppression, all
/// controlled by `opts` (a peer transport runs this inside
/// [`super::ws_apply::import_scope`] so the change is attributed to the peer).
pub async fn ingest_commit_json(
    store: &Db,
    commit_json: &str,
    opts: &CommitIngestOpts,
) -> crate::errors::AtomicResult<String> {
    let response = ingest_commit(store, commit_json, opts).await?;
    let base_domain = store.get_base_domain();
    let origin = opts.response_origin.as_deref().or(base_domain.as_deref());
    let json = response.commit_resource.to_json_ad(origin)?;
    Ok(json)
}

/// [`ingest_commit_json`] minus the final JSON-AD serialization: the same
/// validation and application, returning the full [`CommitResponse`] so an
/// in-process caller (`crate::runtime::AtomicNode`) can use the changed
/// resource and atoms without re-parsing its own output.
pub async fn ingest_commit(
    store: &Db,
    commit_json: &str,
    opts: &CommitIngestOpts,
) -> crate::errors::AtomicResult<crate::commit::CommitResponse> {
    let incoming_commit_resource =
        crate::parse::parse_json_ad_commit_resource(commit_json, store).await?;

    // Reject commits with deprecated set/push/remove fields — use loroUpdate instead.
    // Checked on the parsed commit's properties, not by substring-matching
    // the raw body: a commit whose subject *is* one of these Property
    // resources, or whose values merely mention them, must not be refused.
    if [crate::urls::SET, crate::urls::PUSH, crate::urls::REMOVE]
        .iter()
        .any(|legacy| incoming_commit_resource.get(legacy).is_ok())
    {
        return Err(
            "Commits with `set`, `push`, or `remove` fields are no longer accepted. Use `loroUpdate` instead."
                .into(),
        );
    }

    let incoming_commit = crate::commit::Commit::from_resource(incoming_commit_resource)?;

    // Log incoming commit details for debugging
    if let Some(loro_bytes) = &incoming_commit.loro_update {
        let doc = crate::loro::AtomicLoroDoc::new();
        if doc.import_update(loro_bytes).is_ok() {
            let props = doc.get_all_properties();
            let prop_summary: Vec<String> = props
                .keys()
                .map(|k| k.rsplit('/').next().unwrap_or(k).to_string())
                .collect();
            tracing::info!(
                subject = %incoming_commit.subject,
                signer = %incoming_commit.signer,
                properties = ?prop_summary,
                loro_bytes = loro_bytes.len(),
                "Incoming commit"
            );
        }
    } else {
        tracing::info!(
            subject = %incoming_commit.subject,
            destroy = ?incoming_commit.destroy,
            "Incoming commit (no loroUpdate)"
        );
    }

    if opts.enforce_subject_ownership {
        let is_internal = incoming_commit.subject.is_internal();
        let is_did = incoming_commit.subject.is_did();
        let matches_base = if let Some(base) = store.get_base_domain() {
            // The base domain is the origin this store was booted with, scheme
            // included. Behind a TLS-terminating proxy that is `http://host`
            // while clients name the resource `https://host/…`: same server,
            // so compare the host, not the scheme.
            let host = base
                .trim_start_matches("http://")
                .trim_start_matches("https://");
            incoming_commit.subject.as_str().contains(host)
        } else {
            false
        };

        // Fallback: if it's a local path like http://localhost/ or https://atomicdata.dev/
        // and it matches the current request's Host, we should also allow it.
        let is_local_path =
            !is_did && !is_internal && incoming_commit.subject.as_str().ends_with('/');

        if !is_internal && !is_did && !matches_base && !is_local_path {
            return Err(
                "Subject of commit should be sent to other domain - this store can not own this resource."
                    .into(),
            );
        }
    }

    let signer = incoming_commit.signer.clone();
    let signer_pure = signer.pure_id();

    // The signer's Agent resource is materialized once the commit has been
    // ACCEPTED, never before: `apply_commit` is where the signature and the
    // signer's rights are checked, and an unauthenticated `/commit` naming
    // any `did:ad:agent:` signer must not leave a durable resource behind.
    // A commit that creates the agent itself needs no help; it is excluded.
    let is_self_creating_agent =
        incoming_commit.subject.is_agent_did() && incoming_commit.subject == signer;
    let needs_agent_resource = signer.is_agent_did()
        && !is_self_creating_agent
        && store.get_resource(&signer).await.is_err();

    let commit_opts = crate::commit::CommitOpts {
        validate_schema: true,
        validate_constraints: opts.validate_constraints,
        validate_signature: true,
        // Rejects commits stamped in the future. This is NOT an age bound —
        // a bulk reconcile legitimately re-sends old destroy envelopes to a
        // replica that was offline. Replay of a destroy against a recreated
        // subject is refused in `Commit::apply_opts` (a destroy commit that
        // is already stored here, or one older than the current genesis).
        validate_timestamp: true,
        validate_rights: true,
        // https://github.com/atomicdata-dev/atomic-server/issues/412
        // Reject commits whose Loro ops are concurrent with stored state
        // (i.e. the client's doc wasn't seeded from the server). Without this,
        // LWW silently drops the client's write. For P2P sync use a path that
        // leaves this off — concurrent writes are expected there.
        validate_loro_causality: opts.validate_loro_causality,
        validate_for_agent: Some(signer.to_string()),
        update_index: true,
        // A commit applied inside a peer's import scope is attributed to that
        // peer, so the live push loop does not send it straight back. Not a
        // process-wide mute: a concurrent import on another connection, or a
        // local edit, is broadcast as usual (security audit C16).
        source_id: opts
            .source_id
            .clone()
            .or_else(super::ws_apply::current_import_source),
    };

    let response = store.apply_commit(incoming_commit, &commit_opts).await?;

    if needs_agent_resource {
        let mut new_agent = crate::Resource::new_instance(crate::urls::AGENT, store).await?;
        new_agent.set_subject(signer_pure.clone());
        if let Some(pk) = signer.agent_public_key() {
            new_agent
                .set_string(crate::urls::PUBLIC_KEY.into(), pk, store)
                .await?;
        }
        new_agent.save_locally(store).await?;
        tracing::info!("Auto-created agent resource for {}", signer_pure);
    }

    Ok(response)
}

/// Apply a JSON-AD `COMMIT` received over a peer transport, returning the
/// server-created commit resource as JSON-AD (the `COMMIT_OK` payload).
///
/// This is the transport-agnostic sibling of the server's HTTP/WS commit
/// application. It validates signature, schema, and the signer's rights — the
/// commit is a self-authorizing certificate, so those checks (not the
/// connection's AUTH identity) are the authority. `validate_loro_causality` is
/// off (concurrent peer writes are expected). No linear `previousCommit`
/// chain: peers merge via Loro. No `source_id`: peer transports don't fan
/// out through the commit monitor, so there's no echo to suppress.
///
/// Deliberately skips the server's domain-ownership gate (`apply_commit_json`
/// in `server/src/handlers/commit.rs` rejects a commit whose subject belongs
/// to another domain): a peer replica legitimately hosts subjects it doesn't
/// own — that's what replication is — so no such gate applies here.
async fn apply_peer_commit(store: &Db, commit_json: &str) -> crate::errors::AtomicResult<String> {
    ingest_commit_json(store, commit_json, &CommitIngestOpts::peer()).await
}

/// Collects all resource subjects belonging to a drive via BFS on parent relationships.
/// Returns pure_id() strings (no query params/drive hints) to match LoroSnapshot keys.
pub async fn collect_drive_subjects(
    store: &Db,
    drive_subject: &crate::Subject,
) -> std::collections::HashSet<String> {
    let drive_str = drive_subject.pure_id();
    let mut result = std::collections::HashSet::new();
    result.insert(drive_str.clone());

    if drive_subject.is_did() {
        // BFS through the parent-index. Querying
        // `property=parent value=current` hits the same index used by
        // `useChildren` / `/query` and returns only the subjects that
        // actually point at `current` — no full-store scan, no commits
        // touched (commits have no `parent` propval, so they're absent
        // from the index by construction). Cost drops from
        // O(total `Tree::Resources` rows, including every commit ever
        // signed) to O(drive subjects) — see the
        // `collect_drive_subjects_scales_with_target_drive_only`
        // regression test in `sync/tests.rs`.
        let mut queue = vec![drive_str];

        while let Some(current) = queue.pop() {
            let q = crate::storelike::Query {
                property: Some(crate::urls::PARENT.into()),
                value: Some(crate::Value::AtomicUrl(current.clone().into())),
                filters: Vec::new(),
                limit: None,
                start_val: None,
                end_val: None,
                offset: 0,
                sort_by: None,
                sort_desc: false,
                include_external: true,
                include_nested: false,
                // Sudo: sync needs to enumerate every subject the
                // drive actually contains. Per-agent ACL filtering
                // happens later in `handle_sync_vv` (`check_read` on
                // each subject before push/pull). Scoping the index
                // walk by `for_agent` here would also re-trigger the
                // count-drift fix path for unauthorized rows, which
                // is the wrong layer.
                for_agent: crate::agents::ForAgent::Sudo,
                aggregation: None,
                expression_filters: Vec::new(),
                drive: None,
            };

            if let Ok(qr) = store.query(&q).await {
                for child in qr.subjects {
                    let child_str = child.pure_id();
                    if result.insert(child_str.clone()) {
                        queue.push(child_str);
                    }
                }
            }
        }
    } else {
        // Non-DID (HTTP-URL) drive: subjects start with the drive
        // origin. We keep the legacy full-scan here — there's no
        // parent-index entry for the drive root itself in the
        // HTTP-URL case, and DID drives are the hot path for the
        // SUB → SYNC_DIFF latency we're targeting.
        let drive_pure = drive_subject.pure_id();
        for resource in store.all_resources(false) {
            let subject = resource.get_subject();
            if subject.pure_id().starts_with(&drive_pure) {
                result.insert(subject.pure_id());
            }
        }
    }

    result
}

/// Drive hash, version 2: independent of how many peers the drive has.
///
/// [`compute_drive_hash`] indexes every counter by the drive's sorted peer
/// list, so it (and the `SYNC` frame that goes with it) grow with resources
/// times peers. Every resource a client creates has a peer of its own, so on
/// a drive of R resources that is R x R numbers: 3000 resources hash a 30 MB
/// string and send a 48 MB frame. This form lists each resource's own
/// non-zero counters, `subject:peer=counter,peer=counter`, peers in byte
/// order, subjects in byte order, entries joined with `|`, then SHA-256 as
/// lower-case hex. The browser builds the same string
/// (`canonicalDriveHashV2`); a golden vector pins them together.
pub fn compute_drive_hash_v2(
    vvs: &std::collections::HashMap<String, std::collections::HashMap<String, i32>>,
) -> String {
    let mut subjects: Vec<&String> = vvs.keys().collect();
    subjects.sort();

    let mut hash_input = String::new();

    for (i, subject) in subjects.into_iter().enumerate() {
        if i > 0 {
            hash_input.push('|');
        }
        hash_input.push_str(subject);
        hash_input.push(':');

        let mut peers: Vec<(&String, &i32)> =
            vvs[subject].iter().filter(|(_, c)| **c != 0).collect();
        peers.sort_by(|a, b| a.0.cmp(b.0));

        for (j, (peer, counter)) in peers.into_iter().enumerate() {
            if j > 0 {
                hash_input.push(',');
            }
            hash_input.push_str(peer);
            hash_input.push('=');
            hash_input.push_str(&counter.to_string());
        }
    }

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(hash_input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute SHA-256 drive hash matching the client's algorithm.
/// Hash of sorted entries: "subject1:c0,c1|subject2:c0,c1|..."
pub fn compute_drive_hash(
    vvs: &std::collections::HashMap<String, std::collections::HashMap<String, i32>>,
) -> String {
    let mut peer_set = std::collections::BTreeSet::new();

    for vv in vvs.values() {
        for peer_id in vv.keys() {
            peer_set.insert(peer_id.clone());
        }
    }

    let peers: Vec<String> = peer_set.into_iter().collect();
    let peer_index: std::collections::HashMap<&str, usize> = peers
        .iter()
        .enumerate()
        .map(|(i, p)| (p.as_str(), i))
        .collect();

    let mut entries: Vec<(String, Vec<i32>)> = vvs
        .iter()
        .map(|(subject, vv)| {
            let mut counters = vec![0i32; peers.len()];

            for (peer_id, &counter) in vv {
                if let Some(&idx) = peer_index.get(peer_id.as_str()) {
                    counters[idx] = counter;
                }
            }

            (subject.clone(), counters)
        })
        .collect();

    entries.sort_by(|(a, _), (b, _)| a.cmp(b));

    let hash_input: String = entries
        .iter()
        .map(|(s, c)| {
            let counters = c
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(",");
            format!("{s}:{counters}")
        })
        .collect::<Vec<_>>()
        .join("|");

    // Canonical cross-implementation hash (planning/drive-reconciliation.md
    // Phase 1): SHA-256 of `hash_input`, unconditionally. The browser computes
    // the byte-identical string in JS and hashes it with `crypto.subtle`
    // SHA-256 — see `canonicalDriveHash` in `browser/lib/src/store.ts`. A
    // golden test vector on both sides pins them together. There is no
    // non-crypto fallback: the old `DefaultHasher` path (a non-`ring` build)
    // produced a value the client could never match, silently disabling the
    // reconcile fast path on every sync.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(hash_input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Build server-side version vector map for a drive.
pub fn build_drive_vvs(
    store: &Db,
    drive_subjects: &std::collections::HashSet<String>,
) -> std::collections::HashMap<String, std::collections::HashMap<String, i32>> {
    let mut vvs = std::collections::HashMap::new();

    for subject_str in drive_subjects {
        if let Ok(Some(snapshot_bytes)) = store.kv.get(Tree::LoroSnapshots, subject_str.as_bytes())
        {
            // Read the version vector from the snapshot header instead of
            // rebuilding the whole CRDT doc (see `vv_map_from_snapshot`).
            if let Ok(vv) = AtomicLoroDoc::vv_map_from_snapshot(&snapshot_bytes) {
                vvs.insert(subject_str.clone(), vv);
            }
        }
    }

    vvs
}

/// One drive inventory entry: a subject and its version vector (peer →
/// counter). A sorted list of these is what the probe hash is computed over
/// and what `RBSR_ITEMS` returns.
pub type DriveItem = (String, std::collections::BTreeMap<String, i32>);

/// The drive's inventory as `agent` may see them: the drive resource itself
/// must be readable (else `Err`, the caller refuses with
/// `UNAUTHORIZED_READ`), and every subject the agent cannot `check_read` is
/// left out. This is the gate the full `SYNC` path has always applied per
/// subject; the hash-first probe and the `RBSR_ITEMS` inventory frame
/// used to skip it, which let an anonymous socket enumerate every subject
/// and version vector of any drive it could name.
///
/// Filtering per agent also makes the probe hash *match*: a client only
/// ever hashes what it holds, which is what it may read, so a server hash
/// over the unfiltered set would never agree with it for a drive with any
/// private subject.
pub async fn drive_items_for(
    store: &Db,
    drive: &str,
    agent: &crate::agents::ForAgent,
) -> Result<Vec<DriveItem>, String> {
    let drive_subject = crate::Subject::from_raw(drive, store.get_base_domain().as_deref());
    let drive_resource = store
        .get_resource(&drive_subject)
        .await
        .map_err(|_| "not readable".to_string())?;
    crate::hierarchy::check_read(store, &drive_resource, agent)
        .await
        .map_err(|e| e.to_string())?;

    let drive_subjects = collect_drive_subjects(store, &drive_subject).await;
    let vvs = build_drive_vvs(store, &drive_subjects);

    let mut items: Vec<DriveItem> = Vec::with_capacity(vvs.len());
    for (subject, vv) in vvs {
        let readable = match store
            .get_resource(&crate::Subject::from_raw(
                &subject,
                store.get_base_domain().as_deref(),
            ))
            .await
        {
            Ok(r) => crate::hierarchy::check_read(store, &r, agent).await.is_ok(),
            Err(_) => false,
        };
        if readable {
            items.push((subject, vv.into_iter().collect()));
        }
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(items)
}

/// Sorted inventory in the peer's spelling. Convert before range filtering or
/// hashing: subject bytes and their ordering are part of both.
pub async fn drive_items_for_wire(
    store: &Db,
    drive: &str,
    agent: &crate::agents::ForAgent,
    wire: WireScheme,
) -> Result<Vec<DriveItem>, String> {
    let mut items = drive_items_for(store, drive, agent).await?;
    for (subject, _) in &mut items {
        *subject = wire.subject(subject);
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(items)
}

/// [`drive_sync_hash`] over the subjects `agent` may read — the hash the
/// probe compares against, so it agrees with what that client can hold.
pub async fn drive_sync_hash_for(
    store: &Db,
    drive: &str,
    agent: &crate::agents::ForAgent,
) -> Result<String, String> {
    drive_sync_hash_for_wire(store, drive, agent, WireScheme::CANONICAL).await
}

pub async fn drive_sync_hash_for_wire(
    store: &Db,
    drive: &str,
    agent: &crate::agents::ForAgent,
    wire: WireScheme,
) -> Result<String, String> {
    drive_sync_hash_for_wire_version(store, drive, agent, wire, 1).await
}

/// [`drive_sync_hash_for_wire`] in the hash version the client asked for
/// (`1`: [`compute_drive_hash`], `2`: [`compute_drive_hash_v2`]).
pub async fn drive_sync_hash_for_wire_version(
    store: &Db,
    drive: &str,
    agent: &crate::agents::ForAgent,
    wire: WireScheme,
    hash_version: u8,
) -> Result<String, String> {
    let items = drive_items_for_wire(store, drive, agent, wire).await?;
    let vvs: std::collections::HashMap<String, std::collections::HashMap<String, i32>> = items
        .into_iter()
        .map(|(subject, vv)| (subject, vv.into_iter().collect()))
        .collect();
    Ok(if hash_version >= 2 {
        compute_drive_hash_v2(&vvs)
    } else {
        compute_drive_hash(&vvs)
    })
}

/// Compare client and server VVs, return binary SYNC_OK/SYNC_DIFF/SYNC_PUSH
/// frames over the whole drive. Thin wrapper over [`handle_sync_vv_filtered`].
pub async fn handle_sync_vv(
    drive: &str,
    drive_hash: &str,
    client_peers: &[String],
    client_resources: &std::collections::HashMap<String, Vec<i32>>,
    store: &Db,
    agent: &crate::agents::ForAgent,
) -> Vec<Vec<u8>> {
    handle_sync_vv_filtered(
        drive,
        drive_hash,
        client_peers,
        client_resources,
        None,
        store,
        agent,
        WireScheme::CANONICAL,
        false,
    )
    .await
}

/// Same as [`handle_sync_vv`], but when `subjects` is `Some(set)` only that set
/// is reconciled: a differing set the client chose (it used to come from the
/// RBSR descent, removed 2026-09). The server then builds VVs for only those
/// subjects (O(|set|) rather than O(drive)) and both loops skip anything
/// outside it, so the client sending version vectors for just the differing
/// subjects is processed exactly like the full path processes those subjects.
///
/// **Filtered-path limitation:** it relies purely on version-vector
/// divergence. The full path (`subjects == None`) additionally pulls a subject
/// whose VV *matches* but whose blob the server lacks (an HTTP-POST-metadata
/// backstop, below). That backstop does not run for subjects left out of the
/// set.
///
/// `pull` only names subjects the peer's `SYNC_PUSH` would be admitted for:
/// when `agent` may not write the drive ([`may_accept_drive_write`] with
/// `trust_owned`, the same check [`import_sync_push`] applies), `pull` stays
/// empty, so a read-only session is never asked to push what would be refused.
#[allow(clippy::too_many_arguments)]
pub async fn handle_sync_vv_filtered(
    drive: &str,
    drive_hash: &str,
    client_peers: &[String],
    client_resources: &std::collections::HashMap<String, Vec<i32>>,
    subjects: Option<&std::collections::HashSet<String>>,
    store: &Db,
    agent: &crate::agents::ForAgent,
    wire: WireScheme,
    trust_owned: bool,
) -> Vec<Vec<u8>> {
    handle_sync_vv_reconcile(
        drive,
        drive_hash,
        1,
        // Only built when the hashes differ: a matching drive never pays for
        // the dense-to-sparse walk.
        || {
            let mut client_vvs: std::collections::HashMap<
                String,
                std::collections::HashMap<String, i32>,
            > = std::collections::HashMap::new();

            for (subject, counters) in client_resources {
                let mut vv = std::collections::HashMap::new();

                for (i, &counter) in counters.iter().enumerate() {
                    if counter != 0 {
                        if let Some(peer_id) = client_peers.get(i) {
                            vv.insert(peer_id.clone(), counter);
                        }
                    }
                }

                let entry = client_vvs
                    .entry(crate::Subject::from_raw(subject, None).pure_id())
                    .or_default();
                for (peer, counter) in vv {
                    let current = entry.entry(peer).or_default();
                    *current = (*current).max(counter);
                }
            }

            client_vvs
        },
        subjects,
        store,
        agent,
        wire,
        trust_owned,
    )
    .await
}

/// The reconcile shared by both `SYNC` encodings. `client_vvs` yields the
/// client's version vectors keyed by canonical subject; it runs only when the
/// server hash differs from `drive_hash`, which is computed in `hash_version`.
#[allow(clippy::too_many_arguments)]
pub async fn handle_sync_vv_reconcile(
    drive: &str,
    drive_hash: &str,
    hash_version: u8,
    client_vvs: impl FnOnce()
        -> std::collections::HashMap<String, std::collections::HashMap<String, i32>>,
    subjects: Option<&std::collections::HashSet<String>>,
    store: &Db,
    agent: &crate::agents::ForAgent,
    wire: WireScheme,
    trust_owned: bool,
) -> Vec<Vec<u8>> {
    let canonical_subjects = subjects.map(|set| {
        set.iter()
            .map(|s| crate::Subject::from_raw(s, None).pure_id())
            .collect::<std::collections::HashSet<_>>()
    });
    let subjects = canonical_subjects.as_ref();
    let server_vvs = match subjects {
        // Filtered path: build VVs for only the differing subjects — no full-drive
        // parent walk, no full-drive snapshot reads.
        Some(set) => {
            let mut vvs = std::collections::HashMap::new();
            for subject in set {
                if let Ok(Some(bytes)) = store.kv.get(Tree::LoroSnapshots, subject.as_bytes()) {
                    if let Ok(vv) = AtomicLoroDoc::vv_map_from_snapshot(&bytes) {
                        vvs.insert(subject.clone(), vv);
                    }
                }
            }
            vvs
        }
        None => {
            let drive_subject = crate::Subject::from_raw(drive, store.get_base_domain().as_deref());
            let drive_subjects = collect_drive_subjects(store, &drive_subject).await;
            build_drive_vvs(store, &drive_subjects)
        }
    };

    // Fast path: hash match
    if !drive_hash.is_empty() {
        let wire_vvs = server_vvs
            .iter()
            .map(|(s, vv)| (wire.subject(s), vv.clone()))
            .collect();
        let server_hash = if hash_version >= 2 {
            compute_drive_hash_v2(&wire_vvs)
        } else {
            compute_drive_hash(&wire_vvs)
        };

        if server_hash == drive_hash {
            tracing::info!("SYNC: drive {} — hashes match, in sync", drive);

            return vec![protocol::encode_sync_ok(&wire.subject(drive))];
        }
    }

    let client_vvs = client_vvs();
    let mut pull: Vec<String> = Vec::new();
    let mut pull_from: std::collections::HashMap<String, std::collections::HashMap<String, i32>> =
        std::collections::HashMap::new();
    let mut remove: Vec<String> = Vec::new();
    let mut remove_commits: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    // A destroyed subject has no resource left to `check_read` against, so
    // the signed destroy envelope is gated on read access to the drive being
    // synced. Computed once, lazily: most reconciles carry no tombstones.
    let mut may_read_drive: Option<bool> = None;
    let mut push_entries: Vec<(String, Vec<u8>)> = Vec::new();

    for (subject, server_vv) in &server_vvs {
        // Check read permission
        let resource = match store
            .get_resource(&crate::Subject::from_raw(
                subject,
                store.get_base_domain().as_deref(),
            ))
            .await
        {
            Ok(r) => {
                if crate::hierarchy::check_read(store, &r, agent)
                    .await
                    .is_err()
                {
                    continue;
                }
                r
            }
            Err(_) => continue,
        };

        if let Some(client_vv) = client_vvs.get(subject) {
            let server_ahead = server_vv
                .iter()
                .any(|(p, &sc)| client_vv.get(p).copied().unwrap_or(0) < sc);
            let client_ahead = client_vv
                .iter()
                .any(|(p, &cc)| server_vv.get(p).copied().unwrap_or(0) < cc);

            if server_ahead {
                if let Ok(Some(snapshot_bytes)) =
                    store.kv.get(Tree::LoroSnapshots, subject.as_bytes())
                {
                    if let Ok(doc) = AtomicLoroDoc::from_snapshot(&snapshot_bytes) {
                        let client_loro_vv = AtomicLoroDoc::vv_from_map(client_vv);
                        let delta = doc.export_updates_since(&client_loro_vv);

                        if !delta.is_empty() {
                            push_entries.push((subject.clone(), delta));
                        }
                    }
                }
            }

            if client_ahead {
                pull.push(subject.clone());
                pull_from.insert(subject.clone(), server_vv.clone());
            }

            // New logic: even if VVs match (or server is ahead), if the server is missing the blob, we must pull it.
            // This handles the case where metadata was pushed via HTTP POST /commit but the blob is still on the client.
            if let Ok(blob_val) = resource.get(crate::urls::BLOB) {
                let blob_did = blob_val.to_string();
                if let Some(hash_hex) = crate::Subject::from_raw(&blob_did, None).blob_hash_hex() {
                    if let Ok(hash_bytes) = hex::decode(hash_hex) {
                        if hash_bytes.len() == 32 {
                            let mut hash = [0u8; 32];
                            hash.copy_from_slice(&hash_bytes);
                            if !store.has_blob(&hash).await.unwrap_or(false) {
                                // If we don't have the blob, add to pull so the server requests it
                                if !pull.contains(subject) {
                                    pull.push(subject.clone());
                                    pull_from.insert(subject.clone(), server_vv.clone());
                                }
                            }
                        }
                    }
                }
            }
        } else {
            if let Ok(Some(snapshot_bytes)) = store.kv.get(Tree::LoroSnapshots, subject.as_bytes())
            {
                push_entries.push((subject.clone(), snapshot_bytes));
            }
        }
    }

    // Client resources not on server: pull new data, or tell client to delete tombstones.
    for subject in client_vvs.keys() {
        // On the filtered path, only reconcile the differing set even if the client
        // sent extra version vectors.
        if subjects.is_some_and(|set| !set.contains(subject)) {
            continue;
        }
        if !server_vvs.contains_key(subject) {
            if super::tombstones::is_tombstoned(store, subject) {
                remove.push(subject.clone());
                if let Some(json) = super::tombstones::destroy_envelope(store, subject) {
                    let allowed = match may_read_drive {
                        Some(v) => v,
                        None => {
                            let v = agent_may_read_drive(store, drive, agent).await;
                            may_read_drive = Some(v);
                            v
                        }
                    };
                    if allowed {
                        remove_commits.insert(subject.clone(), json);
                    }
                }
            } else {
                pull.push(subject.clone());
                pull_from.entry(subject.clone()).or_default();
            }
        }
    }

    // Only ask for what `import_sync_push` would accept from this agent.
    // Without this, a read-only reader is told to push (a subject outside the
    // drive tree it happens to hold, or a file whose blob we lack) and its
    // push is then refused as a whole. A drive we have never stored is left
    // alone: `import_sync_push` bootstraps it.
    if !pull.is_empty() {
        let drive_subject = crate::Subject::from_raw(drive, store.get_base_domain().as_deref());
        if let Ok(drive_resource) = store.get_resource(&drive_subject).await {
            if !may_accept_drive_write(store, &drive_resource, agent, trust_owned).await {
                tracing::debug!(
                    "SYNC: drive {} — agent {:?} may not write, not asking for {} subjects",
                    drive,
                    agent,
                    pull.len()
                );
                pull.clear();
                pull_from.clear();
            }
        }
    }

    let push_subjects: Vec<String> = push_entries.iter().map(|(s, _)| s.clone()).collect();

    tracing::info!(
        "SYNC: drive {} — {} to push, {} to pull, {} to remove",
        drive,
        push_subjects.len(),
        pull.len(),
        remove.len(),
    );

    // Every subject on the wire follows the peer's scheme; the map keys must
    // match the lists they annotate, so they are rewritten together.
    let pull_from_wire: std::collections::HashMap<String, std::collections::HashMap<String, i32>> =
        pull_from
            .into_iter()
            .map(|(subject, vv)| (wire.subject(&subject), vv))
            .collect();
    let remove_commits_wire: std::collections::HashMap<String, String> = remove_commits
        .into_iter()
        .map(|(subject, json)| (wire.subject(&subject), json))
        .collect();

    let mut frames = Vec::new();
    frames.push(protocol::encode_sync_diff(
        &wire.subject(drive),
        &wire.subjects(&pull),
        &wire.subjects(&push_subjects),
        &wire.subjects(&remove),
        &pull_from_wire,
        &remove_commits_wire,
    ));

    if !push_entries.is_empty() {
        frames.extend(sync_push_chunks_for_wire(store, drive, &push_entries, wire));
    }

    frames
}

/// `SYNC_PUSH` frames for `entries`, subjects spelled for `wire`.
///
/// `encode_sync_push_chunks` splits by entry count + byte budget and marks
/// the final frame LAST. Each frame is independent on the wire; the receiver
/// loops reading SYNC_PUSH until it sees LAST. Each subject's retained
/// envelopes ride in its chunk so the receiver can attribute what it imports
/// (`envelopes::import_envelope`); the envelope JSON is signed and travels
/// as stored, only the key it is filed under follows the scheme.
pub fn sync_push_chunks_for_wire(
    store: &Db,
    drive: &str,
    entries: &[(String, Vec<u8>)],
    wire: WireScheme,
) -> Vec<Vec<u8>> {
    let envelopes = crate::envelopes::for_subjects(store, entries.iter().map(|(s, _)| s.as_str()));
    let envelopes_wire: std::collections::HashMap<String, Vec<String>> = envelopes
        .into_iter()
        .map(|(subject, list)| (wire.subject(&subject), list))
        .collect();
    let wire_entries: Vec<(String, &[u8])> = entries
        .iter()
        .map(|(s, b)| (wire.subject(s), b.as_slice()))
        .collect();
    let refs: Vec<(&str, &[u8])> = wire_entries.iter().map(|(s, b)| (s.as_str(), *b)).collect();
    protocol::encode_sync_push_chunks_with_envelopes(&wire.subject(drive), &refs, &envelopes_wire)
}

/// Whether an incoming write to `drive_resource` should be accepted.
///
/// The direct case: the peer that sent it can itself write the drive.
///
/// The relayed case (`trust_owned`): a peer we *chose to connect to* — a server
/// that stores our drive, another of our devices — authenticates as its OWN
/// agent, not ours, yet is faithfully relaying updates to a drive WE own. Gating
/// on the transport peer's identity would reject every such update (this is why
/// a phone stops receiving a browser's edits once its drive already exists on
/// the server). So when we initiated the connection, we also accept updates to
/// drives our own agent may write — the drive owner acting as the authority over
/// their own replica. We never relax this for connections dialed *into* us: a
/// stranger who dials us does not get to write our drives just because we own
/// them.
pub(crate) async fn may_accept_drive_write(
    store: &Db,
    drive_resource: &crate::Resource,
    for_agent: &crate::agents::ForAgent,
    trust_owned: bool,
) -> bool {
    if crate::hierarchy::check_write(store, drive_resource, for_agent)
        .await
        .is_ok()
    {
        return true;
    }
    if trust_owned {
        if let Ok(own) = store.get_default_agent() {
            let own_agent = crate::agents::ForAgent::from(own);
            if crate::hierarchy::check_write(store, drive_resource, &own_agent)
                .await
                .is_ok()
            {
                return true;
            }
        }
    }
    false
}

/// Why a `SYNC_PUSH` was refused as a whole. Distinct from "imported zero
/// entries" (every entry tombstoned or malformed), which is still a
/// successful import from the protocol's point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncPushRejected {
    /// The drive the push named.
    pub drive: String,
    /// Human-readable reason; goes on the wire in the `ERROR` frame.
    pub reason: String,
}

impl SyncPushRejected {
    /// The `ERROR` frame (`request_id = 0`, [`protocol::error_code::SYNC_REJECTED`])
    /// that answers the push instead of `SYNC_OK`.
    pub fn to_error_frame(&self) -> Vec<u8> {
        protocol::encode_error(0, protocol::error_code::SYNC_REJECTED, &self.to_string())
    }
}

impl std::fmt::Display for SyncPushRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SYNC_PUSH rejected for drive {}: {}",
            self.drive, self.reason
        )
    }
}

/// Whether `agent` may read `drive`. `false` when the drive is not stored
/// here. Used to gate what a bulk reconcile hands out about a drive's
/// destroyed subjects (the signed destroy envelope names the signer and
/// when they acted), since the destroyed resource itself is gone.
async fn agent_may_read_drive(store: &Db, drive: &str, agent: &crate::agents::ForAgent) -> bool {
    let drive_subject = crate::Subject::from_raw(drive, store.get_base_domain().as_deref());
    match store.get_resource(&drive_subject).await {
        Ok(resource) => crate::hierarchy::check_read(store, &resource, agent)
            .await
            .is_ok(),
        Err(_) => false,
    }
}

/// Whether a write to a drive this node has **never stored** may proceed.
/// Enrolls the drive when the policy wants that.
///
/// Closes unified-sync OQ5: `ForAgent::Public` never creates a drive.
/// An authenticated agent on [`super::policy::OpenPolicy`] still may
/// (localhost first-sync). [`super::policy::OwnerPolicy`] admits only the
/// owner and enrolls. An allowlist's bootstrap grace already shows up as
/// `admit_drive_write == true` and is left alone.
pub(crate) fn admit_unknown_drive(
    store: &Db,
    drive_subject: &str,
    agent: &crate::agents::ForAgent,
) -> bool {
    if matches!(agent, crate::agents::ForAgent::Public) {
        return false;
    }
    let policy = store.sync_policy();
    if policy.admit_drive_write(drive_subject) {
        return true;
    }
    if policy.may_enroll_drive(drive_subject, agent) {
        tracing::info!("enrolling new drive {} for {:?}", drive_subject, agent);
        policy.enroll_drive(drive_subject);
        true
    } else {
        false
    }
}

/// Import resources from a SYNC_PUSH message into the local store.
///
/// `for_agent` is the identity the sending peer proved. `trust_owned` is true
/// when WE dialed this peer, which lets a relayed push to a drive we own through
/// even though the relaying peer is a different agent (see
/// [`may_accept_drive_write`]). When importing locally, pass `Sudo`.
///
/// `Ok((imported, blob_requests))` when the push was admitted — `imported`
/// may still be 0 if every entry was skipped. `Err` when the push was refused
/// as a whole: the agent may not write the drive, or the sync policy does not
/// admit it. Nothing is written in the `Err` case, and the caller must answer
/// with the rejection's `ERROR` frame, never `SYNC_OK`.
pub async fn import_sync_push(
    push: &protocol::DecodedSyncPush,
    store: &Db,
    for_agent: &crate::agents::ForAgent,
    trust_owned: bool,
) -> Result<(usize, Vec<Vec<u8>>), SyncPushRejected> {
    let drive_subject = crate::Subject::from_raw(&push.drive, store.get_base_domain().as_deref());
    let policy = store.sync_policy();

    if let Ok(drive_resource) = store.get_resource(&drive_subject).await {
        if !may_accept_drive_write(store, &drive_resource, for_agent, trust_owned).await {
            tracing::warn!(
                "import_sync_push: agent {:?} has no write access to drive {} (trust_owned={})",
                for_agent,
                push.drive,
                trust_owned
            );
            return Err(SyncPushRejected {
                drive: push.drive.clone(),
                reason: format!("agent {for_agent} has no write right on the drive"),
            });
        }
        // Existing drive: allowlist/quota still apply. No bootstrap — that
        // path is only for a drive we have never stored.
        let decision = policy.admit_decision(&push.drive);
        if !decision.is_admitted() {
            tracing::warn!(
                "import_sync_push: drive {} not admitted by sync policy ({:?}, agent {:?})",
                push.drive,
                decision,
                for_agent
            );
            let reason = match decision {
                super::policy::AdmitDecision::OverQuota => {
                    format!(
                        "drive {} is over its storage quota on this node",
                        push.drive
                    )
                }
                _ => policy.not_enrolled_message(&push.drive),
            };
            return Err(SyncPushRejected {
                drive: push.drive.clone(),
                reason,
            });
        }
    } else if !admit_unknown_drive(store, &push.drive, for_agent) {
        tracing::warn!(
            "import_sync_push: refusing bootstrap of unknown drive {} for {:?}",
            push.drive,
            for_agent
        );
        let reason = if matches!(for_agent, crate::agents::ForAgent::Public) {
            "unauthenticated agent cannot create a drive".to_string()
        } else {
            policy.not_enrolled_message(&push.drive)
        };
        return Err(SyncPushRejected {
            drive: push.drive.clone(),
            reason,
        });
    }

    let mut count = 0;
    let mut blob_requests = Vec::new();
    let mut imported: std::collections::HashSet<String> = std::collections::HashSet::new();

    let base_domain = store.get_base_domain();
    let normalize = |s: &str| crate::Subject::from_raw(s, base_domain.as_deref()).pure_id();
    let admitted_drive = normalize(&push.drive);

    for entry in &push.entries {
        if super::tombstones::is_tombstoned(store, &entry.subject) {
            tracing::debug!(
                "import_sync_push: skip {:?} (tombstoned locally)",
                &entry.subject[..entry.subject.len().min(24)]
            );
            continue;
        }

        let snapshot_key =
            crate::Subject::from_raw(&entry.subject, store.get_base_domain().as_deref()).pure_id();

        // Same read-modify-write as `ws_apply::persist_update`, so the same
        // exclusion: everything from the read below to `add_resource_opts` at
        // the end of this iteration must not interleave with a commit, or one
        // silently replaces the other's snapshot. Held per entry, released at
        // the end of each iteration.
        let _subject_guard = store.subject_locks.lock(&snapshot_key).await;

        // Admission above was for `push.drive` as a whole. Each entry names
        // its own subject, so an existing resource must actually live in
        // that drive, or a peer admitted for one drive could overwrite any
        // resource on this node (its ACLs included) by listing it here. Its
        // stored `drive` stamp is authoritative and is read BEFORE the
        // incoming delta is merged (mirrors `ws_apply::persist_update`).
        let existing_resource = store
            .get_resource(&crate::Subject::from_raw(
                &snapshot_key,
                base_domain.as_deref(),
            ))
            .await
            .ok();
        if let Some(existing) = &existing_resource {
            let stored_drive = if let Ok(drive) = existing.get(crate::urls::DRIVE_PROP) {
                drive.to_string()
            } else if let Ok(parent) = existing.get(crate::urls::PARENT) {
                let parent_subject = crate::Subject::from(parent.to_string());
                if let Ok(parent_resource) = store.get_resource(&parent_subject).await {
                    parent_resource
                        .get(crate::urls::DRIVE_PROP)
                        .map(|v| v.to_string())
                        .unwrap_or_else(|_| parent_subject.to_string())
                } else {
                    existing.get_subject().to_string()
                }
            } else {
                existing.get_subject().to_string()
            };
            if normalize(&stored_drive) != admitted_drive {
                tracing::warn!(
                    "import_sync_push: {} belongs to drive {}, not to {} this push was admitted for; skipped",
                    entry.subject,
                    stored_drive,
                    push.drive
                );
                continue;
            }
        }

        // Load existing doc or create new
        let doc = if let Ok(Some(existing)) =
            store.kv.get(Tree::LoroSnapshots, snapshot_key.as_bytes())
        {
            match AtomicLoroDoc::from_snapshot(&existing) {
                Ok(d) => {
                    // A SYNC_PUSH may carry either an incremental update or a
                    // complete snapshot; Loro accepts both and merges them.
                    if d.import_update(&entry.loro_bytes).is_err() {
                        tracing::warn!(
                            "import_sync_push: delta import failed for {}",
                            entry.subject
                        );
                        continue;
                    }
                    d
                }
                Err(_) => {
                    // Existing snapshot corrupt, treat incoming as fresh
                    match AtomicLoroDoc::from_snapshot(&entry.loro_bytes) {
                        Ok(d) => d,
                        Err(_) => continue,
                    }
                }
            }
        } else {
            // New resource — import as snapshot
            let doc = AtomicLoroDoc::new();
            if doc.import_update(&entry.loro_bytes).is_err() {
                // Try as snapshot
                match AtomicLoroDoc::from_snapshot(&entry.loro_bytes) {
                    Ok(d) => d,
                    Err(_) => {
                        tracing::warn!("import_sync_push: import failed for {}", entry.subject);
                        continue;
                    }
                }
            } else {
                doc
            }
        };

        // No `get_resource` — `apply_state_doc` rebuilds propvals from the
        // merged doc, so the read would be discarded. Sync builds directly.
        let subject = crate::Subject::from_raw(&snapshot_key, store.get_base_domain().as_deref());
        let mut resource = crate::Resource::new(subject.to_string());

        if resource.apply_state_doc(doc).is_err() {
            continue;
        }

        // A new subject: it may only enter the drive this push was admitted
        // for. Its parent's stored drive decides when the parent is known
        // here; otherwise the resource must stamp itself into that drive or
        // be the drive root itself. (A peer gains nothing by stamping a NEW
        // resource into a drive it already has write on.)
        if existing_resource.is_none() {
            let mut claimed = resource
                .get(crate::urls::DRIVE_PROP)
                .map(|v| v.to_string())
                .unwrap_or_else(|_| resource.get_subject().to_string());
            if let Ok(parent_val) = resource.get(crate::urls::PARENT) {
                let parent_subject = crate::Subject::from(parent_val.to_string());
                if let Ok(parent_res) = store.get_resource(&parent_subject).await {
                    claimed = parent_res
                        .get(crate::urls::DRIVE_PROP)
                        .map(|v| v.to_string())
                        .unwrap_or_else(|_| parent_subject.to_string());
                }
            }
            if normalize(&claimed) != admitted_drive {
                tracing::warn!(
                    "import_sync_push: new resource {} resolves to drive {}, not to {} this push was admitted for; skipped",
                    entry.subject,
                    claimed,
                    push.drive
                );
                continue;
            }
        }

        // Only persist after every scope check succeeds. In particular, a
        // rejected new subject must not leave a snapshot that a later valid
        // import would merge. add_resource_opts stores the validated state.
        // Log what properties arrived
        let has_strokes = resource
            .get("https://atomicdata.dev/ontology/canvas/strokeData")
            .is_ok();
        tracing::info!(
            "  sync imported {}: {} props, has_strokes={}",
            &entry.subject[..entry.subject.len().min(30)],
            resource.get_propvals().len(),
            has_strokes,
        );

        store
            .persist_replicated_resource(&resource)
            .await
            .map_err(|error| SyncPushRejected {
                drive: push.drive.clone(),
                reason: format!("Failed to persist {}: {error}", entry.subject),
            })?;
        count += 1;
        imported.insert(snapshot_key.clone());

        // Check for missing blobs
        if let Ok(blob_val) = resource.get(crate::urls::BLOB) {
            let blob_did = blob_val.to_string();
            if let Some(hash_hex) = crate::Subject::from_raw(&blob_did, None).blob_hash_hex() {
                if let Ok(hash_bytes) = hex::decode(hash_hex) {
                    if hash_bytes.len() == 32 {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&hash_bytes);
                        if !store.has_blob(&hash).await.unwrap_or(false) {
                            // Record which (already-admitted, see the top of
                            // this fn) drive this hash belongs to so the
                            // BLOB_RESPONSE handler can gate the write
                            // instead of accepting it unconditionally
                            // (planning/unified-sync.md F4).
                            store.note_pending_blob_request(hash, push.drive.clone());
                            blob_requests.push(protocol::encode_blob_request(&hash));
                        }
                    }
                }
            }
        }
    }

    // Envelopes ride with the entries they sign. Only a subject imported
    // above may receive one (same admission as its entry), and each is
    // verified before it is kept; a bad one is dropped, never the push.
    for envelope in &push.envelopes {
        if !imported.contains(&normalize(&envelope.subject)) {
            continue;
        }
        if let Err(e) =
            crate::envelopes::import_envelope(store, &envelope.subject, &envelope.json).await
        {
            tracing::warn!(
                "import_sync_push: envelope for {} rejected: {e}",
                &envelope.subject[..envelope.subject.len().min(30)]
            );
        }
    }

    tracing::info!(
        "import_sync_push: imported {} resources for drive {}",
        count,
        push.drive
    );
    for entry in &push.entries {
        tracing::info!(
            "  imported: {} ({} bytes)",
            &entry.subject[..entry.subject.len().min(30)],
            entry.loro_bytes.len()
        );
    }
    Ok((count, blob_requests))
}

/// Whether the owner deliberately dialled this node. Peer-to-peer sync only
/// exists with the `iroh` feature — the WASM build of this crate has no peer
/// module — so without it nothing is ever treated as paired.
#[cfg(feature = "iroh")]
fn peer_is_paired(store: &Db, node_id: &str) -> bool {
    crate::sync::peer::is_paired_peer(store, node_id)
}

#[cfg(not(feature = "iroh"))]
fn peer_is_paired(_store: &Db, _node_id: &str) -> bool {
    false
}

/// Serve a remote-supplied `pull` list from local Loro snapshots — gated per
/// subject on `check_read` for the identity the remote proved.
/// This is the initiator-side mirror of the acceptor's `handle_sync_vv`,
/// which has always done this check before pushing: the `pull` half of a
/// `SYNC_DIFF` is chosen by the remote peer, so serving it from a raw
/// `Tree::LoroSnapshots` read would let a dialed peer name any subject in the
/// drive and receive it regardless of read rights. Dialing a peer never
/// established that peer's rights. Fail closed: a subject that doesn't
/// materialize into a resource can't be rights-checked, so it isn't served.
///
/// `paired_peer` is the node id of a peer this node's user deliberately dialled
/// (see `peer::is_paired_peer`). Such a peer may replicate anything WE can
/// read, even though its own agent holds no rights: pairing is an authenticated
/// choice by the owner, and it is the authority a replica should run on. The
/// alternative — the owner hand-writing an ACL entry naming each device's agent
/// on each drive — is what made two of the same person's nodes sync nothing at
/// all while the UI reported "In sync".
///
/// Note this deliberately does NOT widen what gets served: a paired replica is
/// served exactly the subjects this node can read, never more.
pub async fn collect_readable_snapshots(
    store: &Db,
    agent: &crate::agents::ForAgent,
    subjects: &[String],
    paired_peer: Option<&str>,
) -> Vec<(String, Vec<u8>)> {
    // Resolved once: a paired peer's entitlement is "whatever we ourselves may
    // read", so it is our own identity that answers, not the peer's.
    let own_agent = if paired_peer.is_some_and(|node| peer_is_paired(store, node)) {
        store
            .get_default_agent()
            .ok()
            .map(crate::agents::ForAgent::from)
    } else {
        None
    };

    // Subjects with a pending outbox entry are NOT skipped here, unlike the
    // browser's handleSyncDiff. This collector also serves a same-agent
    // replica that may hold none of the drive yet (a second device's first
    // sync), and that replica is allowed the raw state by the Principle 3
    // exception in planning/serverless-p2p.md; withholding it left the
    // device waiting on a live-link drain that may never come. The signed
    // delta follows from the outbox and applies on top idempotently.
    let mut entries = Vec::new();
    for subject in subjects {
        let subj = crate::Subject::from_raw(subject, store.get_base_domain().as_deref());
        match store.get_resource(&subj).await {
            Ok(resource) => {
                let mut readable = crate::hierarchy::check_read(store, &resource, agent)
                    .await
                    .is_ok();

                if !readable {
                    if let Some(own) = own_agent.as_ref() {
                        readable = crate::hierarchy::check_read(store, &resource, own)
                            .await
                            .is_ok();

                        if readable {
                            tracing::debug!(
                                "[sync] serving {} to a paired replica",
                                &subject[..subject.len().min(30)]
                            );
                        }
                    }
                }

                if !readable {
                    tracing::warn!(
                        "[sync] refusing to serve {} to peer: no read access for {:?}",
                        &subject[..subject.len().min(30)],
                        agent
                    );
                    continue;
                }
            }
            Err(_) => continue,
        }
        if let Some(snapshot) = store.get_loro_snapshot_bytes(&subj.pure_id()) {
            entries.push((subject.clone(), snapshot));
        }
    }
    entries
}

#[cfg(test)]
mod bootstrap_and_sub_tests {
    use super::*;
    use crate::agents::ForAgent;
    use crate::sync::policy::OwnerPolicy;
    use crate::sync::protocol::{self, error_code, tag};
    use std::sync::Arc;

    #[tokio::test]
    async fn sync_probe_bootstraps_an_admitted_missing_drive_only() {
        use crate::sync::policy::AllowlistPolicy;
        let db = Db::init_temp("probe_bootstrap").await.unwrap();
        let (alice, private_drive) = db.setup("Alice").await.unwrap();
        let missing = "atomic:admitted-new-drive";
        let unlisted = "atomic:unlisted-new-drive";
        let policy = Arc::new(AllowlistPolicy::new());
        policy.set_grace(std::time::Duration::ZERO);
        policy.set_drive_policies([(missing, Some(1024)), (private_drive.as_str(), None)]);
        db.set_sync_policy(policy.clone());
        let mut owner = ForAgent::from(alice);
        for frame in [
            protocol::encode_sync_probe(missing, "local"),
            protocol::encode_sync_probe_v2(missing, "local"),
        ] {
            let answer = handle_frame(&frame, &db, &mut owner).await;
            assert_eq!(
                answer[0][0],
                tag::SYNC_RESEND,
                "an admitted missing drive must be offered a full reconcile"
            );
        }
        assert_eq!(
            handle_frame(
                &protocol::encode_sync_probe(unlisted, "local"),
                &db,
                &mut owner
            )
            .await[0][0],
            tag::ERROR
        );
        let mut public = ForAgent::Public;
        for drive in [missing, private_drive.as_str()] {
            assert_eq!(
                handle_frame(
                    &protocol::encode_sync_probe(drive, "local"),
                    &db,
                    &mut public
                )
                .await[0][0],
                tag::ERROR
            );
        }
        policy.record_drive_usage([(missing, 2048)]);
        assert_eq!(
            handle_frame(
                &protocol::encode_sync_probe(missing, "local"),
                &db,
                &mut owner
            )
            .await[0][0],
            tag::ERROR
        );
        assert!(
            db.get_resource(&missing.into()).await.is_err(),
            "a probe does not create a resource"
        );
    }

    fn empty_push(drive: &str) -> protocol::DecodedSyncPush {
        let frame = protocol::encode_sync_push(drive, &[], true);
        protocol::decode_sync_push(&frame[1..]).unwrap()
    }

    /// A pushed envelope is kept only when it is verified and names a subject
    /// imported from the same push; one for a subject the push did not carry
    /// (or that was rejected) is dropped without failing the push.
    #[tokio::test]
    async fn push_envelopes_are_kept_only_for_imported_subjects() {
        let source = Db::init_temp("push_envelopes_source").await.unwrap();
        let (alice, drive) = source.setup("Alice").await.unwrap();
        let note = source
            .create_resource(crate::urls::FOLDER, &drive, "note", None)
            .await
            .unwrap();
        let drive_snapshot = source
            .kv
            .get(Tree::LoroSnapshots, drive.as_bytes())
            .unwrap()
            .unwrap();
        let note_snapshot = source
            .kv
            .get(Tree::LoroSnapshots, note.as_bytes())
            .unwrap()
            .unwrap();
        let note_envelope = crate::envelopes::latest_envelope(&source, &note)
            .unwrap()
            .json;
        let drive_envelope = crate::envelopes::latest_envelope(&source, &drive)
            .unwrap()
            .json;

        // Bootstrap the drive on a second node; the note's envelope rides
        // with it, the drive's own envelope names a subject that is not in
        // this frame's entries.
        let entries: [(&str, &[u8]); 2] = [(&drive, &drive_snapshot), (&note, &note_snapshot)];
        let envelopes = [
            (note.as_str(), note_envelope.as_str()),
            ("did:ad:not-in-this-push", drive_envelope.as_str()),
        ];
        let frame = protocol::encode_sync_push_with_envelopes(&drive, &entries, &envelopes, true);
        let push = protocol::decode_sync_push(&frame[1..]).unwrap();

        let sink = Db::init_temp("push_envelopes_sink").await.unwrap();
        let (count, _) = import_sync_push(&push, &sink, &ForAgent::from(alice), false)
            .await
            .unwrap();
        assert_eq!(count, 2);
        let kept = crate::envelopes::envelopes(&sink, &note);
        assert_eq!(kept.len(), 1, "the imported note keeps its envelope");
        assert_eq!(kept[0].json, note_envelope);
        assert!(
            crate::envelopes::envelopes(&sink, "did:ad:not-in-this-push").is_empty(),
            "an envelope for a subject the push did not import is dropped"
        );
        assert!(
            crate::envelopes::envelopes(&sink, &drive).is_empty(),
            "nothing is stored under the envelope's own subject either"
        );
        let report = crate::envelopes::attribute_history(&sink, &note)
            .await
            .unwrap();
        assert!(report.attributions.iter().any(|a| a.verified && a.genesis));
    }

    #[tokio::test]
    async fn rejected_sync_entry_does_not_persist_snapshot() {
        let db = Db::init_temp("rejected_sync_snapshot").await.unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();
        let subject = "atomic:unseen-victim-resource";
        let doc = AtomicLoroDoc::new();
        doc.set_property(
            crate::urls::DRIVE_PROP,
            &crate::Value::AtomicUrl("atomic:other-drive".into()),
        )
        .unwrap();
        doc.set_property(
            crate::urls::NAME,
            &crate::Value::String("Rejected data".into()),
        )
        .unwrap();
        let frame = protocol::encode_sync_push(&drive, &[(subject, &doc.export_snapshot())], true);
        let push = protocol::decode_sync_push(&frame[1..]).unwrap();
        let (count, _) = import_sync_push(&push, &db, &ForAgent::from(alice.clone()), false)
            .await
            .unwrap();
        assert_eq!(count, 0);
        assert!(
            db.kv
                .get(Tree::LoroSnapshots, subject.as_bytes())
                .unwrap()
                .is_none(),
            "rejected data must not seed a later legitimate merge"
        );
        assert!(db.get_resource(&subject.into()).await.is_err());

        // A subsequent valid import of the same subject must start clean.
        let valid = AtomicLoroDoc::new();
        valid
            .set_property(
                crate::urls::DRIVE_PROP,
                &crate::Value::AtomicUrl(drive.clone().into()),
            )
            .unwrap();
        let frame =
            protocol::encode_sync_push(&drive, &[(subject, &valid.export_snapshot())], true);
        let push = protocol::decode_sync_push(&frame[1..]).unwrap();
        let (count, _) = import_sync_push(&push, &db, &ForAgent::from(alice), false)
            .await
            .unwrap();
        assert_eq!(count, 1);
        let stored = db.get_resource(&subject.into()).await.unwrap();
        assert!(
            stored.get(crate::urls::NAME).is_err(),
            "rejected properties must not reappear"
        );
        assert!(db
            .kv
            .get(Tree::LoroSnapshots, subject.as_bytes())
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn parent_only_existing_resource_cannot_be_pushed_through_another_drive() {
        let db = Db::init_temp("parent_only_existing_cross_drive")
            .await
            .unwrap();
        let (_alice, drive) = db.setup("Alice").await.unwrap();
        let other_drive = "https://localhost/other-drive";
        db.add_resource_opts(&crate::Resource::new(other_drive.into()), false, true, true)
            .await
            .unwrap();

        let subject = "https://localhost/parent-only-child";
        let mut child = crate::Resource::new(subject.into());
        child
            .set_unsafe(
                crate::urls::PARENT.into(),
                crate::Value::AtomicUrl(drive.clone().into()),
            )
            .unwrap();
        child
            .set_unsafe(
                crate::urls::NAME.into(),
                crate::Value::String("Original".into()),
            )
            .unwrap();
        db.add_resource_opts(&child, false, true, true)
            .await
            .unwrap();

        let mut incoming = db.get_resource(&subject.into()).await.unwrap();
        incoming
            .set_unsafe(
                crate::urls::NAME.into(),
                crate::Value::String("Must not land".into()),
            )
            .unwrap();
        let bytes = incoming.build_state_doc().unwrap().export_snapshot();
        let frame = protocol::encode_sync_push(other_drive, &[(subject, bytes.as_slice())], true);
        let push = protocol::decode_sync_push(&frame[1..]).unwrap();

        let (count, _) = import_sync_push(&push, &db, &ForAgent::Sudo, false)
            .await
            .unwrap();
        assert_eq!(count, 0);
        assert_eq!(
            db.get_resource(&subject.into())
                .await
                .unwrap()
                .get(crate::urls::NAME)
                .unwrap()
                .to_string(),
            "Original"
        );
    }

    #[tokio::test]
    async fn public_cannot_bootstrap_a_missing_drive_even_on_open() {
        let db = Db::init_temp("oq5_public_open").await.unwrap();
        let drive = "did:ad:newdrivepublic";
        let push = empty_push(drive);

        let err = import_sync_push(&push, &db, &ForAgent::Public, false)
            .await
            .expect_err("Public must not create a drive on an open node");
        assert!(
            err.reason.contains("unauthenticated"),
            "reason names the cause: {}",
            err.reason
        );
        assert!(
            db.get_resource(&drive.into()).await.is_err(),
            "the refused push must not have stored the drive"
        );
    }

    #[tokio::test]
    async fn authenticated_first_sync_on_open_still_admits_a_new_drive() {
        let db = Db::init_temp("oq5_auth_open").await.unwrap();
        let (alice, _) = db.setup("Alice").await.unwrap();
        let drive = "did:ad:newdrivealice";
        let push = empty_push(drive);

        import_sync_push(
            &push,
            &db,
            &ForAgent::AgentSubject(alice.subject.clone()),
            false,
        )
        .await
        .expect("an authenticated agent on Open may bootstrap a drive");
    }

    #[tokio::test]
    async fn owner_mode_refuses_a_stranger_bootstrapping_a_new_drive() {
        let db = Db::init_temp("oq5_owner_stranger").await.unwrap();
        let (owner, _) = db.setup("Owner").await.unwrap();
        let stranger = db.create_agent(Some("Stranger")).await.unwrap();
        db.set_sync_policy(Arc::new(OwnerPolicy::new(owner.subject.to_string())));

        let drive = "did:ad:strangerdrive";
        let push = empty_push(drive);
        let err = import_sync_push(
            &push,
            &db,
            &ForAgent::AgentSubject(stranger.subject.clone()),
            false,
        )
        .await
        .expect_err("a stranger must not dump a drive onto an owner-gated node");
        assert!(
            err.reason.contains("does not host new Drives"),
            "the refusal speaks to the visitor: {}",
            err.reason
        );
        assert!(
            !db.sync_policy().admit_drive_write(drive),
            "the refused drive must not have been enrolled"
        );
    }

    #[tokio::test]
    async fn owner_mode_enrolls_the_owners_new_drive_from_sync_push() {
        let db = Db::init_temp("oq5_owner_self").await.unwrap();
        let (owner, _) = db.setup("Owner").await.unwrap();
        db.set_sync_policy(Arc::new(OwnerPolicy::new(owner.subject.to_string())));

        let drive = "did:ad:ownerssecond";
        let push = empty_push(drive);
        import_sync_push(
            &push,
            &db,
            &ForAgent::AgentSubject(owner.subject.clone()),
            false,
        )
        .await
        .expect("the owner may bootstrap a second drive");
        assert!(
            db.sync_policy().admit_drive_write(drive),
            "the owner's new drive must be enrolled so later writes land"
        );
    }

    #[tokio::test]
    async fn get_many_answers_every_subject_in_order() {
        let db = Db::init_temp("get_many").await.unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();
        let alice_subject = alice.subject.to_string();
        let frame = protocol::encode_get_many(21, &[&drive, "did:ad:missing", &alice_subject]);
        let mut agent = ForAgent::from(alice.clone());
        let out = handle_frame_full(&frame, &db, &mut agent).await;
        assert_eq!(out.frames.len(), 1, "one result frame for the whole batch");
        assert_eq!(out.frames[0][0], tag::GET_MANY_RESULT);
        let result = protocol::decode_get_many_result(&out.frames[0][1..]).unwrap();
        assert_eq!(result.request_id, 21);
        assert_eq!(result.frames.len(), 3);

        let first = protocol::decode_update(&result.frames[0][1..]).unwrap();
        assert_eq!(result.frames[0][0], tag::UPDATE);
        assert_eq!(first.subject, drive);
        assert_eq!(first.request_id, 21);
        assert!(!first.loro_bytes.is_empty());

        assert_eq!(
            result.frames[1][0],
            tag::ERROR,
            "a missing subject is an ERROR entry"
        );
        let missing = protocol::decode_error(&result.frames[1][1..]).unwrap();
        assert!(
            missing.message.contains("did:ad:missing"),
            "{}",
            missing.message
        );

        let third = protocol::decode_update(&result.frames[2][1..]).unwrap();
        assert_eq!(third.subject, alice_subject);
    }

    #[tokio::test]
    async fn legacy_filtered_sync_finds_canonical_snapshots() {
        let db = Db::init_temp("legacy_filtered_sync").await.unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();
        let legacy = crate::identifiers::to_legacy_scheme(&drive);
        let filter = std::collections::HashSet::from([legacy.clone()]);
        let frames = handle_sync_vv_filtered(
            &legacy,
            "",
            &[],
            &Default::default(),
            Some(&filter),
            &db,
            &ForAgent::from(alice.clone()),
            WireScheme::LEGACY,
            false,
        )
        .await;
        let diff = protocol::decode_sync_diff(&frames[0][1..]).unwrap();
        assert!(
            diff.push.contains(&legacy),
            "a legacy filtered request must receive the canonical snapshot"
        );
        let agent = ForAgent::from(alice);
        let snapshots =
            collect_readable_snapshots(&db, &agent, std::slice::from_ref(&legacy), None).await;
        assert_eq!(
            snapshots.len(),
            1,
            "legacy pull requests must find canonical snapshots"
        );
        let items = drive_items_for_wire(&db, &drive, &agent, WireScheme::LEGACY)
            .await
            .unwrap();
        assert!(items.iter().all(|(s, _)| !s.starts_with("atomic:")));
        let vv = &items.iter().find(|(s, _)| s == &legacy).unwrap().1;
        let peers: Vec<String> = vv.keys().cloned().collect();
        let counters: Vec<i32> = peers.iter().map(|p| vv[p]).collect();
        let resources = std::collections::HashMap::from([(legacy.clone(), counters)]);
        for filter in [Some(&filter), None] {
            let frames = handle_sync_vv_filtered(
                &legacy,
                "",
                &peers,
                &resources,
                filter,
                &db,
                &agent,
                WireScheme::LEGACY,
                false,
            )
            .await;
            let diff = protocol::decode_sync_diff(&frames[0][1..]).unwrap();
            assert!(
                !diff.pull.contains(&legacy),
                "the same legacy VV must not be treated as missing"
            );
            assert!(
                !diff.push.contains(&legacy),
                "the same legacy VV must not need a snapshot"
            );
        }
    }

    #[tokio::test]
    async fn get_answers_in_the_scheme_the_peer_listed() {
        let db = Db::init_temp("get_wire_scheme").await.unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();
        assert!(drive.starts_with("atomic:"), "{drive}");
        let mut agent = ForAgent::from(alice.clone());

        // Asked with the legacy spelling by a peer that listed no
        // capabilities: answered in the legacy spelling.
        let legacy_drive = crate::identifiers::to_legacy_scheme(&drive);
        let frame = protocol::encode_get(7, &legacy_drive);
        let out = handle_frame_full_for_caps(&frame, &db, &mut agent, WireScheme::LEGACY).await;
        let update = protocol::decode_update(&out.frames[0][1..]).unwrap();
        assert_eq!(out.frames[0][0], tag::UPDATE);
        assert_eq!(update.subject, legacy_drive);
        if let Some(commit_id) = update.commit_id {
            assert!(commit_id.starts_with("did:ad:commit:"), "{commit_id}");
        }

        // The same request from a peer that listed `canonical-scheme`.
        let caps = vec![crate::identifiers::CAP_CANONICAL_SCHEME.to_string()];
        let out =
            handle_frame_full_for_caps(&frame, &db, &mut agent, WireScheme::from_caps(&caps)).await;
        let update = protocol::decode_update(&out.frames[0][1..]).unwrap();
        assert_eq!(update.subject, drive);

        // GET_MANY takes the same path per entry.
        let frame = protocol::encode_get_many(8, &[&drive]);
        let out = handle_frame_full_for_caps(&frame, &db, &mut agent, WireScheme::LEGACY).await;
        let result = protocol::decode_get_many_result(&out.frames[0][1..]).unwrap();
        let first = protocol::decode_update(&result.frames[0][1..]).unwrap();
        assert_eq!(first.subject, legacy_drive);
    }

    #[tokio::test]
    async fn sub_on_a_public_drive_is_a_session_command_not_an_error() {
        let db = Db::init_temp("sub_public").await.unwrap();
        let (_alice, drive) = db.setup("Alice").await.unwrap();
        let mut resource = db.get_resource(&drive.as_str().into()).await.unwrap();
        resource
            .set_unsafe(
                crate::urls::READ.into(),
                crate::Value::ResourceArray(vec![crate::urls::PUBLIC_AGENT.into()]),
            )
            .unwrap();
        db.add_resource_opts(&resource, false, true, true)
            .await
            .unwrap();

        let frame = protocol::encode_sub(&drive);
        let mut agent = ForAgent::Public;
        let out = handle_frame_full(&frame, &db, &mut agent).await;
        assert!(
            out.frames.is_empty(),
            "a granted SUB has no reply on the wire"
        );
        assert_eq!(out.subscribe.as_deref(), Some(drive.as_str()));
        assert!(out.unsubscribe.is_none());
    }

    #[tokio::test]
    async fn sub_without_read_right_is_refused_out_loud() {
        let db = Db::init_temp("sub_denied").await.unwrap();
        let (_alice, drive) = db.setup("Alice").await.unwrap();
        let mallory = db.create_agent(Some("Mallory")).await.unwrap();

        let frame = protocol::encode_sub(&drive);
        let mut agent = ForAgent::AgentSubject(mallory.subject.clone());
        let out = handle_frame_full(&frame, &db, &mut agent).await;
        assert!(out.subscribe.is_none(), "must not ask the hub to register");
        let err = out
            .frames
            .iter()
            .find(|f| f.first() == Some(&tag::ERROR))
            .expect("an unauthorized SUB is answered with ERROR");
        assert_eq!(
            u16::from_be_bytes([err[3], err[4]]),
            error_code::UNAUTHORIZED_READ
        );
        let msg = String::from_utf8_lossy(&err[5..]);
        assert!(msg.contains("SUB refused"), "{msg}");
        assert!(msg.contains(&drive), "{msg}");
    }

    async fn signed_destroy_json(
        db: &Db,
        agent: &crate::agents::Agent,
        subject: &crate::Subject,
    ) -> String {
        let resource = db.get_resource(subject).await.unwrap();
        let mut builder = crate::commit::CommitBuilder::new(subject.clone());
        builder.destroy(true);
        let commit = builder.sign(agent, db, &resource).await.unwrap();
        commit
            .into_resource(db)
            .await
            .unwrap()
            .to_json_ad(None)
            .unwrap()
    }

    async fn secret_child(db: &Db, drive: &str) -> String {
        db.create_resource(
            crate::urls::CLASS,
            drive,
            "Secret Doc",
            Some(vec![
                (
                    crate::urls::DESCRIPTION,
                    crate::Value::String("top secret".into()),
                ),
                (
                    crate::urls::SHORTNAME,
                    crate::Value::Slug("secret-doc".into()),
                ),
            ]),
        )
        .await
        .unwrap()
    }

    fn decode_diff(frames: Vec<Vec<u8>>) -> protocol::DecodedSyncDiff {
        frames
            .into_iter()
            .find(|f| f.first() == Some(&tag::SYNC_DIFF))
            .and_then(|f| protocol::decode_sync_diff(&f[1..]))
            .expect("reconcile answers with a SYNC_DIFF")
    }

    /// A reader who may not write the drive is never asked to push: its
    /// `SYNC_PUSH` would be refused as a whole (`import_sync_push`). Covers
    /// both ways the full reconcile asks for a subject: one the client holds
    /// that the drive tree lacks, and one whose VV matches but whose blob the
    /// server does not have. The owner, on the same state, is still asked.
    #[tokio::test]
    async fn full_sync_asks_only_drive_writers_to_push() {
        let db = Db::init_temp("pull_write_gate").await.unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();
        let bob = db.create_agent(Some("Bob")).await.unwrap();
        let drive_subject = crate::Subject::from_raw(&drive, None);
        let mut drive_res = db.get_resource(&drive_subject).await.unwrap();
        drive_res
            .set_unsafe(
                crate::urls::READ.into(),
                crate::Value::ResourceArray(vec![bob.subject.to_string().into()]),
            )
            .unwrap();
        db.add_resource_opts(&drive_res, false, true, true)
            .await
            .unwrap();

        // A file whose blob this server never received.
        let file = secret_child(&db, &drive).await;
        let file_subject = crate::Subject::from_raw(&file, None);
        let mut file_res = db.get_resource(&file_subject).await.unwrap();
        file_res
            .set_unsafe(
                crate::urls::BLOB.into(),
                crate::Value::String(format!("did:ad:blob:{}", "ab".repeat(32))),
            )
            .unwrap();
        db.add_resource_opts(&file_res, false, true, true)
            .await
            .unwrap();

        let bob_agent = ForAgent::AgentSubject(bob.subject.clone());
        let mut items = drive_items_for(&db, &drive, &bob_agent).await.unwrap();
        assert!(
            items.iter().any(|(s, _)| s == &file_subject.pure_id()),
            "Bob can read the file"
        );
        // Something the client holds that is not in the drive tree.
        items.push((
            "atomic:outside-the-drive".to_string(),
            std::collections::BTreeMap::from([("client-peer".to_string(), 3)]),
        ));
        let mut peers: Vec<String> = items
            .iter()
            .flat_map(|(_, vv)| vv.keys().cloned())
            .collect();
        peers.sort();
        peers.dedup();
        let resources: std::collections::HashMap<String, Vec<i32>> = items
            .iter()
            .map(|(s, vv)| {
                let counters = peers
                    .iter()
                    .map(|p| vv.get(p).copied().unwrap_or(0))
                    .collect();
                (s.clone(), counters)
            })
            .collect();

        let reconcile = |agent: ForAgent| {
            let (drive, peers, resources, db) = (&drive, &peers, &resources, &db);
            async move {
                decode_diff(
                    handle_sync_vv_filtered(
                        drive,
                        "",
                        peers,
                        resources,
                        None,
                        db,
                        &agent,
                        WireScheme::CANONICAL,
                        false,
                    )
                    .await,
                )
            }
        };

        let reader = reconcile(bob_agent.clone()).await;
        assert!(
            reader.pull.is_empty() && reader.pull_from.is_empty(),
            "a read-only session must not be asked to push: {:?}",
            reader.pull
        );

        let owner = reconcile(ForAgent::AgentSubject(alice.subject.clone())).await;
        assert!(
            owner.pull.contains(&file_subject.pure_id()),
            "the owner is asked for the missing blob's file: {:?}",
            owner.pull
        );
        assert!(
            owner.pull.contains(&"atomic:outside-the-drive".to_string()),
            "the owner is asked for what the server lacks: {:?}",
            owner.pull
        );
    }

    /// The destroyed resource is gone, so the only thing left to check the
    /// envelope against is the drive: a session that may not read the
    /// drive gets the subject-only `remove[]` entry and no envelope.
    #[tokio::test]
    async fn sync_diff_envelope_is_only_handed_to_drive_readers() {
        let db = Db::init_temp("envelope_read_gate").await.unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();
        let child = secret_child(&db, &drive).await;
        let subject = crate::Subject::from_raw(&child, None);
        let json = signed_destroy_json(&db, &alice, &subject).await;
        ingest_commit_json(&db, &json, &CommitIngestOpts::peer())
            .await
            .expect("the owner's destroy applies");
        assert!(super::super::tombstones::destroy_envelope(&db, &child).is_some());

        let mut client_resources = std::collections::HashMap::new();
        client_resources.insert(child.clone(), Vec::<i32>::new());

        let public = decode_diff(
            handle_sync_vv_filtered(
                &drive,
                "",
                &[],
                &client_resources,
                None,
                &db,
                &ForAgent::Public,
                WireScheme::CANONICAL,
                false,
            )
            .await,
        );
        assert_eq!(public.remove, vec![child.clone()]);
        assert!(
            public.remove_commits.is_empty(),
            "an anonymous session must not receive the signed destroy envelope"
        );

        let owner = decode_diff(
            handle_sync_vv_filtered(
                &drive,
                "",
                &[],
                &client_resources,
                None,
                &db,
                &ForAgent::AgentSubject(alice.subject.clone()),
                WireScheme::CANONICAL,
                false,
            )
            .await,
        );
        assert!(
            owner.remove_commits.contains_key(&child),
            "a drive reader receives the envelope"
        );
    }

    /// A destroy envelope is durable and re-sent by bulk sync, so a stale
    /// replica can present it again after the subject was legitimately
    /// recreated. The commit is already stored here: refuse it.
    #[tokio::test]
    async fn replayed_destroy_is_refused_after_the_subject_is_recreated() {
        let db = Db::init_temp("destroy_replay_stored").await.unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();
        let subject = crate::Subject::from_raw(&drive, None);
        let json = signed_destroy_json(&db, &alice, &subject).await;

        ingest_commit_json(&db, &json, &CommitIngestOpts::peer())
            .await
            .expect("the first destroy applies");
        assert!(db.get_resource(&subject).await.is_err());

        // The private drive has a deterministic subject: a repeat genesis
        // brings back the very same DID (and clears the tombstone).
        let again = db.ensure_private_drive().await.unwrap();
        assert_eq!(again, drive, "repeat genesis recreates the same subject");
        assert!(db.get_resource(&subject).await.is_ok());

        let err = ingest_commit_json(&db, &json, &CommitIngestOpts::peer())
            .await
            .expect_err("the same envelope must not destroy the recreated drive");
        assert!(err.to_string().contains("already applied"), "{err}");
        assert!(
            db.get_resource(&subject).await.is_ok(),
            "the recreated drive survives the replay"
        );
        assert!(!super::super::tombstones::is_tombstoned(&db, &drive));
    }

    /// A destroy older than the genesis of the resource it names cannot be
    /// about this resource: refuse it even when the commit is unknown here.
    #[tokio::test]
    async fn destroy_predating_the_genesis_is_refused() {
        let db = Db::init_temp("destroy_replay_genesis").await.unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();
        let child = secret_child(&db, &drive).await;
        let subject = crate::Subject::from_raw(&child, None);

        let mut resource = db.get_resource(&subject).await.unwrap();
        resource
            .set_unsafe(
                crate::urls::CREATED_AT.into(),
                crate::Value::Timestamp(crate::utils::now() + 60_000),
            )
            .unwrap();
        db.add_resource_opts(&resource, false, true, true)
            .await
            .unwrap();

        let json = signed_destroy_json(&db, &alice, &subject).await;
        let err = ingest_commit_json(&db, &json, &CommitIngestOpts::peer())
            .await
            .expect_err("a destroy stamped before the genesis is a replay");
        assert!(err.to_string().contains("predates"), "{err}");
        assert!(db.get_resource(&subject).await.is_ok());
        assert!(!super::super::tombstones::is_tombstoned(&db, &child));
    }

    async fn signed_rename_json(
        db: &Db,
        agent: &crate::agents::Agent,
        subject: &crate::Subject,
    ) -> String {
        let resource = db.get_resource(subject).await.unwrap();
        let mut builder = crate::commit::CommitBuilder::new(subject.clone());
        builder.set(
            crate::urls::NAME.into(),
            crate::Value::String(format!("renamed by {}", agent.subject)),
        );
        let commit = builder.sign(agent, db, &resource).await.unwrap();
        commit
            .into_resource(db)
            .await
            .unwrap()
            .to_json_ad(None)
            .unwrap()
    }

    /// The signer's Agent resource is materialized only for a commit that
    /// was accepted. A refused commit from a key nobody here has seen must
    /// not leave a durable resource behind (C7).
    #[tokio::test]
    async fn signer_agent_is_only_created_for_an_accepted_commit() {
        let db = Db::init_temp("agent_after_accept").await.unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();
        let child = secret_child(&db, &drive).await;
        let subject = crate::Subject::from_raw(&child, None);

        let stranger = crate::agents::Agent::new(Some("Stranger")).unwrap();
        let json = signed_rename_json(&db, &stranger, &subject).await;
        ingest_commit_json(&db, &json, &CommitIngestOpts::peer())
            .await
            .expect_err("a stranger may not edit Alice's document");
        // `Db::get_resource` synthesizes a minimal Agent for any unknown
        // `did:ad:agent:` subject, so ask the KV, not the resolver.
        assert!(
            !db.has_resource_locally(&stranger.subject.pure_id()),
            "a refused commit must not store the signer's Agent resource"
        );

        // Bob is granted write on the drive; his first accepted commit
        // brings his Agent resource into being.
        let bob = crate::agents::Agent::new(Some("Bob")).unwrap();
        let drive_subject = crate::Subject::from_raw(&drive, None);
        let mut drive_res = db.get_resource(&drive_subject).await.unwrap();
        drive_res
            .set_unsafe(
                crate::urls::WRITE.into(),
                crate::Value::ResourceArray(vec![
                    alice.subject.to_string().into(),
                    bob.subject.to_string().into(),
                ]),
            )
            .unwrap();
        db.add_resource_opts(&drive_res, false, true, true)
            .await
            .unwrap();
        assert!(!db.has_resource_locally(&bob.subject.pure_id()));

        let json = signed_rename_json(&db, &bob, &subject).await;
        ingest_commit_json(&db, &json, &CommitIngestOpts::peer())
            .await
            .expect("a drive writer's commit applies");
        let renamed = db.get_resource(&subject).await.unwrap();
        assert!(
            renamed
                .get(crate::urls::NAME)
                .unwrap()
                .to_string()
                .contains("Bob")
                || renamed
                    .get(crate::urls::NAME)
                    .unwrap()
                    .to_string()
                    .contains(&bob.subject.to_string()),
            "Bob's accepted commit lands"
        );
    }

    #[tokio::test]
    async fn unsub_is_a_session_command() {
        let db = Db::init_temp("unsub_cmd").await.unwrap();
        let frame = protocol::encode_unsub("did:ad:whatever");
        let mut agent = ForAgent::Public;
        let out = handle_frame_full(&frame, &db, &mut agent).await;
        assert!(out.frames.is_empty());
        assert_eq!(out.unsubscribe.as_deref(), Some("did:ad:whatever"));
    }
}
