//! The actor messages are used for communication between Actix Actors.
//! In this case it's for communication between the CommitMonitor and the WebSocketConnection.

use actix::{prelude::Message, Addr};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// An `AUTH` on a connection changed its identity. The commit monitor
/// re-evaluates every subscription the connection holds against the new
/// agent and drops the ones it may no longer read; the ones it keeps are
/// re-bound to the new agent. Sent by the WebSocket actor only when the
/// identity actually changed.
#[derive(Message)]
#[rtype(result = "()")]
pub struct RebindAgent {
    pub addr: Addr<crate::handlers::web_sockets::WebSocketConnection>,
    /// The new identity as a subject string (`ForAgent`'s `Display`).
    pub agent: String,
}

/// A message containing a Resource, which should be sent to subscribers
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct CommitMessage {
    /// Full resource of the Commit itself, the new resource, and the old one
    pub commit_response: atomic_lib::commit::CommitResponse,
}

// === Loro CRDT Sync Messages ===

#[derive(Deserialize, Serialize)]
pub struct LoroSubscriptionJSON {
    pub subject: atomic_lib::Subject,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct SubscribeLoroSync {
    pub addr: Addr<crate::handlers::web_sockets::WebSocketConnection>,
    pub subject: atomic_lib::Subject,
    pub agent: String,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct UnsubscribeLoroSync {
    pub addr: Addr<crate::handlers::web_sockets::WebSocketConnection>,
    pub subject: atomic_lib::Subject,
}

/// A Loro CRDT document update for real-time sync (not persisted): the
/// `EPHEMERAL (0x40)` frame of kind `DOC`, on its way between a websocket
/// and the broadcaster. `update` is the raw Loro bytes off the wire;
/// `agent` is the identity the server verified for the sender (a peer's
/// frame carries the agent the relaying node verified).
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct LoroSyncUpdate {
    pub subject: atomic_lib::Subject,
    pub agent: String,
    pub update: Vec<u8>,
    pub addr: Option<Addr<crate::handlers::web_sockets::WebSocketConnection>>,
}

/// A Loro ephemeral update (cursors, presence) — not persisted. The
/// `EPHEMERAL (0x40)` frame of kind `LORO`; fields as [`LoroSyncUpdate`].
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct LoroEphemeralUpdate {
    pub subject: atomic_lib::Subject,
    pub agent: String,
    pub update: Vec<u8>,
    pub addr: Option<Addr<crate::handlers::web_sockets::WebSocketConnection>>,
}

// === Drive presence messages ===
//
// Ephemeral "who is where" state for a whole drive (issue #1229). Like the
// Loro ephemeral channel above, payloads are opaque Loro EphemeralStore
// bytes that the server relays without inspecting — but the subscription is
// keyed by *drive*, not by resource, and the broadcaster caches each
// connection's latest state so late joiners see who's present immediately.

/// Subscribe a connection to the ephemeral presence channel of a drive.
/// Requires read access on the drive resource.
#[derive(Message)]
#[rtype(result = "()")]
pub struct SubscribePresence {
    pub addr: Addr<crate::handlers::web_sockets::WebSocketConnection>,
    pub drive: atomic_lib::Subject,
    pub agent: String,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct UnsubscribePresence {
    pub addr: Addr<crate::handlers::web_sockets::WebSocketConnection>,
    pub drive: atomic_lib::Subject,
}

/// A drive-scoped presence update — not persisted. The `EPHEMERAL (0x40)`
/// frame of kind `PRESENCE`. `update` carries the sender's full
/// `EphemeralStore.encodeAll()` bytes so the broadcaster can cache it per
/// connection and replay it to newcomers. The field is named `subject`
/// (holding the drive) like the two Loro messages above.
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct PresenceUpdate {
    pub subject: atomic_lib::Subject,
    pub agent: String,
    pub update: Vec<u8>,
    pub addr: Option<Addr<crate::handlers::web_sockets::WebSocketConnection>>,
}

/// Drive presence that arrived from a PEER, not from a local websocket.
///
/// Distinct from [`PresenceUpdate`] because that one is gated on the sender
/// being a subscriber — which is where the drive read-access check happens for
/// local clients, and is exactly the gate that should NOT be faked for relayed
/// traffic. A peer's presence has already passed its own read check in the sync
/// read loop, and there is no local connection to attribute it to, so it fans
/// out to every subscriber with nobody to exclude.
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct RemotePresenceUpdate {
    pub subject: atomic_lib::Subject,
    pub agent: String,
    pub update: Vec<u8>,
}

/// The `SUB <subject>` frame: subscribe this connection to a subject. For a
/// drive that means every commit under it plus the drive resource itself;
/// for any other resource, that one subject. The commit monitor decides
/// which by looking at the resource (`Handler<Subscribe>`).
#[derive(Message)]
#[rtype(result = "()")]
pub struct Subscribe {
    pub addr: Addr<crate::handlers::web_sockets::WebSocketConnection>,
    /// The subject as it came off the wire (HTTP URL or DID). Drive
    /// fan-out is keyed by this raw string, so `UNSUB` must send the same.
    pub subject: String,
    pub agent: String,
    /// Identifier of the originating WS connection. The commit monitor
    /// stores this alongside the subscriber address and skips broadcasts
    /// to subscribers whose `source_id` matches an event's `source_id`,
    /// so a client never receives its own commit back.
    pub source_id: String,
}

/// The `UNSUB <subject>` frame: cancel a [`Subscribe`]. Removes this
/// connection from the drive fan-out set and from the per-resource
/// subscription. No answer frame: an `UNSUB` for a subject the connection
/// never subscribed is a no-op.
#[derive(Message)]
#[rtype(result = "()")]
pub struct Unsubscribe {
    pub addr: Addr<crate::handlers::web_sockets::WebSocketConnection>,
    /// The subject, as passed to `Subscribe::subject`.
    pub subject: String,
}

/// Sent by `WebSocketConnection::stopped` to the commit monitor. The handler
/// walks every subscription map (resource, drive, Loro ephemera, presence)
/// and removes every entry whose `Addr` matches. Without this, stale entries
/// accumulate over the server's lifetime and every fanout pass pays for
/// dead `Addr`s.
#[derive(Message)]
#[rtype(result = "()")]
pub struct UnsubscribeAll {
    pub addr: Addr<crate::handlers::web_sockets::WebSocketConnection>,
}

/// Pre-encoded wire frame (`UPDATE` or `DESTROY`) ready for `ctx.binary`.
///
/// Sent by `CommitMonitor`'s fanout: the frame is encoded **once** from
/// the `CommitMessage`, wrapped in an `Arc`, then dispatched to every
/// subscriber. Each `do_send` clones only the `Arc` pointer (O(1))
/// instead of cloning the full `CommitMessage` (which would re-clone the
/// Loro update bytes per subscriber). See
/// `planning/arc-actor-message-payloads.md` for the perf rationale.
#[derive(Message, Clone)]
#[rtype(result = "()")]
pub struct SendFrame {
    pub frame: Arc<[u8]>,
}

/// Tell a connection that a subscription it asked for was refused, as an
/// `ERROR` frame (`request_id = 0`,
/// [`atomic_lib::sync::protocol::error_code::UNAUTHORIZED_READ`]). Every
/// subscription handler used to drop a failed `check_read` on the floor, so
/// a client could not tell "subscribed, nothing has changed yet" from
/// "never subscribed" — the same silence `SYNC_OK`-on-rejection produced
/// for pushes. Sent from the actor that made the decision, since the
/// connection actor fired the request off with `do_send` and is not
/// waiting on a reply.
pub fn refuse_subscription(
    addr: &Addr<crate::handlers::web_sockets::WebSocketConnection>,
    what: &str,
    subject: &str,
    reason: &str,
) {
    let frame = atomic_lib::sync::protocol::encode_error(
        0,
        atomic_lib::sync::protocol::error_code::UNAUTHORIZED_READ,
        &format!("{what} refused for {subject}: {reason}"),
    );
    addr.do_send(SendFrame {
        frame: Arc::from(frame),
    });
}

/// Forwarded into `CommitMonitor` by the `DbEvent` listener task: a resource
/// changed *without* an applied commit, so `handle_commit` never ran and
/// nothing has told the subscribed clients.
///
/// That is how a peer's data arrives — a live `UPDATE` frame or a bulk
/// `SYNC_PUSH` import writes raw CRDT state straight into the store. Before
/// this existed, the second device held the new data on disk and went on
/// rendering the old, until it was restarted.
///
/// The snapshot and `commit_id` are pre-fetched off-actor, so the fanout loop
/// stays O(1) per subscriber.
#[derive(Message, Clone)]
#[rtype(result = "()")]
pub struct ExternalChange {
    /// Subject that changed, resolved against the base domain.
    pub subject: String,
    /// The subject's drive, used to route drive-wide subscribers. `None` keeps
    /// the change away from every drive subscriber rather than fanning blindly.
    pub drive: Option<atomic_lib::Subject>,
    /// Full Loro state. `None` for a destroy.
    pub loro_snapshot: Option<Arc<[u8]>>,
    /// The resource's `lastCommit`, when it has one.
    pub commit_id: Option<String>,
    /// True when the resource was destroyed rather than updated.
    pub destroyed: bool,
    /// Source connection id for echo suppression.
    pub source_id: Option<String>,
}
