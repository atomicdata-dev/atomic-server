//! The Commit Monitor checks for new commits and notifies listeners.
//! It is used for WebSockets to notify front-end clients of changes in Resources,
//! and to flush the vector search index.

use crate::{
    actor_messages::{
        CommitMessage, ExternalChange, LoroEphemeralUpdate, LoroSyncUpdate, PresenceUpdate,
        RebindAgent, RemotePresenceUpdate, SendFrame, Subscribe, SubscribeLoroSync,
        SubscribePresence, Unsubscribe, UnsubscribeAll, UnsubscribeLoroSync, UnsubscribePresence,
    },
    handlers::{web_sockets::WebSocketConnection, ws_v2},
    vector_search::VectorSearchState,
};
use actix::{
    prelude::{Actor, AsyncContext, Context, Handler},
    ActorFutureExt, Addr, ResponseActFuture, WrapFuture,
};
use atomic_lib::{agents::ForAgent, Db, DbEvent, Storelike};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// One connection's registration on a subject, drive or filter.
#[derive(Debug, Clone)]
pub struct Subscriber {
    /// Connection id; a change this connection originated is not echoed back
    /// to it (see [`skip_same_source`]).
    source_id: String,
    /// The identity the subscription was admitted under, as a subject
    /// string. Kept so [`Handler<RebindAgent>`] can re-evaluate the
    /// registration when the connection's `AUTH` changes it.
    agent: String,
}

type Subscribers = HashMap<Addr<WebSocketConnection>, Subscriber>;

#[derive(Eq, Hash, PartialEq, Clone)]
struct LoroSubscriber {
    addr: Addr<WebSocketConnection>,
    can_write: bool,
}

/// One connection's latest presence, as replayed to a late joiner.
#[derive(Clone)]
struct CachedPresence {
    agent: String,
    update: Vec<u8>,
}

/// The Commit Monitor is an Actor that manages subscriptions for subjects and sends Commits to listeners.
/// It's also responsible for checking whether the rights are present.
///
/// Two subscription maps, both fed by the one `SUB <subject>` frame
/// (`Handler<Subscribe>`):
///
/// - **Resource subscriptions** (`subscriptions`): one subject each. Match
///   commits whose target matches exactly. The `CommitMessage` handler scans
///   this map directly.
/// - **Drive subscriptions** (`drive_subscriptions`): a `SUB` whose subject
///   is a drive. Match every commit on resources that belong to that drive —
///   a resource's owning drive is its genesis-stamped `drive` propval (DID
///   subjects) or its own URL under the drive (HTTP subjects), tested via
///   [`atomic_lib::Subject::is_within_drive`]. A commit only ever reaches
///   subscribers of its OWN drive — never others (no cross-drive leak).
///   Subscribers receive a `SendFrame` carrying the pre-encoded `UPDATE` /
///   `DESTROY` wire bytes, encoded once at the fanout site and Arc-shared.
///
/// The same actor also owns the non-persisted realtime channel that used
/// to live on `LoroSyncBroadcaster`: Loro doc/cursor ephemera (keyed by
/// resource) and drive presence (keyed by drive). One mailbox, one
/// `UnsubscribeAll` on socket close.
#[allow(clippy::mutable_key_type)]
pub struct CommitMonitor {
    /// Maintains a list of all the resources that are being subscribed to, and maps these to websocket connections.
    /// Inner map: subscriber `Addr` → [`Subscriber`] (its `source_id` is used
    /// to suppress broadcasts back to the connection that originated the change).
    subscriptions: HashMap<atomic_lib::Subject, Subscribers>,
    /// Drive-wide subscriptions: keyed by drive subject string.
    drive_subscriptions: HashMap<String, Subscribers>,
    /// Real-time Loro doc + cursor subscriptions, keyed by resource subject.
    /// Not persisted; write access is recorded so only a writer can inject
    /// a `DOC` update.
    loro_subscriptions: HashMap<atomic_lib::Subject, HashSet<LoroSubscriber>>,
    /// Drive-scoped presence: each connection's latest payload, replayed
    /// to late joiners at subscribe time.
    #[allow(clippy::mutable_key_type)]
    presence:
        HashMap<atomic_lib::Subject, HashMap<Addr<WebSocketConnection>, Option<CachedPresence>>>,
    store: Db,
    vector_search_state: VectorSearchState,
    /// Set by every commit handler that may have queued a vector-index
    /// write. A standalone `tokio::spawn` task drains this flag and
    /// calls `flush_pending()`. The actor itself never owns the flush —
    /// that decoupling matters because the actor mailbox is shared with
    /// `CommitMessage` / `Subscribe` / drive-broadcast notifications.
    pending_commit: Arc<AtomicBool>,
}

const DEFAULT_REBUILD_INDEX_MS: u64 = 5000;

/// Vector-index flush cadence. Defaults to 5s.
/// `ATOMIC_SEARCH_INDEX_INTERVAL_MS` can lower it for tests.
fn rebuild_index_interval() -> std::time::Duration {
    let ms = std::env::var("ATOMIC_SEARCH_INDEX_INTERVAL_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .unwrap_or(DEFAULT_REBUILD_INDEX_MS);

    std::time::Duration::from_millis(ms)
}

// Since his Actor only starts once, there is no need to handle its lifecycle
impl Actor for CommitMonitor {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        tracing::debug!("CommitMonitor started");
        if tokio::runtime::Handle::try_current().is_ok() {
            // Vector-index flush runs OFF the actor on its own tokio task.
            let flag = self.pending_commit.clone();
            let vector_search_state = self.vector_search_state.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(rebuild_index_interval());
                // `interval.tick()` returns immediately on first call;
                // skip it so we don't flush at boot.
                interval.tick().await;
                loop {
                    interval.tick().await;
                    if !flag.swap(false, Ordering::AcqRel) {
                        continue;
                    }
                    if let Err(e) = vector_search_state.flush_pending().await {
                        tracing::error!("Vector index periodic flush failed: {}", e);
                        flag.store(true, Ordering::Release);
                    }
                }
            });

            // Bridge DbEvents to actor messages. Commits already route
            // through `Handler<CommitMessage>` (set via `set_handle_commit`
            // in `appstate.rs`); what this listener carries is the
            // commit-less change (a peer sync writing straight into the
            // store) that would otherwise never reach a subscriber.
            let mut events_rx = self.store.subscribe_events();
            let addr = ctx.address();
            let store_for_listener = self.store.clone();
            tokio::spawn(async move {
                while let Ok(event) = events_rx.recv().await {
                    // Changes that no commit produced. `handle_commit` — the
                    // usual route from "the store moved" to "tell the clients"
                    // — never runs for these, so without this arm a device that
                    // receives a peer's data holds it on disk and keeps
                    // rendering what it had before.
                    match &event {
                        DbEvent::Changed {
                            subject,
                            source_id,
                            from_commit: false,
                            ..
                        } => {
                            if let Some(msg) =
                                external_change(&store_for_listener, subject, source_id.clone())
                                    .await
                            {
                                addr.do_send(msg);
                            }
                            continue;
                        }
                        DbEvent::Destroyed {
                            subject,
                            drive,
                            source_id,
                            from_commit: false,
                            ..
                        } => {
                            addr.do_send(ExternalChange {
                                subject: subject.to_string(),
                                // Without this the removal reaches only
                                // subscribers of the subject itself, and the
                                // client subscribes per drive — so a
                                // cascade-deleted child was announced to
                                // nobody and stayed in every open tab, and in
                                // the local database across a reload.
                                drive: drive.clone(),
                                loro_snapshot: None,
                                commit_id: None,
                                destroyed: true,
                                source_id: source_id.clone(),
                            });
                            continue;
                        }
                        _ => {}
                    }
                }
            });
        } else {
            tracing::warn!("No Tokio runtime available; skipping CommitMonitor interval");
        }
    }
}

impl Handler<Subscribe> for CommitMonitor {
    type Result = ResponseActFuture<Self, ()>;

    /// The one registration frame, `SUB <subject>`. Auth gate: the agent must
    /// have read access on the subject. What gets registered depends on what
    /// the subject is:
    ///
    /// - a **drive** (`isA` includes `Drive`): the connection joins
    ///   `drive_subscriptions` so [`Handler<CommitMessage>`] fans every
    ///   commit under the drive to it, *and* `subscriptions` for the drive
    ///   resource itself (renames, ACL edits), which a DID drive subject
    ///   would otherwise never prefix-match;
    /// - anything else: `subscriptions` for that one subject.
    ///
    /// Until 2026-09-04 the second case was a separate text frame
    /// (`SUBSCRIBE <subject>`) with its own actor message and handler, and a
    /// `SUB` on a non-drive subject registered a drive fan-out entry that
    /// delivered every commit twice for URL subjects.
    #[tracing::instrument(
        name = "handle_subscribe",
        skip_all,
        fields(subject = %msg.subject, agent = %msg.agent)
    )]
    fn handle(&mut self, msg: Subscribe, _ctx: &mut Context<Self>) -> Self::Result {
        let store = self.store.clone();
        Box::pin(
            async move {
                let subject =
                    atomic_lib::Subject::from_raw(&msg.subject, store.get_base_domain().as_deref());
                if !subject.is_local() {
                    tracing::warn!("can't subscribe to external resource: {subject}");
                    return None;
                }
                let resource = match store.get_resource(&subject).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!("Subscribe: {subject} not found: {e}");
                        // Same frame as a rights failure: whether the subject
                        // is unreadable or absent is not something an agent
                        // without read rights gets to learn here, any more
                        // than a GET would tell it.
                        crate::actor_messages::refuse_subscription(
                            &msg.addr,
                            "SUB",
                            &subject.to_string(),
                            "not readable",
                        );
                        return None;
                    }
                };
                if let Err(e) = atomic_lib::hierarchy::check_read(
                    &store,
                    &resource,
                    &ForAgent::from(msg.agent.clone()),
                )
                .await
                {
                    tracing::debug!("Subscribe: {} cannot read {subject}: {e}", msg.agent);
                    crate::actor_messages::refuse_subscription(
                        &msg.addr,
                        "SUB",
                        &subject.to_string(),
                        &e.to_string(),
                    );
                    return None;
                }
                let is_drive = resource
                    .get(atomic_lib::urls::IS_A)
                    .ok()
                    .and_then(|classes| classes.to_subjects(None).ok())
                    .is_some_and(|classes| classes.iter().any(|c| c == atomic_lib::urls::DRIVE));
                Some((msg, subject, is_drive))
            }
            .into_actor(self)
            .map(|admitted, actor, _ctx| {
                #[allow(clippy::mutable_key_type)]
                if let Some((msg, subject, is_drive)) = admitted {
                    let subscriber = Subscriber {
                        source_id: msg.source_id,
                        agent: msg.agent,
                    };
                    if is_drive {
                        actor
                            .drive_subscriptions
                            .entry(msg.subject)
                            .or_default()
                            .insert(msg.addr.clone(), subscriber.clone());
                    }
                    actor
                        .subscriptions
                        .entry(subject)
                        .or_default()
                        .insert(msg.addr, subscriber);
                }
            }),
        )
    }
}

impl Handler<Unsubscribe> for CommitMonitor {
    type Result = ();

    /// The inverse of [`Handler<Subscribe>`] (`UNSUB <subject>`): drops both
    /// the drive fan-out entry (keyed by the raw subject string `SUB`
    /// registered under) and the per-resource entry. Until 2026-09 the
    /// `UNSUB` frame only edited a set on the connection actor that nothing
    /// read, so the fan-out kept firing for the life of the socket.
    #[allow(clippy::mutable_key_type)]
    fn handle(&mut self, msg: Unsubscribe, _ctx: &mut Context<Self>) {
        if let Some(subs) = self.drive_subscriptions.get_mut(&msg.subject) {
            subs.remove(&msg.addr);
            if subs.is_empty() {
                self.drive_subscriptions.remove(&msg.subject);
            }
        }
        let subject =
            atomic_lib::Subject::from_raw(&msg.subject, self.store.get_base_domain().as_deref());
        if let Some(subs) = self.subscriptions.get_mut(&subject) {
            subs.remove(&msg.addr);
            if subs.is_empty() {
                self.subscriptions.remove(&subject);
            }
        }
    }
}

/// True iff a `DbEvent`/`CommitResponse` with `event_source` should NOT be
/// delivered to a subscriber registered with `subscriber_source`. Same
/// connection on both sides means the client originated this change and
/// already has it locally — sending it back is the self-echo we want to
/// suppress. Missing event source (`None`) means a non-WS origin (HTTP
/// commit, internal write) and we deliver to everyone.
fn skip_same_source(event_source: Option<&str>, subscriber_source: &str) -> bool {
    event_source.is_some_and(|s| s == subscriber_source)
}

impl Handler<UnsubscribeAll> for CommitMonitor {
    type Result = ();

    /// Sent on WebSocket close: remove this connection from every map so
    /// future fanouts don't iterate over a dead `Addr`. Without it, every
    /// reconnect leaks an entry per subscription primitive used.
    #[allow(clippy::mutable_key_type)]
    fn handle(&mut self, msg: UnsubscribeAll, _ctx: &mut Context<Self>) {
        for conns in self.subscriptions.values_mut() {
            conns.remove(&msg.addr);
        }
        self.subscriptions.retain(|_, conns| !conns.is_empty());

        for conns in self.drive_subscriptions.values_mut() {
            conns.remove(&msg.addr);
        }
        self.drive_subscriptions
            .retain(|_, conns| !conns.is_empty());

        for subscribers in self.loro_subscriptions.values_mut() {
            subscribers.retain(|s| s.addr != msg.addr);
        }
        self.loro_subscriptions
            .retain(|_, subscribers| !subscribers.is_empty());

        for subscribers in self.presence.values_mut() {
            subscribers.remove(&msg.addr);
        }
        self.presence
            .retain(|_, subscribers| !subscribers.is_empty());
    }
}

/// Gather what a subscriber needs to render a change that arrived without a
/// commit: the resource's full Loro state (there is no delta to send — the
/// writer had none), its `lastCommit`, and the drive it belongs to.
///
/// Returns `None` when there is no state worth sending; the client can still
/// GET the subject explicitly.
async fn external_change(
    store: &Db,
    subject: &atomic_lib::Subject,
    source_id: Option<String>,
) -> Option<ExternalChange> {
    let snapshot = store
        .kv
        .get(
            atomic_lib::db::trees::Tree::LoroSnapshots,
            subject.pure_id().as_bytes(),
        )
        .ok()
        .flatten()
        .filter(|bytes| !bytes.is_empty())?;

    // Present locally by construction — this event fired because it was just
    // written — so this reads the store rather than reaching for the network.
    let resource = store.get_resource(subject).await.ok();
    let commit_id = resource
        .as_ref()
        .and_then(|r| r.get(atomic_lib::urls::LAST_COMMIT).ok())
        .map(|v| v.to_string())
        .filter(|s| !s.is_empty());

    Some(ExternalChange {
        subject: subject.to_string(),
        drive: resource.as_ref().and_then(|r| r.get_drive()),
        loro_snapshot: Some(Arc::from(snapshot.into_boxed_slice())),
        commit_id,
        destroyed: false,
        source_id,
    })
}

impl Handler<ExternalChange> for CommitMonitor {
    type Result = ();

    /// Fan a commit-less change out to the subject's subscribers and to the
    /// subscribers of its drive — the same two audiences, and the same
    /// drive-boundary check, that `Handler<CommitMessage>` serves.
    fn handle(&mut self, msg: ExternalChange, _ctx: &mut Context<Self>) {
        let base_domain = self.store.get_base_domain();
        let subject = atomic_lib::Subject::from_raw(&msg.subject, base_domain.as_deref());

        // `external_change` reads the payload straight out of
        // `Tree::LoroSnapshots`: full state, so a SNAPSHOT.
        let change = if msg.destroyed {
            ws_v2::Change::Destroyed
        } else {
            let Some(snapshot) = msg.loro_snapshot.as_ref() else {
                return;
            };
            ws_v2::Change::Snapshot {
                bytes: snapshot,
                commit_id: msg.commit_id.as_deref(),
            }
        };
        let frame = ws_v2::encode_change_frame(&self.store, &subject, change);

        let source = msg.source_id.as_deref();

        if let Some(subscribers) = self.subscriptions.get(&subject) {
            for (connection, subscriber) in subscribers {
                if skip_same_source(source, &subscriber.source_id) {
                    continue;
                }
                connection.do_send(SendFrame {
                    frame: frame.clone(),
                });
            }
        }

        // A resource belongs to exactly one drive; a change must only reach
        // that drive's subscribers. No drive, no drive-wide fanout — never a
        // blind broadcast (see `Handler<CommitMessage>`).
        let Some(owner) = msg.drive.as_ref() else {
            return;
        };

        for (drive, subscribers) in &self.drive_subscriptions {
            let drive_subject = atomic_lib::Subject::from_raw(drive, base_domain.as_deref());
            if !owner.is_within_drive(&drive_subject) {
                continue;
            }
            for (connection, subscriber) in subscribers {
                if skip_same_source(source, &subscriber.source_id) {
                    continue;
                }
                connection.do_send(SendFrame {
                    frame: frame.clone(),
                });
            }
        }
    }
}

/// What one connection holds in one of the two subscription maps, for
/// [`Handler<RebindAgent>`]. Carries the map key so the verdict can be
/// applied after the async read checks come back.
enum Held {
    Subject(atomic_lib::Subject),
    Drive(String),
}

/// Apply a re-evaluation verdict to one registration: keep it under the
/// new agent, or drop it (and the key, if that emptied it). Returns whether
/// something was dropped.
#[allow(clippy::mutable_key_type)]
fn rebind_one<K: std::hash::Hash + Eq>(
    map: &mut HashMap<K, Subscribers>,
    key: &K,
    addr: &Addr<WebSocketConnection>,
    agent: &str,
    readable: bool,
) -> bool {
    let Some(subs) = map.get_mut(key) else {
        return false;
    };
    if readable {
        if let Some(sub) = subs.get_mut(addr) {
            sub.agent = agent.to_string();
        }
        return false;
    }
    let dropped = subs.remove(addr).is_some();
    if subs.is_empty() {
        map.remove(key);
    }
    dropped
}

impl Handler<RebindAgent> for CommitMonitor {
    type Result = ResponseActFuture<Self, ()>;

    /// A connection's identity changed (an `AUTH` landed, or a different
    /// agent authenticated on an already-authenticated socket). Until
    /// 2026-09 the agent a subscription was admitted under was checked once
    /// and then forgotten, so a `SUB` accepted as Alice kept delivering
    /// after the socket re-authenticated as Mallory. Every registration this
    /// connection holds is re-checked against the new identity: readable
    /// ones are re-bound to it, the rest are dropped silently (the client
    /// that switched agents re-subscribes on its own, and gets the refusal
    /// then).
    #[allow(clippy::mutable_key_type)]
    fn handle(&mut self, msg: RebindAgent, _ctx: &mut Context<Self>) -> Self::Result {
        let base_domain = self.store.get_base_domain();
        let mut checks: Vec<(Held, atomic_lib::Subject)> = Vec::new();
        for (subject, subs) in &self.subscriptions {
            if subs.contains_key(&msg.addr) {
                checks.push((Held::Subject(subject.clone()), subject.clone()));
            }
        }
        for (drive, subs) in &self.drive_subscriptions {
            if subs.contains_key(&msg.addr) {
                checks.push((
                    Held::Drive(drive.clone()),
                    atomic_lib::Subject::from_raw(drive, base_domain.as_deref()),
                ));
            }
        }
        if checks.is_empty() {
            return Box::pin(async {}.into_actor(self));
        }

        let store = self.store.clone();
        let agent = msg.agent.clone();
        let addr = msg.addr;
        Box::pin(
            async move {
                let for_agent = ForAgent::from(agent.clone());
                let mut verdicts = Vec::with_capacity(checks.len());
                for (held, target) in checks {
                    let readable = match store.get_resource(&target).await {
                        Ok(resource) => {
                            atomic_lib::hierarchy::check_read(&store, &resource, &for_agent)
                                .await
                                .is_ok()
                        }
                        Err(_) => false,
                    };
                    verdicts.push((held, readable));
                }
                (verdicts, agent, addr)
            }
            .into_actor(self)
            .map(|(verdicts, agent, addr), actor, _ctx| {
                let mut dropped = 0usize;
                for (held, readable) in verdicts {
                    let was_dropped = match held {
                        Held::Subject(subject) => {
                            rebind_one(&mut actor.subscriptions, &subject, &addr, &agent, readable)
                        }
                        Held::Drive(drive) => rebind_one(
                            &mut actor.drive_subscriptions,
                            &drive,
                            &addr,
                            &agent,
                            readable,
                        ),
                    };
                    if was_dropped {
                        dropped += 1;
                    }
                }
                if dropped > 0 {
                    tracing::debug!(
                        agent = %agent,
                        dropped,
                        "rebind: dropped subscriptions the new identity cannot read"
                    );
                }
            }),
        )
    }
}

impl Handler<CommitMessage> for CommitMonitor {
    type Result = ResponseActFuture<Self, ()>;

    #[tracing::instrument(name = "handle_commit_message", skip_all, fields(subscriptions = &self.subscriptions.len(), s = %msg.commit_response.commit_resource.get_subject()))]
    fn handle(&mut self, msg: CommitMessage, _: &mut Context<Self>) -> Self::Result {
        // Normalize the subject using the base domain so it matches subscriptions
        let target_subject = atomic_lib::Subject::from_raw(
            msg.commit_response.commit.subject.as_str(),
            self.store.get_base_domain().as_deref(),
        );

        let event_source = msg.commit_response.source_id.as_deref();

        // Encode the wire frame ONCE up front, wrap in `Arc`. Each
        // subscriber `do_send` then clones only the Arc pointer (O(1))
        // instead of cloning the full `CommitMessage` and re-encoding
        // per-connection.
        let frame = encode_commit_frame(&self.store, &msg);

        if let Some(frame) = frame.as_ref() {
            // Per-resource subscribers
            if let Some(subscribers) = self.subscriptions.get(&target_subject) {
                tracing::debug!(
                    "Sending commit {} to {} subscribers",
                    target_subject,
                    subscribers.len()
                );
                for (connection, subscriber) in subscribers {
                    if skip_same_source(event_source, &subscriber.source_id) {
                        continue;
                    }
                    connection.do_send(SendFrame {
                        frame: frame.clone(),
                    });
                }
            } else {
                tracing::debug!("No subscribers for {}", target_subject);
            }

            // Drive-wide subscribers. A resource belongs to exactly ONE drive,
            // and a commit must only ever reach subscribers of THAT drive —
            // never others. Fanning a `did:ad:` commit out to every drive
            // subscriber leaks it to agents with no rights on it (a
            // cross-tenant security hole).
            //
            // We test membership via the resource's OWNING subject: for a DID
            // resource that's its `drive` propval (stamped at genesis); for a
            // URL resource with no such propval it's the subject itself, which
            // lives under its drive's URL. `Subject::is_within_drive` then does
            // the identity / path-boundary check. A DID resource with no drive
            // propval reaches no drive subscriber rather than fanning out
            // blindly.
            let base_domain = self.store.get_base_domain();
            let resource_drive = msg
                .commit_response
                .resource_new
                .as_ref()
                .and_then(|r| r.get_drive());
            let owner = resource_drive.as_ref().unwrap_or(&target_subject);
            for (drive, subscribers) in &self.drive_subscriptions {
                let drive_subject = atomic_lib::Subject::from_raw(drive, base_domain.as_deref());
                if !owner.is_within_drive(&drive_subject) {
                    continue;
                }
                for (connection, subscriber) in subscribers {
                    if skip_same_source(event_source, &subscriber.source_id) {
                        continue;
                    }
                    connection.do_send(SendFrame {
                        frame: frame.clone(),
                    });
                }
            }
        }

        let store = self.store.clone();
        let vector_search_state = self.vector_search_state.clone();
        let resource_old = msg.commit_response.resource_old.clone();
        let resource_new = msg.commit_response.resource_new.clone();
        let target_str = target_subject.to_string();

        Box::pin(
            async move {
                // Skip vector re-indexing when only non-text properties changed (e.g. parent adding
                // a child to its subResources array). If the indexable text content is identical,
                // neither a remove nor an add is needed — the existing vector entry is still correct.
                // This is important for performance!
                let vector_text_unchanged = resource_old
                    .as_ref()
                    .zip(resource_new.as_ref())
                    .is_some_and(|(old, new)| {
                        crate::vector_search::get_resource_text_parts(old)
                            == crate::vector_search::get_resource_text_parts(new)
                    });

                if let Some(resource) = resource_new.as_ref() {
                    if let Ok(classes) = resource.get(atomic_lib::urls::IS_A) {
                        if let Ok(subjects) = classes.to_subjects(None) {
                            if subjects.contains(&atomic_lib::urls::DRIVE.to_string()) {
                                crate::metrics::drive_created();
                            }
                        }
                    }
                }

                if vector_search_state.is_enabled() && !vector_text_unchanged {
                    if resource_old.is_some() {
                        vector_search_state
                            .remove_resource(&target_str)
                            .await
                            .map_err(|e| {
                                format!(
                                    "Handling commit in CommitMonitor failed for vector search: {}",
                                    e
                                )
                            })?;
                    }
                    if let Some(resource) = resource_new {
                        vector_search_state
                            .add_resource(&resource, &store)
                            .await
                            .map_err(|e| {
                                format!(
                                    "Handling commit in CommitMonitor failed for vector search: {}",
                                    e
                                )
                            })?;
                    }
                }
                Ok::<_, String>(())
            }
            .into_actor(self)
            .map(|res, actor, _ctx| {
                if let Err(e) = res {
                    tracing::error!("{}", e);
                }
                // Off-actor flush task picks this up on its next tick.
                actor.pending_commit.store(true, Ordering::Release);
            }),
        )
    }
}

/// Encode the wire frame (`UPDATE` or `DESTROY`) for a `CommitMessage`,
/// wrapped in `Arc<[u8]>` for cheap fanout. Returns `None` when the
/// commit produces no frame (neither a Loro update nor a destroy flag).
///
/// Mirrors the per-connection encoding that
/// `WebSocketConnection::Handler<SendFrame>` used to do before this was
/// hoisted up to the fanout site. Origin resolution uses the shared
/// store's base domain — all connections on this server resolve
/// `internal:/…` subjects the same way, so encoding once is correct.
fn encode_commit_frame(store: &Db, msg: &CommitMessage) -> Option<Arc<[u8]>> {
    let commit = &msg.commit_response.commit;

    if let Some(loro_update) = &commit.loro_update {
        // The wire `commit_id` becomes the client's `lastCommit`
        // propval and, on its next commit, its `previousCommit`. The
        // latter is parsed as an AtomicURL by the server's JSON-AD
        // parser — a raw base64 signature isn't a URL and gets
        // rejected. Always emit the full `did:ad:commit:{signature}`
        // DID. (`commit.url` is never populated in practice, so the
        // previous `or(signature)` fallback was always taken —
        // silently dropping the prefix.)
        let commit_id = commit
            .url
            .clone()
            .or_else(|| {
                commit
                    .signature
                    .as_ref()
                    .map(|s| format!("did:ad:commit:{}", s))
            })
            .unwrap_or_default();
        Some(ws_v2::encode_change_frame(
            store,
            &commit.subject,
            ws_v2::Change::Delta {
                bytes: loro_update,
                commit_id: &commit_id,
            },
        ))
    } else if commit.destroy.unwrap_or(false) {
        Some(ws_v2::encode_change_frame(
            store,
            &commit.subject,
            ws_v2::Change::Destroyed,
        ))
    } else {
        None
    }
}

impl Handler<SubscribeLoroSync> for CommitMonitor {
    type Result = ResponseActFuture<Self, ()>;

    #[allow(clippy::mutable_key_type)]
    fn handle(&mut self, msg: SubscribeLoroSync, _ctx: &mut Context<Self>) -> Self::Result {
        let store = self.store.clone();
        Box::pin(
            async move {
                if !msg.subject.is_local() {
                    tracing::warn!("can't subscribe to external resource: {}", msg.subject);
                    return None;
                }

                let resource = match store.get_resource(&msg.subject).await {
                    Ok(resource) => resource,
                    Err(e) => {
                        tracing::debug!(
                            "LoroSync subscribe failed for {} by {}: {}",
                            &msg.subject,
                            msg.agent,
                            e
                        );
                        return None;
                    }
                };

                let mut can_write = false;

                match atomic_lib::hierarchy::check_write(
                    &store,
                    &resource,
                    &ForAgent::AgentSubject(msg.agent.clone().into()),
                )
                .await
                {
                    Ok(_) => {
                        can_write = true;
                    }
                    Err(_) => {
                        match atomic_lib::hierarchy::check_read(
                            &store,
                            &resource,
                            &ForAgent::AgentSubject(msg.agent.clone().into()),
                        )
                        .await
                        {
                            Ok(_) => {}
                            Err(unauthorized_err) => {
                                tracing::debug!(
                                    "Not allowed {} to subscribe to LoroSync for {}: {}",
                                    &msg.agent,
                                    &msg.subject,
                                    unauthorized_err
                                );
                                crate::actor_messages::refuse_subscription(
                                    &msg.addr,
                                    "LORO_SYNC_SUBSCRIBE",
                                    &msg.subject.to_string(),
                                    &unauthorized_err.to_string(),
                                );
                                return None;
                            }
                        }
                    }
                }
                Some((msg.subject.clone(), msg.addr, can_write))
            }
            .into_actor(self)
            .map(|res, actor, _ctx| {
                if let Some((subject, addr, can_write)) = res {
                    let set = actor
                        .loro_subscriptions
                        .entry(subject.clone())
                        .or_insert_with(HashSet::new);
                    set.insert(LoroSubscriber { addr, can_write });
                    tracing::debug!("LoroSync subscribed to {}", subject);
                }
            }),
        )
    }
}

impl Handler<UnsubscribeLoroSync> for CommitMonitor {
    type Result = ();

    fn handle(&mut self, msg: UnsubscribeLoroSync, _ctx: &mut Context<Self>) {
        if let Some(subscribers) = self.loro_subscriptions.get_mut(&msg.subject) {
            subscribers.retain(|s| s.addr != msg.addr);

            if subscribers.is_empty() {
                self.loro_subscriptions.remove(&msg.subject);
            }
        }
    }
}

impl Handler<LoroSyncUpdate> for CommitMonitor {
    type Result = ();

    fn handle(&mut self, msg: LoroSyncUpdate, _ctx: &mut Context<Self>) {
        let Some(subscribers) = self.loro_subscriptions.get(&msg.subject) else {
            return;
        };

        // No sender address means a peer relayed this in. There is no local
        // connection to attribute it to and none to exclude from the fan-out;
        // the sending node ran its own write check before relaying, and this
        // one ran another when the frame arrived.
        let Some(addr) = &msg.addr else {
            for subscriber in subscribers {
                subscriber.addr.do_send(msg.clone());
            }

            return;
        };

        if !subscribers.iter().any(|s| s.addr == *addr && s.can_write) {
            tracing::warn!("not allowed to send LoroSync update to {}", msg.subject);
            return;
        }

        // Out to peers as well as to local subscribers, so an edit in progress
        // reaches the other device rather than waiting for a save. Only local
        // updates get here (the branch above returns early for relayed ones),
        // so there is no echo to guard against.
        if let Ok(agent) = self.store.get_default_agent() {
            atomic_lib::sync::peer::broadcast_ephemeral(
                atomic_lib::sync::protocol::ephemeral_kind::DOC,
                msg.subject.as_str(),
                &agent.subject.to_string(),
                &msg.update,
                None,
            );
        }

        for subscriber in subscribers {
            if subscriber.addr == *addr {
                continue;
            }

            subscriber.addr.do_send(msg.clone());
        }
    }
}

impl Handler<LoroEphemeralUpdate> for CommitMonitor {
    type Result = ();

    fn handle(&mut self, msg: LoroEphemeralUpdate, _ctx: &mut Context<Self>) {
        // Relay to peers before the local fan-out below, and only for presence
        // that originated here (`addr` is the websocket it came from; a frame
        // we relayed IN from a peer has none, and must not be sent back out or
        // two nodes trade cursors forever).
        if msg.addr.is_some() {
            if let Ok(agent) = self.store.get_default_agent() {
                atomic_lib::sync::peer::broadcast_ephemeral(
                    atomic_lib::sync::protocol::ephemeral_kind::LORO,
                    msg.subject.as_str(),
                    &agent.subject.to_string(),
                    &msg.update,
                    None,
                );
            }
        }

        let Some(subscribers) = self.loro_subscriptions.get(&msg.subject) else {
            return;
        };

        let sender = msg.addr.as_ref();

        for subscriber in subscribers {
            if let Some(sender_addr) = sender {
                if subscriber.addr == *sender_addr {
                    continue;
                }
            }
            subscriber.addr.do_send(msg.clone());
        }
    }
}

impl Handler<SubscribePresence> for CommitMonitor {
    type Result = ResponseActFuture<Self, ()>;

    #[allow(clippy::mutable_key_type)]
    fn handle(&mut self, msg: SubscribePresence, _ctx: &mut Context<Self>) -> Self::Result {
        let store = self.store.clone();
        Box::pin(
            async move {
                if !msg.drive.is_local() {
                    tracing::warn!(
                        "can't subscribe to presence of external drive: {}",
                        msg.drive
                    );
                    return None;
                }

                let resource = match store.get_resource(&msg.drive).await {
                    Ok(resource) => resource,
                    Err(e) => {
                        tracing::debug!(
                            "Presence subscribe failed for {} by {}: {}",
                            &msg.drive,
                            msg.agent,
                            e
                        );
                        return None;
                    }
                };

                if let Err(unauthorized_err) = atomic_lib::hierarchy::check_read(
                    &store,
                    &resource,
                    &ForAgent::AgentSubject(msg.agent.clone().into()),
                )
                .await
                {
                    tracing::debug!(
                        "Not allowed {} to subscribe to presence for {}: {}",
                        &msg.agent,
                        &msg.drive,
                        unauthorized_err
                    );
                    crate::actor_messages::refuse_subscription(
                        &msg.addr,
                        "PRESENCE_SUBSCRIBE",
                        &msg.drive.to_string(),
                        &unauthorized_err.to_string(),
                    );
                    return None;
                }

                Some((msg.drive, msg.addr))
            }
            .into_actor(self)
            .map(|res, actor, _ctx| {
                if let Some((drive, addr)) = res {
                    let subscribers = actor.presence.entry(drive.clone()).or_default();

                    // Bring the newcomer up to date: replay every other
                    // connection's cached state. LWW timestamps inside the
                    // EphemeralStore payloads make duplicate replays
                    // harmless.
                    for cached in subscribers
                        .iter()
                        .filter(|(peer, _)| **peer != addr)
                        .filter_map(|(_, state)| state.clone())
                    {
                        addr.do_send(PresenceUpdate {
                            subject: drive.clone(),
                            agent: cached.agent,
                            update: cached.update,
                            addr: None,
                        });
                    }

                    subscribers.entry(addr).or_insert(None);
                    tracing::debug!("Presence subscribed to {}", drive);
                }
            }),
        )
    }
}

impl Handler<UnsubscribePresence> for CommitMonitor {
    type Result = ();

    fn handle(&mut self, msg: UnsubscribePresence, _ctx: &mut Context<Self>) {
        if let Some(subscribers) = self.presence.get_mut(&msg.drive) {
            subscribers.remove(&msg.addr);

            if subscribers.is_empty() {
                self.presence.remove(&msg.drive);
            }
        }
    }
}

impl Handler<PresenceUpdate> for CommitMonitor {
    type Result = ();

    fn handle(&mut self, msg: PresenceUpdate, _ctx: &mut Context<Self>) {
        let Some(subscribers) = self.presence.get_mut(&msg.subject) else {
            return;
        };

        let Some(sender) = msg.addr.as_ref() else {
            tracing::warn!("no addr in presence update for {}", msg.subject);
            return;
        };

        // Only subscribers may broadcast — subscribing is where the drive
        // read-access check happens, so this is the auth gate.
        let Some(cached) = subscribers.get_mut(sender) else {
            tracing::warn!("presence update from non-subscriber for {}", msg.subject);
            return;
        };
        *cached = Some(CachedPresence {
            agent: msg.agent.clone(),
            update: msg.update.clone(),
        });

        // Relay to peers. Only local presence reaches here (the handler above
        // requires a sender address), so there is no echo to guard against.
        if let Ok(agent) = self.store.get_default_agent() {
            atomic_lib::sync::peer::broadcast_ephemeral(
                atomic_lib::sync::protocol::ephemeral_kind::PRESENCE,
                msg.subject.as_str(),
                &agent.subject.to_string(),
                &msg.update,
                None,
            );
        }

        for subscriber in subscribers.keys() {
            if subscriber == sender {
                continue;
            }

            subscriber.do_send(msg.clone());
        }
    }
}

impl Handler<RemotePresenceUpdate> for CommitMonitor {
    type Result = ();

    /// Fan a peer's presence out to everyone watching that drive here.
    ///
    /// No sender to exclude and no subscriber check: the frame came from
    /// another node, which applied its own read gate before relaying it, and
    /// there is no local connection it could be attributed to.
    fn handle(&mut self, msg: RemotePresenceUpdate, _ctx: &mut Context<Self>) {
        let Some(subscribers) = self.presence.get(&msg.subject) else {
            return;
        };

        let local = PresenceUpdate {
            subject: msg.subject.clone(),
            agent: msg.agent,
            update: msg.update,
            addr: None,
        };

        for subscriber in subscribers.keys() {
            subscriber.do_send(local.clone());
        }
    }
}

/// Spawns a commit monitor actor
pub fn create_commit_monitor(
    store: Db,
    vector_search_state: VectorSearchState,
) -> Addr<CommitMonitor> {
    tracing::info!("spawning commit monitor");
    crate::commit_monitor::CommitMonitor::create(|_ctx: &mut Context<CommitMonitor>| {
        CommitMonitor {
            subscriptions: HashMap::new(),
            drive_subscriptions: HashMap::new(),
            loro_subscriptions: HashMap::new(),
            presence: HashMap::new(),
            store,
            vector_search_state,
            pending_commit: Arc::new(AtomicBool::new(false)),
        }
    })
}
