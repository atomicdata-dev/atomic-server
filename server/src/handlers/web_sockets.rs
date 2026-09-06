/*!
## WebSockets

Binary-first WebSocket protocol (v2). All resource data travels as raw Loro bytes.
Text messages are only used for Loro collaborative editing sync (LORO_SYNC_*) and
query subscription updates (QUERY_UPDATE), which will migrate to binary later.

**Canonical wire-format spec:** `docs/src/websockets.md` (published as
<https://docs.atomicdata.dev/websockets.html>). Frame encoders/decoders live
in [`atomic_lib::sync::protocol`]; the TypeScript counterparts are
`browser/lib/src/ws-v2.ts` (encoding) and `browser/lib/src/websockets.ts`
(high-level client). Update all four together when changing the protocol.
 */
use actix::{
    Actor, ActorContext, ActorFutureExt, Addr, AsyncContext, Handler, Message, Running,
    StreamHandler, WrapFuture,
};
use actix_web::{web, HttpRequest, HttpResponse};
use actix_web_actors::ws::{self, WsResponseBuilder};
use atomic_lib::{
    agents::ForAgent, authentication::get_agent_from_auth_values_and_check, Db, Storelike,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::{
    actor_messages::SendFrame, appstate::AppState, commit_monitor::CommitMonitor,
    errors::AtomicServerResult, handlers::ws_v2, helpers::get_auth_headers,
    vector_search::VectorSearchState,
};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
// How long a connection can go without receiving anything from the
// client before we declare it dead. Generous on purpose — TCP RST
// already catches truly broken connections, and the renderer can
// legitimately stall PONG delivery for several seconds when the JS
// thread is saturated (parallel playwright workers, heavy WASM init).
// A tighter budget here disconnects healthy clients under load.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(60);

/// Per-process counter for generating WebSocket connection identifiers.
/// Used as the `source_id` carried on `CommitOpts`/`CommitResponse` so
/// the commit monitor can suppress same-source broadcasts (no echo of
/// a client's own commit back to the connection that sent it).
static CONNECTION_COUNTER: AtomicU64 = AtomicU64::new(0);

fn new_connection_id() -> String {
    let n = CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("ws-{n}")
}

/// Upgrade an HTTP request to a WebSocket connection.
#[tracing::instrument(skip(appstate, stream))]
pub async fn web_socket_handler(
    req: HttpRequest,
    stream: web::Payload,
    appstate: web::Data<AppState>,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let auth_header_values = get_auth_headers(req.headers(), "ws")?;
    let for_agent =
        get_agent_from_auth_values_and_check(auth_header_values, &appstate.store).await?;

    // The origin this socket was opened on, as the client sees it (scheme
    // and `Host`, honouring forwarded headers the way the rest of the server
    // does). The browser signs exactly this as `AUTH.requestedSubject`.
    let request_origin = {
        let info = req.connection_info();
        Some(format!("{}://{}", info.scheme(), info.host()))
    };

    let result = WsResponseBuilder::new(
        WebSocketConnection {
            hb: Instant::now(),
            request_origin,
            auth_nonce: atomic_lib::sync::protocol::new_challenge_nonce(),
            client_capabilities: Vec::new(),
            commit_monitor_addr: appstate.commit_monitor.clone(),
            agent: for_agent,
            store: appstate.store.clone(),
            connection_id: new_connection_id(),
            vector_search_state: appstate.vector_search_state.clone(),
            index_status_broadcast: appstate.index_status_broadcast.clone(),
            index_status_subscribed: std::collections::HashSet::new(),
        },
        &req,
        stream,
    )
    .protocols(&["atomicdata-ws.v2"])
    // actix-web-actors defaults `max_size` to 65 536 bytes (64 KiB). Real
    // Loro snapshots — especially for documents with editing history or
    // canvases with many strokes — routinely exceed that, and JSON/base64
    // wrapping (the RBSR text frames) adds another ~40% on top of the raw
    // bytes. A frame over the limit causes actix to drop the TCP socket
    // without sending a Close control frame, which the browser sees as a
    // CloseEvent `code=1006, wasClean=false`: an unexplained reconnect
    // every second when the client tries to ship a doc's snapshot back.
    // 16 MiB is well above realistic doc sizes (Loro's own snapshot
    // benchmarks top out in the low MBs even for multi-megabyte texts) and
    // still far below the ~4 GiB WebSocket frame ceiling, so we don't risk
    // silently truncating legitimate payloads.
    .frame_size(16 * 1024 * 1024)
    .start()?;

    Ok(result)
}

pub struct WebSocketConnection {
    hb: Instant,
    /// `scheme://host[:port]` the upgrade request arrived on; one of the two
    /// origins an `AUTH.requestedSubject` may name (the other is the
    /// configured server URL).
    request_origin: Option<String>,
    /// The nonce this connection sent in its `CHALLENGE` (0x42). An `AUTH`
    /// whose `requestedSubject` carries a fragment must carry this one, so a
    /// proof captured here cannot open a session anywhere else.
    auth_nonce: String,
    /// Capability names the client listed in a `HELLO` (0x37), if it sent
    /// one. Consulted before answering `COMMIT` with a slim `COMMIT_OK`.
    client_capabilities: Vec<String>,
    commit_monitor_addr: Addr<CommitMonitor>,
    agent: ForAgent,
    store: Db,
    /// Unique-per-process identifier. Threaded through `CommitOpts` into
    /// `CommitResponse` and the emitted `DbEvent`s, so the commit monitor
    /// can suppress broadcasts back to this connection.
    connection_id: String,
    vector_search_state: VectorSearchState,
    index_status_broadcast: Arc<IndexStatusBroadcast>,
    index_status_subscribed: std::collections::HashSet<String>,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct IndexStatusPush {
    pub drive: String,
    pub indexing: bool,
}

/// Fan-out for `INDEX_STATUS` websocket messages (per subscribed drive).
pub struct IndexStatusBroadcast {
    inner: Arc<Mutex<std::collections::HashMap<String, Vec<Addr<WebSocketConnection>>>>>,
}

impl IndexStatusBroadcast {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    pub fn subscribe(&self, drive: String, addr: Addr<WebSocketConnection>) {
        let mut g = self.inner.lock().expect("index status broadcast mutex");
        g.entry(drive).or_default().push(addr);
    }

    pub fn unsubscribe_drive(&self, drive: &str, addr: &Addr<WebSocketConnection>) {
        let mut g = self.inner.lock().expect("index status broadcast mutex");
        if let Some(v) = g.get_mut(drive) {
            v.retain(|a: &Addr<WebSocketConnection>| a != addr);
        }
    }

    pub fn unsubscribe_all_for_addr(&self, addr: &Addr<WebSocketConnection>) {
        let mut g = self.inner.lock().expect("index status broadcast mutex");
        for v in g.values_mut() {
            v.retain(|a: &Addr<WebSocketConnection>| a != addr);
        }
    }

    pub fn notify(&self, drive: &str, indexing: bool) {
        let addrs: Vec<Addr<WebSocketConnection>> = {
            let g = self.inner.lock().expect("index status broadcast mutex");
            g.get(drive).cloned().unwrap_or_default()
        };
        for addr in addrs {
            let _ = addr.do_send(IndexStatusPush {
                drive: drive.to_string(),
                indexing,
            });
        }
    }
}

impl Actor for WebSocketConnection {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        // First frame on the wire, before the client has said anything: the
        // nonce its AUTH proof can bind itself to. Clients that predate the
        // frame ignore it (every decoder in the tree drops unknown tags) and
        // authenticate on their timestamp as before.
        ctx.binary(atomic_lib::sync::protocol::encode_challenge(
            &self.auth_nonce,
        ));
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                tracing::info!("Websocket heartbeat failed, disconnecting");
                ctx.stop();

                return;
            }

            ctx.ping(b"");
        });
    }

    fn stopped(&mut self, ctx: &mut Self::Context) {
        // Remove ourselves from every subscription map. Without this,
        // closed connections leave stale `Addr`s in `CommitMonitor`,
        // which every subsequent fanout iterates over (do_send to a
        // stopped actor silently no-ops).
        let addr = ctx.address();
        self.commit_monitor_addr
            .do_send(crate::actor_messages::UnsubscribeAll { addr });
    }
    fn stopping(&mut self, ctx: &mut Self::Context) -> Running {
        self.index_status_broadcast
            .unsubscribe_all_for_addr(&ctx.address());
        Running::Stop
    }
}

// ---- Incoming message routing ----

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for WebSocketConnection {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Ping(msg)) => {
                self.hb = Instant::now();
                ctx.pong(&msg);
            }
            Ok(ws::Message::Pong(_)) => {
                self.hb = Instant::now();
            }
            Ok(ws::Message::Binary(bin)) => {
                self.handle_binary(&bin, ctx);
            }
            Ok(ws::Message::Text(text)) => {
                // Remaining text messages: Loro sync, presence, RBSR
                self.handle_text(&text, ctx);
            }
            Ok(ws::Message::Close(reason)) => {
                ctx.close(reason);
                ctx.stop();
            }
            _ => ctx.stop(),
        }
    }
}

impl WebSocketConnection {
    /// Whether this session has a proven identity: auth headers on the
    /// upgrade request, or an `AUTH` frame that succeeded. A session that
    /// has neither is `Public`.
    fn is_authenticated(&self) -> bool {
        !matches!(self.agent, ForAgent::Public)
    }

    /// Gate for frames that need an identity. Reads (`GET`, `SUB <drive>`,
    /// `SYNC`) stay open to anonymous sessions, gated per subject
    /// on `check_read` exactly like an anonymous HTTP GET — that is what
    /// lets a public drive's share link show live updates without an
    /// account. Everything that writes (`SYNC_PUSH`, `BLOB_RESPONSE`,
    /// `EPHEMERAL`, …) or that registers an
    /// identity-bearing subscription goes through here, and an anonymous
    /// session gets an `ERROR` (`AUTH_REQUIRED`, request_id 0) instead of
    /// being handled as `Public`. The socket stays open: the client can
    /// still `AUTH` and retry. See `docs/src/websockets.md`.
    fn require_auth(&self, what: &str, ctx: &mut ws::WebsocketContext<Self>) -> bool {
        if self.is_authenticated() {
            return true;
        }
        tracing::debug!("ws {}: refused {what} before AUTH", self.connection_id);
        ctx.binary(ws_v2::encode_error(
            0,
            ws_v2::error_code::AUTH_REQUIRED,
            &format!("AUTH required before {what}"),
        ));
        false
    }

    /// Handle a binary v2 frame.
    fn handle_binary(&mut self, bin: &[u8], ctx: &mut ws::WebsocketContext<Self>) {
        if bin.is_empty() {
            return;
        }

        // Writes need an identity. The engine would refuse them for `Public`
        // anyway (no write right, no admission) — but "refuse" used to mean
        // a silent drop answered with `SYNC_OK`; now it is an explicit
        // `AUTH_REQUIRED` before the frame is even looked at.
        if matches!(bin[0], ws_v2::tag::SYNC_PUSH | ws_v2::tag::BLOB_RESPONSE)
            && !self.require_auth(&format!("frame 0x{:02x}", bin[0]), ctx)
        {
            return;
        }

        match bin[0] {
            // AUTH is engine-owned (verify + assign identity). It's the one
            // engine-delegated frame that MUTATES the session agent, so unlike
            // the read-only delegations below we must write the (possibly
            // changed) agent back onto the actor after the future resolves —
            // a cloned agent handed to `handle_frame` would otherwise drop the
            // identity the AUTH just proved.
            ws_v2::tag::AUTH => {
                let store = self.store.clone();
                let mut agent = self.agent.clone();
                let bin_vec = bin.to_vec();
                let request_origin = self.request_origin.clone();
                let nonce = self.auth_nonce.clone();
                ctx.spawn(
                    async move {
                        // The browser signs the server origin as
                        // `requestedSubject`; hold it to that, so a proof
                        // signed for another server (or an HTTP auth header
                        // for some resource URL) does not open a session
                        // here. Iroh binds the subject to the drive instead,
                        // in `peer.rs`. Two origins are acceptable, the same
                        // way the HTTP auth headers compare against the
                        // request URL: the origin this upgrade request came
                        // in on (a proxy or a test harness may reach the
                        // server under a name other than its configured
                        // URL, and the browser signs the one it used) and
                        // the configured server URL.
                        let base_domain = store.get_base_domain();
                        let accepted: Vec<&str> =
                            [request_origin.as_deref(), base_domain.as_deref()]
                                .into_iter()
                                .flatten()
                                .collect();
                        let responses = atomic_lib::sync::engine::handle_auth_frame(
                            &bin_vec[1..],
                            &store,
                            &mut agent,
                            atomic_lib::sync::engine::AuthBinding::Origins(&accepted),
                            atomic_lib::sync::engine::AuthChallenge::Issued(&nonce),
                        )
                        .await;
                        (responses, agent)
                    }
                    .into_actor(self)
                    .map(|(responses, agent), actor, ctx| {
                        // Subscriptions were admitted under the previous
                        // identity; have the monitor re-check them against
                        // this one (see `Handler<RebindAgent>`).
                        if actor.agent != agent {
                            actor
                                .commit_monitor_addr
                                .do_send(crate::actor_messages::RebindAgent {
                                    addr: ctx.address(),
                                    agent: agent.to_string(),
                                });
                        }
                        actor.agent = agent;
                        for response in responses {
                            ctx.binary(response);
                        }
                    }),
                );
            }

            // GET is engine-owned too (read-only: resolve subject, materialize
            // state, emit UPDATE). The engine resolves `internal:/` against the
            // node's base domain, so folding it in here also removed the drift
            // where only the server resolved it and an Iroh peer received raw
            // `internal:/` subjects. Delegated alongside the other read-only
            // frames below.
            //
            // SUB/UNSUB are engine-owned as of 2026-09: parse + `check_read`
            // live in `handle_frame_full`. This handler only registers the
            // connection with the commit monitor when the engine admits the
            // subscription. The monitor still re-checks on `Subscribe` as
            // defence in depth.
            ws_v2::tag::GET
            | ws_v2::tag::SYNC
            | ws_v2::tag::SYNC_PUSH
            | ws_v2::tag::BLOB_REQUEST
            | ws_v2::tag::BLOB_RESPONSE
            | ws_v2::tag::SUB
            | ws_v2::tag::UNSUB => {
                let store = self.store.clone();
                let mut agent = self.agent.clone();
                let bin_vec = bin.to_vec();
                ctx.spawn(
                    async move {
                        atomic_lib::sync::engine::handle_frame_full(&bin_vec, &store, &mut agent)
                            .await
                    }
                    .into_actor(self)
                    .map(|out, actor, ctx| {
                        for response in out.frames {
                            ctx.binary(response);
                        }
                        if let Some(subject) = out.subscribe {
                            actor
                                .commit_monitor_addr
                                .do_send(crate::actor_messages::Subscribe {
                                    addr: ctx.address(),
                                    subject,
                                    agent: actor.agent.to_string(),
                                    source_id: actor.connection_id.clone(),
                                });
                        }
                        if let Some(subject) = out.unsubscribe {
                            actor
                                .commit_monitor_addr
                                .do_send(crate::actor_messages::Unsubscribe {
                                    addr: ctx.address(),
                                    subject,
                                });
                        }
                    }),
                );
            }

            ws_v2::tag::COMMIT => {
                let Some(decoded) = ws_v2::decode_commit(&bin[1..]) else {
                    return;
                };
                let request_id = decoded.request_id;
                let body = decoded.commit_json.to_string();
                let store = self.store.clone();
                let source_id = self.connection_id.clone();
                let origin = self
                    .store
                    .get_base_domain()
                    .unwrap_or_else(|| "http://localhost".to_string());
                let slim_ack = self
                    .client_capabilities
                    .iter()
                    .any(|c| c == atomic_lib::sync::protocol::CAP_COMMIT_OK_SLIM);
                ctx.spawn(
                    async move {
                        let result = crate::handlers::commit::apply_commit_json(
                            &store,
                            &origin,
                            &body,
                            Some(source_id),
                        )
                        .await;
                        (request_id, result)
                    }
                    .into_actor(self)
                    .map(move |(rid, res), _actor, ctx| match res {
                        Ok(server_commit_json) => {
                            // A client that listed `commit-ok-slim` in its
                            // HELLO only wants the id it must chain the next
                            // commit on; it already holds the commit it just
                            // signed.
                            let slim_id = if slim_ack {
                                serde_json::from_str::<serde_json::Value>(&server_commit_json)
                                    .ok()
                                    .and_then(|v| v.get("@id")?.as_str().map(str::to_owned))
                            } else {
                                None
                            };
                            match slim_id {
                                Some(id) => ctx.binary(ws_v2::encode_commit_ok_slim(rid, &id)),
                                None => {
                                    ctx.binary(ws_v2::encode_commit_ok(rid, &server_commit_json))
                                }
                            }
                        }
                        Err(e) => {
                            // F5 (planning/unified-sync.md): classify so the
                            // outbox can switch on a structured code instead
                            // of pattern-matching this exact message text.
                            let msg = e.to_string();
                            let code = ws_v2::classify_commit_error(&msg);
                            ctx.binary(ws_v2::encode_error(rid, code, &msg));
                        }
                    }),
                );
            }

            // Liveness probe from the browser. A browser cannot see the
            // protocol-level pings this actor sends, so it sends this and
            // expects it back; no answer within its deadline means the socket
            // is dead and it reconnects. Peer (QUIC) streams never echo it —
            // see `protocol::tag::KEEPALIVE`.
            ws_v2::tag::KEEPALIVE => {
                ctx.binary(atomic_lib::sync::protocol::encode_keepalive());
            }

            // A browser or Rust client introducing itself: display name plus
            // the capabilities it speaks. Nothing is answered (the server's
            // own list rides on AUTH_OK); the list steers what this
            // connection is sent from here on, e.g. a slim `COMMIT_OK`.
            // Until 2026-09 this tag was Iroh-only and fell through to the
            // debug log below.
            ws_v2::tag::HELLO => {
                let caps = atomic_lib::sync::protocol::decode_hello_caps(&bin[1..]);
                tracing::debug!(
                    connection = %self.connection_id,
                    ?caps,
                    "client HELLO"
                );
                self.client_capabilities = caps;
            }

            // Live collaboration: an edit in progress (`DOC`), cursors
            // (`LORO`) or drive presence (`PRESENCE`), relayed without
            // inspection. The frame's own `agent` field is ignored on the
            // way in: the broadcaster attributes it to the identity this
            // connection proved, and stamps that on the way out. Until
            // 2026-09-04 these were the text frames `LORO_SYNC_UPDATE`,
            // `LORO_EPHEMERAL_UPDATE` and `PRESENCE_UPDATE` (base64 JSON).
            ws_v2::tag::EPHEMERAL => {
                if !self.require_auth("EPHEMERAL", ctx) {
                    return;
                }
                let Some(decoded) = atomic_lib::sync::protocol::decode_ephemeral(&bin[1..]) else {
                    tracing::debug!(connection = %self.connection_id, "malformed EPHEMERAL");
                    return;
                };
                let subject = atomic_lib::Subject::from(decoded.drive);
                let agent = self.agent.to_string();
                let addr = Some(ctx.address());
                use atomic_lib::sync::protocol::ephemeral_kind;
                match decoded.kind {
                    ephemeral_kind::DOC => {
                        self.commit_monitor_addr
                            .do_send(crate::actor_messages::LoroSyncUpdate {
                                subject,
                                agent,
                                update: decoded.payload,
                                addr,
                            });
                    }
                    ephemeral_kind::LORO => {
                        self.commit_monitor_addr.do_send(
                            crate::actor_messages::LoroEphemeralUpdate {
                                subject,
                                agent,
                                update: decoded.payload,
                                addr,
                            },
                        );
                    }
                    ephemeral_kind::PRESENCE => {
                        self.commit_monitor_addr
                            .do_send(crate::actor_messages::PresenceUpdate {
                                subject,
                                agent,
                                update: decoded.payload,
                                addr,
                            });
                    }
                    other => {
                        tracing::debug!("Unknown EPHEMERAL kind {other}");
                    }
                }
            }

            _ => {
                tracing::debug!("Unhandled binary tag: 0x{:02x}", bin[0]);
            }
        }
    }

    /// Handle the remaining text messages (Loro and presence subscriptions,
    /// RBSR, index status).
    fn handle_text(&mut self, text: &str, ctx: &mut ws::WebsocketContext<Self>) {
        if let Some(json) = text.strip_prefix("SUBSCRIBE_INDEX_STATUS ") {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(json) {
                if let Some(drive) = v.get("drive").and_then(|d| d.as_str()) {
                    let addr = ctx.address();
                    self.index_status_broadcast
                        .subscribe(drive.to_string(), addr.clone());
                    self.index_status_subscribed.insert(drive.to_string());
                    let indexing = self.vector_search_state.is_drive_indexing(drive);
                    let payload = serde_json::json!({ "drive": drive, "indexing": indexing });
                    if let Ok(s) = serde_json::to_string(&payload) {
                        ctx.text(format!("INDEX_STATUS {s}"));
                    }
                }
            }
        } else if let Some(json) = text.strip_prefix("UNSUBSCRIBE_INDEX_STATUS ") {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(json) {
                if let Some(drive) = v.get("drive").and_then(|d| d.as_str()) {
                    self.index_status_broadcast
                        .unsubscribe_drive(drive, &ctx.address());
                    self.index_status_subscribed.remove(drive);
                }
            }
        } else if let Some(json) = text.strip_prefix("LORO_SYNC_SUBSCRIBE ") {
            if !self.require_auth("LORO_SYNC_SUBSCRIBE", ctx) {
                return;
            }
            if let Ok(msg) =
                serde_json::from_str::<crate::actor_messages::LoroSubscriptionJSON>(json)
            {
                self.commit_monitor_addr
                    .do_send(crate::actor_messages::SubscribeLoroSync {
                        addr: ctx.address(),
                        subject: msg.subject,
                        agent: self.agent.to_string(),
                    });
            }
        } else if let Some(json) = text.strip_prefix("LORO_SYNC_UNSUBSCRIBE ") {
            if let Ok(msg) =
                serde_json::from_str::<crate::actor_messages::LoroSubscriptionJSON>(json)
            {
                self.commit_monitor_addr
                    .do_send(crate::actor_messages::UnsubscribeLoroSync {
                        addr: ctx.address(),
                        subject: msg.subject,
                    });
            }
        } else if let Some(json) = text.strip_prefix("PRESENCE_SUBSCRIBE ") {
            // Drive-scoped ephemeral presence (issue #1229). Reuses the
            // Loro subscription JSON shape: `{"subject": "<drive>"}`.
            if !self.require_auth("PRESENCE_SUBSCRIBE", ctx) {
                return;
            }
            if let Ok(msg) =
                serde_json::from_str::<crate::actor_messages::LoroSubscriptionJSON>(json)
            {
                self.commit_monitor_addr
                    .do_send(crate::actor_messages::SubscribePresence {
                        addr: ctx.address(),
                        drive: msg.subject,
                        agent: self.agent.to_string(),
                    });
            }
        } else if let Some(json) = text.strip_prefix("PRESENCE_UNSUBSCRIBE ") {
            if let Ok(msg) =
                serde_json::from_str::<crate::actor_messages::LoroSubscriptionJSON>(json)
            {
                self.commit_monitor_addr
                    .do_send(crate::actor_messages::UnsubscribePresence {
                        addr: ctx.address(),
                        drive: msg.subject,
                    });
            }
        } else if let Some(json) = text.strip_prefix("RBSR_FP ") {
            // RBSR: answer range fingerprints so the client can find the
            // differing subjects without transmitting the whole version vector.
            // Stateless (rebuilds `drive_items` per request) — the incremental
            // fingerprint tree that makes this cheaper is Phase 2c.
            //
            // Gated on `check_read` per subject for this session's agent, like
            // the full `SYNC` exchange. Without that an anonymous socket
            // could enumerate every subject and version vector of any drive.
            if let Ok(req) = serde_json::from_str::<RbsrFpRequest>(json) {
                let store = self.store.clone();
                let agent = self.agent.clone();
                ctx.spawn(
                    async move {
                        let items =
                            atomic_lib::sync::engine::drive_items_for(&store, &req.drive, &agent)
                                .await;
                        items
                            .map(|items| {
                                let fps: Vec<String> = req
                                    .ranges
                                    .iter()
                                    .map(|(lo, hi)| {
                                        hex::encode(atomic_lib::sync::rbsr::range_fingerprint(
                                            &items,
                                            lo,
                                            hi.as_deref(),
                                        ))
                                    })
                                    .collect();
                                serde_json::json!({ "drive": req.drive, "fps": fps }).to_string()
                            })
                            .map_err(|reason| (req.drive.clone(), reason))
                    }
                    .into_actor(self)
                    .map(|resp, _actor, ctx| match resp {
                        Ok(resp) => ctx.text(format!("RBSR_FP {resp}")),
                        Err((drive, reason)) => ctx.binary(ws_v2::encode_error(
                            0,
                            ws_v2::error_code::UNAUTHORIZED_READ,
                            &format!("RBSR_FP refused for {drive}: {reason}"),
                        )),
                    }),
                );
            }
        } else if let Some(json) = text.strip_prefix("RBSR_ITEMS ") {
            if let Ok(req) = serde_json::from_str::<RbsrItemsRequest>(json) {
                let store = self.store.clone();
                let agent = self.agent.clone();
                ctx.spawn(
                    async move {
                        let items =
                            atomic_lib::sync::engine::drive_items_for(&store, &req.drive, &agent)
                                .await;
                        items
                            .map(|items| {
                                let hi = req.hi.as_deref();
                                let out: Vec<(String, Vec<(String, i32)>)> = items
                                    .into_iter()
                                    .filter(|(s, _)| {
                                        s.as_str() >= req.lo.as_str()
                                            && hi.map(|h| s.as_str() < h).unwrap_or(true)
                                    })
                                    .map(|(s, vv)| (s, vv.into_iter().collect()))
                                    .collect();
                                serde_json::json!({ "drive": req.drive, "items": out }).to_string()
                            })
                            .map_err(|reason| (req.drive.clone(), reason))
                    }
                    .into_actor(self)
                    .map(|resp, _actor, ctx| match resp {
                        Ok(resp) => ctx.text(format!("RBSR_ITEMS {resp}")),
                        Err((drive, reason)) => ctx.binary(ws_v2::encode_error(
                            0,
                            ws_v2::error_code::UNAUTHORIZED_READ,
                            &format!("RBSR_ITEMS refused for {drive}: {reason}"),
                        )),
                    }),
                );
            }
        } else {
            tracing::debug!("Unknown text message: {}", &text[..text.len().min(50)]);
        }
    }
}

#[derive(serde::Deserialize)]
struct RbsrFpRequest {
    drive: String,
    /// `[lo, hi]` ranges; `hi == null` means unbounded above.
    ranges: Vec<(String, Option<String>)>,
}

#[derive(serde::Deserialize)]
struct RbsrItemsRequest {
    drive: String,
    lo: String,
    hi: Option<String>,
}

// ---- Outgoing message handlers (Actor → WebSocket) ----

impl Handler<SendFrame> for WebSocketConnection {
    type Result = ();

    /// Receives a pre-encoded `UPDATE` / `DESTROY` wire frame from
    /// `CommitMonitor`'s fanout and writes it to the WebSocket. The
    /// encoding work happened once at the fanout site; here we hand
    /// the `Arc<[u8]>` to `Bytes::from_owner` so actix shares ownership
    /// without copying the bytes.
    fn handle(&mut self, msg: SendFrame, ctx: &mut ws::WebsocketContext<Self>) {
        ctx.binary(actix_web::web::Bytes::from_owner(msg.frame));
    }
}

/// The three live-collaboration fan-outs leave as one `EPHEMERAL (0x40)`
/// frame, the kind byte telling them apart.
fn send_ephemeral(
    kind: u8,
    subject: &atomic_lib::Subject,
    agent: &str,
    update: &[u8],
    ctx: &mut ws::WebsocketContext<WebSocketConnection>,
) {
    ctx.binary(atomic_lib::sync::protocol::encode_ephemeral(
        kind,
        subject.as_str(),
        agent,
        update,
    ));
}

impl Handler<crate::actor_messages::LoroSyncUpdate> for WebSocketConnection {
    type Result = ();

    fn handle(
        &mut self,
        msg: crate::actor_messages::LoroSyncUpdate,
        ctx: &mut ws::WebsocketContext<Self>,
    ) {
        send_ephemeral(
            atomic_lib::sync::protocol::ephemeral_kind::DOC,
            &msg.subject,
            &msg.agent,
            &msg.update,
            ctx,
        );
    }
}

impl Handler<crate::actor_messages::LoroEphemeralUpdate> for WebSocketConnection {
    type Result = ();

    fn handle(
        &mut self,
        msg: crate::actor_messages::LoroEphemeralUpdate,
        ctx: &mut ws::WebsocketContext<Self>,
    ) {
        send_ephemeral(
            atomic_lib::sync::protocol::ephemeral_kind::LORO,
            &msg.subject,
            &msg.agent,
            &msg.update,
            ctx,
        );
    }
}

impl Handler<crate::actor_messages::PresenceUpdate> for WebSocketConnection {
    type Result = ();

    fn handle(
        &mut self,
        msg: crate::actor_messages::PresenceUpdate,
        ctx: &mut ws::WebsocketContext<Self>,
    ) {
        send_ephemeral(
            atomic_lib::sync::protocol::ephemeral_kind::PRESENCE,
            &msg.subject,
            &msg.agent,
            &msg.update,
            ctx,
        );
    }
}

impl Handler<IndexStatusPush> for WebSocketConnection {
    type Result = ();

    fn handle(&mut self, msg: IndexStatusPush, ctx: &mut ws::WebsocketContext<Self>) {
        let payload = serde_json::json!({
            "drive": msg.drive,
            "indexing": msg.indexing,
        });
        if let Ok(s) = serde_json::to_string(&payload) {
            ctx.text(format!("INDEX_STATUS {}", s));
        }
    }
}
