use actix::{Actor, ActorContext, Addr, AsyncContext, Handler, StreamHandler};
use actix_web::{web, HttpRequest, HttpResponse};
use actix_web_actors::ws;
use std::time::{Duration, Instant};

use crate::{
    actor_messages::CommitMessage, appstate::AppState, commit_monitor::CommitMonitor,
    errors::AtomicServerResult, helpers::get_auth_headers,
};

/// Get an HTTP request, upgrade it to a Websocket connection
#[tracing::instrument(skip(appstate, stream))]
pub async fn web_socket_handler(
    req: HttpRequest,
    stream: web::Payload,
    appstate: web::Data<AppState>,
) -> AtomicServerResult<HttpResponse> {
    // Authentication check. If the user has no headers, continue with the Public Agent.
    let auth_header_values = get_auth_headers(req.headers(), "ws".into())?;
    let for_agent = atomic_lib::authentication::get_agent_from_headers_and_check(
        auth_header_values,
        &appstate.store,
    )?;
    tracing::debug!("Starting websocket for {}", for_agent);

    let result = ws::start(
        WebSocketConnection::new(appstate.commit_monitor.clone(), for_agent),
        &req,
        stream,
    )?;
    Ok(result)
}

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// This connection is used for relaying relevant Commits to the client.
/// The client sends SUBSCRIBE messages to the server to indicate which Resources it is interested in
// TODO: Add the Agent that opened the websocket, if provided
pub struct WebSocketConnection {
    /// Client must send ping at least once per 10 seconds (CLIENT_TIMEOUT),
    /// otherwise we drop connection.
    hb: Instant,
    /// The Subjects that the client is subscribed to
    subscribed: std::collections::HashSet<String>,
    /// The CommitMonitor Actor that receives and sends messages for Commits
    commit_monitor_addr: Addr<CommitMonitor>,
    /// The Agent who is connected.
    /// If it's not specified, it's the Public Agent.
    agent: String,
}

impl Actor for WebSocketConnection {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        self.hb(ctx);
    }
}

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
            // TODO: Check if it's a subscribe / unsubscribe / commit message
            Ok(ws::Message::Text(bytes)) => {
                let text = bytes.to_string();
                tracing::debug!("Incoming websocket text message: {:?}", text);
                match text.as_str() {
                    s if s.starts_with("SUBSCRIBE ") => {
                        let mut parts = s.split("SUBSCRIBE ");
                        if let Some(subject) = parts.nth(1) {
                            self.commit_monitor_addr
                                .do_send(crate::actor_messages::Subscribe {
                                    addr: ctx.address(),
                                    subject: subject.to_string(),
                                    agent: self.agent.clone(),
                                });
                            self.subscribed.insert(subject.into());
                        } else {
                            ctx.text("ERROR: SUBSCRIBE without subject")
                        }
                    }
                    s if s.starts_with("UNSUBSCRIBE ") => {
                        let mut parts = s.split("UNSUBSCRIBE ");
                        if let Some(subject) = parts.nth(1) {
                            self.subscribed.remove(subject);
                        } else {
                            ctx.text("ERROR: UNSUBSCRIBE without subject")
                        }
                    }
                    s if s.starts_with("GET ") => {
                        let mut parts = s.split("GET ");
                        if let Some(_subject) = parts.nth(1) {
                            ctx.text("ERROR: GET not yet supported, see https://github.com/joepio/atomic-data-rust/issues/180")
                        }
                    }
                    other => {
                        tracing::warn!("Unmatched message: {}", other);
                        ctx.text(format!("ERROR: Server received unknown message: {}", other));
                    }
                };
            }
            Ok(ws::Message::Binary(_bin)) => ctx.text("ERROR: Binary not supported"),
            Ok(ws::Message::Close(reason)) => {
                ctx.close(reason);
                ctx.stop();
            }
            _ => ctx.stop(),
        }
    }
}

impl WebSocketConnection {
    fn new(commit_monitor_addr: Addr<CommitMonitor>, agent: String) -> Self {
        Self {
            hb: Instant::now(),
            // Maybe this should be stored only in the CommitMonitor, and not here.
            subscribed: std::collections::HashSet::new(),
            commit_monitor_addr,
            agent,
        }
    }

    /// Sends ping to client every second. If there is no response, the Actor is stopped.
    fn hb(&self, ctx: &mut <Self as Actor>::Context) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            // check client heartbeats
            if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                // heartbeat timed out
                tracing::info!("Websocket Client heartbeat failed, disconnecting!");

                // We need to kill the Actor responsible for Commit monitoring, too
                // act.lobby_addr.do_send(Disconnect { id: act.id, room_id: act.room });

                // stop actor
                ctx.stop();

                // don't try to send a ping
                return;
            }
            ctx.ping(b"");
        });
    }
}

impl Handler<CommitMessage> for WebSocketConnection {
    type Result = ();

    fn handle(&mut self, msg: CommitMessage, ctx: &mut ws::WebsocketContext<Self>) {
        let resource = msg.commit_response.commit_resource;
        tracing::debug!(
            "handle commit in web socket connection for resource {}",
            resource.get_subject()
        );
        let formatted_commit = format!("COMMIT {}", resource.to_json_ad().unwrap());
        ctx.text(formatted_commit);
    }
}
