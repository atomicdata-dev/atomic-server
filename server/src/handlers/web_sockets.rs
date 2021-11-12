use actix::{Actor, ActorContext, Addr, AsyncContext, Handler, StreamHandler};
use actix_web::{web, Error, HttpRequest, HttpResponse};
use actix_web_actors::ws::{self};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::{actor_messages::CommitMessage, appstate::AppState, commit_monitor::CommitMonitor};

/// Get an HTTP request, upgrade it to a Websocket connection
pub async fn web_socket_handler(
    req: HttpRequest,
    stream: web::Payload,
    data: web::Data<Mutex<AppState>>,
) -> Result<HttpResponse, Error> {
    log::info!("Starting websocket");
    let context = data.lock().unwrap();
    ws::start(
        WebSocketConnection::new(context.commit_monitor.clone()),
        &req,
        stream,
    )
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
            Ok(ws::Message::Text(text)) => {
                log::info!("Incoming websocket text message: {:?}", text);
                match text.as_str() {
                    s if s.starts_with("SUBSCRIBE ") => {
                        let mut parts = s.split("SUBSCRIBE ");
                        if let Some(subject) = parts.nth(1) {
                            self.commit_monitor_addr
                                .do_send(crate::actor_messages::Subscribe {
                                    addr: ctx.address(),
                                    subject: subject.to_string(),
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
                    other => {
                        log::warn!("Unmatched message: {}", other);
                        ctx.text(format!("Server receieved unknown message: {}", other));
                    }
                };
            }
            Ok(ws::Message::Binary(bin)) => ctx.binary(bin),
            Ok(ws::Message::Close(reason)) => {
                ctx.close(reason);
                ctx.stop();
            }
            _ => ctx.stop(),
        }
    }
}

impl WebSocketConnection {
    fn new(commit_monitor_addr: Addr<CommitMonitor>) -> Self {
        Self {
            hb: Instant::now(),
            // Maybe this should be stored only in the CommitMonitor, and not here.
            subscribed: std::collections::HashSet::new(),
            commit_monitor_addr,
        }
    }

    /// Sends ping to client every second. If there is no response, the Actor is stopped.
    fn hb(&self, ctx: &mut <Self as Actor>::Context) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            // check client heartbeats
            if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                // heartbeat timed out
                log::info!("Websocket Client heartbeat failed, disconnecting!");

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
        let resource = msg.commit_response.commit;
        log::info!(
            "handle commit in web socket connection for resource {}",
            resource.get_subject()
        );
        let formatted_commit = format!("COMMIT {}", resource.to_json_ad().unwrap());
        ctx.text(formatted_commit);
    }
}
