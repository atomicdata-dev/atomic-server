use actix::{fut, Actor, ActorContext, Addr, AsyncContext, Running, StreamHandler};
use actix_web::{web, Error, HttpRequest, HttpResponse};
use actix_web_actors::ws::{self, WebsocketContext};
use std::{
    borrow::Borrow,
    time::{Duration, Instant},
};

/// Get an HTTP request, upgrade it to a Websocket connection
pub async fn web_socket_handler(
    req: HttpRequest,
    stream: web::Payload,
) -> Result<HttpResponse, Error> {
    log::info!("Starting websocket");
    let resp = ws::start(WebSocketConnection::new(), &req, stream);
    resp
}

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

// websocket connection is long running connection, it easier
/// to handle with an actor
struct WebSocketConnection {
    /// Client must send ping at least once per 10 seconds (CLIENT_TIMEOUT),
    /// otherwise we drop connection.
    hb: Instant,
    /// The Subjects that the client is subscribed to
    subscribed: std::collections::HashSet<String>,
    /// The Agent that opened the websocket, if provided
    agent: Option<String>,
}

impl Actor for WebSocketConnection {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        self.hb(ctx);
    }
}

/// Handler for `ws::Message`
impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for WebSocketConnection {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        log::info!("Incoming websocket mssage: {:?}", msg);
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
                match text.as_str() {
                    s if s.starts_with("SUBSCRIBE ") => {
                        let mut parts = s.split("SUBSCRIBE ");
                        if let Some(subject) = parts.nth(1) {
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
    fn new() -> Self {
        Self {
            agent: None,
            hb: Instant::now(),
            // Maybe this should be stored only in the CommitMonitor, and not here.
            subscribed: std::collections::HashSet::new(),
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

            let subscribedstring = act.subscribed.clone();

            // TODO: Try sending a Commit!
            ctx.text(format!("You're subscribed to {:?}", subscribedstring));
            ctx.ping(b"");
        });
    }
}
