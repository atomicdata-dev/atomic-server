/*!
## WebSockets

For every Connection to `/ws`, the [web_socket_handler] creates a [WebSocketConnection].
This keeps track of the Agent and handles messages.

For information about the protocol, see https://docs.atomicdata.dev/websockets.html
 */
use actix::{Actor, ActorContext, Addr, AsyncContext, Handler, StreamHandler};
use actix_web::{web, HttpRequest, HttpResponse};
use actix_web_actors::ws;
use atomic_lib::{
    authentication::{get_agent_from_auth_values_and_check, AuthValues},
    errors::AtomicResult,
    Db, Storelike,
};
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
    let for_agent = atomic_lib::authentication::get_agent_from_auth_values_and_check(
        auth_header_values,
        &appstate.store,
    )?;
    tracing::debug!("Starting websocket for {}", for_agent);

    let result = ws::start(
        WebSocketConnection::new(
            appstate.commit_monitor.clone(),
            for_agent,
            // We need to make sure this is easily clone-able
            appstate.store.clone(),
        ),
        &req,
        stream,
    )?;
    Ok(result)
}

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

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
    store: Db,
}

impl Actor for WebSocketConnection {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        self.hb(ctx);
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for WebSocketConnection {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        if let Err(e) = handle_ws_message(msg, ctx, self) {
            ctx.text(format!("ERROR {e}"));
            tracing::error!("Handling WebSocket message: {}", e);
            ctx.stop();
        }
    }
}

fn handle_ws_message(
    msg: Result<ws::Message, ws::ProtocolError>,
    ctx: &mut ws::WebsocketContext<WebSocketConnection>,
    conn: &mut WebSocketConnection,
) -> AtomicResult<()> {
    match msg {
        Ok(ws::Message::Ping(msg)) => {
            conn.hb = Instant::now();
            ctx.pong(&msg);
            Ok(())
        }
        Ok(ws::Message::Pong(_)) => {
            conn.hb = Instant::now();
            Ok(())
        }
        // TODO: Check if it's a subscribe / unsubscribe / commit message
        Ok(ws::Message::Text(bytes)) => {
            let text = bytes.to_string();
            tracing::debug!("Incoming websocket text message: {:?}", text);
            match text.as_str() {
                s if s.starts_with("SUBSCRIBE ") => {
                    let mut parts = s.split("SUBSCRIBE ");
                    if let Some(subject) = parts.nth(1) {
                        conn.commit_monitor_addr
                            .do_send(crate::actor_messages::Subscribe {
                                addr: ctx.address(),
                                subject: subject.to_string(),
                                agent: conn.agent.clone(),
                            });
                        conn.subscribed.insert(subject.into());
                        Ok(())
                    } else {
                        Err("SUBSCRIBE needs a subject".into())
                    }
                }
                s if s.starts_with("UNSUBSCRIBE ") => {
                    let mut parts = s.split("UNSUBSCRIBE ");
                    if let Some(subject) = parts.nth(1) {
                        conn.subscribed.remove(subject);
                        Ok(())
                    } else {
                        Err("UNSUBSCRIBE needs a subject".into())
                    }
                }
                s if s.starts_with("GET ") => {
                    let mut parts = s.split("GET ");
                    if let Some(subject) = parts.nth(1) {
                        match conn
                            .store
                            .get_resource_extended(subject, false, Some(&conn.agent))
                        {
                            Ok(r) => {
                                let serialized =
                                    r.to_json_ad().expect("Can't serialize Resource to JSON-AD");
                                ctx.text(format!("RESOURCE {serialized}"));
                                Ok(())
                            }
                            Err(e) => {
                                let r = e.into_resource(subject.into());
                                let serialized_err =
                                    r.to_json_ad().expect("Can't serialize Resource to JSON-AD");
                                ctx.text(format!("RESOURCE {serialized_err}"));
                                Ok(())
                            }
                        }
                    } else {
                        Err("GET needs a subject".into())
                    }
                }
                s if s.starts_with("AUTHENTICATE ") => {
                    let mut parts = s.split("AUTHENTICATE ");
                    if let Some(json) = parts.nth(1) {
                        let auth_header_values: AuthValues = match serde_json::from_str(json) {
                            Ok(auth) => auth,
                            Err(err) => {
                                return Err(format!("Invalid AUTHENTICATE JSON: {}", err).into())
                            }
                        };
                        match get_agent_from_auth_values_and_check(
                            Some(auth_header_values),
                            // How will we get a Store here?
                            &conn.store,
                        ) {
                            Ok(a) => {
                                conn.agent = a.clone();
                                tracing::info!("Authenticated websocket for {}", a);
                                Ok(())
                            }
                            Err(e) => Err(format!("Authentication failed: {}", e).into()),
                        }
                    } else {
                        Err("AUTHENTICATE needs a JSON object".into())
                    }
                }
                other => {
                    tracing::warn!("Unknown websocket message: {}", other);
                    Err(format!("Unknown message: {}", other).into())
                }
            }
        }
        Ok(ws::Message::Binary(_bin)) => Err("ERROR: Binary not supported".into()),
        Ok(ws::Message::Close(reason)) => {
            ctx.close(reason);
            ctx.stop();
            Ok(())
        }
        _ => {
            ctx.stop();
            Ok(())
        }
    }
}

impl WebSocketConnection {
    fn new(commit_monitor_addr: Addr<CommitMonitor>, agent: String, store: Db) -> Self {
        let size = std::mem::size_of::<Db>();
        if size > 10000 {
            tracing::warn!(
                "Cloned Store is over 10kB, this will hurt performance: {:?} bytes",
                size
            );
        }

        Self {
            hb: Instant::now(),
            // Maybe this should be stored only in the CommitMonitor, and not here.
            subscribed: std::collections::HashSet::new(),
            commit_monitor_addr,
            agent,
            store,
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
