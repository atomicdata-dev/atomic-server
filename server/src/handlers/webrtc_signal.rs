//! Ephemeral rendezvous only: no drive data, account or hosting subscription.
//! Room secrets are carried in the first frame, never in URLs/access logs.
use actix::{Actor, ActorContext, Addr, AsyncContext, Handler, Message, StreamHandler};
use actix_web::{web, HttpRequest, HttpResponse};
use actix_web_actors::ws;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        LazyLock, Mutex,
    },
    time::{Duration, Instant},
};

const MAX_ROOMS: usize = 512;
const MAX_PEERS: usize = 8;
const MAX_MESSAGE: usize = 64 * 1024;
type Rooms = HashMap<String, HashMap<String, Addr<SignalSocket>>>;
static CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
struct ConnectionPermit;
impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
    }
}
static ROOMS: LazyLock<Mutex<Rooms>> = LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Message)]
#[rtype(result = "()")]
struct Signal(String);

pub async fn handler(req: HttpRequest, stream: web::Payload) -> actix_web::Result<HttpResponse> {
    if CONNECTIONS
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            (n < 2048).then_some(n + 1)
        })
        .is_err()
    {
        return Ok(HttpResponse::ServiceUnavailable().finish());
    }
    ws::WsResponseBuilder::new(
        SignalSocket {
            _permit: ConnectionPermit,
            room: None,
            peer: String::new(),
            heartbeat: Instant::now(),
            rate_start: Instant::now(),
            messages: 0,
        },
        &req,
        stream,
    )
    .frame_size(MAX_MESSAGE)
    .start()
}

struct SignalSocket {
    _permit: ConnectionPermit,
    room: Option<String>,
    peer: String,
    heartbeat: Instant,
    rate_start: Instant,
    messages: usize,
}

fn valid_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Coturn REST credentials: the long-term shared secret never leaves the server.
fn ice_servers(peer: &str) -> serde_json::Value {
    use base64::Engine;
    use hmac::{Hmac, KeyInit, Mac};
    let mut servers = vec![serde_json::json!({"urls":"stun:stun.cloudflare.com:3478"})];
    if let (Ok(urls), Ok(secret)) = (
        std::env::var("ATOMICSERVER_WEBRTC_TURN_URLS"),
        std::env::var("ATOMICSERVER_WEBRTC_TURN_SECRET"),
    ) {
        if !secret.is_empty() {
            let expiry = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + 3600;
            let username = format!("{expiry}:{peer}");
            let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret.as_bytes())
                .expect("HMAC accepts any key length");
            mac.update(username.as_bytes());
            let credential =
                base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
            let urls: Vec<_> = urls
                .split(',')
                .map(str::trim)
                .filter(|url| url.starts_with("turn:") || url.starts_with("turns:"))
                .collect();
            if !urls.is_empty() {
                servers.push(
                    serde_json::json!({"urls":urls,"username":username,"credential":credential}),
                );
            }
        }
    }
    serde_json::Value::Array(servers)
}

impl Actor for SignalSocket {
    type Context = ws::WebsocketContext<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(16);
        ctx.run_later(Duration::from_secs(10), |socket, ctx| {
            if socket.room.is_none() {
                ctx.stop();
            }
        });
        // Expire even healthy rendezvous sockets; clients renew discovery.
        ctx.run_later(Duration::from_secs(30 * 60), |_, ctx| ctx.stop());
        ctx.run_interval(Duration::from_secs(20), |socket, ctx| {
            if socket.heartbeat.elapsed() > Duration::from_secs(60) {
                ctx.stop();
            } else {
                ctx.ping(b"");
            }
        });
    }
    fn stopped(&mut self, _: &mut Self::Context) {
        let Some(room) = &self.room else {
            return;
        };
        let mut rooms = ROOMS.lock().unwrap();
        if let Some(peers) = rooms.get_mut(room) {
            peers.remove(&self.peer);
            let notice = serde_json::json!({"type":"left", "peer":self.peer}).to_string();
            for addr in peers.values() {
                let _ = addr.try_send(Signal(notice.clone()));
            }
            if peers.is_empty() {
                rooms.remove(room);
            }
        }
    }
}

impl Handler<Signal> for SignalSocket {
    type Result = ();
    fn handle(&mut self, message: Signal, ctx: &mut Self::Context) {
        ctx.text(message.0);
    }
}

impl SignalSocket {
    fn text(&mut self, text: &str, ctx: &mut ws::WebsocketContext<Self>) -> Result<(), ()> {
        if text.len() > MAX_MESSAGE {
            return Err(());
        }
        if self.rate_start.elapsed() > Duration::from_secs(60) {
            self.rate_start = Instant::now();
            self.messages = 0;
        }
        self.messages += 1;
        if self.messages > 60 {
            return Err(());
        }
        let message: serde_json::Value = serde_json::from_str(text).map_err(|_| ())?;
        if self.room.is_none() {
            if message["type"] != "join" {
                return Err(());
            }
            let room = message["room"].as_str().filter(|s| valid_id(s)).ok_or(())?;
            let peer = message["peer"].as_str().filter(|s| valid_id(s)).ok_or(())?;
            let mut rooms = ROOMS.lock().unwrap();
            if !rooms.contains_key(room) && rooms.len() >= MAX_ROOMS {
                return Err(());
            }
            let peers = rooms.entry(room.into()).or_default();
            if peers.len() >= MAX_PEERS || peers.contains_key(peer) {
                return Err(());
            }
            ctx.text(serde_json::json!({"type":"joined", "peers":peers.keys().collect::<Vec<_>>(), "iceServers":ice_servers(peer)}).to_string());
            let notice = serde_json::json!({"type":"peer", "peer":peer}).to_string();
            for addr in peers.values() {
                addr.try_send(Signal(notice.clone())).map_err(|_| ())?;
            }
            peers.insert(peer.into(), ctx.address());
            self.room = Some(room.into());
            self.peer = peer.into();
            return Ok(());
        }
        let kind = message["type"].as_str().ok_or(())?;
        if kind != "offer" && kind != "answer" {
            return Err(());
        }
        let target = message["to"].as_str().ok_or(())?;
        let sdp = message["sdp"]
            .as_str()
            .filter(|s| s.len() <= 60 * 1024)
            .ok_or(())?;
        let rooms = ROOMS.lock().unwrap();
        let addr = rooms
            .get(self.room.as_ref().unwrap())
            .and_then(|peers| peers.get(target))
            .ok_or(())?;
        addr.try_send(Signal(
            serde_json::json!({"type":kind,"from":self.peer,"sdp":sdp}).to_string(),
        ))
        .map_err(|_| ())
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for SignalSocket {
    fn handle(&mut self, message: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match message {
            Ok(ws::Message::Text(text)) => {
                if self.text(&text, ctx).is_err() {
                    ctx.close(None);
                    ctx.stop();
                }
            }
            Ok(ws::Message::Ping(bytes)) => {
                self.heartbeat = Instant::now();
                ctx.pong(&bytes);
            }
            Ok(ws::Message::Pong(_)) => self.heartbeat = Instant::now(),
            _ => {
                ctx.close(None);
                ctx.stop();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn room_ids_require_full_random_tokens() {
        assert!(valid_id(&"a1".repeat(32)));
        assert!(!valid_id("workspace-name"));
        assert!(!valid_id(&"z".repeat(64)));
        assert!(!valid_id(&"a".repeat(63)));
    }
}
