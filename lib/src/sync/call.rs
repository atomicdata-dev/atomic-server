//! Host ABI calls between nodes: `CALL` / `CALL_RESULT` on an Iroh stream.
//!
//! A node that has no local provider for an interface in a drive may forward
//! the call to a peer it syncs the drive with. This module is only the
//! transport. The rights model lives with the host ABI (the server crate):
//! it registers a [`CallHandler`], which runs the call on the responding node.
//!
//! Auth across the hop is the stream's ordinary `AUTH`, signed by the dialing
//! *node's* agent and bound to `drive#nodeId`, like a sync. The caller's own
//! key is not on this node, so the `CALL` names the caller and the node
//! vouches for it; the handler decides what that is worth.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock},
    time::Duration,
};

pub use iroh::Endpoint;

use super::protocol::{self, CallFailure, CallRequest, CallResponse};
use crate::{agents::ForAgent, Db, Storelike};

/// The boxed future a handler returns.
pub type CallFuture<'a> = Pin<Box<dyn Future<Output = CallResponse> + Send + 'a>>;

/// Runs a forwarded call on this node. Registered by the host ABI.
pub trait CallHandler: Send + Sync {
    /// `via` is the agent the peer proved on this connection (the forwarding
    /// node's), not the caller named in `request`.
    fn call(&self, store: Db, via: ForAgent, request: CallRequest) -> CallFuture<'_>;
}

static HANDLER: RwLock<Option<Arc<dyn CallHandler>>> = RwLock::new(None);

/// Registers (or replaces) the handler for `CALL` frames.
pub fn set_call_handler(handler: Arc<dyn CallHandler>) {
    if let Ok(mut slot) = HANDLER.write() {
        *slot = Some(handler);
    }
}

fn failure(code: &str, message: impl Into<String>) -> CallResponse {
    CallResponse {
        error: Some(CallFailure {
            code: code.into(),
            message: message.into(),
        }),
        ..Default::default()
    }
}

/// Answers one `CALL` payload (after the tag) on an authenticated stream.
///
/// `paired` is whether the owner of this node chose to sync with the peer: a
/// call runs apps and spends their secrets, so a peer that merely found this
/// node (and can authenticate as some agent) is not served.
pub(crate) async fn serve(
    payload: &[u8],
    store: &Db,
    via: &ForAgent,
    paired: bool,
) -> Vec<Vec<u8>> {
    let Some((id, request)) = protocol::decode_call(payload) else {
        return vec![protocol::encode_error(
            0,
            protocol::error_code::UNKNOWN,
            "CALL payload does not parse",
        )];
    };
    let handler = HANDLER.read().ok().and_then(|slot| slot.clone());
    let response = match handler {
        _ if !paired => failure("forbidden", "only a paired peer may forward a call here"),
        Some(handler) => handler.call(store.clone(), via.clone(), request).await,
        None => failure("unsupported", "this node does not run apps for peers"),
    };
    vec![protocol::encode_call_result(id, &response)]
}

/// The drive a `CALL` frame names, for the AUTH ↔ drive binding.
pub(crate) fn frame_drive(payload: &[u8]) -> Option<String> {
    protocol::decode_call(payload).map(|(_, r)| r.drive)
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// The responder runs the whole chain, which the host bounds at 30 s.
const RESULT_TIMEOUT: Duration = Duration::from_secs(40);

async fn write_frame(send: &mut iroh::endpoint::SendStream, frame: &[u8]) -> Result<(), String> {
    send.write_all(&(frame.len() as u32).to_be_bytes())
        .await
        .map_err(|e| e.to_string())?;
    send.write_all(frame).await.map_err(|e| e.to_string())
}

/// Calls `request` on `remote_node_id`: connect, `AUTH` as this node's agent
/// for `request.drive`, `CALL`, wait for `CALL_RESULT`. `Err` is a transport
/// failure; an answer from the peer, error or not, is `Ok`.
pub async fn call_peer_using(
    endpoint: &Endpoint,
    store: &Db,
    remote_node_id: &str,
    request: &CallRequest,
) -> Result<CallResponse, String> {
    use tokio::io::AsyncReadExt;

    let remote_key = super::peer::normalize_node_id(remote_node_id);
    let node_id: iroh::NodeId = remote_key
        .parse()
        .map_err(|e| format!("invalid NodeID '{remote_node_id}': {e}"))?;
    let dial = super::peer::dial_target(store, node_id);
    let conn = tokio::time::timeout(
        CONNECT_TIMEOUT,
        endpoint.connect(dial, super::peer::ATOMIC_ALPN),
    )
    .await
    .map_err(|_| "connect timed out".to_string())?
    .map_err(|e| format!("connect failed: {e}"))?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;

    // The same proof a sync sends: this node's agent, for this drive, naming
    // the node it dials.
    let agent = store.get_default_agent().map_err(|e| e.to_string())?;
    let auth = protocol::encode_auth(
        &agent,
        &super::peer::auth_subject_for(
            &crate::identifiers::to_legacy_scheme(&request.drive),
            &remote_key,
        ),
    )
    .map_err(|e| e.to_string())?;
    write_frame(&mut send, &auth).await?;
    write_frame(&mut send, &protocol::encode_call(1, request)).await?;

    let read = async {
        let mut authed = false;
        loop {
            let len = recv.read_u32().await.map_err(|e| e.to_string())? as usize;
            let cap = if authed {
                protocol::IROH_FRAME_MAX_BYTES
            } else {
                protocol::IROH_PREAUTH_FRAME_MAX_BYTES
            };
            if len == 0 || len > cap {
                return Err("peer sent a frame of unacceptable size".to_string());
            }
            let mut buf = vec![0u8; len];
            recv.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
            match buf[0] {
                protocol::tag::AUTH_OK => authed = true,
                protocol::tag::CALL_RESULT => {
                    return protocol::decode_call_result(&buf[1..])
                        .map(|(_, r)| r)
                        .ok_or_else(|| "CALL_RESULT does not parse".to_string());
                }
                protocol::tag::ERROR => {
                    let message = protocol::decode_error(&buf[1..])
                        .map(|e| e.message)
                        .unwrap_or_default();
                    return Err(format!("peer refused: {message}"));
                }
                // HELLO and the peer's auth-back AUTH are not for us.
                _ => {}
            }
        }
    };
    let outcome = tokio::time::timeout(RESULT_TIMEOUT, read)
        .await
        .map_err(|_| "no answer from the peer".to_string())?;
    let _ = send.finish();
    outcome
}

/// [`call_peer_using`] on the peers this node syncs `request.drive` with
/// ([`super::peer::KnownPeer::drives`]), in order, until one answers with
/// anything but `not-found`. `None` when no peer knows the drive or none could
/// be reached.
pub async fn call_known_peers_using(
    endpoint: &Endpoint,
    store: &Db,
    request: &CallRequest,
) -> Option<CallResponse> {
    let mut last = None;
    for peer in super::peer::get_known_peers(store) {
        if !peer.drives.iter().any(|d| d == &request.drive) {
            continue;
        }
        match call_peer_using(endpoint, store, &peer.node_id, request).await {
            Ok(response) => {
                let missing = response
                    .error
                    .as_ref()
                    .is_some_and(|e| e.code == "not-found");
                if !missing {
                    return Some(response);
                }
                last = Some(response);
            }
            Err(e) => tracing::warn!("[call] peer {} unreachable: {e}", peer.node_id),
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{peer, protocol::CallBudgetWire};
    use iroh::protocol::Router;

    /// Answers with what it saw, so the test can read the rights off the wire.
    struct Echo;

    impl CallHandler for Echo {
        fn call(&self, _store: Db, via: ForAgent, request: CallRequest) -> CallFuture<'_> {
            Box::pin(async move {
                CallResponse {
                    result: Some(format!("{via}|{}|{}", request.caller, request.depth)),
                    calls_left: request.budget.calls.saturating_sub(1),
                    fuel_left: request.budget.fuel,
                    ..Default::default()
                }
            })
        }
    }

    #[test]
    fn frames_round_trip() {
        let request = CallRequest {
            drive: "did:ad:drive".into(),
            interface: "atomic:example/counter@1".into(),
            function: "increment".into(),
            args: "{}".into(),
            caller: "did:ad:agent:x".into(),
            depth: 2,
            budget: CallBudgetWire {
                calls: 3,
                fuel: 4,
                effects: Some(vec!["read".into()]),
                secrets: false,
            },
        };
        let frame = protocol::encode_call(7, &request);
        assert_eq!(frame[0], protocol::tag::CALL);
        assert_eq!(protocol::decode_call(&frame[1..]), Some((7, request)));

        let response = CallResponse {
            result: Some("{}".into()),
            calls_left: 1,
            ..Default::default()
        };
        let frame = protocol::encode_call_result(7, &response);
        assert_eq!(frame[0], protocol::tag::CALL_RESULT);
        assert_eq!(
            protocol::decode_call_result(&frame[1..]),
            Some((7, response))
        );
        assert!(protocol::decode_call(&[0]).is_none());
    }

    /// Node A (the responder) with a drive, and a dialing endpoint that is node
    /// B's, with B's own store signed in as the same person.
    async fn pair_of_nodes(name: &str) -> (Db, Db, Endpoint, String, String, Router) {
        let db_a = Db::init_temp(&format!("{name}_a")).await.unwrap();
        let (agent, drive) = db_a.setup("Alice").await.unwrap();
        let db_b = Db::init_temp(&format!("{name}_b")).await.unwrap();
        db_b.load_agent_from_secret(&agent.build_secret().unwrap())
            .await
            .unwrap();
        let (node_a, router_a) = peer::start(db_a.clone()).await.unwrap();
        set_call_handler(Arc::new(Echo));
        let ep_b = Endpoint::builder()
            .discovery_n0()
            .discovery_local_network()
            .bind()
            .await
            .unwrap();
        ep_b.add_node_addr(router_a.endpoint().node_addr().await.unwrap())
            .unwrap();
        // The router must outlive the call: only the first test's router is
        // kept by the global, a later one stops serving once dropped.
        (db_a, db_b, ep_b, node_a.to_string(), drive, router_a)
    }

    fn some_call(drive: &str) -> CallRequest {
        CallRequest {
            drive: drive.into(),
            interface: "i".into(),
            function: "f".into(),
            args: "{}".into(),
            caller: "did:ad:agent:someone".into(),
            depth: 1,
            budget: CallBudgetWire {
                calls: 5,
                fuel: 9,
                effects: None,
                secrets: true,
            },
        }
    }

    /// A dialer's CALL reaches the responder's handler authenticated as the
    /// dialing node's agent, and the answer comes back.
    #[tokio::test]
    async fn a_call_reaches_the_peer_as_the_dialing_nodes_agent() {
        let (db_a, db_b, ep_b, node_a, drive, _router) = pair_of_nodes("call_peer").await;
        // The owner of A paired with B.
        peer::add_known_peer(&db_a, &ep_b.node_id().to_string(), "b");

        let answer = call_peer_using(&ep_b, &db_b, &node_a, &some_call(&drive))
            .await
            .unwrap();
        let via = db_b.get_default_agent().unwrap().subject;
        assert_eq!(
            answer.result.as_deref(),
            Some(format!("{via}|did:ad:agent:someone|1").as_str())
        );
        assert_eq!((answer.calls_left, answer.fuel_left), (4, 9));
    }

    /// A call runs apps and spends their secrets: a node that authenticates
    /// but that the owner never paired with is not served.
    #[tokio::test]
    async fn a_call_from_a_node_that_was_never_paired_is_refused() {
        let (_db_a, db_b, ep_b, node_a, drive, _router) = pair_of_nodes("call_unpaired").await;

        let answer = call_peer_using(&ep_b, &db_b, &node_a, &some_call(&drive))
            .await
            .unwrap();
        assert!(answer.result.is_none(), "{answer:?}");
        assert_eq!(answer.error.map(|e| e.code).as_deref(), Some("forbidden"));
    }
}
