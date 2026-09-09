use crate::{
    appstate::AppState, context::RequestContext, errors::AtomicServerResult,
    helpers::get_client_agent,
};
use actix_web::{web, HttpRequest, HttpResponse};
use atomic_lib::agents::ForAgent;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ForgetPeerParams {
    /// The peer's node id, as `did:ad:node:<hex>` or raw hex.
    pub node: String,
}

/// `POST /forget-peer?node=<did:ad:node:...>` — stop syncing with a paired
/// device. A browser tab is not itself a node, so this is how someone reading a
/// server disconnects the phone that paired with it.
///
/// Requires write on a drive this node dialed the peer for (recorded on the
/// [`KnownPeer`](atomic_lib::sync::peer::KnownPeer) at pairing time), or the
/// node's own agent (the desktop/mobile user, who adopted the node's identity
/// at sign-in; in Owner host mode, the owner). A merely valid signature is not
/// enough: any `did:ad:agent:` key authenticates without being known to this
/// store, so "signed-in" would let anyone on the internet drop the operator's
/// paired devices. Not gated on root-write either, which would lock out a
/// drive owner who is not the node's root admin (a phone that pushed its drive
/// here owns that drive, not the server root): whoever may write the drive
/// chose to sync it with that device, and may undo that. A peer recorded
/// before drives were tracked can only be forgotten by the node's own agent.
///
/// This drops the live connection and removes the reconnect entry. It does not
/// blocklist: a device that actively dials again will reconnect, because the
/// pairing is mutual and only the other device can forget its side.
/// The node's own agent, the Owner-mode owner, or Sudo.
fn is_node_admin(appstate: &AppState, for_agent: &ForAgent) -> bool {
    use atomic_lib::Storelike;
    match for_agent {
        ForAgent::Sudo => true,
        ForAgent::Public => false,
        ForAgent::AgentSubject(subject) => {
            let store = &appstate.store;
            let agent = store.normalize_subject(subject);
            if appstate.config.host_mode.is_owner(&agent.to_string()) {
                return true;
            }
            store
                .get_default_agent()
                .map(|own| store.normalize_subject(&own.subject) == agent)
                .unwrap_or(false)
        }
    }
}

/// Whether `for_agent` may write any of the drives this node dialed `node`
/// for. `false` for an unknown peer or one recorded without drives.
async fn may_write_a_paired_drive(
    store: &atomic_lib::Db,
    node: &str,
    for_agent: &ForAgent,
) -> bool {
    use atomic_lib::Storelike;
    let key = atomic_lib::sync::peer::normalize_node_id(node);
    let Some(peer) = atomic_lib::sync::peer::get_known_peers(store)
        .into_iter()
        .find(|p| atomic_lib::sync::peer::normalize_node_id(&p.node_id) == key)
    else {
        return false;
    };
    for drive in &peer.drives {
        if let Ok(drive_resource) = store
            .get_resource(&atomic_lib::Subject::from(drive.as_str()))
            .await
        {
            if atomic_lib::hierarchy::check_write(store, &drive_resource, for_agent)
                .await
                .is_ok()
            {
                return true;
            }
        }
    }
    false
}

#[tracing::instrument(skip_all)]
pub async fn handle_forget_peer(
    appstate: web::Data<AppState>,
    params: web::Query<ForgetPeerParams>,
    req: HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let store = &appstate.store;
    let origin = RequestContext::new(&req, &appstate).origin;

    // The client signs the full request URL (path + query); rebuild it exactly
    // so the signature check matches what it signed.
    let full_url = format!("{}{}", origin, req.uri());
    let for_agent = get_client_agent(req.headers(), &appstate, &full_url).await?;

    let node = params.node.clone();
    if !is_node_admin(&appstate, &for_agent)
        && !may_write_a_paired_drive(store, &node, &for_agent).await
    {
        return Err(atomic_lib::errors::AtomicError::unauthorized(
            "Forgetting a device requires write rights on a drive it was paired for.".into(),
        )
        .into());
    }

    // Unconditional: the user asked to drop this device, so whichever
    // connection currently holds the link should go. `remove_live_peer` is for
    // a connection retiring itself and refuses if a newer one has replaced it.
    crate::iroh_transport::remove_live_peer_any(&node);
    crate::iroh_transport::remove_known_peer(store, &node);

    Ok(HttpResponse::Ok().json(serde_json::json!({ "ok": true })))
}
