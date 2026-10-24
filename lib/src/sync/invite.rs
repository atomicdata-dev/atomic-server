//! Redeeming an invite without a server: `INVITE` / `INVITE_OK` on an Iroh
//! stream.
//!
//! An invite token (`crate::invite_token`) is signed by the inviter's agent
//! and names its target. A server is not needed to honour it: any device
//! that holds the inviter's agent and the target can sign the rights change
//! itself. The invitee finds such a device the way it finds any device of a
//! drive (the pkarr record lists the node ids) and dials it.
//!
//! The responder grants only when all of these hold, so a device that merely
//! stores the drive can never be talked into sharing it:
//! - the token has not expired,
//! - the token's signer is **this node's own agent** (only then can this node
//!   sign the change as the inviter) and the signature verifies,
//! - that agent may still write the target in this node's store,
//! - the `AUTH` on the stream proved who the invitee is.
//!
//! It then adds the invitee to the target's `read` (and, for a write invite,
//! `write`) list in a commit signed by this node's agent, queues it for the
//! inviter's servers and lets live peers carry it to the inviter's other
//! devices. The invitee afterwards syncs the drive from this node like any
//! peer, and the sync policy admits it because it can now read.
//!
//! Not enforced here: `max_usages`. Counting acceptances needs state that all
//! the inviter's devices share; a peer redemption is as often as the token
//! is opened. Expiry and the rights check still apply.

use std::time::Duration;

pub use iroh::Endpoint;

use super::protocol::{self, InviteGranted};
use crate::{
    agents::ForAgent,
    invite_token::{grant_rights, InviteToken},
    Db, Storelike,
};

fn refuse(message: &str) -> Vec<Vec<u8>> {
    vec![protocol::encode_error(
        0,
        protocol::error_code::INVITE_REFUSED,
        message,
    )]
}

/// What a person sees when the invite itself has run out.
pub const EXPIRED: &str = "This invite has expired. Ask for a new one.";

/// The drive an `INVITE` frame names, for the AUTH ↔ drive binding.
pub(crate) fn frame_drive(payload: &[u8]) -> Option<String> {
    let token = InviteToken::decode(&protocol::decode_invite(payload)?).ok()?;
    Some(token.target.to_string())
}

/// Answers one `INVITE` payload (after the tag) on an authenticated stream.
/// `via` is the agent the peer proved on this connection: the invitee.
pub(crate) async fn serve(payload: &[u8], store: &Db, via: &ForAgent) -> Vec<Vec<u8>> {
    let invitee = match via {
        ForAgent::AgentSubject(s) => s.to_string(),
        _ => return refuse("Sign in before you open an invite."),
    };
    let Some(token) =
        protocol::decode_invite(payload).and_then(|raw| InviteToken::decode(&raw).ok())
    else {
        return refuse("This invite is damaged. Ask for a new one.");
    };
    if token.check_expiry(crate::utils::now()).is_err() {
        return refuse(EXPIRED);
    }
    let agent = match store.get_default_agent() {
        Ok(a) => a,
        Err(_) => return refuse("This device has no account to share from."),
    };
    if token.signer != agent.subject {
        return refuse("This device did not make this invite, so it cannot accept it.");
    }
    if token.verify_signature(&agent.public_key).is_err() {
        return refuse("This invite is damaged. Ask for a new one.");
    }
    if store.get_resource(&token.target.clone()).await.is_err() {
        return refuse("This device does not have the shared drive.");
    }
    if token.check_signer_may_write(store).await.is_err() {
        return refuse("The person who made this invite can no longer share this.");
    }

    let target = token.target.to_string();
    let outbox = super::outbox::Outbox::new(store.clone());
    // A write right is also a read right (the Share dialog lists writers as
    // readers), so no reader has to infer it.
    for write in [false, true] {
        if write && !token.write {
            continue;
        }
        match grant_rights(&invitee, &target, write, store).await {
            Ok(response) => {
                let _ = outbox.mark_dirty(&response).await;
            }
            Err(e) => {
                tracing::warn!("[invite] could not grant {invitee} on {target}: {e}");
                return refuse("Could not share this just now. Try again.");
            }
        }
    }
    tracing::info!(
        "[invite] {invitee} may now {} {target}",
        if token.write { "edit" } else { "read" }
    );
    vec![protocol::encode_invite_ok(&InviteGranted {
        drive: target,
        write: token.write,
    })]
}

/// Why a redemption failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemError {
    /// Whether a device answered. `false`: nothing could be reached.
    pub reached: bool,
    /// A plain sentence for the person.
    pub message: String,
}

impl std::fmt::Display for RedeemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<RedeemError> for crate::errors::AtomicError {
    fn from(e: RedeemError) -> Self {
        e.message.into()
    }
}

/// Said when no device that holds the drive answers.
pub const OFFLINE: &str =
    "The device that made this invite is offline. Ask them to open the app, then try again.";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const ANSWER_TIMEOUT: Duration = Duration::from_secs(20);

fn unreached(message: impl Into<String>) -> RedeemError {
    RedeemError {
        reached: false,
        message: message.into(),
    }
}

async fn write_frame(send: &mut iroh::endpoint::SendStream, frame: &[u8]) -> Result<(), String> {
    send.write_all(&(frame.len() as u32).to_be_bytes())
        .await
        .map_err(|e| e.to_string())?;
    send.write_all(frame).await.map_err(|e| e.to_string())
}

/// Redeems `token` at one device: connect, `AUTH` as this node's agent for the
/// token's target, `INVITE`, wait for `INVITE_OK`.
pub async fn redeem_at(
    endpoint: &Endpoint,
    store: &Db,
    remote_node_id: &str,
    token: &str,
) -> Result<InviteGranted, RedeemError> {
    use tokio::io::AsyncReadExt;

    let parsed = InviteToken::decode(token)
        .map_err(|_| unreached("This is not a valid invite. Check the link and try again."))?;
    if parsed.check_expiry(crate::utils::now()).is_err() {
        return Err(unreached(EXPIRED));
    }
    let remote_key = super::peer::normalize_node_id(remote_node_id);
    let node_id: iroh::NodeId = remote_key
        .parse()
        .map_err(|_| unreached("That device address is not valid."))?;
    let dial = super::peer::dial_target(store, node_id);
    let conn = tokio::time::timeout(
        CONNECT_TIMEOUT,
        endpoint.connect(dial, super::peer::ATOMIC_ALPN),
    )
    .await
    .map_err(|_| unreached(OFFLINE))?
    .map_err(|_| unreached(OFFLINE))?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(|_| unreached(OFFLINE))?;

    let agent = store
        .get_default_agent()
        .map_err(|_| unreached("Sign in before you open an invite."))?;
    let auth = protocol::encode_auth(
        &agent,
        &super::peer::auth_subject_for(
            &crate::identifiers::to_legacy_scheme(parsed.target.as_str()),
            &remote_key,
        ),
    )
    .map_err(|e| unreached(e.to_string()))?;
    write_frame(&mut send, &auth).await.map_err(unreached)?;
    write_frame(&mut send, &protocol::encode_invite(token))
        .await
        .map_err(unreached)?;

    let read = async {
        let mut authed = false;
        loop {
            let len = recv.read_u32().await.map_err(|_| unreached(OFFLINE))? as usize;
            let cap = if authed {
                protocol::IROH_FRAME_MAX_BYTES
            } else {
                protocol::IROH_PREAUTH_FRAME_MAX_BYTES
            };
            if len == 0 || len > cap {
                return Err(unreached("The other device sent something unreadable."));
            }
            let mut buf = vec![0u8; len];
            recv.read_exact(&mut buf)
                .await
                .map_err(|_| unreached(OFFLINE))?;
            match buf[0] {
                protocol::tag::AUTH_OK => authed = true,
                protocol::tag::INVITE_OK => {
                    return protocol::decode_invite_ok(&buf[1..])
                        .ok_or_else(|| unreached("The other device sent something unreadable."));
                }
                protocol::tag::ERROR => {
                    let message = protocol::decode_error(&buf[1..])
                        .map(|e| e.message)
                        .filter(|m| !m.is_empty())
                        .unwrap_or_else(|| "The other device refused this invite.".into());
                    return Err(RedeemError {
                        reached: true,
                        message,
                    });
                }
                // HELLO and the peer's auth-back AUTH are not for us.
                _ => {}
            }
        }
    };
    let outcome = tokio::time::timeout(ANSWER_TIMEOUT, read)
        .await
        .map_err(|_| unreached(OFFLINE))?;
    let _ = send.finish();
    outcome
}

/// [`redeem_at`] on each of `node_ids` until one grants. A device that answers
/// with a refusal is remembered, the rest are still tried (another device of
/// the inviter may hold the account); when none grants, the refusal wins over
/// "offline" because it says something the person can act on.
pub async fn redeem_at_any(
    endpoint: &Endpoint,
    store: &Db,
    node_ids: &[String],
    token: &str,
) -> Result<(InviteGranted, String), RedeemError> {
    let mut refusal: Option<RedeemError> = None;
    let mut last: Option<RedeemError> = None;
    for id in node_ids {
        match redeem_at(endpoint, store, id, token).await {
            Ok(granted) => return Ok((granted, id.clone())),
            Err(e) if e.reached => {
                refusal.get_or_insert(e);
            }
            Err(e) => last = Some(e),
        }
    }
    Err(refusal.or(last).unwrap_or_else(|| unreached(OFFLINE)))
}
