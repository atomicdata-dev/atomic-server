//! Check signatures in authentication headers, find the correct agent. Authorization is done in Hierarchies

use crate::{
    agents::{decode_base64, ForAgent},
    commit::check_timestamp,
    errors::AtomicResult,
    urls, Storelike,
};

/// Set of values extracted from the request.
/// Most are coming from headers.
#[derive(serde::Deserialize)]
pub struct AuthValues {
    // x-atomic-public-key
    #[serde(rename = "https://atomicdata.dev/properties/auth/publicKey")]
    pub public_key: String,
    // x-atomic-timestamp
    #[serde(rename = "https://atomicdata.dev/properties/auth/timestamp")]
    pub timestamp: i64,
    // x-atomic-signature
    // Base64 encoded public key from `subject_url timestamp`
    #[serde(rename = "https://atomicdata.dev/properties/auth/signature")]
    pub signature: String,
    #[serde(rename = "https://atomicdata.dev/properties/auth/requestedSubject")]
    pub requested_subject: String,
    #[serde(rename = "https://atomicdata.dev/properties/auth/agent")]
    pub agent_subject: String,
}

/// Checks if the signature is valid for this timestamp.
/// Does not check if the agent has rights to access the subject.
#[tracing::instrument(skip_all)]
pub fn check_auth_signature(subject: &str, auth_header: &AuthValues) -> AtomicResult<()> {
    let agent_pubkey = decode_base64(&auth_header.public_key)?;
    let message = format!("{} {}", subject, &auth_header.timestamp);
    let peer_public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, agent_pubkey);
    let signature_bytes = decode_base64(&auth_header.signature)?;
    peer_public_key
                .verify(message.as_bytes(), &signature_bytes)
                .map_err(|_e| {
                    format!(
                        "Incorrect signature for auth headers. This could be due to an error during signing or serialization of the commit. Compare this to the serialized message in the client: '{}'",
                        message,
                    )
                })?;
    Ok(())
}

/// Get the Agent's subject from [AuthValues]
/// Checks if the auth headers are correct, whether signature matches the public key, whether the timestamp is valid.
/// by default, returns the public agent
#[tracing::instrument(skip_all)]
pub fn get_agent_from_auth_values_and_check(
    auth_header_values: Option<AuthValues>,
    store: &impl Storelike,
) -> AtomicResult<ForAgent> {
    if let Some(auth_vals) = auth_header_values {
        // If there are auth headers, check 'em, make sure they are valid.
        check_auth_signature(&auth_vals.requested_subject, &auth_vals)
            .map_err(|e| format!("Error checking authentication headers. {}", e))?;
        // check if the timestamp is valid
        check_timestamp(auth_vals.timestamp)?;
        // check if the public key belongs to the agent
        let found_public_key = store.get_value(&auth_vals.agent_subject, urls::PUBLIC_KEY)?;
        if found_public_key.to_string() != auth_vals.public_key {
            Err(
                "The public key in the auth headers does not match the public key in the agent"
                    .to_string()
                    .into(),
            )
        } else {
            Ok(ForAgent::AgentSubject(auth_vals.agent_subject))
        }
    } else {
        Ok(ForAgent::Public)
    }
}

// fn get_agent_from_value_index() {
//     let map = store.get_prop_subject_map(&auth_vals.public_key)?;
//     let agents = map.get(crate::urls::PUBLIC_KEY).ok_or(format!(
//         "No agents for this public key: {}",
//         &auth_vals.public_key
//     ))?;
//     // TODO: This is unreliable, as this will break if multiple atoms with the same public key exist.
//     if agents.len() > 1 {
//         return Err("Multiple agents for this public key".into());
//     } else if let Some(found) = agents.iter().next() {
//         for_agent = Some(found.to_string());
//     }
// }
