//! Check signatures in authentication headers, find the correct agent. Authorization is done in Hierarchies

use crate::{
    agents::{decode_base64, ForAgent},
    errors::AtomicResult,
    urls,
    utils::check_timestamp_fresh,
    Storelike,
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
    let pubkey_bytes: [u8; 32] = agent_pubkey
        .try_into()
        .map_err(|_| "Ed25519 public key must be 32 bytes")?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    let signature_bytes = decode_base64(&auth_header.signature)?;
    let sig_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "Ed25519 signature must be 64 bytes")?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    use ed25519_dalek::Verifier;

    let result = verifying_key.verify(message.as_bytes(), &sig);

    if result.is_err() {
        // The client may have signed the URL without its query string (e.g.
        // it signed `http://host/setup` and the request is `/setup?reset=true`).
        // That form is still bound to the host, so it is accepted.
        //
        // A path-only message (`"/setup <ts>"`) is NOT: such a signature is
        // valid on every host and tenant for the whole timestamp window, and
        // it sidesteps the WebSocket challenge binding, which relies on the
        // full requested subject being what was signed.
        if let Ok(url) = url::Url::parse(subject) {
            if url.query().is_some() {
                let mut url_no_query = url.clone();
                url_no_query.set_query(None);
                let message_no_query = format!("{} {}", url_no_query, &auth_header.timestamp);
                if verifying_key
                    .verify(message_no_query.as_bytes(), &sig)
                    .is_ok()
                {
                    return Ok(());
                }
            }
        }

        // If we haven't returned Ok, return the original error.
        return Err(format!(
            "Incorrect signature for auth headers. This could be due to an error during signing or serialization of the commit. Compare this to the serialized message in the client: {}",
            message,
        )
        .into());
    }

    Ok(())
}

const ACCEPTABLE_TIME_DIFFERENCE: i64 = 10000;

/// How old a signed authentication proof may be, in milliseconds.
///
/// An `AUTH` frame or signed auth header is a bearer proof: whoever holds
/// the bytes is the agent, for as long as the responder accepts them. Until
/// 2026-09 the only timestamp check was "not in the future", so a captured
/// proof never expired. Clients sign immediately before sending (the
/// browser per request and per socket, `WsClient` at `authenticate()`, the
/// Iroh initiator at dial), so a few minutes leaves ample room for clock
/// skew and slow links without turning a capture into a permanent key.
pub const AUTH_MAX_AGE_MS: i64 = 5 * 60 * 1000;

/// Get the Agent's subject from [AuthValues]
/// Checks if the auth headers are correct, whether signature matches the public key, whether the timestamp is valid.
/// by default, returns the public agent
#[tracing::instrument(skip_all)]
pub async fn get_agent_from_auth_values_and_check(
    auth_header_values: Option<AuthValues>,
    store: &impl Storelike,
) -> AtomicResult<ForAgent> {
    if let Some(auth_vals) = auth_header_values {
        // If there are auth headers, check 'em, make sure they are valid.
        check_auth_signature(&auth_vals.requested_subject, &auth_vals)
            .map_err(|e| format!("Error checking authentication headers. {}", e))?;
        // check if the timestamp is valid: not in the future, and not so old
        // that a captured proof could be replayed indefinitely.
        check_timestamp_fresh(
            auth_vals.timestamp,
            ACCEPTABLE_TIME_DIFFERENCE,
            AUTH_MAX_AGE_MS,
        )
        .map_err(|e| format!("Authentication timestamp rejected. {}", e))?;
        // check if the public key belongs to the agent
        // For DID subjects, we need to fetch the agent resource locally
        // unless it's a DID based on the public key, in which case we can verify it directly.
        let agent_subject = crate::Subject::from_raw(auth_vals.agent_subject.trim(), None);
        let public_key_trimmed = auth_vals.public_key.trim();

        if agent_subject.is_did() {
            // The DID subject embeds the agent's public key
            // (`did:ad:agent:{pubkey}`) and the auth header carries the same
            // key. The two may use different base64 alphabets — the url-safe
            // alphabet (the new default) vs the legacy standard alphabet
            // (`+` `/` `=`) — so a raw-string `ends_with` wrongly rejects a key
            // whose decoded BYTES are identical. Compare the decoded bytes.
            let did_pubkey = agent_subject
                .as_str()
                .strip_prefix(crate::subject::DID_AD_AGENT_PREFIX)
                .unwrap_or_else(|| agent_subject.as_str());
            if public_keys_match(did_pubkey, public_key_trimmed) {
                return Ok(ForAgent::AgentSubject(agent_subject));
            } else {
                return Err(format!(
                    "The public key in the auth headers '{}' does not match the DID subject '{}'",
                    public_key_trimmed, auth_vals.agent_subject
                )
                .into());
            }
        }

        // Legacy `https://host/agents/{pubkey}` subjects are treated as
        // `did:ad:agent:{pubkey}` by every rights check, so the key in the
        // path is the identity being claimed: bind it to the signing key.
        // Looking the key up in a resource at that URL instead would let
        // anyone host `https://theirs/agents/<victim key>` carrying their own
        // key and be authorized as the victim (including as the server's own
        // root agent, whose key is public).
        if let Some(path_key) = crate::agents::legacy_agent_pubkey(agent_subject.as_str()) {
            if public_keys_match(&path_key, public_key_trimmed) {
                return Ok(ForAgent::AgentSubject(agent_subject));
            }
            return Err(format!(
                "The public key in the auth headers '{}' does not match the agent subject '{}'",
                public_key_trimmed, auth_vals.agent_subject
            )
            .into());
        }

        // Any other agent subject must be a resource this store already
        // holds. Never fetch it over the network during authentication: that
        // is an unauthenticated SSRF, and the fetched body would be written
        // into the store as a trusted resource.
        let normalized_agent = store.normalize_subject(&agent_subject);
        if !normalized_agent.is_local() {
            return Err(format!(
                "Agent subject '{}' is hosted elsewhere and cannot be used to authenticate here; sign in with a did:ad:agent identity",
                auth_vals.agent_subject
            )
            .into());
        }
        let agent_resource = store.get_resource(&normalized_agent).await?;
        let found_public_key = agent_resource.get(urls::PUBLIC_KEY)?;
        if !public_keys_match(found_public_key.to_string().trim(), public_key_trimmed) {
            Err(
                "The public key in the auth headers does not match the public key in the agent"
                    .to_string()
                    .into(),
            )
        } else {
            Ok(ForAgent::AgentSubject(agent_subject))
        }
    } else {
        Ok(ForAgent::Public)
    }
}

/// Two base64-encoded public keys match if their decoded bytes are equal.
/// Tolerates differing base64 alphabets (url-safe — the new default — vs the
/// legacy standard alphabet with `+` `/` `=`), so an agent whose DID or stored
/// key was minted with one alphabet still authenticates against an auth header
/// using the other. Falls back to `false` if either string can't be decoded.
pub fn public_keys_match(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }

    matches!(
        (
            crate::agents::decode_base64(a),
            crate::agents::decode_base64(b),
        ),
        (Ok(da), Ok(db)) if da == db
    )
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

#[cfg(test)]
mod test {
    use super::public_keys_match;

    /// The same ed25519 key, encoded in the legacy standard base64 alphabet
    /// (as embedded in a legacy agent DID) and in the url-safe alphabet (as
    /// sent in modern auth headers), must be recognised as the same key —
    /// otherwise legacy agents can't authenticate (WS AUTH fails → the client
    /// never gets AUTH_OK → it falls offline and edits never sync).
    #[test]
    fn public_keys_match_across_base64_alphabets() {
        let standard = "gJRZVTGPngaG3mSPA/e6LEewKixYpZtuUYQhNg+t7Y4=";
        let url_safe = "gJRZVTGPngaG3mSPA_e6LEewKixYpZtuUYQhNg-t7Y4";
        assert!(
            public_keys_match(standard, url_safe),
            "standard and url-safe encodings of the same key should match"
        );
        assert!(public_keys_match(standard, standard));
        assert!(public_keys_match(url_safe, url_safe));
    }

    #[test]
    fn public_keys_match_rejects_different_keys() {
        let a = "gJRZVTGPngaG3mSPA_e6LEewKixYpZtuUYQhNg-t7Y4";
        let b = "AAAAVTGPngaG3mSPA_e6LEewKixYpZtuUYQhNg-t7Y4";
        assert!(!public_keys_match(a, b));
    }
}
