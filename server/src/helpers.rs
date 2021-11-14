//! Functions useful in the server

use actix_web::http::HeaderMap;
use atomic_lib::authentication::AuthValues;

use crate::errors::AtomicServerResult;

// Returns None if the string is empty.
// Useful for parsing form inputs.
pub fn empty_to_nothing(string: Option<String>) -> Option<String> {
    match string.as_ref() {
        Some(st) => {
            if st.is_empty() {
                None
            } else {
                string
            }
        }
        None => None,
    }
}

/// Returns the authentication headers from the request
pub fn get_auth_headers(
    map: &HeaderMap,
    requested_subject: String,
) -> AtomicServerResult<Option<AuthValues>> {
    let public_key = map.get("x-atomic-public-key");
    let signature = map.get("x-atomic-signature");
    let timestamp = map.get("x-atomic-timestamp");
    let agent = map.get("x-atomic-agent");
    match (public_key, signature, timestamp, agent) {
        (Some(pk), Some(sig), Some(ts), Some(a)) => Ok(Some(AuthValues {
            public_key: pk
                .to_str()
                .map_err(|_e| "Only string headers allowed")?
                .to_string(),
            signature: sig
                .to_str()
                .map_err(|_e| "Only string headers allowed")?
                .to_string(),
            agent_subject: a
                .to_str()
                .map_err(|_e| "Only string headers allowed")?
                .to_string(),
            timestamp: ts
                .to_str()
                .map_err(|_e| "Only string headers allowed")?
                .parse::<i64>()
                .map_err(|_e| "Timestamp must be a number (milliseconds since unix epoch)")?,
            requested_subject,
        })),
        (None, None, None, None) => Ok(None),
        _missing => Err("Missing authentication headers. You need `x-atomic-public-key`, `x-atomic-signature`, `x-atomic-agent` and `x-atomic-timestamp` for authentication checks.".into()),
    }
}
