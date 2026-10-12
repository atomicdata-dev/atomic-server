//! Self-contained signed tokens, so the authorization server keeps no state.
//!
//! `kind.payload.mac`: a kind tag, the claims as base64url JSON, and a keyed
//! BLAKE3 MAC over both. The key is derived from the node key for this one
//! purpose, so it cannot be used to open a stored secret and vice versa. A
//! token made for one kind (a client id, an authorization code, an access
//! token) is refused as any other.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::appstate::AppState;

const CONTEXT: &str = "atomic-server 2026-09 hosted MCP token key v1";
const AGENT_CONTEXT: &str = "atomic-server 2026-09 hosted MCP issued agent v1";

pub const CLIENT: &str = "client";
pub const CODE: &str = "code";
pub const ACCESS: &str = "access";
pub const REFRESH: &str = "refresh";

/// How long a token is good for, in seconds.
pub const CODE_TTL: i64 = 120;
pub const ACCESS_TTL: i64 = 60 * 60;
pub const REFRESH_TTL: i64 = 60 * 60 * 24 * 90;
pub const CLIENT_TTL: i64 = 60 * 60 * 24 * 365;

#[derive(Serialize, Deserialize)]
struct Envelope<T> {
    exp: i64,
    #[serde(flatten)]
    claims: T,
}

/// A dynamically registered OAuth client. The id is this, signed: nothing to
/// store, and a redirect URI that was not registered can never be forged.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Client {
    pub name: String,
    pub redirect_uris: Vec<String>,
}

/// What an authorization code stands for. Bound to the client, the redirect
/// URI and the PKCE challenge it was issued for.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Code {
    pub agent: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub challenge: String,
    /// The person who approved, and the nonce of the issued agent: what the
    /// node needs to derive the agent's key again when the client writes.
    pub person: String,
    pub nonce: String,
    /// Whether the person let the client edit, not only read.
    pub write: bool,
}

/// An access or refresh token: the issued agent it acts as. Reading is
/// always through the agent's rights; `write` is the person's separate say on
/// whether the client may also change things, checked on top of those rights.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Grant {
    pub agent: String,
    pub client_id: String,
    pub person: String,
    pub nonce: String,
    pub write: bool,
}

impl Grant {
    /// The scope string OAuth clients see.
    pub fn scope(&self) -> &'static str {
        if self.write {
            "read write"
        } else {
            "read"
        }
    }

    /// The issued agent, with its key, so the node can sign for it.
    pub fn agent_key(&self, appstate: &AppState) -> Result<atomic_lib::agents::Agent, String> {
        issued_agent(appstate, &self.person, &self.client_id, &self.nonce, None)
    }
}

fn key(appstate: &AppState) -> Result<[u8; 32], String> {
    appstate.store.derive_node_key(CONTEXT).ok_or_else(|| {
        "This node has no key, so it cannot issue MCP tokens. Start it once normally to create one."
            .to_string()
    })
}

pub fn now() -> i64 {
    atomic_lib::utils::now() / 1000
}

fn mac(key: &[u8; 32], kind: &str, payload: &str) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(kind.as_bytes());
    hasher.update(b".");
    hasher.update(payload.as_bytes());
    hasher.finalize()
}

pub fn sign<T: Serialize>(
    appstate: &AppState,
    kind: &str,
    ttl: i64,
    claims: &T,
) -> Result<String, String> {
    let key = key(appstate)?;
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&Envelope {
            exp: now() + ttl,
            claims,
        })
        .map_err(|e| e.to_string())?,
    );
    let tag = URL_SAFE_NO_PAD.encode(mac(&key, kind, &payload).as_bytes());

    Ok(format!("{kind}.{payload}.{tag}"))
}

/// The claims of a token of `kind`, or why it is not good. `blake3::Hash`
/// compares in constant time.
pub fn verify<T: DeserializeOwned>(
    appstate: &AppState,
    kind: &str,
    token: &str,
) -> Result<T, String> {
    let key = key(appstate)?;
    let mut parts = token.split('.');
    let (Some(k), Some(payload), Some(tag), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("Malformed token".into());
    };
    if k != kind {
        return Err("Wrong kind of token".into());
    }
    let given: [u8; 32] = URL_SAFE_NO_PAD
        .decode(tag)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("Malformed token")?;
    if mac(&key, kind, payload) != blake3::Hash::from_bytes(given) {
        return Err("Invalid token signature".into());
    }
    let envelope: Envelope<T> = URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or("Malformed token")?;
    if envelope.exp < now() {
        return Err("Expired token".into());
    }

    Ok(envelope.claims)
}

/// The agent the node issues for one approval: an Ed25519 identity derived
/// from the node key, the approving person, the client and a nonce. Nobody
/// stores its private key: the node derives it again from the claims in the
/// token when the client writes, and signs the commit as this agent, never as
/// the person.
pub fn issued_agent(
    appstate: &AppState,
    person: &str,
    client_id: &str,
    nonce: &str,
    name: Option<&str>,
) -> Result<atomic_lib::agents::Agent, String> {
    let node_key = appstate
        .store
        .derive_node_key(AGENT_CONTEXT)
        .ok_or("This node has no key, so it cannot issue agents.")?;
    let mut hasher = blake3::Hasher::new_keyed(&node_key);
    for part in [person, client_id, nonce] {
        // Length-prefixed, so ("ab", "c") and ("a", "bc") differ.
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    let seed = hasher.finalize();

    atomic_lib::agents::Agent::new_from_private_key(
        name,
        &atomic_lib::agents::encode_base64(seed.as_bytes()),
    )
    .map_err(|e| e.to_string())
}
