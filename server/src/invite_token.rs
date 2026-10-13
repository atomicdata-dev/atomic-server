use atomic_lib::{db::trees::Tree, errors::AtomicResult, urls, Db, Resource, Storelike, Value};
use base64::{engine::general_purpose, Engine};
use serde::{Deserialize, Serialize};

/// Error shown when an invite has been accepted by as many agents as it allows.
pub const INVITE_EXHAUSTED: &str = "This invite has no usages left. Ask for a new one.";

/// Serializes check-then-record of acceptances, so two people opening a
/// one-use link at the same moment cannot both get in.
pub fn acceptance_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// A stateless invite token that is signed by the user.
/// It is a base64-encoded JSON-AD representation of a "virtual" Invite resource.
#[derive(Debug, Serialize, Deserialize)]
pub struct InviteToken {
    pub target: atomic_lib::Subject,
    pub write: bool,
    pub expires_at: i64,
    pub signer: atomic_lib::Subject,
    pub signature: String,
    /// How many different agents may accept this invite. Part of the signed
    /// payload, so the recipient cannot raise it. `None` means unlimited
    /// (and is how tokens issued before the limit existed decode).
    pub max_usages: Option<i64>,
}

impl InviteToken {
    /// The JSON-AD that the issuer signs: everything except the signature.
    fn signable_json(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut map = serde_json::Map::new();
        map.insert(
            urls::TARGET.into(),
            serde_json::Value::String(self.target.as_str().to_string()),
        );
        map.insert(urls::WRITE_BOOL.into(), serde_json::Value::Bool(self.write));
        map.insert(
            urls::EXPIRES_AT.into(),
            serde_json::Value::Number(self.expires_at.into()),
        );
        map.insert(
            urls::SIGNER.into(),
            serde_json::Value::String(self.signer.as_str().to_string()),
        );
        // Only present when limited, so unlimited tokens keep their old bytes.
        if let Some(max) = self.max_usages {
            map.insert(
                urls::USAGES_LEFT.into(),
                serde_json::Value::Number(max.into()),
            );
        }
        map
    }

    /// Key under which the agents that accepted this invite are recorded.
    /// The signature identifies the token: it covers every signed field.
    fn acceptances_key(&self) -> Vec<u8> {
        format!("invite-acceptances:{}", self.signature).into_bytes()
    }

    /// Agents that have accepted this invite so far.
    pub fn accepted_by(&self, store: &Db) -> AtomicResult<Vec<String>> {
        match store.kv.get(Tree::PluginMeta, &self.acceptances_key())? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("Malformed invite acceptance record: {e}").into()),
            None => Ok(Vec::new()),
        }
    }

    /// How many agents can still accept, or `None` when unlimited.
    pub fn usages_left(&self, store: &Db) -> AtomicResult<Option<i64>> {
        let Some(max) = self.max_usages else {
            return Ok(None);
        };

        Ok(Some((max - self.accepted_by(store)?.len() as i64).max(0)))
    }

    /// Errors with [`INVITE_EXHAUSTED`] when the limit is reached and `agent`
    /// has not accepted before. Someone who already accepted may open the
    /// link again: that grants nothing new, so it does not use a place.
    pub fn check_usages(&self, store: &Db, agent: &str) -> AtomicResult<()> {
        if self.usages_left(store)? == Some(0)
            && !self.accepted_by(store)?.iter().any(|a| a == agent)
        {
            return Err(INVITE_EXHAUSTED.into());
        }
        Ok(())
    }

    /// Records that `agent` accepted. Callers must hold [`acceptance_lock`]
    /// from before [`Self::check_usages`] until after this call.
    pub fn record_acceptance(&self, store: &Db, agent: &str) -> AtomicResult<()> {
        let mut accepted = self.accepted_by(store)?;
        if accepted.iter().any(|a| a == agent) {
            return Ok(());
        }
        accepted.push(agent.to_string());
        store.kv.insert(
            Tree::PluginMeta,
            &self.acceptances_key(),
            &serde_json::to_vec(&accepted).map_err(|e| e.to_string())?,
        )
    }
    /// Creates a new signed InviteToken
    #[cfg(test)]
    pub fn new(
        target: String,
        write: bool,
        expires_at: i64,
        signer_agent: &atomic_lib::agents::Agent,
        max_usages: Option<i64>,
    ) -> AtomicResult<Self> {
        // Normalize the target through Subject parsing so the signed string
        // matches what encode()/verify() will produce via self.target.as_str().
        let mut token = Self {
            target: atomic_lib::Subject::from(target),
            write,
            expires_at,
            signer: signer_agent.subject.clone(),
            signature: String::new(),
            max_usages,
        };

        let serialized = serde_jcs::to_string(&token.signable_json())
            .map_err(|e| format!("Failed to serialize invite data: {}", e))?;

        token.signature = atomic_lib::commit::sign_message(
            &serialized,
            signer_agent
                .private_key
                .as_ref()
                .ok_or("Agent has no private key")?,
            &signer_agent.public_key,
        )?;

        Ok(token)
    }

    /// Encodes the InviteToken into a base64 string.
    #[cfg(test)]
    pub fn encode(&self) -> AtomicResult<String> {
        let mut map = self.signable_json();
        map.insert(
            urls::SIGNATURE.into(),
            serde_json::Value::String(self.signature.clone()),
        );

        let bytes = serde_json::to_vec(&map)
            .map_err(|e| format!("Failed to serialize invite token: {}", e))?;

        Ok(general_purpose::STANDARD.encode(bytes))
    }

    /// Decodes a base64 encoded JSON-AD token into an InviteToken.
    pub fn decode(token: &str) -> AtomicResult<Self> {
        let bytes = general_purpose::STANDARD
            .decode(token)
            .map_err(|e| format!("Invalid base64 in invite token: {}", e))?;

        let json: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("Invalid JSON in invite token: {}", e))?;

        let target = json
            .get(urls::TARGET)
            .ok_or("Missing target in invite token")?
            .as_str()
            .ok_or("Target must be a string")?
            .to_string();
        let target = atomic_lib::Subject::from(target);

        let write = json
            .get(urls::WRITE_BOOL)
            .ok_or("Missing write in invite token")?
            .as_bool()
            .ok_or("Write must be a boolean")?;

        let expires_at = json
            .get(urls::EXPIRES_AT)
            .ok_or("Missing expires_at in invite token")?
            .as_i64()
            .ok_or("Expires_at must be an integer")?;

        let signer_str = json
            .get(urls::SIGNER)
            .ok_or("Missing signer in invite token")?
            .as_str()
            .ok_or("Signer must be a string")?
            .to_string();
        let signer = atomic_lib::Subject::from(signer_str);

        let signature = json
            .get(urls::SIGNATURE)
            .ok_or("Missing signature in invite token")?
            .as_str()
            .ok_or("Signature must be a string")?
            .to_string();

        let max_usages = match json.get(urls::USAGES_LEFT) {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => Some(
                v.as_i64()
                    .filter(|n| *n >= 0)
                    .ok_or("Usages must be a non-negative integer")?,
            ),
        };

        Ok(Self {
            target,
            write,
            expires_at,
            signer,
            signature,
            max_usages,
        })
    }

    /// Verifies the token's signature and the signer's rights.
    pub async fn verify(&self, store: &Db) -> AtomicResult<()> {
        tracing::debug!(
            "Verifying invite token: signer={}, target={}, expires_at={}",
            self.signer,
            self.target,
            self.expires_at
        );

        // 1. Check expiration
        let now = atomic_lib::utils::now();
        if self.expires_at < now {
            return Err("Invite token has expired".into());
        }

        // 2. Verify signature
        // We construct a temporary resource to use atomic_lib's validation logic
        let mut resource = Resource::new("local:invite".into());
        resource.set_unsafe(urls::TARGET.into(), Value::AtomicUrl(self.target.clone()))?;
        resource.set_unsafe(urls::WRITE_BOOL.into(), Value::Boolean(self.write))?;
        resource.set_unsafe(urls::EXPIRES_AT.into(), Value::Timestamp(self.expires_at))?;
        resource.set_unsafe(urls::SIGNER.into(), Value::AtomicUrl(self.signer.clone()))?;
        resource.set_unsafe(
            urls::SIGNATURE.into(),
            Value::String(self.signature.clone()),
        )?;

        // We need to verify that the signer signed this data.
        // atomic_lib::commit::Commit::validate_signature uses a similar logic.
        // But here we are not validating a Commit, but a signed virtual resource.

        // Let's manually verify the signature for now, using the signer's public key.
        let signer_resource = store
            .get_resource(&self.signer)
            .await
            .map_err(|e| format!("Could not fetch invite issuer ({}): {}", self.signer, e))?;

        tracing::debug!(
            "Fetched signer resource, subject={}",
            signer_resource.get_subject()
        );

        let public_key = match signer_resource.get(urls::PUBLIC_KEY) {
            Ok(pk) => pk.to_string(),
            Err(e) => {
                if let Some(pk) = self
                    .signer
                    .as_str()
                    .strip_prefix(atomic_lib::subject::DID_AD_AGENT_PREFIX)
                {
                    pk.to_string()
                } else {
                    return Err(e);
                }
            }
        };
        tracing::debug!("Public key for verification: {}", public_key);
        let pubkey_bytes = atomic_lib::agents::decode_base64(&public_key)?;

        // The data that was signed is the JSON-AD without the signature.
        let signable_json = self.signable_json();

        let serialized = serde_jcs::to_string(&signable_json)
            .map_err(|e| format!("Failed to serialize invite data for verification: {}", e))?;

        tracing::debug!("Serialized signable data for verification: {}", serialized);

        let signature_bytes = atomic_lib::agents::decode_base64(&self.signature)?;

        let peer_public_key =
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pubkey_bytes);
        peer_public_key
            .verify(serialized.as_bytes(), &signature_bytes)
            .map_err(|_| format!(
                "Invalid signature in invite token. signer={}, public_key={}, signature={}, serialized_data={}",
                self.signer, public_key, self.signature, serialized
            ))?;

        // 3. Check signer's rights to the target
        let target_resource = store
            .get_resource(&self.target.clone())
            .await
            .map_err(|_| format!("Target resource not found: {}", self.target))?;

        atomic_lib::hierarchy::check_write(
            store,
            &target_resource,
            &atomic_lib::agents::ForAgent::AgentSubject(self.signer.clone()),
        )
        .await
        .map_err(|_| {
            format!(
                "Invite issuer ( { } ) no longer has write rights to the target resource ( { } )",
                self.signer, self.target
            )
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use atomic_lib::Storelike;

    #[tokio::test]
    async fn test_invite_token_cycle() {
        let store = atomic_lib::Db::init_temp("test_invite_token_cycle")
            .await
            .expect("Could not init db");
        atomic_lib::test_utils::setup_test_env(&store)
            .await
            .expect("Could not setup test env");
        let agent = store.get_default_agent().expect("Could not get agent");

        let target = urls::PROPERTIES.to_string();
        let expires_at = atomic_lib::utils::now() + 10000;

        // Construct the signable data manually for the test
        let mut signable_json = serde_json::Map::new();
        signable_json.insert(
            urls::TARGET.into(),
            serde_json::Value::String(target.clone()),
        );
        signable_json.insert(urls::WRITE_BOOL.into(), serde_json::Value::Bool(true));
        signable_json.insert(
            urls::EXPIRES_AT.into(),
            serde_json::Value::Number(expires_at.into()),
        );
        signable_json.insert(
            urls::SIGNER.into(),
            serde_json::Value::String(agent.subject.as_str().to_string()),
        );

        let serialized = serde_jcs::to_string(&signable_json).unwrap();
        let signature = atomic_lib::commit::sign_message(
            &serialized,
            agent.private_key.as_ref().unwrap(),
            &agent.public_key,
        )
        .unwrap();

        let token = InviteToken {
            target: atomic_lib::Subject::from(target.clone()),
            write: true,
            expires_at,
            signer: agent.subject.clone(),
            signature,
            max_usages: None,
        };

        let encoded = token.encode().expect("Failed to encode");
        let decoded = InviteToken::decode(&encoded).expect("Failed to decode");

        assert_eq!(decoded.target, target);
        assert!(decoded.write);
        assert_eq!(decoded.expires_at, expires_at);
        assert_eq!(decoded.signer, agent.subject);

        decoded.verify(&store).await.expect("Verification failed");
    }

    #[tokio::test]
    async fn test_invite_token_new_roundtrip() {
        let store = atomic_lib::Db::init_temp("test_invite_token_new_roundtrip")
            .await
            .expect("Could not init db");
        atomic_lib::test_utils::setup_test_env(&store)
            .await
            .expect("Could not setup test env");
        let agent = store.get_default_agent().expect("Could not get agent");

        let target = urls::PROPERTIES.to_string();
        let expires_at = atomic_lib::utils::now() + 10000;

        // Use the production code path: InviteToken::new
        let token = InviteToken::new(target.clone(), true, expires_at, &agent, None)
            .expect("Failed to create invite token");

        let encoded = token.encode().expect("Failed to encode");
        let decoded = InviteToken::decode(&encoded).expect("Failed to decode");

        assert_eq!(decoded.target, target);
        assert!(decoded.write);
        assert_eq!(decoded.expires_at, expires_at);
        assert_eq!(decoded.signer, agent.subject);

        decoded
            .verify(&store)
            .await
            .expect("Verification failed for token created via InviteToken::new");
    }

    #[tokio::test]
    async fn test_invite_token_root_url_target() {
        // Regression test: root URLs like "http://localhost:9883" get a trailing
        // slash added by Url::parse ("http://localhost:9883/"). This caused a
        // mismatch between the string signed in new() and the string used in
        // encode()/verify(), resulting in "Invalid signature in invite token".
        let store = atomic_lib::Db::init_temp("test_invite_token_root_url")
            .await
            .expect("Could not init db");
        atomic_lib::test_utils::setup_test_env(&store)
            .await
            .expect("Could not setup test env");
        let agent = store.get_default_agent().expect("Could not get agent");

        // Use a root URL without trailing slash, like get_origin() produces
        let target = "https://atomicdata.dev".to_string();
        let expires_at = atomic_lib::utils::now() + 10000;

        let token = InviteToken::new(target.clone(), true, expires_at, &agent, None)
            .expect("Failed to create invite token");

        let encoded = token.encode().expect("Failed to encode");
        let decoded = InviteToken::decode(&encoded).expect("Failed to decode");

        // The target should be normalized consistently
        assert_eq!(decoded.target.as_str(), token.target.as_str());

        decoded
            .verify(&store)
            .await
            .expect("Verification failed for root URL target");
    }

    #[tokio::test]
    async fn test_invite_token_expired() {
        let store = atomic_lib::Db::init_temp("test_invite_token_expired")
            .await
            .expect("Could not init db");
        atomic_lib::test_utils::setup_test_env(&store)
            .await
            .expect("Could not setup test env");
        let agent = store.get_default_agent().expect("Could not get agent");

        let target = urls::PROPERTIES.to_string();
        let expires_at = atomic_lib::utils::now() - 10000; // Expired

        let token = InviteToken {
            target: atomic_lib::Subject::from(target),
            write: true,
            expires_at,
            signer: agent.subject.clone(),
            signature: "invalid".to_string(),
            max_usages: None,
        };

        let result = token.verify(&store).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    async fn limited_setup(name: &str, max: i64) -> (atomic_lib::Db, InviteToken) {
        let store = atomic_lib::Db::init_temp(name).await.unwrap();
        atomic_lib::test_utils::setup_test_env(&store)
            .await
            .unwrap();
        let agent = store.get_default_agent().unwrap();
        let token = InviteToken::new(
            urls::PROPERTIES.to_string(),
            false,
            atomic_lib::utils::now() + 10000,
            &agent,
            Some(max),
        )
        .unwrap();
        (store, token)
    }

    #[tokio::test]
    async fn limited_token_roundtrips_and_is_signed() {
        let (store, token) = limited_setup("invite_limited_roundtrip", 2).await;
        let decoded = InviteToken::decode(&token.encode().unwrap()).unwrap();
        assert_eq!(decoded.max_usages, Some(2));
        decoded.verify(&store).await.unwrap();

        // Raising the limit by hand invalidates the signature.
        let mut tampered = InviteToken::decode(&token.encode().unwrap()).unwrap();
        tampered.max_usages = Some(1000);
        assert!(tampered.verify(&store).await.is_err());
        tampered.max_usages = None;
        assert!(tampered.verify(&store).await.is_err());
    }

    #[tokio::test]
    async fn rejects_acceptance_beyond_limit() {
        let (store, token) = limited_setup("invite_limited_exhausted", 1).await;
        assert_eq!(token.usages_left(&store).unwrap(), Some(1));

        token.check_usages(&store, "did:ad:agent:first").unwrap();
        token
            .record_acceptance(&store, "did:ad:agent:first")
            .unwrap();
        assert_eq!(token.usages_left(&store).unwrap(), Some(0));

        let err = token
            .check_usages(&store, "did:ad:agent:second")
            .unwrap_err();
        assert!(err.to_string().contains("no usages left"), "{err}");

        // The first agent opening the link again is not a new usage.
        token.check_usages(&store, "did:ad:agent:first").unwrap();
        token
            .record_acceptance(&store, "did:ad:agent:first")
            .unwrap();
        assert_eq!(token.usages_left(&store).unwrap(), Some(0));
    }

    #[tokio::test]
    async fn unlimited_token_never_runs_out() {
        let (store, mut token) = limited_setup("invite_unlimited", 1).await;
        token.max_usages = None;
        for i in 0..5 {
            let agent = format!("did:ad:agent:{i}");
            token.check_usages(&store, &agent).unwrap();
            token.record_acceptance(&store, &agent).unwrap();
        }
        assert_eq!(token.usages_left(&store).unwrap(), None);
    }
}
