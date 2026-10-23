use atomic_lib::{db::trees::Tree, errors::AtomicResult, urls, Db, Storelike};

/// Error shown when an invite has been accepted by as many agents as it allows.
pub const INVITE_EXHAUSTED: &str = "This invite has no usages left. Ask for a new one.";

/// Serializes check-then-record of acceptances, so two people opening a
/// one-use link at the same moment cannot both get in.
pub fn acceptance_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub use atomic_lib::invite_token::InviteToken;

/// Server-side behaviour of an [`InviteToken`]: acceptance records, signature
/// and rights verification against the store.
#[allow(async_fn_in_trait)]
pub trait InviteTokenExt {
    fn acceptances_key(&self) -> Vec<u8>;
    fn accepted_by(&self, store: &Db) -> AtomicResult<Vec<String>>;
    fn usages_left(&self, store: &Db) -> AtomicResult<Option<i64>>;
    fn check_usages(&self, store: &Db, agent: &str) -> AtomicResult<()>;
    fn record_acceptance(&self, store: &Db, agent: &str) -> AtomicResult<()>;
    async fn verify(&self, store: &Db) -> AtomicResult<()>;
}
impl InviteTokenExt for InviteToken {
    /// Key under which the agents that accepted this invite are recorded.
    /// The signature identifies the token: it covers every signed field.
    fn acceptances_key(&self) -> Vec<u8> {
        format!("invite-acceptances:{}", self.signature).into_bytes()
    }

    /// Agents that have accepted this invite so far.
    fn accepted_by(&self, store: &Db) -> AtomicResult<Vec<String>> {
        match store.kv.get(Tree::PluginMeta, &self.acceptances_key())? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("Malformed invite acceptance record: {e}").into()),
            None => Ok(Vec::new()),
        }
    }

    /// How many agents can still accept, or `None` when unlimited.
    fn usages_left(&self, store: &Db) -> AtomicResult<Option<i64>> {
        let Some(max) = self.max_usages else {
            return Ok(None);
        };

        Ok(Some((max - self.accepted_by(store)?.len() as i64).max(0)))
    }

    /// Errors with [`INVITE_EXHAUSTED`] when the limit is reached and `agent`
    /// has not accepted before. Someone who already accepted may open the
    /// link again: that grants nothing new, so it does not use a place.
    fn check_usages(&self, store: &Db, agent: &str) -> AtomicResult<()> {
        if self.usages_left(store)? == Some(0)
            && !self.accepted_by(store)?.iter().any(|a| a == agent)
        {
            return Err(INVITE_EXHAUSTED.into());
        }
        Ok(())
    }

    /// Records that `agent` accepted. Callers must hold [`acceptance_lock`]
    /// from before [`Self::check_usages`] until after this call.
    fn record_acceptance(&self, store: &Db, agent: &str) -> AtomicResult<()> {
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
    /// Verifies the token's signature and the signer's rights.
    async fn verify(&self, store: &Db) -> AtomicResult<()> {
        tracing::debug!(
            "Verifying invite token: signer={}, target={}, expires_at={}",
            self.signer,
            self.target,
            self.expires_at
        );

        // 1. Check expiration
        self.check_expiry(atomic_lib::utils::now())?;

        // 2. Verify signature against the signer's public key.
        let signer_resource = store
            .get_resource(&self.signer)
            .await
            .map_err(|e| format!("Could not fetch invite issuer ({}): {}", self.signer, e))?;

        let public_key = match signer_resource.get(urls::PUBLIC_KEY) {
            Ok(pk) => pk.to_string(),
            Err(e) => match self.signer_public_key() {
                Some(pk) => pk.to_string(),
                None => return Err(e),
            },
        };
        self.verify_signature(&public_key)?;

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
