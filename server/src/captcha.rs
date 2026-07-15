//! Captcha verification for published-form submissions (Phase 6 of
//! `planning/atomic-forms.md`). The default implementation is ALTCHA
//! proof-of-work v2 (self-hosted, no third party, no user interaction):
//! `GET /form/{id}/challenge` issues an HMAC-signed challenge, the visitor's
//! browser burns a bit of CPU solving it (the official `altcha` widget), and
//! the submit handler verifies + consumes the solution.
//!
//! The trait exists so other providers (Turnstile, hCaptcha — which verify
//! via an HTTP call, hence the async `verify`) can slot in without touching
//! the form handlers.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use altcha::{
    create_challenge, verify_solution, CreateChallengeOptions, HmacAlgorithm, Payload,
    VerifySolutionOptions,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::Rng;
use serde_json::{json, Value as JsonValue};

use atomic_lib::{db::trees::Tree, utils::random_string, Db};

#[async_trait::async_trait]
pub trait CaptchaVerifier: Send + Sync {
    /// Client-side config embedded in the form definition response's
    /// `captcha` field — tells the runtime which provider to render and
    /// where to fetch challenges.
    fn client_config(&self, form_id: &str) -> JsonValue;

    /// A fresh challenge for `GET /form/{id}/challenge`.
    fn issue(&self) -> Result<JsonValue, String>;

    /// Verifies and consumes (one-time use) the submit body's captcha
    /// payload. `Err` holds a visitor-facing message.
    async fn verify(&self, payload: Option<&str>) -> Result<(), String>;
}

/// How long an issued challenge stays valid. Generous because the widget
/// solves right after page load (`auto=onload`) while the visitor may fill
/// the form slowly; a longer window doesn't lower the attacker's cost since
/// every challenge is one-time use.
const CHALLENGE_TTL: Duration = Duration::from_secs(60 * 60);

/// PBKDF2/SHA-256 iterations per counter attempt — the wide-compatibility
/// algorithm ALTCHA's docs recommend (runs on WebCrypto, no extra binaries).
#[cfg(not(test))]
const POW_COST: u32 = 5_000;
/// Deterministic-mode counter range: the solver performs exactly `counter`
/// key derivations, so difficulty is `counter × cost` and solve time is
/// predictable. Kept below the docs' 5000–10000 suggestion so a mid-range
/// phone solves in the background within a couple of seconds — spam
/// deterrence comes from the combination with the rate limiter + honeypot,
/// not from this cost alone.
#[cfg(not(test))]
const POW_COUNTER_RANGE: std::ops::Range<u32> = 1_000..4_000;

// Tests solve challenges natively in unoptimized debug builds — production
// difficulty would take minutes there.
#[cfg(test)]
const POW_COST: u32 = 10;
#[cfg(test)]
const POW_COUNTER_RANGE: std::ops::Range<u32> = 2..20;

const HMAC_SECRET_KEY: &[u8] = b"_altcha_hmac_secret_v1";

pub struct AltchaVerifier {
    /// HMAC secret signing challenge parameters.
    secret: String,
    /// Separate secret signing the derived key (enables the crate's
    /// fast-path verification: one HMAC instead of re-deriving the key).
    key_secret: String,
    /// Nonces of already-verified challenges (replay protection — neither
    /// ALTCHA library ships this). In-process like the submit rate limiter;
    /// entries older than [CHALLENGE_TTL] would fail the expiry check anyway
    /// and are pruned lazily.
    consumed: Mutex<HashMap<String, Instant>>,
}

impl AltchaVerifier {
    pub fn new(secret: String) -> Self {
        let key_secret = format!("{secret}:key");
        Self {
            secret,
            key_secret,
            consumed: Mutex::new(HashMap::new()),
        }
    }

    /// Loads the HMAC secret from redb, minting + persisting one on first
    /// use (mirrors the publish-slug map in `crate::forms`). Persisting it
    /// means a server restart doesn't invalidate challenges visitors have
    /// already solved.
    pub fn from_store(store: &Db) -> Self {
        let secret = match store.kv.get(Tree::PluginMeta, HMAC_SECRET_KEY) {
            Ok(Some(bytes)) => String::from_utf8_lossy(&bytes).into_owned(),
            _ => {
                let secret = random_string(64);
                if let Err(e) = store
                    .kv
                    .insert(Tree::PluginMeta, HMAC_SECRET_KEY, secret.as_bytes())
                {
                    tracing::warn!(
                        "Could not persist captcha HMAC secret, challenges won't survive a restart: {e}"
                    );
                }
                secret
            }
        };
        Self::new(secret)
    }

    fn issue_with_expiry(&self, expires_at: u64) -> Result<JsonValue, String> {
        let counter = rand::thread_rng().gen_range(POW_COUNTER_RANGE);
        let challenge = create_challenge(CreateChallengeOptions {
            algorithm: "PBKDF2/SHA-256".to_string(),
            cost: POW_COST,
            counter: Some(counter),
            expires_at: Some(expires_at),
            hmac_signature_secret: Some(self.secret.clone()),
            hmac_key_signature_secret: Some(self.key_secret.clone()),
            ..Default::default()
        })
        .map_err(|e| e.to_string())?;
        serde_json::to_value(&challenge).map_err(|e| e.to_string())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[async_trait::async_trait]
impl CaptchaVerifier for AltchaVerifier {
    fn client_config(&self, form_id: &str) -> JsonValue {
        json!({
            "provider": "altcha",
            "challengeUrl": format!("/form/{form_id}/challenge"),
        })
    }

    fn issue(&self) -> Result<JsonValue, String> {
        self.issue_with_expiry(unix_now() + CHALLENGE_TTL.as_secs())
    }

    async fn verify(&self, payload: Option<&str>) -> Result<(), String> {
        let payload = payload
            .filter(|p| !p.is_empty())
            .ok_or("Captcha verification is required")?;

        // The widget's hidden input holds base64(JSON { challenge, solution }).
        let bytes = BASE64
            .decode(payload)
            .map_err(|_| "Malformed captcha payload")?;
        let payload: Payload =
            serde_json::from_slice(&bytes).map_err(|_| "Malformed captcha payload")?;

        let result = verify_solution(VerifySolutionOptions {
            challenge: &payload.challenge,
            solution: &payload.solution,
            hmac_algorithm: HmacAlgorithm::Sha256,
            hmac_key_signature_secret: Some(self.key_secret.clone()),
            hmac_signature_secret: self.secret.clone(),
        })
        .map_err(|e| e.to_string())?;

        if result.expired {
            return Err("Captcha expired, please verify again".into());
        }
        if !result.verified {
            return Err("Captcha verification failed".into());
        }

        // One-time use: consume the challenge's nonce (random per challenge,
        // covered by the verified HMAC signature). Check-and-insert under one
        // lock so two racing submits can't both pass.
        let nonce = payload.challenge.parameters.nonce.clone();
        let mut consumed = self.consumed.lock().unwrap();
        let now = Instant::now();
        consumed.retain(|_, at| now.duration_since(*at) < CHALLENGE_TTL);
        if consumed.insert(nonce, now).is_some() {
            return Err("Captcha already used, please verify again".into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use altcha::{solve_challenge, Challenge, SolveChallengeOptions};

    fn solve_to_payload(challenge_json: &JsonValue) -> String {
        let challenge: Challenge = serde_json::from_value(challenge_json.clone()).unwrap();
        let solution = solve_challenge(SolveChallengeOptions::new(&challenge))
            .unwrap()
            .expect("test challenge should be solvable");
        let payload = json!({
            "challenge": challenge,
            "solution": solution,
        });
        BASE64.encode(serde_json::to_vec(&payload).unwrap())
    }

    #[tokio::test]
    async fn solve_and_verify_roundtrip() {
        let verifier = AltchaVerifier::new("test-secret".into());
        let challenge = verifier.issue().unwrap();
        let payload = solve_to_payload(&challenge);

        verifier.verify(Some(&payload)).await.unwrap();
    }

    #[tokio::test]
    async fn replayed_payload_is_rejected() {
        let verifier = AltchaVerifier::new("test-secret".into());
        let challenge = verifier.issue().unwrap();
        let payload = solve_to_payload(&challenge);

        verifier.verify(Some(&payload)).await.unwrap();
        let err = verifier.verify(Some(&payload)).await.unwrap_err();
        assert!(err.contains("already used"), "{err}");
    }

    #[tokio::test]
    async fn missing_and_malformed_payloads_are_rejected() {
        let verifier = AltchaVerifier::new("test-secret".into());

        assert!(verifier.verify(None).await.is_err());
        assert!(verifier.verify(Some("")).await.is_err());
        assert!(verifier.verify(Some("not-base64!!")).await.is_err());
        // Valid base64, not a payload.
        assert!(verifier
            .verify(Some(&BASE64.encode(b"{\"nope\": true}")))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn tampered_solution_is_rejected() {
        let verifier = AltchaVerifier::new("test-secret".into());
        let challenge_json = verifier.issue().unwrap();
        let challenge: Challenge = serde_json::from_value(challenge_json).unwrap();
        let mut solution = solve_challenge(SolveChallengeOptions::new(&challenge))
            .unwrap()
            .unwrap();
        solution.derived_key = "00".repeat(32);
        let payload =
            BASE64.encode(serde_json::to_vec(&json!({ "challenge": challenge, "solution": solution })).unwrap());

        let err = verifier.verify(Some(&payload)).await.unwrap_err();
        assert!(err.contains("failed"), "{err}");
    }

    #[tokio::test]
    async fn foreign_secret_is_rejected() {
        // A challenge signed by someone else's secret must not verify.
        let issuer = AltchaVerifier::new("other-secret".into());
        let verifier = AltchaVerifier::new("test-secret".into());
        let payload = solve_to_payload(&issuer.issue().unwrap());

        let err = verifier.verify(Some(&payload)).await.unwrap_err();
        assert!(err.contains("failed"), "{err}");
    }

    #[tokio::test]
    async fn expired_challenge_is_rejected() {
        let verifier = AltchaVerifier::new("test-secret".into());
        let challenge = verifier.issue_with_expiry(unix_now() - 1).unwrap();
        let payload = solve_to_payload(&challenge);

        let err = verifier.verify(Some(&payload)).await.unwrap_err();
        assert!(err.contains("expired"), "{err}");
    }
}
