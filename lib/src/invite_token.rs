//! Stateless, user-signed invite tokens.
//!
//! A token is the base64 (standard alphabet, padded, like `btoa`) of a JSON-AD
//! object describing a "virtual" invite. The issuer signs the canonical
//! (sorted keys, minified) JSON of every field except the signature. The wire
//! format is shared with `generateInviteToken` in `@tomic/lib`.
//!
//! This module is transport- and storage-free (no database, no async). The
//! server layers acceptance records and rights checks on top of it.

use crate::{agents::Agent, errors::AtomicResult, urls, Subject};
use base64::{engine::general_purpose, Engine};
use serde::{Deserialize, Serialize};

/// A stateless invite token that is signed by the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteToken {
    pub target: Subject,
    pub write: bool,
    pub expires_at: i64,
    pub signer: Subject,
    pub signature: String,
    /// How many different agents may accept this invite. Part of the signed
    /// payload, so the recipient cannot raise it. `None` means unlimited
    /// (and is how tokens issued before the limit existed decode).
    pub max_usages: Option<i64>,
}

impl InviteToken {
    /// Creates a new signed InviteToken.
    pub fn new(
        target: String,
        write: bool,
        expires_at: i64,
        signer_agent: &Agent,
        max_usages: Option<i64>,
    ) -> AtomicResult<Self> {
        // Normalize the target through Subject parsing so the signed string
        // matches what encode()/verify() will produce via self.target.as_str().
        let mut token = Self {
            target: Subject::from(target),
            write,
            expires_at,
            signer: signer_agent.subject.clone(),
            signature: String::new(),
            max_usages,
        };

        token.signature = crate::commit::sign_message(
            &token.signable_string()?,
            signer_agent
                .private_key
                .as_ref()
                .ok_or("Agent has no private key")?,
            &signer_agent.public_key,
        )?;

        Ok(token)
    }

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

    /// The exact string that is signed (canonical JSON, sorted keys).
    fn signable_string(&self) -> AtomicResult<String> {
        serde_jcs::to_string(&self.signable_json())
            .map_err(|e| format!("Failed to serialize invite data: {}", e).into())
    }

    /// Encodes the InviteToken into a base64 string.
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
        let target = Subject::from(target);

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
        let signer = Subject::from(signer_str);

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

    /// Errors when the token has expired at `now` (Unix milliseconds).
    pub fn check_expiry(&self, now: i64) -> AtomicResult<()> {
        if self.expires_at < now {
            return Err("Invite token has expired".into());
        }
        Ok(())
    }

    /// The signer's public key as embedded in a `did:ad:agent:` subject, if it is one.
    pub fn signer_public_key(&self) -> Option<&str> {
        self.signer
            .as_str()
            .strip_prefix(crate::subject::DID_AD_AGENT_PREFIX)
    }

    /// Verifies the signature against the signer's base64 public key.
    pub fn verify_signature(&self, public_key: &str) -> AtomicResult<()> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let serialized = self.signable_string()?;
        let invalid = || {
            format!(
                "Invalid signature in invite token. signer={}, public_key={}, signature={}, serialized_data={}",
                self.signer, public_key, self.signature, serialized
            )
        };
        let key_bytes: [u8; 32] = crate::agents::decode_base64(public_key)?
            .try_into()
            .map_err(|_| invalid())?;
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| invalid())?;
        let sig_bytes: [u8; 64] = crate::agents::decode_base64(&self.signature)?
            .try_into()
            .map_err(|_| invalid())?;
        key.verify(serialized.as_bytes(), &Signature::from_bytes(&sig_bytes))
            .map_err(|_| invalid().into())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn agent() -> Agent {
        Agent::new(Some("inviter")).unwrap()
    }

    #[test]
    fn created_token_verifies_with_the_lib() {
        let agent = agent();
        let token = InviteToken::new(
            "https://example.com/drive".into(),
            true,
            4_102_444_800_000,
            &agent,
            Some(3),
        )
        .unwrap();
        let decoded = InviteToken::decode(&token.encode().unwrap()).unwrap();
        assert_eq!(decoded.max_usages, Some(3));
        assert!(decoded.write);
        decoded.verify_signature(&agent.public_key).unwrap();
        decoded.check_expiry(1).unwrap();
        assert!(decoded.check_expiry(4_102_444_800_001).is_err());

        let mut tampered = decoded.clone();
        tampered.max_usages = Some(1000);
        assert!(tampered.verify_signature(&agent.public_key).is_err());
        tampered.max_usages = None;
        assert!(tampered.verify_signature(&agent.public_key).is_err());
        assert!(decoded
            .verify_signature(&Agent::new(None).unwrap().public_key)
            .is_err());
    }

    /// Builds a token the way `generateInviteToken` of `@tomic/lib` does:
    /// `fast-json-stable-stringify` of the signable object (keys sorted, no
    /// whitespace), signed, then `btoa(JSON.stringify({...signable, signature}))`
    /// (insertion order: target, write, expiresAt, signer, [usagesLeft], signature).
    /// Keys are generated at run time; the JSON text is written out literally.
    #[test]
    fn accepts_the_tomic_lib_wire_format() {
        let agent = agent();
        let signer = agent.subject.to_string();
        let target = "https://example.com/drive";
        let expires = 4_102_444_800_000_i64;

        // fast-json-stable-stringify output, sorted by key.
        let signable = format!(
            concat!(
                "{{\"https://atomicdata.dev/properties/invite/expiresAt\":{expires},",
                "\"https://atomicdata.dev/properties/invite/target\":\"{target}\",",
                "\"https://atomicdata.dev/properties/invite/usagesLeft\":2,",
                "\"https://atomicdata.dev/properties/invite/write\":false,",
                "\"https://atomicdata.dev/properties/signer\":\"{signer}\"}}"
            ),
            signer = signer,
            expires = expires,
            target = target,
        );
        let signature = crate::commit::sign_message(
            &signable,
            agent.private_key.as_ref().unwrap(),
            &agent.public_key,
        )
        .unwrap();
        // JSON.stringify keeps insertion order, not sorted order.
        let json = format!(
            concat!(
                "{{\"https://atomicdata.dev/properties/invite/target\":\"{target}\",",
                "\"https://atomicdata.dev/properties/invite/write\":false,",
                "\"https://atomicdata.dev/properties/invite/expiresAt\":{expires},",
                "\"https://atomicdata.dev/properties/signer\":\"{signer}\",",
                "\"https://atomicdata.dev/properties/invite/usagesLeft\":2,",
                "\"https://atomicdata.dev/properties/signature\":\"{signature}\"}}"
            ),
            target = target,
            expires = expires,
            signer = signer,
            signature = signature,
        );
        let ts_token = general_purpose::STANDARD.encode(json.as_bytes());
        assert_eq!(ts_token.len() % 4, 0, "btoa pads");

        let decoded = InviteToken::decode(&ts_token).unwrap();
        assert_eq!(decoded.max_usages, Some(2));
        decoded.verify_signature(&agent.public_key).unwrap();

        // And the lib signs byte-identical signable data and signature
        // (ed25519 is deterministic), so TS can verify what the lib creates.
        let ours = InviteToken::new(target.into(), false, expires, &agent, Some(2)).unwrap();
        assert_eq!(ours.signable_string().unwrap(), signable);
        assert_eq!(ours.signature, signature);
    }
}
