//! Envelope v2 — the multi-wrapper protected-secret format from atomic-saas
//! `planning/BACKUP_SECURITY.md`.
//!
//! Not to be confused with `envelope.rs`, which seals vault *objects*. This
//! protects a *secret* — the Ed25519 agent secret, or a `DriveVaultKey` — such
//! that the server storing it can never read it, and the user can open it from
//! more than one independent credential.
//!
//! A random DEK encrypts the secret once. The DEK is then wrapped once per
//! registered credential. Adding or removing a credential rewraps a 32-byte
//! key, never the secret itself, which is what makes credential changes cheap
//! and independent of each other.
//!
//! The rule the design exists to enforce: **no human-memorable secret may ever
//! be the sole thing guarding an offline-crackable blob.** v1 wrapped the agent
//! secret with a user-chosen password over PBKDF2, which is an afternoon on one
//! GPU — and because an Ed25519 agent key can never be rotated, that is a
//! harvest-now-crack-later exposure rather than a bounded one.
//!
//! ## Cipher choice
//!
//! XChaCha20-Poly1305 throughout, where `BACKUP_SECURITY.md` sketched AES-GCM.
//! AES-GCM's advantage would be running natively in WebCrypto without WASM, but
//! Argon2id — the KDF behind the mandatory recovery-code wrapper — is precisely
//! the primitive the Web platform lacks, so any unwrap already loads WASM. That
//! leaves one AEAD across vault objects and envelopes instead of two, and no
//! new dependency.

use super::keys::{argon2id_derive_key, Argon2Params, KEK_LEN};
use crate::errors::AtomicResult;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Envelope format version. v1 (PBKDF2 + AES-GCM, single password wrapper) is
/// deliberately not readable here: it is a different scheme, and this module
/// refusing it is better than appearing to support it.
pub const SECRET_ENVELOPE_VERSION: u32 = 2;

const NONCE_LEN: usize = 24;
const DEK_LEN: usize = 32;
/// 128 bits. Enough that the recovery code is not the weak link even though it
/// is the one wrapper a human handles.
const RECOVERY_CODE_BYTES: usize = 16;

/// How a wrapper's key-encryption key is obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WrapperKind {
    /// Machine-generated ~128-bit code, stretched with Argon2id. Mandatory:
    /// it is the only wrapper that works with no platform account and no
    /// hardware, and the safety net when a passkey is lost.
    RecoveryCode,
    /// A KEK derived by a WebAuthn PRF assertion. The KEK arrives from the
    /// browser already derived — WebAuthn is not something Rust performs.
    WebauthnPrf,
    /// User-chosen password over Argon2id. Supported so product can offer it,
    /// deliberately never the only wrapper.
    Password,
    /// A KEK derived from the agent's signature over a fixed message.
    ///
    /// The wrapper that means a user manages **no new secret**. Whatever
    /// already restores their identity — a passkey, the recovery code on the
    /// identity envelope — also restores every drive key, because holding the
    /// agent secret is sufficient to unwrap them.
    ///
    /// This wraps a random drive key; it does not derive one. Deriving would
    /// weld data encryption to identity permanently: no re-keying a drive
    /// without a new identity, no sharing a drive without sharing the agent
    /// secret. Wrapping keeps the drive key independent while costing the user
    /// nothing — `CLOUD_VAULT_ARCHITECTURE.md`'s key diagram says *wraps* for
    /// exactly this reason.
    AgentSecret,
    /// A key the node itself holds, outside the database it protects.
    ///
    /// The wrapper that lets a secret be used with nobody present — a plugin
    /// importing at 3am cannot be asked for a passkey. It follows that this
    /// wrapper does **not** protect against a compromised running server: the
    /// process can open what it can open. What it does protect is every way a
    /// database leaves the machine intact — a stolen disk, a backup, a copied
    /// store file, a support bundle — which is the realistic path.
    ///
    /// A secret wrapped only by a user credential has no unattended path, by
    /// construction. That is the trade, not a gap to engineer around.
    NodeKey,
}

/// Argon2id parameters as stored, so a blob written today stays openable after
/// the defaults are re-tuned. Reading these from the blob rather than from
/// today's constants is what makes that true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredKdfParams {
    pub mem_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl From<Argon2Params> for StoredKdfParams {
    fn from(p: Argon2Params) -> Self {
        Self {
            mem_kib: p.mem_kib,
            iterations: p.iterations,
            parallelism: p.parallelism,
        }
    }
}

impl From<StoredKdfParams> for Argon2Params {
    fn from(p: StoredKdfParams) -> Self {
        Self {
            mem_kib: p.mem_kib,
            iterations: p.iterations,
            parallelism: p.parallelism,
        }
    }
}

/// One credential's route to the DEK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wrapper {
    pub kind: WrapperKind,
    /// Stable handle — a WebAuthn credential id, or a label like "recovery
    /// code". Lets a UI name what it is about to remove.
    pub id: String,
    /// Present for Argon2id-stretched wrappers, absent for PRF.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf: Option<StoredKdfParams>,
    /// Argon2id salt, base64. Absent for PRF.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    pub nonce: String,
    pub wrapped_dek: String,
}

/// The stored blob.
///
/// Serialized as JSON rather than MessagePack: it is small, it is read during
/// account recovery — the worst possible moment to be unable to eyeball a
/// value — and a human staring at it while restoring should be able to tell
/// which wrappers exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretEnvelope {
    pub format_version: u32,
    pub nonce: String,
    pub ciphertext: String,
    pub wrappers: Vec<Wrapper>,
}

/// How a caller proves it may open the envelope.
pub enum Unlock<'a> {
    /// A recovery code or password as typed. Argon2id runs against the salt
    /// stored in the matching wrapper.
    Secret(&'a str),
    /// A KEK the caller already derived, for PRF.
    Kek([u8; KEK_LEN]),
    /// The account's agent secret, as raw bytes.
    AgentSecret(&'a [u8]),
}

/// What to add when creating an envelope or registering a credential.
pub enum NewWrapper<'a> {
    RecoveryCode {
        code: &'a str,
    },
    Password {
        password: &'a str,
    },
    WebauthnPrf {
        credential_id: String,
        kek: [u8; KEK_LEN],
    },
    /// Wrap under the account's agent secret. Raw secret bytes, not a KEK —
    /// the derivation is this module's business so every caller gets the same
    /// domain separation.
    AgentSecret {
        agent_secret: &'a [u8],
    },
    /// Wrap under the node's own key, so the host can open this unattended.
    NodeKey {
        kek: [u8; KEK_LEN],
    },
}

impl NewWrapper<'_> {
    fn kind(&self) -> WrapperKind {
        match self {
            NewWrapper::RecoveryCode { .. } => WrapperKind::RecoveryCode,
            NewWrapper::Password { .. } => WrapperKind::Password,
            NewWrapper::WebauthnPrf { .. } => WrapperKind::WebauthnPrf,
            NewWrapper::AgentSecret { .. } => WrapperKind::AgentSecret,
            NewWrapper::NodeKey { .. } => WrapperKind::NodeKey,
        }
    }

    fn id(&self) -> String {
        match self {
            NewWrapper::RecoveryCode { .. } => "recovery-code".to_string(),
            NewWrapper::Password { .. } => "password".to_string(),
            NewWrapper::WebauthnPrf { credential_id, .. } => credential_id.clone(),
            NewWrapper::AgentSecret { .. } => "agent-secret".to_string(),
            NewWrapper::NodeKey { .. } => "node-key".to_string(),
        }
    }
}

/// A freshly generated recovery code, in the grouped form shown to the user.
///
/// Crockford base32: no `I`, `L`, `O` or `U`, so it survives being read aloud,
/// written down and typed back. Grouped in fives for the same reason.
pub fn generate_recovery_code() -> String {
    let mut bytes = [0u8; RECOVERY_CODE_BYTES];
    rand::thread_rng().fill_bytes(&mut bytes);
    let raw = base32_encode(&bytes);
    raw.as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).unwrap_or_default().to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// Codes are compared after stripping grouping and case, so a user who types
/// the dashes (or omits them, or shouts it in caps) still gets in.
pub fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        // Crockford's documented confusables, resolved on input.
        .map(|c| match c {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        })
        .collect()
}

/// Domain separator for the agent-derived KEK.
const AGENT_SECRET_CONTEXT: &str = "atomic-vault 2026 agent secret wrapper";

/// The message an agent signs to prove it can open its own vault keys.
///
/// Fixed, so the resulting signature is reproducible on any device that holds
/// the agent — Ed25519 signatures are deterministic (RFC 8032), which is what
/// makes a signature usable as key material at all.
pub const AGENT_VAULT_PROOF_MESSAGE: &[u8] = b"atomic-vault-key-derivation-v1";

/// The KEK derived from an agent's proof.
///
/// `proof` is the agent's signature over [`AGENT_VAULT_PROOF_MESSAGE`], not the
/// private key. Two reasons that matters:
///
/// The private key is deliberately not extractable in the browser — the
/// `CryptoProvider` exposes signing, not key bytes — and a scheme that needed
/// the raw key would rule out hardware-backed and non-extractable keys
/// permanently.
///
/// It also removes an ambiguity that caused a real bug: the "agent secret" has
/// several representations (a base64 JSON blob, the `privateKey` inside it, the
/// decoded seed), and wrapping under one while unwrapping with another produced
/// an envelope nothing could open. A signature has exactly one representation.
pub fn agent_secret_kek(proof: &[u8]) -> [u8; KEK_LEN] {
    blake3::derive_key(AGENT_SECRET_CONTEXT, proof)
}

const BASE32_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            let index = ((buffer >> (bits - 5)) & 0x1F) as usize;
            out.push(BASE32_ALPHABET[index] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(BASE32_ALPHABET[index] as char);
    }
    out
}

fn b64(bytes: &[u8]) -> String {
    crate::agents::encode_base64(bytes)
}

fn unb64(text: &str) -> AtomicResult<Vec<u8>> {
    crate::agents::decode_base64(text).map_err(|e| format!("malformed envelope field: {e}").into())
}

fn seal(key: &[u8; 32], plaintext: &[u8]) -> AtomicResult<(String, String)> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| "failed to seal envelope")?;
    Ok((b64(&nonce_bytes), b64(&ciphertext)))
}

fn unseal(key: &[u8; 32], nonce: &str, ciphertext: &str) -> AtomicResult<Vec<u8>> {
    let nonce_bytes = unb64(nonce)?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err("envelope nonce has the wrong length".into());
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(&nonce_bytes),
            unb64(ciphertext)?.as_slice(),
        )
        .map_err(|_| "could not open envelope: wrong credential, or the blob was altered".into())
}

fn wrap_dek(dek: &[u8; DEK_LEN], spec: &NewWrapper) -> AtomicResult<Wrapper> {
    let (kdf, salt, kek) = match spec {
        NewWrapper::RecoveryCode { code } | NewWrapper::Password { password: code } => {
            let params = Argon2Params::default();
            let mut salt_bytes = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut salt_bytes);
            let kek =
                argon2id_derive_key(normalize_for(spec, code).as_bytes(), &salt_bytes, params)
                    .map_err(|e| format!("failed to stretch credential: {e}"))?;
            (Some(params.into()), Some(b64(&salt_bytes)), kek)
        }
        NewWrapper::WebauthnPrf { kek, .. } => (None, None, *kek),
        // No KDF: the agent secret is already a full-strength random key, so
        // stretching it would cost time and add nothing.
        NewWrapper::AgentSecret { agent_secret } => (None, None, agent_secret_kek(agent_secret)),
        NewWrapper::NodeKey { kek } => (None, None, *kek),
    };

    let (nonce, wrapped_dek) = seal(&kek, dek)?;
    Ok(Wrapper {
        kind: spec.kind(),
        id: spec.id(),
        kdf,
        salt,
        nonce,
        wrapped_dek,
    })
}

/// Recovery codes are normalized before stretching; passwords are not, because
/// a password's exact bytes are what the user chose.
fn normalize_for(spec: &NewWrapper, secret: &str) -> String {
    match spec {
        NewWrapper::RecoveryCode { .. } => normalize_recovery_code(secret),
        _ => secret.to_string(),
    }
}

impl SecretEnvelope {
    /// Protect `secret` under the given credentials.
    ///
    /// Requires at least one wrapper — an envelope nobody can open is not a
    /// backup. The stronger product rule (never a lone wrapper, so a lost
    /// passkey is not a lost identity) is enforced at the enrollment call site,
    /// where the UI can actually tell the user what second credential to add.
    pub fn create(secret: &[u8], wrappers: &[NewWrapper]) -> AtomicResult<Self> {
        if wrappers.is_empty() {
            return Err("an envelope needs at least one wrapper, or nothing can open it".into());
        }

        let mut dek = [0u8; DEK_LEN];
        rand::thread_rng().fill_bytes(&mut dek);

        let (nonce, ciphertext) = seal(&dek, secret)?;
        let wrapped = wrappers
            .iter()
            .map(|spec| wrap_dek(&dek, spec))
            .collect::<AtomicResult<Vec<_>>>()?;

        Ok(Self {
            format_version: SECRET_ENVELOPE_VERSION,
            nonce,
            ciphertext,
            wrappers: wrapped,
        })
    }

    /// Recover the DEK using whichever wrapper `unlock` opens.
    ///
    /// Tries every wrapper of a compatible kind rather than requiring the
    /// caller to name one: a user typing a code does not know which wrapper
    /// index it belongs to, and a wrong guess should read as "wrong code", not
    /// "wrong wrapper".
    fn recover_dek(&self, unlock: &Unlock) -> AtomicResult<[u8; DEK_LEN]> {
        self.check_version()?;

        for wrapper in &self.wrappers {
            let kek = match (unlock, wrapper.kind) {
                (Unlock::Secret(secret), WrapperKind::RecoveryCode | WrapperKind::Password) => {
                    let (Some(kdf), Some(salt)) = (wrapper.kdf, wrapper.salt.as_ref()) else {
                        continue;
                    };
                    let normalized = if wrapper.kind == WrapperKind::RecoveryCode {
                        normalize_recovery_code(secret)
                    } else {
                        (*secret).to_string()
                    };
                    match argon2id_derive_key(normalized.as_bytes(), &unb64(salt)?, kdf.into()) {
                        Ok(kek) => kek,
                        Err(_) => continue,
                    }
                }
                (Unlock::Kek(kek), WrapperKind::WebauthnPrf | WrapperKind::NodeKey) => *kek,
                (Unlock::AgentSecret(secret), WrapperKind::AgentSecret) => agent_secret_kek(secret),
                _ => continue,
            };

            if let Ok(dek) = unseal(&kek, &wrapper.nonce, &wrapper.wrapped_dek) {
                return dek
                    .try_into()
                    .map_err(|_| "envelope contained a malformed DEK".into());
            }
        }

        Err("no wrapper in this envelope accepted that credential".into())
    }

    /// Open the envelope and return the protected secret.
    pub fn unwrap_secret(&self, unlock: &Unlock) -> AtomicResult<Vec<u8>> {
        let dek = self.recover_dek(unlock)?;
        unseal(&dek, &self.nonce, &self.ciphertext)
    }

    /// Register another credential.
    ///
    /// Gated on opening the envelope first: without that, anyone who could
    /// write to the blob could add a wrapper of their own and take the secret
    /// with it. The server never can — it holds ciphertext — but the rule
    /// belongs in the format, not in the storage layer's good intentions.
    pub fn add_wrapper(&mut self, unlock: &Unlock, spec: &NewWrapper) -> AtomicResult<()> {
        let dek = self.recover_dek(unlock)?;
        let new_id = spec.id();
        if self.wrappers.iter().any(|w| w.id == new_id) {
            return Err(format!("a wrapper named {new_id} is already registered").into());
        }
        self.wrappers.push(wrap_dek(&dek, spec)?);
        Ok(())
    }

    /// Remove a credential. Refuses to remove the last one — that would leave a
    /// blob nobody can ever open, which is indistinguishable from having
    /// deleted the secret except that it looks like a backup still exists.
    pub fn remove_wrapper(&mut self, id: &str) -> AtomicResult<()> {
        if self.wrappers.len() <= 1 {
            return Err("cannot remove the only wrapper: the secret would be unrecoverable".into());
        }
        let before = self.wrappers.len();
        self.wrappers.retain(|w| w.id != id);
        if self.wrappers.len() == before {
            return Err(format!("no wrapper named {id}").into());
        }
        Ok(())
    }

    pub fn has_kind(&self, kind: WrapperKind) -> bool {
        self.wrappers.iter().any(|w| w.kind == kind)
    }

    fn check_version(&self) -> AtomicResult<()> {
        if self.format_version != SECRET_ENVELOPE_VERSION {
            return Err(format!(
                "unsupported envelope format version {}, this build understands {SECRET_ENVELOPE_VERSION}",
                self.format_version
            )
            .into());
        }
        Ok(())
    }

    pub fn to_json(&self) -> AtomicResult<String> {
        serde_json::to_string(self).map_err(|e| format!("failed to serialize envelope: {e}").into())
    }

    pub fn from_json(json: &str) -> AtomicResult<Self> {
        let envelope: Self =
            serde_json::from_str(json).map_err(|e| format!("failed to parse envelope: {e}"))?;
        envelope.check_version()?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Argon2id at production settings is intentionally slow; tests use the
    /// cheap parameters the KDF module already reserves for this.
    fn fast_params() -> Argon2Params {
        Argon2Params {
            mem_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        }
    }

    /// Build an envelope with cheap KDF params by rewriting them after
    /// creation is not possible (the KEK depends on them), so tests that need
    /// speed construct wrappers directly through the same code path with
    /// patched defaults would be fragile. Instead these tests accept the real
    /// cost for the few cases that need a code wrapper, and use PRF wrappers
    /// (no KDF) everywhere else.
    fn prf(id: &str, byte: u8) -> NewWrapper<'static> {
        NewWrapper::WebauthnPrf {
            credential_id: id.to_string(),
            kek: [byte; KEK_LEN],
        }
    }

    const SECRET: &[u8] = b"an ed25519 agent secret";

    #[test]
    fn round_trips_through_a_prf_wrapper() {
        let envelope = SecretEnvelope::create(SECRET, &[prf("passkey-a", 1)]).unwrap();
        let opened = envelope.unwrap_secret(&Unlock::Kek([1; KEK_LEN])).unwrap();
        assert_eq!(opened, SECRET);
    }

    #[test]
    fn the_secret_is_not_in_the_blob() {
        let envelope = SecretEnvelope::create(SECRET, &[prf("passkey-a", 1)]).unwrap();
        let json = envelope.to_json().unwrap();
        assert!(!json.contains("ed25519 agent secret"));
        assert!(!json.as_bytes().windows(SECRET.len()).any(|w| w == SECRET));
    }

    #[test]
    fn any_registered_credential_opens_it() {
        // The point of the design: two independent routes to one secret.
        let envelope =
            SecretEnvelope::create(SECRET, &[prf("passkey-a", 1), prf("passkey-b", 2)]).unwrap();
        assert_eq!(
            envelope.unwrap_secret(&Unlock::Kek([1; KEK_LEN])).unwrap(),
            SECRET
        );
        assert_eq!(
            envelope.unwrap_secret(&Unlock::Kek([2; KEK_LEN])).unwrap(),
            SECRET
        );
    }

    #[test]
    fn an_unregistered_credential_does_not() {
        let envelope = SecretEnvelope::create(SECRET, &[prf("passkey-a", 1)]).unwrap();
        assert!(envelope.unwrap_secret(&Unlock::Kek([9; KEK_LEN])).is_err());
    }

    #[test]
    fn a_recovery_code_opens_it() {
        let code = generate_recovery_code();
        let envelope =
            SecretEnvelope::create(SECRET, &[NewWrapper::RecoveryCode { code: &code }]).unwrap();
        assert_eq!(
            envelope.unwrap_secret(&Unlock::Secret(&code)).unwrap(),
            SECRET
        );
        assert!(envelope
            .unwrap_secret(&Unlock::Secret("WRONG-CODE-HERE"))
            .is_err());
    }

    /// A user reading a code off paper will not reproduce the grouping or the
    /// case, and Crockford's confusable characters are exactly the ones people
    /// mistranscribe.
    #[test]
    fn recovery_codes_tolerate_how_humans_retype_them() {
        let code = generate_recovery_code();
        let envelope =
            SecretEnvelope::create(SECRET, &[NewWrapper::RecoveryCode { code: &code }]).unwrap();

        let no_dashes = code.replace('-', "");
        let lowercased = code.to_lowercase();
        let spaced = code.replace('-', " ");

        for variant in [no_dashes, lowercased, spaced] {
            assert_eq!(
                envelope.unwrap_secret(&Unlock::Secret(&variant)).unwrap(),
                SECRET,
                "failed for {variant:?}"
            );
        }
    }

    #[test]
    fn generated_codes_are_unique_and_shaped_for_transcription() {
        let a = generate_recovery_code();
        let b = generate_recovery_code();
        assert_ne!(a, b);
        // 128 bits of base32 is 26 characters, grouped in fives.
        assert_eq!(a.replace('-', "").len(), 26);
        assert!(a.contains('-'));
        for c in a.chars().filter(|c| *c != '-') {
            assert!(
                !matches!(c, 'I' | 'L' | 'O' | 'U'),
                "confusable character {c} in {a}"
            );
        }
    }

    #[test]
    fn adding_a_credential_requires_opening_the_envelope_first() {
        let mut envelope = SecretEnvelope::create(SECRET, &[prf("passkey-a", 1)]).unwrap();

        // Someone who cannot open it cannot register themselves into it.
        assert!(envelope
            .add_wrapper(&Unlock::Kek([9; KEK_LEN]), &prf("attacker", 3))
            .is_err());

        envelope
            .add_wrapper(&Unlock::Kek([1; KEK_LEN]), &prf("passkey-b", 2))
            .unwrap();
        assert_eq!(
            envelope.unwrap_secret(&Unlock::Kek([2; KEK_LEN])).unwrap(),
            SECRET
        );
    }

    #[test]
    fn duplicate_wrapper_ids_are_refused() {
        let mut envelope = SecretEnvelope::create(SECRET, &[prf("passkey-a", 1)]).unwrap();
        assert!(envelope
            .add_wrapper(&Unlock::Kek([1; KEK_LEN]), &prf("passkey-a", 5))
            .is_err());
    }

    #[test]
    fn removing_a_credential_leaves_the_others_working() {
        let mut envelope =
            SecretEnvelope::create(SECRET, &[prf("passkey-a", 1), prf("passkey-b", 2)]).unwrap();
        envelope.remove_wrapper("passkey-a").unwrap();
        assert!(envelope.unwrap_secret(&Unlock::Kek([1; KEK_LEN])).is_err());
        assert_eq!(
            envelope.unwrap_secret(&Unlock::Kek([2; KEK_LEN])).unwrap(),
            SECRET
        );
    }

    #[test]
    fn the_last_credential_cannot_be_removed() {
        let mut envelope = SecretEnvelope::create(SECRET, &[prf("passkey-a", 1)]).unwrap();
        let err = envelope
            .remove_wrapper("passkey-a")
            .unwrap_err()
            .to_string();
        assert!(err.contains("unrecoverable"), "{err}");
        assert_eq!(
            envelope.unwrap_secret(&Unlock::Kek([1; KEK_LEN])).unwrap(),
            SECRET
        );
    }

    #[test]
    fn an_envelope_with_no_wrappers_is_refused() {
        assert!(SecretEnvelope::create(SECRET, &[]).is_err());
    }

    #[test]
    fn survives_json_storage() {
        let envelope =
            SecretEnvelope::create(SECRET, &[prf("passkey-a", 1), prf("passkey-b", 2)]).unwrap();
        let restored = SecretEnvelope::from_json(&envelope.to_json().unwrap()).unwrap();
        assert_eq!(restored, envelope);
        assert_eq!(
            restored.unwrap_secret(&Unlock::Kek([2; KEK_LEN])).unwrap(),
            SECRET
        );
    }

    /// v1 blobs are a different scheme. Refusing them loudly beats appearing to
    /// support them and returning nonsense.
    #[test]
    fn v1_blobs_are_refused_rather_than_misread() {
        let v1 = r#"{"format_version":1,"nonce":"","ciphertext":"","wrappers":[]}"#;
        let err = SecretEnvelope::from_json(v1).unwrap_err().to_string();
        assert!(err.contains("version"), "{err}");
    }

    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        let mut envelope = SecretEnvelope::create(SECRET, &[prf("passkey-a", 1)]).unwrap();
        envelope.ciphertext = b64(b"replaced by an attacker");
        assert!(envelope.unwrap_secret(&Unlock::Kek([1; KEK_LEN])).is_err());
    }

    /// A `DriveVaultKey` is protected exactly like an agent secret — the point
    /// of building this as a shared module rather than twice.
    #[test]
    fn protects_a_drive_vault_key_too() {
        let drive_key = super::super::dek::DriveVaultKey::generate(1);
        let envelope =
            SecretEnvelope::create(drive_key.expose_secret(), &[prf("passkey-a", 1)]).unwrap();
        let recovered = envelope.unwrap_secret(&Unlock::Kek([1; KEK_LEN])).unwrap();
        assert_eq!(recovered, drive_key.expose_secret());
    }

    /// The whole point of the wrapper: a user who can restore their identity can
    /// restore their drive keys, with nothing extra to remember.
    #[test]
    fn an_agent_secret_opens_the_envelope() {
        let agent_secret = b"an ed25519 private key's bytes";
        let drive_key = super::super::dek::DriveVaultKey::generate(1);
        let envelope = SecretEnvelope::create(
            drive_key.expose_secret(),
            &[NewWrapper::AgentSecret { agent_secret }],
        )
        .unwrap();

        let recovered = envelope
            .unwrap_secret(&Unlock::AgentSecret(agent_secret))
            .unwrap();
        assert_eq!(recovered, drive_key.expose_secret());
    }

    #[test]
    fn a_different_agent_secret_does_not() {
        let envelope = SecretEnvelope::create(
            SECRET,
            &[NewWrapper::AgentSecret {
                agent_secret: b"mine",
            }],
        )
        .unwrap();
        assert!(envelope
            .unwrap_secret(&Unlock::AgentSecret(b"someone else's"))
            .is_err());
    }

    /// The wrapping key must not be the signing key. If the same bytes both
    /// signed commits and decrypted backups, a flaw in either use would become
    /// a flaw in both.
    #[test]
    fn the_wrapping_key_is_derived_not_the_agent_secret_itself() {
        let agent_secret = [42u8; 32];
        let kek = agent_secret_kek(&agent_secret);
        assert_ne!(kek, agent_secret, "the KEK must not be the secret itself");

        // Deterministic, or a restore on another device could not reproduce it.
        assert_eq!(kek, agent_secret_kek(&agent_secret));
    }

    /// A drive key wrapped under the agent secret can gain a recovery-code
    /// wrapper later without re-encrypting anything — the point of wrapping a
    /// DEK rather than the secret.
    #[test]
    fn a_recovery_code_can_be_added_to_an_agent_wrapped_envelope() {
        let agent_secret = b"agent bytes";
        let mut envelope =
            SecretEnvelope::create(SECRET, &[NewWrapper::AgentSecret { agent_secret }]).unwrap();

        let code = generate_recovery_code();
        envelope
            .add_wrapper(
                &Unlock::AgentSecret(agent_secret),
                &NewWrapper::RecoveryCode { code: &code },
            )
            .unwrap();

        // Both routes now open the same secret.
        assert_eq!(
            envelope.unwrap_secret(&Unlock::Secret(&code)).unwrap(),
            SECRET
        );
        assert_eq!(
            envelope
                .unwrap_secret(&Unlock::AgentSecret(agent_secret))
                .unwrap(),
            SECRET
        );
    }

    /// Losing the agent secret must not be survivable *through this wrapper* —
    /// that is what the second wrapper is for. Pins that the agent wrapper
    /// alone genuinely gates on the secret.
    #[test]
    fn without_the_agent_secret_there_is_no_way_in() {
        let envelope = SecretEnvelope::create(
            SECRET,
            &[NewWrapper::AgentSecret {
                agent_secret: b"lost forever",
            }],
        )
        .unwrap();
        assert!(envelope.unwrap_secret(&Unlock::Kek([0; KEK_LEN])).is_err());
        assert!(envelope.unwrap_secret(&Unlock::Secret("guess")).is_err());
    }

    #[test]
    fn stored_kdf_params_survive_a_defaults_change() {
        // Reading params from the blob rather than from today's constants is
        // what keeps an old backup openable after the defaults are re-tuned.
        let stored: StoredKdfParams = fast_params().into();
        let back: Argon2Params = stored.into();
        assert_eq!(back.mem_kib, fast_params().mem_kib);
        assert_eq!(back.iterations, fast_params().iterations);
    }
}
