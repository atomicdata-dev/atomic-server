//! End-to-end encryption for conversations: direct messages and group chats.
//!
//! A conversation is a drive its members share. Whoever hosts it stores and
//! forwards ciphertext: it still verifies commit signatures and the ACL, which
//! stay plaintext, but it never sees what a message says. Design notes:
//! `planning/encrypted-conversations.md`.
//!
//! Three pieces:
//!
//! - **An agent's encryption key.** An X25519 key derived from the agent's
//!   vault proof (its deterministic signature over a fixed message, see
//!   [`crate::vault::secret_envelope::AGENT_VAULT_PROOF_MESSAGE`]) under its
//!   own context string. Every device that holds the agent derives the same
//!   key, so a new device or a restored identity reads every past
//!   conversation. The public half is published on the Agent resource.
//! - **A [`Keyring`]** per conversation: one random key per epoch, wrapped to
//!   each member's public key. A membership change starts a new epoch, so
//!   someone who leaves cannot read what follows.
//! - **Sealed messages.** XChaCha20-Poly1305 under a per-message key derived
//!   from the epoch key and a random message id. The header and the
//!   conversation's subject are associated data, so a ciphertext cannot be
//!   moved into another conversation. Revealing one message's key (to report
//!   abuse) reveals nothing else.
//! - **Sealed files.** An attachment is encrypted under its own random key,
//!   which travels only inside the sealed message that carries it. See
//!   [`seal_file`].

use crate::errors::AtomicResult;
use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

/// Turns the vault proof into the agent's X25519 secret. Distinct from the
/// vault's own context, so the same proof yields unrelated keys.
const ENCRYPTION_KEY_CONTEXT: &str = "atomic 2026 agent conversation encryption key";
/// Turns an X25519 shared secret into the key that wraps an epoch key.
const WRAP_CONTEXT: &str = "atomic 2026 conversation key wrap";
/// Turns an epoch key and a message id into that message's key.
const MESSAGE_CONTEXT: &str = "atomic 2026 sealed message key";
/// Prefixes the associated data of a sealed file, so a file ciphertext can
/// never be read as a message or the other way around.
const FILE_CONTEXT: &str = "atomic 2026 conversation file";

pub const KEYRING_FORMAT: u32 = 1;
const SEALED_VERSION: u8 = 1;
const FILE_VERSION: u8 = 1;
/// version (1) + nonce (24); the AEAD tag (16) follows the ciphertext.
const FILE_HEADER_LEN: usize = 1 + NONCE_LEN;
const FILE_TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const MESSAGE_ID_LEN: usize = 16;
/// version (1) + epoch (4, big-endian) + message id (16) + nonce (24).
const SEALED_HEADER_LEN: usize = 1 + 4 + MESSAGE_ID_LEN + NONCE_LEN;

fn b64(bytes: &[u8]) -> String {
    crate::agents::encode_base64(bytes)
}

fn unb64_array<const N: usize>(text: &str, what: &str) -> AtomicResult<[u8; N]> {
    crate::agents::decode_base64(text)?
        .try_into()
        .map_err(|_| format!("{what} has the wrong length").into())
}

/// The agent's X25519 secret, derived from its vault proof.
fn encryption_secret(vault_proof: &[u8]) -> StaticSecret {
    StaticSecret::from(blake3::derive_key(ENCRYPTION_KEY_CONTEXT, vault_proof))
}

/// The public key others encrypt to, base64url. Published on the Agent
/// resource as `encryptionKey`.
pub fn encryption_public_key(vault_proof: &[u8]) -> String {
    b64(PublicKey::from(&encryption_secret(vault_proof)).as_bytes())
}

/// One epoch's key, in the clear. Only ever held in memory.
#[derive(Clone)]
pub struct ConversationKey {
    pub epoch: u32,
    key: [u8; KEY_LEN],
}

impl ConversationKey {
    fn generate(epoch: u32) -> Self {
        let mut key = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key);
        Self { epoch, key }
    }
}

impl std::fmt::Debug for ConversationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationKey")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// A member, as the creator of an epoch sees them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    /// The agent's subject, `did:ad:agent:…`.
    pub agent: String,
    /// Their `encryptionKey`, base64url.
    pub encryption_key: String,
}

/// An epoch key sealed to one member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyWrapper {
    pub agent: String,
    /// The one-off X25519 public key the sender used for this wrapper.
    pub ephemeral: String,
    pub nonce: String,
    pub wrapped_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochKeys {
    pub epoch: u32,
    pub wrappers: Vec<KeyWrapper>,
}

/// Every epoch key of one conversation, each wrapped to that epoch's members.
///
/// Stored as JSON on the conversation's root. The host can read who has a
/// wrapper (it already knows the members from the ACL) and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyring {
    pub format: u32,
    pub epochs: Vec<EpochKeys>,
}

impl Default for Keyring {
    fn default() -> Self {
        Self {
            format: KEYRING_FORMAT,
            epochs: Vec::new(),
        }
    }
}

/// What the wrap key and the wrapper's associated data are bound to, so a
/// wrapper cannot be relabelled for another agent or epoch.
fn wrapper_binding(agent: &str, epoch: u32) -> Vec<u8> {
    [agent.as_bytes(), &[0], &epoch.to_be_bytes()].concat()
}

fn wrap_key_for(
    shared: &x25519_dalek::SharedSecret,
    ephemeral: &PublicKey,
    recipient: &PublicKey,
    binding: &[u8],
) -> [u8; KEY_LEN] {
    let mut hasher = blake3::Hasher::new_derive_key(WRAP_CONTEXT);
    hasher.update(shared.as_bytes());
    hasher.update(ephemeral.as_bytes());
    hasher.update(recipient.as_bytes());
    hasher.update(binding);
    *hasher.finalize().as_bytes()
}

fn aead_seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    msg: &[u8],
    aad: &[u8],
) -> AtomicResult<Vec<u8>> {
    XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(XNonce::from_slice(nonce), Payload { msg, aad })
        .map_err(|_| "failed to encrypt".into())
}

fn aead_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    msg: &[u8],
    aad: &[u8],
) -> AtomicResult<Vec<u8>> {
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(XNonce::from_slice(nonce), Payload { msg, aad })
        .map_err(|_| "could not decrypt: wrong key, or the data was altered".into())
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

fn wrap(key: &ConversationKey, member: &Member) -> AtomicResult<KeyWrapper> {
    let recipient = PublicKey::from(unb64_array::<KEY_LEN>(
        &member.encryption_key,
        "encryption key",
    )?);
    let ephemeral_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let ephemeral = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&recipient);
    // A low-order public key makes the shared secret independent of our
    // secret, so anyone could compute the wrap key.
    if !shared.was_contributory() {
        return Err(format!("{} has an invalid encryption key", member.agent).into());
    }
    let binding = wrapper_binding(&member.agent, key.epoch);
    let kek = wrap_key_for(&shared, &ephemeral, &recipient, &binding);
    let nonce = random_nonce();
    let wrapped = aead_seal(&kek, &nonce, &key.key, &binding)?;
    Ok(KeyWrapper {
        agent: member.agent.clone(),
        ephemeral: b64(ephemeral.as_bytes()),
        nonce: b64(&nonce),
        wrapped_key: b64(&wrapped),
    })
}

fn unwrap(wrapper: &KeyWrapper, epoch: u32, vault_proof: &[u8]) -> AtomicResult<ConversationKey> {
    let secret = encryption_secret(vault_proof);
    let recipient = PublicKey::from(&secret);
    let ephemeral = PublicKey::from(unb64_array::<KEY_LEN>(&wrapper.ephemeral, "ephemeral key")?);
    let shared = secret.diffie_hellman(&ephemeral);
    if !shared.was_contributory() {
        return Err("key wrapper has an invalid ephemeral key".into());
    }
    let binding = wrapper_binding(&wrapper.agent, epoch);
    let kek = wrap_key_for(&shared, &ephemeral, &recipient, &binding);
    let nonce = unb64_array::<NONCE_LEN>(&wrapper.nonce, "wrapper nonce")?;
    let key: [u8; KEY_LEN] = aead_open(
        &kek,
        &nonce,
        &crate::agents::decode_base64(&wrapper.wrapped_key)?,
        &binding,
    )?
    .try_into()
    .map_err(|_| "wrapped conversation key has the wrong length")?;
    Ok(ConversationKey { epoch, key })
}

impl Keyring {
    pub fn from_json(json: &str) -> AtomicResult<Self> {
        let keyring: Self =
            serde_json::from_str(json).map_err(|e| format!("failed to parse keyring: {e}"))?;
        if keyring.format != KEYRING_FORMAT {
            return Err(format!(
                "unsupported keyring format {}, this build understands {KEYRING_FORMAT}",
                keyring.format
            )
            .into());
        }
        Ok(keyring)
    }

    pub fn to_json(&self) -> AtomicResult<String> {
        serde_json::to_string(self).map_err(|e| format!("failed to serialize keyring: {e}").into())
    }

    pub fn current_epoch(&self) -> Option<u32> {
        self.epochs.iter().map(|e| e.epoch).max()
    }

    /// Starts a new epoch with a fresh key, wrapped to exactly `members`.
    ///
    /// Call it to create a conversation and on every membership change. Who is
    /// left out of `members` cannot read anything sealed from now on.
    pub fn add_epoch(&mut self, members: &[Member]) -> AtomicResult<u32> {
        if members.is_empty() {
            return Err("an epoch needs at least one member, or nobody can read it".into());
        }
        let epoch = self.current_epoch().map_or(0, |e| e + 1);
        let key = ConversationKey::generate(epoch);
        let wrappers = members
            .iter()
            .map(|m| wrap(&key, m))
            .collect::<AtomicResult<Vec<_>>>()?;
        self.epochs.push(EpochKeys { epoch, wrappers });
        Ok(epoch)
    }

    /// Every epoch key `agent` can open, oldest first. Epochs they were not a
    /// member of are skipped, not an error.
    pub fn open(&self, agent: &str, vault_proof: &[u8]) -> AtomicResult<Vec<ConversationKey>> {
        let mut keys = Vec::new();
        for epoch in &self.epochs {
            if let Some(wrapper) = epoch.wrappers.iter().find(|w| w.agent == agent) {
                keys.push(unwrap(wrapper, epoch.epoch, vault_proof)?);
            }
        }
        keys.sort_by_key(|k| k.epoch);
        Ok(keys)
    }

    /// The newest epoch key, which is what new messages are sealed with.
    pub fn open_current(&self, agent: &str, vault_proof: &[u8]) -> AtomicResult<ConversationKey> {
        let current = self
            .current_epoch()
            .ok_or("this conversation has no keys yet")?;
        self.open(agent, vault_proof)?
            .into_iter()
            .find(|k| k.epoch == current)
            .ok_or_else(|| format!("{agent} is not a member of the current epoch").into())
    }
}

fn message_key(key: &ConversationKey, message_id: &[u8]) -> [u8; KEY_LEN] {
    let mut hasher = blake3::Hasher::new_derive_key(MESSAGE_CONTEXT);
    hasher.update(&key.key);
    hasher.update(message_id);
    *hasher.finalize().as_bytes()
}

/// The parsed fixed-size prefix of a sealed message.
struct SealedHeader<'a> {
    bytes: &'a [u8],
    epoch: u32,
    message_id: &'a [u8],
    nonce: [u8; NONCE_LEN],
    ciphertext: &'a [u8],
}

fn parse_sealed(raw: &[u8]) -> AtomicResult<SealedHeader<'_>> {
    if raw.len() < SEALED_HEADER_LEN {
        return Err("sealed message is too short".into());
    }
    if raw[0] != SEALED_VERSION {
        return Err(format!("unsupported sealed message version {}", raw[0]).into());
    }
    let epoch = u32::from_be_bytes(raw[1..5].try_into().expect("four bytes"));
    let message_id = &raw[5..5 + MESSAGE_ID_LEN];
    let nonce: [u8; NONCE_LEN] = raw[5 + MESSAGE_ID_LEN..SEALED_HEADER_LEN]
        .try_into()
        .expect("nonce length");
    Ok(SealedHeader {
        bytes: &raw[..SEALED_HEADER_LEN],
        epoch,
        message_id,
        nonce,
        ciphertext: &raw[SEALED_HEADER_LEN..],
    })
}

/// The header plus the conversation it belongs to.
fn sealed_aad(header: &[u8], conversation: &str) -> Vec<u8> {
    [header, conversation.as_bytes()].concat()
}

/// Encrypts a message's payload for `conversation` (the chat it is posted
/// in) under the given epoch key. Returns base64url, the value of `sealed`.
pub fn seal_message(
    key: &ConversationKey,
    conversation: &str,
    plaintext: &[u8],
) -> AtomicResult<String> {
    let mut message_id = [0u8; MESSAGE_ID_LEN];
    rand::thread_rng().fill_bytes(&mut message_id);
    let nonce = random_nonce();
    let header = [
        &[SEALED_VERSION][..],
        &key.epoch.to_be_bytes(),
        &message_id,
        &nonce,
    ]
    .concat();
    let ciphertext = aead_seal(
        &message_key(key, &message_id),
        &nonce,
        plaintext,
        &sealed_aad(&header, conversation),
    )?;
    Ok(b64(&[header, ciphertext].concat()))
}

/// The epoch a sealed message was written in, readable without any key.
pub fn sealed_epoch(sealed: &str) -> AtomicResult<u32> {
    Ok(parse_sealed(&crate::agents::decode_base64(sealed)?)?.epoch)
}

/// Decrypts a sealed message with whichever of `keys` matches its epoch.
pub fn open_message(
    keys: &[ConversationKey],
    conversation: &str,
    sealed: &str,
) -> AtomicResult<Vec<u8>> {
    let raw = crate::agents::decode_base64(sealed)?;
    let header = parse_sealed(&raw)?;
    let key = keys
        .iter()
        .find(|k| k.epoch == header.epoch)
        .ok_or_else(|| format!("no key for epoch {}", header.epoch))?;
    aead_open(
        &message_key(key, header.message_id),
        &header.nonce,
        header.ciphertext,
        &sealed_aad(header.bytes, conversation),
    )
}

/// The key of one message, base64url, for reporting it. Whoever receives it
/// can read that message and no other.
pub fn reveal_message_key(keys: &[ConversationKey], sealed: &str) -> AtomicResult<String> {
    let raw = crate::agents::decode_base64(sealed)?;
    let header = parse_sealed(&raw)?;
    let key = keys
        .iter()
        .find(|k| k.epoch == header.epoch)
        .ok_or_else(|| format!("no key for epoch {}", header.epoch))?;
    Ok(b64(&message_key(key, header.message_id)))
}

/// Opens one message with a key from [`reveal_message_key`].
pub fn open_revealed_message(
    message_key: &str,
    conversation: &str,
    sealed: &str,
) -> AtomicResult<Vec<u8>> {
    let key = unb64_array::<KEY_LEN>(message_key, "message key")?;
    let raw = crate::agents::decode_base64(sealed)?;
    let header = parse_sealed(&raw)?;
    aead_open(
        &key,
        &header.nonce,
        header.ciphertext,
        &sealed_aad(header.bytes, conversation),
    )
}

fn file_aad(conversation: &str) -> Vec<u8> {
    [FILE_CONTEXT.as_bytes(), conversation.as_bytes()].concat()
}

/// Encrypts an attachment for `conversation`. Returns the file key (base64url)
/// and the ciphertext, laid out as `version(1) | nonce(24) | ciphertext+tag`.
///
/// The key is random and belongs to this file alone. It is not derived from
/// the conversation's epoch key: it travels only inside the sealed message
/// that references the file, so rotating the epoch later changes nothing, and
/// revealing one attachment's key reveals nothing else. The conversation's
/// subject is associated data, so the ciphertext cannot be moved into another
/// conversation. Sealing the same bytes twice gives unrelated ciphertexts.
pub fn seal_file(conversation: &str, plaintext: &[u8]) -> AtomicResult<(String, Vec<u8>)> {
    let mut key = [0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    let nonce = random_nonce();
    // One allocation: header, then the plaintext, encrypted where it lies.
    let mut out = Vec::with_capacity(FILE_HEADER_LEN + plaintext.len() + FILE_TAG_LEN);
    out.push(FILE_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(plaintext);
    let tag = XChaCha20Poly1305::new(Key::from_slice(&key))
        .encrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            &file_aad(conversation),
            &mut out[FILE_HEADER_LEN..],
        )
        .map_err(|_| "failed to encrypt the file")?;
    out.extend_from_slice(&tag);
    Ok((b64(&key), out))
}

/// Decrypts what [`seal_file`] produced, given the conversation it was sealed
/// for and the key from the message that references it.
pub fn open_file(conversation: &str, key: &str, sealed: &[u8]) -> AtomicResult<Vec<u8>> {
    let key = unb64_array::<KEY_LEN>(key, "file key")?;
    if sealed.len() < FILE_HEADER_LEN + FILE_TAG_LEN {
        return Err("sealed file is too short".into());
    }
    if sealed[0] != FILE_VERSION {
        return Err(format!("unsupported sealed file version {}", sealed[0]).into());
    }
    let nonce = &sealed[1..FILE_HEADER_LEN];
    let (body, tag) =
        sealed[FILE_HEADER_LEN..].split_at(sealed.len() - FILE_HEADER_LEN - FILE_TAG_LEN);
    let mut plaintext = body.to_vec();
    XChaCha20Poly1305::new(Key::from_slice(&key))
        .decrypt_in_place_detached(
            XNonce::from_slice(nonce),
            &file_aad(conversation),
            &mut plaintext,
            tag.into(),
        )
        .map_err(|_| "could not decrypt the file: wrong key, or the data was altered")?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: &str = "did:ad:conversation-room";

    fn proof(byte: u8) -> Vec<u8> {
        vec![byte; 64]
    }

    fn member(name: &str, byte: u8) -> Member {
        Member {
            agent: format!("did:ad:agent:{name}"),
            encryption_key: encryption_public_key(&proof(byte)),
        }
    }

    fn two_person_keyring() -> Keyring {
        let mut keyring = Keyring::default();
        keyring
            .add_epoch(&[member("alice", 1), member("bob", 2)])
            .unwrap();
        keyring
    }

    #[test]
    fn the_encryption_key_is_the_same_on_every_device() {
        assert_eq!(
            encryption_public_key(&proof(1)),
            encryption_public_key(&proof(1))
        );
        assert_ne!(
            encryption_public_key(&proof(1)),
            encryption_public_key(&proof(2))
        );
    }

    #[test]
    fn the_encryption_key_is_not_the_vault_key() {
        let vault_kek = crate::vault::secret_envelope::agent_secret_kek(&proof(1));
        assert_ne!(encryption_secret(&proof(1)).to_bytes(), vault_kek);
    }

    #[test]
    fn both_members_read_what_either_writes() {
        let keyring = two_person_keyring();
        let alice = keyring
            .open_current("did:ad:agent:alice", &proof(1))
            .unwrap();
        let bob = keyring.open("did:ad:agent:bob", &proof(2)).unwrap();

        let sealed = seal_message(&alice, ROOM, b"hello bob").unwrap();
        assert_eq!(open_message(&bob, ROOM, &sealed).unwrap(), b"hello bob");
    }

    #[test]
    fn someone_outside_the_conversation_cannot_open_it() {
        let keyring = two_person_keyring();
        // Carol claims Bob's wrapper with her own key.
        assert!(keyring.open("did:ad:agent:bob", &proof(3)).is_err());
        // And has no wrapper of her own.
        assert!(keyring
            .open("did:ad:agent:carol", &proof(3))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_wrapper_cannot_be_relabelled_for_another_agent() {
        let mut keyring = two_person_keyring();
        // Bob's wrapper, renamed to Alice. Alice's key can't open it, and Bob's
        // key fails too, because the agent is bound into the wrap.
        keyring.epochs[0].wrappers[1].agent = "did:ad:agent:alice".into();
        keyring.epochs[0].wrappers.remove(0);
        assert!(keyring.open("did:ad:agent:alice", &proof(1)).is_err());
        assert!(keyring.open("did:ad:agent:alice", &proof(2)).is_err());
    }

    #[test]
    fn a_message_cannot_be_moved_to_another_conversation() {
        let keyring = two_person_keyring();
        let keys = keyring.open("did:ad:agent:alice", &proof(1)).unwrap();
        let sealed = seal_message(&keys[0], ROOM, b"only here").unwrap();
        assert!(open_message(&keys, "did:ad:other-room", &sealed).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let keyring = two_person_keyring();
        let keys = keyring.open("did:ad:agent:alice", &proof(1)).unwrap();
        let mut raw =
            crate::agents::decode_base64(&seal_message(&keys[0], ROOM, b"x").unwrap()).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(open_message(&keys, ROOM, &b64(&raw)).is_err());
    }

    #[test]
    fn someone_who_left_cannot_read_the_next_epoch() {
        let mut keyring = two_person_keyring();
        keyring.add_epoch(&[member("alice", 1)]).unwrap();

        let alice = keyring
            .open_current("did:ad:agent:alice", &proof(1))
            .unwrap();
        assert_eq!(alice.epoch, 1);
        let sealed = seal_message(&alice, ROOM, b"after bob left").unwrap();

        let bob = keyring.open("did:ad:agent:bob", &proof(2)).unwrap();
        assert_eq!(bob.len(), 1, "bob keeps epoch 0 only");
        assert!(open_message(&bob, ROOM, &sealed).is_err());
        assert!(keyring.open_current("did:ad:agent:bob", &proof(2)).is_err());
        assert_eq!(sealed_epoch(&sealed).unwrap(), 1);
    }

    #[test]
    fn earlier_epochs_stay_readable_for_members() {
        let mut keyring = two_person_keyring();
        let first = keyring
            .open_current("did:ad:agent:alice", &proof(1))
            .unwrap();
        let old = seal_message(&first, ROOM, b"old").unwrap();
        keyring
            .add_epoch(&[member("alice", 1), member("bob", 2), member("carol", 3)])
            .unwrap();

        assert_eq!(
            open_message(
                &keyring.open("did:ad:agent:bob", &proof(2)).unwrap(),
                ROOM,
                &old
            )
            .unwrap(),
            b"old"
        );
        // Carol joined in epoch 1 and does not see history.
        assert!(open_message(
            &keyring.open("did:ad:agent:carol", &proof(3)).unwrap(),
            ROOM,
            &old
        )
        .is_err());
    }

    #[test]
    fn a_revealed_message_key_opens_that_message_only() {
        let keyring = two_person_keyring();
        let keys = keyring.open("did:ad:agent:bob", &proof(2)).unwrap();
        let reported = seal_message(&keys[0], ROOM, b"abusive").unwrap();
        let other = seal_message(&keys[0], ROOM, b"private").unwrap();

        let revealed = reveal_message_key(&keys, &reported).unwrap();
        assert_eq!(
            open_revealed_message(&revealed, ROOM, &reported).unwrap(),
            b"abusive"
        );
        assert!(open_revealed_message(&revealed, ROOM, &other).is_err());
    }

    #[test]
    fn a_low_order_encryption_key_is_refused() {
        let mut keyring = Keyring::default();
        let bad = Member {
            agent: "did:ad:agent:mallory".into(),
            encryption_key: b64(&[0u8; 32]),
        };
        assert!(keyring.add_epoch(&[bad]).is_err());
    }

    #[test]
    fn a_file_round_trips() {
        let (key, sealed) = seal_file(ROOM, b"holiday photo").unwrap();
        assert_ne!(&sealed[FILE_HEADER_LEN..], b"holiday photo");
        assert_eq!(open_file(ROOM, &key, &sealed).unwrap(), b"holiday photo");
    }

    #[test]
    fn a_file_cannot_be_moved_to_another_conversation() {
        let (key, sealed) = seal_file(ROOM, b"only here").unwrap();
        assert!(open_file("did:ad:other-room", &key, &sealed).is_err());
    }

    #[test]
    fn a_file_needs_its_own_key() {
        let (_, sealed) = seal_file(ROOM, b"secret").unwrap();
        let (other_key, _) = seal_file(ROOM, b"secret").unwrap();
        assert!(open_file(ROOM, &other_key, &sealed).is_err());
        assert!(open_file(ROOM, "not a key", &sealed).is_err());
    }

    #[test]
    fn a_tampered_file_is_refused_wherever_the_byte_flips() {
        let (key, sealed) = seal_file(ROOM, b"some bytes worth protecting").unwrap();
        // Version, nonce, body and tag.
        for index in [
            0,
            1,
            FILE_HEADER_LEN,
            sealed.len() - FILE_TAG_LEN,
            sealed.len() - 1,
        ] {
            let mut altered = sealed.clone();
            altered[index] ^= 1;
            assert!(
                open_file(ROOM, &key, &altered).is_err(),
                "flipping byte {index} went unnoticed"
            );
        }
        assert!(open_file(ROOM, &key, &sealed[..sealed.len() - 1]).is_err());
        assert!(open_file(ROOM, &key, &[]).is_err());
    }

    #[test]
    fn sealing_the_same_file_twice_gives_different_output() {
        let (key_a, a) = seal_file(ROOM, b"same bytes").unwrap();
        let (key_b, b) = seal_file(ROOM, b"same bytes").unwrap();
        assert_ne!(key_a, key_b);
        assert_ne!(a, b);
        assert_ne!(a[1..FILE_HEADER_LEN], b[1..FILE_HEADER_LEN], "nonce reused");
    }

    #[test]
    fn an_empty_file_round_trips() {
        let (key, sealed) = seal_file(ROOM, b"").unwrap();
        assert_eq!(sealed.len(), FILE_HEADER_LEN + FILE_TAG_LEN);
        assert!(open_file(ROOM, &key, &sealed).unwrap().is_empty());
    }

    #[test]
    fn the_largest_attachment_round_trips() {
        let plaintext: Vec<u8> = (0..25 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let (key, sealed) = seal_file(ROOM, &plaintext).unwrap();
        assert_eq!(
            sealed.len(),
            plaintext.len() + FILE_HEADER_LEN + FILE_TAG_LEN
        );
        assert!(open_file(ROOM, &key, &sealed).unwrap() == plaintext);
    }

    #[test]
    fn the_keyring_round_trips_through_json() {
        let keyring = two_person_keyring();
        let parsed = Keyring::from_json(&keyring.to_json().unwrap()).unwrap();
        assert_eq!(parsed, keyring);
        assert!(Keyring::from_json(r#"{"format":2,"epochs":[]}"#).is_err());
    }
}
