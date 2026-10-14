//! Shared crypto for client-side envelope encryption: a random DEK encrypts
//! the protected secret once, wrapped independently per credential
//! (`secret_envelope`: the agent's vault proof, or a node key). `keys` also
//! carries the Argon2id KDF that the browser's recovery-code backup
//! (`recovery.ts`, stored by atomic-saas) loads through `atomic-wasm`; that
//! backup's envelope format itself lives in TypeScript.
//!
//! The drive-level Cloud Vault key material lives here too
//! (`planning/CLOUD_VAULT_ARCHITECTURE.md`).

pub mod keys;

// Phase 0/1 of the Cloud Vault build: the drive key hierarchy and the object
// envelope. Gated on `db-redb` because that is the feature carrying
// `chacha20poly1305`, and every host that can run a vault client already
// enables it (see the host table in CLOUD_VAULT_ARCHITECTURE.md).
#[cfg(feature = "db")]
pub mod blobs;
#[cfg(feature = "db")]
pub mod dek;
#[cfg(feature = "db")]
pub mod envelope;
#[cfg(feature = "db")]
pub mod inspect;
#[cfg(feature = "db")]
pub mod pack;
#[cfg(feature = "db")]
pub mod secret_envelope;
#[cfg(feature = "db")]
pub mod store;
#[cfg(feature = "db")]
pub mod sync;
