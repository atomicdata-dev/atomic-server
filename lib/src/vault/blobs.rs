//! File bytes remain separate from graph packs. Only encrypted dependencies
//! name their plaintext hashes; object storage sees drive-scoped keyed ids.
use super::{
    dek::DriveVaultKey,
    envelope::{self, ObjectKind},
    store::VaultObjectStore,
};
use crate::{errors::AtomicResult, resources::Resource, Subject};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CHUNK_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobDependency {
    pub hash: String,
    pub content_id: String,
    pub size: u64,
    pub chunks: u32,
}

/// Public upload metadata. Contains no plaintext hash or resource identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobUpload {
    pub object_key: String,
    pub content_hash: String,
    pub chunk_index: u32,
}

pub fn object_key(pseudonym: &str, content_id: &str, chunk: u32) -> String {
    format!("vault/{pseudonym}/blobs/{content_id}/{chunk:06}")
}

pub fn references(resource: &Resource) -> AtomicResult<BTreeSet<String>> {
    let values = if let Ok(chunks) = resource.get(crate::urls::CHUNKS) {
        chunks.to_subjects(None)?
    } else if let Ok(blob) = resource.get(crate::urls::BLOB) {
        vec![blob.to_string()]
    } else {
        Vec::new()
    };
    values
        .into_iter()
        .map(|value| {
            let subject = Subject::from_raw(&value, None);
            subject
                .blob_hash_hex()
                .map(str::to_owned)
                .ok_or_else(|| format!("invalid file blob reference: {value}").into())
        })
        .collect()
}

// Immutable object ids include the epoch: a confirmed old ciphertext must not
// suppress upload of the new ciphertext, or be overwritten during rotation.
fn content_id(key: &DriveVaultKey, bytes: &[u8]) -> String {
    let mut hash = blake3::Hasher::new_keyed(&key.blob_id(bytes));
    hash.update(b"atomic-vault-blob-object-v1");
    hash.update(&key.epoch().to_be_bytes());
    hash.finalize().to_hex().to_string()
}

pub fn seal(
    key: &DriveVaultKey,
    pseudonym: &str,
    hash: &str,
    bytes: &[u8],
    vault: &dyn VaultObjectStore,
) -> AtomicResult<(BlobDependency, Vec<BlobUpload>)> {
    if blake3::hash(bytes).to_hex().as_str() != hash {
        return Err("file bytes do not match their blob hash; backup refused".into());
    }
    let content_id = content_id(key, bytes);
    let chunks = bytes.len().div_ceil(CHUNK_BYTES).max(1);
    let mut uploads = Vec::new();
    for index in 0..chunks {
        let start = index * CHUNK_BYTES;
        let chunk = &bytes[start..bytes.len().min(start + CHUNK_BYTES)];
        let chunk_index = u32::try_from(index).map_err(|e| e.to_string())?;
        let object_key = object_key(pseudonym, &content_id, chunk_index);
        vault.put(&object_key, &envelope::seal(key, ObjectKind::Blob, chunk)?)?;
        uploads.push(BlobUpload {
            object_key,
            content_hash: content_id.clone(),
            chunk_index,
        });
    }
    Ok((
        BlobDependency {
            hash: hash.into(),
            content_id,
            size: bytes.len() as u64,
            chunks: u32::try_from(chunks).map_err(|e| e.to_string())?,
        },
        uploads,
    ))
}

pub fn open(
    key: &DriveVaultKey,
    prefix: &str,
    dependency: &BlobDependency,
    vault: &dyn VaultObjectStore,
) -> AtomicResult<Vec<u8>> {
    for hash in [&dependency.hash, &dependency.content_id] {
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("invalid vault blob hash".into());
        }
    }
    if u64::from(dependency.chunks) != dependency.size.div_ceil(CHUNK_BYTES as u64).max(1) {
        return Err("invalid vault blob chunk count".into());
    }
    let mut bytes = Vec::new();
    for index in 0..dependency.chunks {
        let object_key = format!("{prefix}blobs/{}/{index:06}", dependency.content_id);
        let (header, chunk) = envelope::open(key, &vault.get(&object_key)?)?;
        let remaining = dependency.size.saturating_sub(bytes.len() as u64);
        if header.kind != ObjectKind::Blob
            || chunk.len() as u64 != remaining.min(CHUNK_BYTES as u64)
        {
            return Err("invalid vault blob chunk kind or length".into());
        }
        bytes.extend(chunk);
    }
    if blake3::hash(&bytes).to_hex().as_str() != dependency.hash
        || content_id(key, &bytes) != dependency.content_id
    {
        return Err("vault blob content does not match its dependency".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::super::store::MemoryVaultStore;
    use super::*;

    #[test]
    fn rotating_an_epoch_keeps_both_ciphertexts_recoverable() {
        let vault = MemoryVaultStore::new();
        let old = DriveVaultKey::from_bytes([3; 32], 1);
        let next = DriveVaultKey::from_bytes([3; 32], 2);
        let bytes = b"same file across rotation";
        let hash = blake3::hash(bytes).to_hex().to_string();
        let (a, _) = seal(&old, "drive", &hash, bytes, &vault).unwrap();
        let (b, _) = seal(&next, "drive", &hash, bytes, &vault).unwrap();
        assert_ne!(a.content_id, b.content_id);
        assert_eq!(open(&old, "vault/drive/", &a, &vault).unwrap(), bytes);
        assert_eq!(open(&next, "vault/drive/", &b, &vault).unwrap(), bytes);
    }

    #[test]
    fn chunks_are_encrypted_separate_and_verified() {
        let key = DriveVaultKey::from_bytes([3; 32], 2);
        for size in [0, 17, CHUNK_BYTES + 13] {
            let vault = MemoryVaultStore::new();
            let bytes = vec![42; size];
            let hash = blake3::hash(&bytes).to_hex().to_string();
            let (dependency, uploads) = seal(&key, "p", &hash, &bytes, &vault).unwrap();
            assert_eq!(open(&key, "vault/p/", &dependency, &vault).unwrap(), bytes);
            assert!(!uploads[0].object_key.contains(&hash));
            assert!(open(
                &DriveVaultKey::from_bytes([3; 32], 1),
                "vault/p/",
                &dependency,
                &vault
            )
            .is_err());
            let mut damaged = vault.get(&uploads[0].object_key).unwrap();
            *damaged.last_mut().unwrap() ^= 1;
            vault.put(&uploads[0].object_key, &damaged).unwrap();
            assert!(open(&key, "vault/p/", &dependency, &vault).is_err());
        }
    }
}
