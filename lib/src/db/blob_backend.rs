//! File bytes have independent storage from transactional graph state.
use super::{trees::Tree, Db};
use crate::errors::AtomicResult;
use async_trait::async_trait;

#[async_trait]
pub trait BlobBackend: Send + Sync {
    async fn get(&self, key: &[u8]) -> AtomicResult<Option<Vec<u8>>>;
    async fn put(&self, key: &[u8], bytes: &[u8]) -> AtomicResult<()>;
    /// Metadata only: usage accounting must not download every file.
    async fn size(&self, key: &[u8]) -> AtomicResult<Option<u64>>;
}

impl Db {
    pub async fn get_blob(&self, key: &[u8]) -> AtomicResult<Option<Vec<u8>>> {
        match &self.blob_backend {
            Some(backend) => backend.get(key).await,
            None => self.kv.get(Tree::Blobs, key),
        }
    }

    pub async fn put_blob(&self, key: &[u8], bytes: &[u8]) -> AtomicResult<()> {
        match &self.blob_backend {
            Some(backend) => backend.put(key, bytes).await,
            None => self.kv.insert(Tree::Blobs, key, bytes),
        }
    }

    pub async fn blob_size(&self, key: &[u8]) -> AtomicResult<Option<u64>> {
        match &self.blob_backend {
            Some(backend) => backend.size(key).await,
            None => Ok(self.kv.get(Tree::Blobs, key)?.map(|b| b.len() as u64)),
        }
    }

    pub async fn has_blob(&self, key: &[u8]) -> AtomicResult<bool> {
        Ok(self.blob_size(key).await?.is_some())
    }

    /// Run before starting transports. Copy and verify each existing local blob
    /// before removing it. A failed/interrupted migration is safe to retry.
    /// Never fall back to local storage after selecting a remote backend.
    pub async fn migrate_blobs_to_backend(&self) -> AtomicResult<usize> {
        let Some(backend) = &self.blob_backend else {
            return Ok(0);
        };
        let mut migrated = 0;
        while let Some((key, bytes)) = self.kv.first_entry(Tree::Blobs)? {
            backend.put(&key, &bytes).await?;
            let stored = backend
                .get(&key)
                .await?
                .ok_or("Blob migration verification: object missing")?;
            if stored != bytes {
                return Err("Blob migration verification: contents differ".into());
            }
            self.kv.remove(Tree::Blobs, &key)?;
            self.kv.flush()?;
            migrated += 1;
        }
        Ok(migrated)
    }
}
