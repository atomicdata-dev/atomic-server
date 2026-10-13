//! File bytes have independent storage from transactional graph state.
use super::{
    kv_store::KvStore,
    trees::{Method, Operation, Tree},
    Db,
};
use crate::errors::AtomicResult;
use async_trait::async_trait;
use std::sync::Arc;

/// One stored blob, as listed for garbage collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobInfo {
    /// The BLAKE3 hash the blob is stored under.
    pub key: Vec<u8>,
    pub size: u64,
    /// Milliseconds since the Unix epoch of the most recent `put` of this key
    /// (a re-upload of existing bytes counts: it restarts the grace period).
    /// `None` when the backend has never recorded one, which only legacy
    /// local blobs written before timestamps existed can be.
    pub modified_ms: Option<i64>,
}

fn gc_unsupported<T>() -> AtomicResult<T> {
    Err("this blob backend does not support listing or deleting blobs, so it cannot be garbage collected".into())
}

#[async_trait]
pub trait BlobBackend: Send + Sync {
    async fn get(&self, key: &[u8]) -> AtomicResult<Option<Vec<u8>>>;
    /// Read an object whose key is NOT the BLAKE3 hash of its bytes, such as a
    /// derived rendition stored under a synthetic cache key. `get` may verify
    /// that the bytes hash to the key; this read must not. Defaults to `get`.
    async fn get_unverified(&self, key: &[u8]) -> AtomicResult<Option<Vec<u8>>> {
        self.get(key).await
    }
    async fn put(&self, key: &[u8], bytes: &[u8]) -> AtomicResult<()>;
    /// Metadata only: usage accounting must not download every file.
    async fn size(&self, key: &[u8]) -> AtomicResult<Option<u64>>;

    // Garbage collection (planning/s3-blob-storage.md, "GC / refcounting").
    // The defaults refuse, so a backend written before GC existed keeps
    // compiling and is never swept by accident.

    /// Every blob in this backend, with size and last-put time. Must be
    /// complete or an error: a sweep trusts the listing to be the whole store.
    async fn list(&self) -> AtomicResult<Vec<BlobInfo>> {
        gc_unsupported()
    }
    /// Remove a blob. Deleting a blob that is already gone is not an error.
    async fn delete(&self, _key: &[u8]) -> AtomicResult<()> {
        gc_unsupported()
    }
    /// Last-put time of one blob; `None` when it is absent or has no recorded time.
    async fn modified_ms(&self, _key: &[u8]) -> AtomicResult<Option<i64>> {
        gc_unsupported()
    }
    /// Give blobs without a recorded time one, as of now, so they get a full
    /// grace period before they can be swept. Backends whose objects always
    /// carry a timestamp (S3) do nothing.
    async fn record_first_seen(&self, _keys: &[Vec<u8>]) -> AtomicResult<()> {
        Ok(())
    }
}

/// Prefix in `Tree::PluginMeta` for the redb blob tree's last-put times:
/// `blob-seen/v1/<hex hash>` -> big-endian `i64` milliseconds. `Tree::Blobs`
/// itself has no room for metadata (value = the file bytes, keys are hashes,
/// redb has no object mtime), and rewriting its values would break every
/// reader and the migration to S3. A side entry written in the same atomic
/// batch as the bytes costs one tiny row per blob and needs no new table or
/// data migration. Blobs from before this existed have no row; the first GC
/// pass stamps them (see [`BlobBackend::record_first_seen`]).
pub(super) const SEEN_PREFIX: &str = "blob-seen/v1/";

fn seen_key(key: &[u8]) -> Vec<u8> {
    format!("{SEEN_PREFIX}{}", hex::encode(key)).into_bytes()
}

fn decode_seen(bytes: &[u8]) -> Option<i64> {
    Some(i64::from_be_bytes(bytes.try_into().ok()?))
}

fn op(tree: Tree, method: Method, key: Vec<u8>, val: Option<Vec<u8>>) -> Operation {
    Operation {
        tree,
        method,
        key,
        val,
    }
}

/// The local `Tree::Blobs` as a [`BlobBackend`]: today's default storage.
pub struct RedbBlobBackend {
    kv: Arc<dyn KvStore>,
}

impl RedbBlobBackend {
    pub fn new(kv: Arc<dyn KvStore>) -> Self {
        Self { kv }
    }

    fn seen(&self, key: &[u8]) -> AtomicResult<Option<i64>> {
        Ok(self
            .kv
            .get(Tree::PluginMeta, &seen_key(key))?
            .and_then(|b| decode_seen(&b)))
    }
}

/// Keys per page when walking `Tree::Blobs`; sizes only, so pages stay small.
const LIST_PAGE: usize = 1000;

#[async_trait]
impl BlobBackend for RedbBlobBackend {
    async fn get(&self, key: &[u8]) -> AtomicResult<Option<Vec<u8>>> {
        self.kv.get(Tree::Blobs, key)
    }

    async fn put(&self, key: &[u8], bytes: &[u8]) -> AtomicResult<()> {
        // One batch: the bytes never exist without their time.
        self.kv.apply_batch(&[
            op(
                Tree::Blobs,
                Method::Insert,
                key.to_vec(),
                Some(bytes.to_vec()),
            ),
            op(
                Tree::PluginMeta,
                Method::Insert,
                seen_key(key),
                Some(crate::utils::now().to_be_bytes().to_vec()),
            ),
        ])
    }

    async fn size(&self, key: &[u8]) -> AtomicResult<Option<u64>> {
        Ok(self.kv.get(Tree::Blobs, key)?.map(|b| b.len() as u64))
    }

    async fn list(&self) -> AtomicResult<Vec<BlobInfo>> {
        let mut out = Vec::new();
        let mut start = Vec::new();
        // Keys are raw hashes; 0xFF * 64 sorts after any 32-byte key.
        let end = vec![0xFF; 64];
        loop {
            let page =
                self.kv
                    .range_value_sizes(Tree::Blobs, start.clone(), end.clone(), LIST_PAGE)?;
            let Some((last, _)) = page.last() else {
                break;
            };
            start = last.clone();
            start.push(0);
            let full = page.len() == LIST_PAGE;
            for (key, size) in page {
                let modified_ms = self.seen(&key)?;
                out.push(BlobInfo {
                    key,
                    size,
                    modified_ms,
                });
            }
            if !full {
                break;
            }
        }
        Ok(out)
    }

    async fn delete(&self, key: &[u8]) -> AtomicResult<()> {
        self.kv.apply_batch(&[
            op(Tree::Blobs, Method::Delete, key.to_vec(), None),
            op(Tree::PluginMeta, Method::Delete, seen_key(key), None),
        ])
    }

    async fn modified_ms(&self, key: &[u8]) -> AtomicResult<Option<i64>> {
        if !self.kv.contains_key(Tree::Blobs, key)? {
            return Ok(None);
        }
        self.seen(key)
    }

    async fn record_first_seen(&self, keys: &[Vec<u8>]) -> AtomicResult<()> {
        let now = crate::utils::now().to_be_bytes().to_vec();
        let mut ops = Vec::new();
        for key in keys {
            // Only if still unstamped: a put since the listing already
            // recorded a (newer or equal) time that must stand.
            if self.kv.contains_key(Tree::Blobs, key)? && self.seen(key)?.is_none() {
                ops.push(op(
                    Tree::PluginMeta,
                    Method::Insert,
                    seen_key(key),
                    Some(now.clone()),
                ));
            }
        }
        if ops.is_empty() {
            return Ok(());
        }
        self.kv.apply_batch(&ops)
    }
}

impl Db {
    /// The backend in use: the configured remote one, else the local tree.
    pub fn blob_store(&self) -> Arc<dyn BlobBackend> {
        match &self.blob_backend {
            Some(backend) => backend.clone(),
            None => Arc::new(RedbBlobBackend::new(self.kv.clone())),
        }
    }

    pub async fn get_blob(&self, key: &[u8]) -> AtomicResult<Option<Vec<u8>>> {
        match &self.blob_backend {
            Some(backend) => backend.get(key).await,
            None => self.kv.get(Tree::Blobs, key),
        }
    }

    /// Like `get_blob`, for derived objects (renditions) stored under a
    /// synthetic key that is not the hash of their bytes.
    pub async fn get_derived_blob(&self, key: &[u8]) -> AtomicResult<Option<Vec<u8>>> {
        match &self.blob_backend {
            Some(backend) => backend.get_unverified(key).await,
            None => self.kv.get(Tree::Blobs, key),
        }
    }

    pub async fn put_blob(&self, key: &[u8], bytes: &[u8]) -> AtomicResult<()> {
        self.blob_store().put(key, bytes).await
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
            RedbBlobBackend::new(self.kv.clone()).delete(&key).await?;
            self.kv.flush()?;
            migrated += 1;
        }
        Ok(migrated)
    }
}
