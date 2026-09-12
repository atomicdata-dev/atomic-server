//! Optional S3-compatible storage for hosted file bytes. No disk cache/fallback.
use async_trait::async_trait;
use atomic_lib::{db::blob_backend::BlobBackend, errors::AtomicResult};
use object_store::{aws::AmazonS3Builder, path::Path, ObjectStore};
use std::sync::Arc;

pub struct ObjectBlobBackend {
    store: Arc<dyn ObjectStore>,
    prefix: Path,
}

impl ObjectBlobBackend {
    pub fn new(store: Arc<dyn ObjectStore>, prefix: &str) -> AtomicResult<Self> {
        Ok(Self {
            store,
            prefix: Path::parse(prefix).map_err(|e| e.to_string())?,
        })
    }
    fn path(&self, key: &[u8]) -> Path {
        self.prefix.child(hex::encode(key))
    }
}

#[async_trait]
impl BlobBackend for ObjectBlobBackend {
    async fn get(&self, key: &[u8]) -> AtomicResult<Option<Vec<u8>>> {
        match self.store.get(&self.path(key)).await {
            Ok(object) => Ok(Some(
                object.bytes().await.map_err(|e| e.to_string())?.to_vec(),
            )),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(error) => Err(error.to_string().into()),
        }
    }
    async fn put(&self, key: &[u8], bytes: &[u8]) -> AtomicResult<()> {
        self.store
            .put(&self.path(key), bytes.to_vec().into())
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    async fn size(&self, key: &[u8]) -> AtomicResult<Option<u64>> {
        match self.store.head(&self.path(key)).await {
            Ok(meta) => Ok(Some(meta.size)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(error) => Err(error.to_string().into()),
        }
    }
}

/// Explicit config, usable by embedders without changing process environment.
/// Values (especially credentials) must never be logged.
pub fn from_config(
    mut env: impl FnMut(&str) -> Option<String>,
) -> AtomicResult<Option<Arc<dyn BlobBackend>>> {
    let mode = env("ATOMIC_BLOB_BACKEND").unwrap_or_else(|| "redb".into());
    match mode.as_str() {
        "redb" => return Ok(None),
        "s3" => {}
        _ => return Err("ATOMIC_BLOB_BACKEND must be redb or s3".into()),
    }
    let bucket = env("ATOMIC_S3_BUCKET")
        .filter(|v| !v.trim().is_empty())
        .ok_or("ATOMIC_S3_BUCKET is required for S3 blob storage")?;
    let mut builder = AmazonS3Builder::new().with_bucket_name(bucket);
    if let Some(v) = env("ATOMIC_S3_REGION") {
        builder = builder.with_region(v);
    }
    if let Some(v) = env("ATOMIC_S3_ENDPOINT") {
        builder = builder.with_endpoint(v);
    }
    let access = env("ATOMIC_S3_ACCESS_KEY_ID");
    let secret = env("ATOMIC_S3_SECRET_ACCESS_KEY");
    match (access, secret) {
        (Some(a), Some(s)) if !a.is_empty() && !s.is_empty() => {
            builder = builder.with_access_key_id(a).with_secret_access_key(s);
        }
        (None, None) => {} // Object store's instance credential provider.
        _ => return Err("Set both ATOMIC_S3_ACCESS_KEY_ID and ATOMIC_S3_SECRET_ACCESS_KEY".into()),
    }
    if let Some(v) = env("ATOMIC_S3_PATH_STYLE") {
        builder = builder.with_virtual_hosted_style_request(
            !v.parse::<bool>()
                .map_err(|_| "ATOMIC_S3_PATH_STYLE must be true or false")?,
        );
    }
    if let Some(v) = env("ATOMIC_S3_ALLOW_HTTP") {
        builder = builder.with_allow_http(
            v.parse::<bool>()
                .map_err(|_| "ATOMIC_S3_ALLOW_HTTP must be true or false")?,
        );
    }
    let prefix = env("ATOMIC_S3_PREFIX").unwrap_or_else(|| "blobs".into());
    Ok(Some(Arc::new(ObjectBlobBackend::new(
        Arc::new(builder.build().map_err(|e| e.to_string())?),
        &prefix,
    )?)))
}

pub async fn configure(store: &mut atomic_lib::Db) -> AtomicResult<()> {
    store.blob_backend = from_config(|key| std::env::var(key).ok())?;
    if let Some(backend) = &store.blob_backend {
        // Read/write readiness, including on an empty node. A fixed harmless
        // marker avoids leaving one object behind for every restart.
        let key = blake3::hash(b"atomic-blob-storage-readiness-v1");
        let bytes = b"atomic-blob-storage-readiness-v1";
        backend
            .put(key.as_bytes(), bytes)
            .await
            .map_err(|e| e.to_string())?;
        if backend.get(key.as_bytes()).await?.as_deref() != Some(bytes.as_slice()) {
            return Err("S3 blob storage readiness verification failed".into());
        }
        let count = store
            .migrate_blobs_to_backend()
            .await
            .map_err(|e| e.to_string())?;
        tracing::info!(
            migrated_blobs = count,
            "S3 file storage ready; local blob storage disabled"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use atomic_lib::{db::trees::Tree, Db};

    async fn exercise_remote_storage(backend: Arc<dyn BlobBackend>) {
        let mut first = Db::init_redb(None).await.unwrap();
        first.blob_backend = Some(backend.clone());
        let bytes = b"file contents survive replacement of the server node";
        let hash = blake3::hash(bytes);
        first.put_blob(hash.as_bytes(), bytes).await.unwrap();
        first.put_blob(hash.as_bytes(), bytes).await.unwrap();
        assert_eq!(first.kv.len(Tree::Blobs).unwrap(), 0);
        assert_eq!(
            first.blob_size(hash.as_bytes()).await.unwrap(),
            Some(bytes.len() as u64)
        );
        drop(first);
        let mut replacement = Db::init_redb(None).await.unwrap();
        replacement.blob_backend = Some(backend);
        assert_eq!(
            replacement
                .get_blob(hash.as_bytes())
                .await
                .unwrap()
                .unwrap(),
            bytes
        );
        assert_eq!(replacement.kv.len(Tree::Blobs).unwrap(), 0);
    }

    fn remote() -> Arc<dyn BlobBackend> {
        Arc::new(
            ObjectBlobBackend::new(
                Arc::new(object_store::memory::InMemory::new()),
                "hosted-blobs",
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn files_survive_node_replacement_without_local_copies() {
        exercise_remote_storage(remote()).await;
    }

    #[tokio::test]
    async fn peer_sync_uses_remote_storage_and_reports_failed_writes() {
        use atomic_lib::{
            agents::ForAgent,
            sync::{engine::handle_frame, protocol},
        };
        let mut db = Db::init_redb(None).await.unwrap();
        db.blob_backend = Some(remote());
        let bytes = b"file received through peer sync";
        let hash = blake3::hash(bytes);
        db.note_pending_blob_request(*hash.as_bytes(), "test-drive".into());
        let response = protocol::encode_blob_response(hash.as_bytes(), bytes);
        assert!(handle_frame(&response, &db, &mut ForAgent::Sudo)
            .await
            .is_empty());
        assert_eq!(db.get_blob(hash.as_bytes()).await.unwrap().unwrap(), bytes);
        let reply = handle_frame(
            &protocol::encode_blob_request(hash.as_bytes()),
            &db,
            &mut ForAgent::Sudo,
        )
        .await;
        assert_eq!(reply, vec![response.clone()]);
        assert_eq!(db.kv.len(Tree::Blobs).unwrap(), 0);

        db.blob_backend = Some(Arc::new(FailedBackend { corrupt: false }));
        db.note_pending_blob_request(*hash.as_bytes(), "test-drive".into());
        let failed = handle_frame(&response, &db, &mut ForAgent::Sudo).await;
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0][0], protocol::tag::ERROR);
        assert_eq!(db.kv.len(Tree::Blobs).unwrap(), 0);
    }

    #[tokio::test]
    async fn existing_blobs_are_verified_and_removed_from_local_storage() {
        let mut db = Db::init_redb(None).await.unwrap();
        let bytes = b"existing uploaded file";
        let hash = blake3::hash(bytes);
        db.put_blob(hash.as_bytes(), bytes).await.unwrap();
        assert_eq!(db.kv.len(Tree::Blobs).unwrap(), 1);
        db.blob_backend = Some(remote());
        assert_eq!(db.migrate_blobs_to_backend().await.unwrap(), 1);
        assert_eq!(db.migrate_blobs_to_backend().await.unwrap(), 0);
        assert_eq!(db.kv.len(Tree::Blobs).unwrap(), 0);
        assert_eq!(db.get_blob(hash.as_bytes()).await.unwrap().unwrap(), bytes);
    }

    struct FailedBackend {
        corrupt: bool,
    }
    #[async_trait]
    impl BlobBackend for FailedBackend {
        async fn put(&self, _: &[u8], _: &[u8]) -> AtomicResult<()> {
            if self.corrupt {
                Ok(())
            } else {
                Err("storage unavailable".into())
            }
        }
        async fn get(&self, _: &[u8]) -> AtomicResult<Option<Vec<u8>>> {
            if self.corrupt {
                Ok(Some(b"corrupted".to_vec()))
            } else {
                Err("storage unavailable".into())
            }
        }
        async fn size(&self, _: &[u8]) -> AtomicResult<Option<u64>> {
            Err("storage unavailable".into())
        }
    }

    #[tokio::test]
    async fn storage_failure_never_falls_back_to_local_disk() {
        let mut db = Db::init_redb(None).await.unwrap();
        db.blob_backend = Some(Arc::new(FailedBackend { corrupt: false }));
        assert!(db.put_blob(&[1; 32], b"new file").await.is_err());
        assert!(db.get_blob(&[1; 32]).await.is_err());
        assert!(db.has_blob(&[1; 32]).await.is_err());
        assert_eq!(db.kv.len(Tree::Blobs).unwrap(), 0);
    }

    #[tokio::test]
    async fn failed_migration_preserves_original_bytes() {
        for corrupt in [false, true] {
            let mut db = Db::init_redb(None).await.unwrap();
            db.put_blob(&[1; 32], b"original").await.unwrap();
            db.blob_backend = Some(Arc::new(FailedBackend { corrupt }));
            assert!(db.migrate_blobs_to_backend().await.is_err());
            assert_eq!(
                db.kv.get(Tree::Blobs, &[1; 32]).unwrap().unwrap(),
                b"original"
            );
        }
    }

    #[test]
    fn missing_or_invalid_config_cannot_select_a_local_fallback() {
        assert!(from_config(|k| (k == "ATOMIC_BLOB_BACKEND").then(|| "s3".into())).is_err());
        assert!(from_config(|k| (k == "ATOMIC_BLOB_BACKEND").then(|| "typo".into())).is_err());
        assert!(from_config(|_| None).unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires ATOMIC_BLOB_BACKEND=s3 and ATOMIC_S3_* pointing at a test bucket"]
    async fn s3_files_survive_node_replacement() {
        let backend = from_config(|key| std::env::var(key).ok())
            .unwrap()
            .expect("S3 config required");
        exercise_remote_storage(backend).await;
    }
}
