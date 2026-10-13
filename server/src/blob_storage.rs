//! Optional S3-compatible storage for hosted file bytes. No disk cache/fallback.
use async_trait::async_trait;
use atomic_lib::{
    db::blob_backend::{BlobBackend, BlobInfo},
    errors::AtomicResult,
};
use futures::TryStreamExt;
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
        match self.get_unverified(key).await? {
            Some(bytes) if blake3::hash(&bytes).as_bytes().as_slice() != key => {
                Err("Blob storage hash mismatch".into())
            }
            found => Ok(found),
        }
    }
    async fn get_unverified(&self, key: &[u8]) -> AtomicResult<Option<Vec<u8>>> {
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

    /// Everything under the prefix whose name is a BLAKE3 hash. Objects with
    /// any other name are not ours (a shared bucket, the console's folders)
    /// and are left out, so a sweep can never touch them. S3 always records a
    /// last-modified time, and a `put` of existing bytes replaces the object,
    /// so it is the last-put time the grace period needs.
    async fn list(&self) -> AtomicResult<Vec<BlobInfo>> {
        let metas: Vec<_> = self
            .store
            .list(Some(&self.prefix))
            .try_collect()
            .await
            .map_err(|e| e.to_string())?;
        Ok(metas
            .into_iter()
            .filter_map(|meta| {
                let key = hex::decode(meta.location.filename()?).ok()?;
                (key.len() == 32 && self.path(&key) == meta.location).then(|| BlobInfo {
                    key,
                    size: meta.size,
                    modified_ms: Some(meta.last_modified.timestamp_millis()),
                })
            })
            .collect())
    }

    async fn delete(&self, key: &[u8]) -> AtomicResult<()> {
        match self.store.delete(&self.path(key)).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(error) => Err(error.to_string().into()),
        }
    }

    async fn modified_ms(&self, key: &[u8]) -> AtomicResult<Option<i64>> {
        match self.store.head(&self.path(key)).await {
            Ok(meta) => Ok(Some(meta.last_modified.timestamp_millis())),
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

/// The object `configure` writes to prove read/write access. Not a file, so
/// no resource references it; garbage collection must leave it alone.
pub fn readiness_marker() -> blake3::Hash {
    blake3::hash(b"atomic-blob-storage-readiness-v1")
}

pub async fn configure(store: &mut atomic_lib::Db) -> AtomicResult<()> {
    store.blob_backend = from_config(|key| std::env::var(key).ok())?;
    if let Some(backend) = &store.blob_backend {
        // Read/write readiness, including on an empty node. A fixed harmless
        // marker avoids leaving one object behind for every restart.
        let key = readiness_marker();
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

/// `24h`, `90m`, `7d`, `45s` or a bare number of seconds.
pub fn parse_duration(raw: &str) -> AtomicResult<std::time::Duration> {
    let raw = raw.trim().to_lowercase();
    let (digits, unit) = match raw.find(|c: char| !c.is_ascii_digit()) {
        Some(at) => raw.split_at(at),
        None => (raw.as_str(), "s"),
    };
    let factor = match unit.trim() {
        "s" | "sec" | "secs" => 1,
        "m" | "min" | "mins" => 60,
        "h" | "hr" | "hrs" => 3600,
        "d" | "day" | "days" => 86_400,
        _ => return Err(format!("`{raw}` is not a duration; use e.g. 90m, 24h or 7d").into()),
    };
    let amount: u64 = digits
        .parse()
        .map_err(|_| format!("`{raw}` is not a duration; use e.g. 90m, 24h or 7d"))?;
    Ok(std::time::Duration::from_secs(
        amount.saturating_mul(factor),
    ))
}

/// How often to sweep; `None` when switched off (`0`, `off`, `never`, `false`).
pub fn parse_gc_interval(raw: &str) -> AtomicResult<Option<std::time::Duration>> {
    if matches!(
        raw.trim().to_lowercase().as_str(),
        "off" | "never" | "false" | "disabled"
    ) {
        return Ok(None);
    }
    let interval = parse_duration(raw)?;
    Ok((!interval.is_zero()).then_some(interval))
}

/// Why a real (deleting) pass is not allowed on this store, if so. An object
/// store can be shared by several nodes; the mark phase only knows this node's
/// database, so deleting there needs the operator's word that it is exclusive.
pub fn gc_delete_refusal(store: &atomic_lib::Db, s3_exclusive: bool) -> Option<String> {
    (store.blob_backend.is_some() && !s3_exclusive).then(|| {
        "blob garbage collection will not delete from S3-compatible storage unless \
         ATOMIC_BLOB_GC_S3_EXCLUSIVE=true asserts that this bucket and prefix belong to \
         this node alone (another node sharing them would lose its files); \
         `gc-blobs --dry-run` is always allowed"
            .to_string()
    })
}

/// One mark-and-sweep pass over the blob backend with this server's settings.
/// `s3_exclusive` is `ATOMIC_BLOB_GC_S3_EXCLUSIVE`; a deleting pass on an
/// object store is refused without it, a dry run never is.
pub async fn run_gc(
    store: &atomic_lib::Db,
    grace: std::time::Duration,
    dry_run: bool,
    s3_exclusive: bool,
) -> AtomicResult<atomic_lib::db::blob_gc::BlobGcReport> {
    if !dry_run {
        if let Some(refusal) = gc_delete_refusal(store, s3_exclusive) {
            return Err(refusal.into());
        }
    }
    // The S3 readiness probe is an object no resource can reference.
    let options = atomic_lib::db::blob_gc::BlobGcOptions::new(grace)
        .dry_run(dry_run)
        .keep([*readiness_marker().as_bytes()]);
    store.gc_blobs(&options).await
}

/// Start the periodic blob sweep, unless `ATOMIC_BLOB_GC_INTERVAL` is `0`/`off`.
/// Bad settings are an error at startup, not a sweep that never happens.
pub fn spawn_gc(appstate: crate::appstate::AppState) -> AtomicResult<()> {
    let opts = &appstate.config.opts;
    let grace =
        parse_duration(&opts.blob_gc_grace).map_err(|e| format!("ATOMIC_BLOB_GC_GRACE: {e}"))?;
    let Some(interval) = parse_gc_interval(&opts.blob_gc_interval)
        .map_err(|e| format!("ATOMIC_BLOB_GC_INTERVAL: {e}"))?
    else {
        tracing::info!("Blob garbage collection is off (ATOMIC_BLOB_GC_INTERVAL)");
        return Ok(());
    };
    let s3_exclusive = opts.blob_gc_s3_exclusive;
    if let Some(refusal) = gc_delete_refusal(&appstate.store, s3_exclusive) {
        tracing::warn!("Blob garbage collection is off: {refusal}");
        return Ok(());
    }
    tracing::info!(
        interval_secs = interval.as_secs(),
        grace_secs = grace.as_secs(),
        "Blob garbage collection enabled"
    );
    actix_web::rt::spawn(async move {
        // Not during boot, when indexes and transports are still starting.
        actix_web::rt::time::sleep(interval.min(std::time::Duration::from_secs(300))).await;
        loop {
            let started = std::time::Instant::now();
            match run_gc(&appstate.store, grace, false, s3_exclusive).await {
                Ok(report) => tracing::info!(
                    scanned = report.scanned,
                    referenced = report.referenced,
                    in_grace = report.in_grace,
                    deleted = report.deleted,
                    freed_bytes = report.deleted_bytes,
                    failed = report.failed,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "Blob garbage collection finished"
                ),
                // Nothing was deleted: the set of referenced blobs is unknown.
                Err(e) => tracing::error!("Blob garbage collection aborted, nothing deleted: {e}"),
            }
            actix_web::rt::time::sleep(interval).await;
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use atomic_lib::{db::trees::Tree, Db};

    async fn exercise_remote_storage(backend: Arc<dyn BlobBackend>) {
        use atomic_lib::vault::{
            dek::DriveVaultKey,
            store::MemoryVaultStore,
            sync::{drive_prefix, export_vault_segment, import_vault_batch, CheckpointPolicy},
        };
        use atomic_lib::{urls, Storelike, Subject, Value};
        let mut first = Db::init_redb(None).await.unwrap();
        first.blob_backend = Some(backend.clone());
        let (_, drive) = first.setup("vault-file-owner").await.unwrap();
        let bytes = b"file contents survive replacement of the server node";
        let hash = blake3::hash(bytes);
        let file_subject = first
            .create_resource(urls::FILE, &drive, "recovered.txt", None)
            .await
            .unwrap();
        let mut file = first
            .get_resource(&Subject::from_raw(&file_subject, None))
            .await
            .unwrap();
        file.set_unsafe(
            urls::BLOB.into(),
            Value::AtomicUrl(Subject::from_blob_hash(hash.as_bytes())),
        )
        .unwrap();
        first
            .add_resource_opts(&file, false, true, true)
            .await
            .unwrap();
        first.put_blob(hash.as_bytes(), bytes).await.unwrap();
        first.put_blob(hash.as_bytes(), bytes).await.unwrap();
        assert_eq!(first.kv.len(Tree::Blobs).unwrap(), 0);
        assert_eq!(
            first.blob_size(hash.as_bytes()).await.unwrap(),
            Some(bytes.len() as u64)
        );
        let vault = MemoryVaultStore::new();
        let key = DriveVaultKey::generate(2);
        export_vault_segment(
            &first,
            &Subject::from_raw(&drive, None),
            &key,
            &vault,
            "file-recovery",
            "device-a",
            1,
            1,
            false,
            &Default::default(),
            CheckpointPolicy::default(),
        )
        .await
        .unwrap()
        .expect("file metadata is backed up");
        drop(first);
        let mut replacement = Db::init_redb(None).await.unwrap();
        let summary = import_vault_batch(
            &replacement,
            &key,
            &vault,
            &drive_prefix("file-recovery"),
            None,
        )
        .await
        .unwrap();
        assert_eq!(summary.objects_unreadable, 0);
        let restored_file = replacement.get_resource(file.get_subject()).await.unwrap();
        assert_eq!(
            restored_file.get(urls::BLOB).unwrap().to_string(),
            file.get(urls::BLOB).unwrap().to_string()
        );
        assert_eq!(
            restored_file.get(urls::NAME).unwrap().to_string(),
            "recovered.txt"
        );
        // Graph recovery cannot conjure file bytes. Without the S3 backend,
        // the restored reference still exists but the file is unavailable.
        assert!(replacement
            .get_blob(hash.as_bytes())
            .await
            .unwrap()
            .is_none());
        replacement.blob_backend = Some(backend);
        let restored_hash = restored_file.get(urls::BLOB).unwrap().to_string();
        let restored_hash = Subject::from_raw(&restored_hash, None);
        let restored_hash = hex::decode(restored_hash.blob_hash_hex().unwrap()).unwrap();
        assert_eq!(
            replacement.get_blob(&restored_hash).await.unwrap().unwrap(),
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
    async fn corrupt_object_is_never_returned_as_valid_blob_bytes() {
        let objects = Arc::new(object_store::memory::InMemory::new());
        let backend = ObjectBlobBackend::new(objects.clone(), "blobs").unwrap();
        let bytes = b"original bytes";
        let hash = blake3::hash(bytes);
        backend.put(hash.as_bytes(), bytes).await.unwrap();
        assert_eq!(backend.get(hash.as_bytes()).await.unwrap().unwrap(), bytes);
        objects
            .put(
                &backend.path(hash.as_bytes()),
                b"corrupted bytes".to_vec().into(),
            )
            .await
            .unwrap();
        assert!(backend
            .get(hash.as_bytes())
            .await
            .unwrap_err()
            .to_string()
            .contains("hash mismatch"));
    }

    #[tokio::test]
    async fn website_images_use_object_storage_and_publication_allowlist() {
        use atomic_lib::website::{project_id, WebsitePackage};
        let mut db = Db::init_redb(None).await.unwrap();
        db.blob_backend = Some(remote());
        let bytes = b"optimized image bytes";
        let hash = blake3::hash(bytes).to_hex().to_string();
        let path = format!("assets/{hash}.webp");
        db.website_put_asset("site", &hash, bytes).await.unwrap();
        assert_eq!(db.kv.len(Tree::Blobs).unwrap(), 0);
        assert!(db
            .website_asset(&project_id("other"), &hash)
            .await
            .unwrap()
            .is_none());
        let package = WebsitePackage {
            version: 1,
            files: [("index.html".into(), format!("<img src=\"/{path}\">"))].into(),
            assets: [(path.clone(), hash)].into(),
            metadata: None,
        };
        assert!(db.website_upload("other", "drive", &package).await.is_err());
        let state = db.website_upload("site", "drive", &package).await.unwrap();
        let id = project_id("site");
        assert!(db
            .website_public_asset(&id, None, &path)
            .await
            .unwrap()
            .is_none());
        db.website_activate(&id, state.revision, Some(package.id().unwrap()), "owner")
            .unwrap();
        assert_eq!(
            db.website_public_asset(&id, None, &path)
                .await
                .unwrap()
                .unwrap()
                .1,
            bytes
        );
        let manifest = serde_json::to_string(
            &db.website_package(&id, &package.id().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!manifest.contains("optimized image bytes"));
        let revision = db.website_state(&id).unwrap().unwrap().revision;
        db.website_activate(&id, revision, None, "owner").unwrap();
        assert!(db
            .website_public_asset(&id, None, &path)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn files_survive_node_replacement_without_local_copies() {
        exercise_remote_storage(remote()).await;
    }

    #[tokio::test]
    async fn shared_files_count_once_per_drive_independently_of_other_owners() {
        use atomic_lib::{urls, Storelike, Value};
        use futures::TryStreamExt;
        let objects = Arc::new(object_store::memory::InMemory::new());
        let mut db = Db::init_redb(None).await.unwrap();
        db.blob_backend = Some(Arc::new(
            ObjectBlobBackend::new(objects.clone(), "files").unwrap(),
        ));
        let bytes = b"the same file uploaded by two different users";
        let hash = blake3::hash(bytes);
        let blob = format!("did:ad:blob:{}", hash.to_hex());
        let mut drives = Vec::new();
        let mut references = Vec::new();
        for (owner, copies) in [("alice", 2), ("bob", 1)] {
            let (_, drive) = db.setup(owner).await.unwrap();
            for copy in 0..copies {
                db.put_blob(hash.as_bytes(), bytes).await.unwrap();
                let subject = db
                    .create_resource(urls::FILE, &drive, &format!("copy-{copy}"), None)
                    .await
                    .unwrap();
                let mut file = db.get_resource(&subject.as_str().into()).await.unwrap();
                file.set_unsafe(urls::BLOB.into(), Value::AtomicUrl(blob.as_str().into()))
                    .unwrap();
                db.add_resource_opts(&file, false, true, true)
                    .await
                    .unwrap();
                references.push(file.get_subject().clone());
            }
            drives.push(drive);
        }
        assert_ne!(drives[0], drives[1]);
        // Actual storage contains one object despite three file references.
        let stored: Vec<_> = objects.list(None).try_collect().await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].size, bytes.len() as u64);
        assert_eq!(db.kv.len(Tree::Blobs).unwrap(), 0);
        // Co-location, report order and reporting just one hosted drive must
        // never change either owner's quota usage.
        for report in [
            drives.clone(),
            vec![drives[1].clone(), drives[0].clone()],
            vec![drives[0].clone()],
            vec![drives[1].clone()],
        ] {
            let usage = db.per_drive_usage(&report).await.unwrap();
            assert_eq!(usage.len(), report.len());
            for row in usage {
                assert_eq!(row.blob_bytes, bytes.len() as u64, "{}", row.drive_subject);
            }
        }
        // Removing Alice's two references must not transfer any usage to Bob.
        for reference in &references[..2] {
            db.remove_resource(reference).await.unwrap();
        }
        let usage = db.per_drive_usage(&drives).await.unwrap();
        assert_eq!(
            usage
                .iter()
                .find(|r| r.drive_subject == drives[0])
                .unwrap()
                .blob_bytes,
            0
        );
        assert_eq!(
            usage
                .iter()
                .find(|r| r.drive_subject == drives[1])
                .unwrap()
                .blob_bytes,
            bytes.len() as u64
        );
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

    /// Mark and sweep against an S3-style store: unreferenced objects go, a
    /// referenced one stays however old, and objects that are not blobs (a
    /// foreign name under the prefix, the readiness probe) are never touched.
    async fn exercise_gc(objects: Arc<dyn ObjectStore>) {
        use atomic_lib::{urls, Storelike, Value};
        use std::time::Duration;

        let backend = Arc::new(ObjectBlobBackend::new(objects.clone(), "files").unwrap());
        let mut db = Db::init_redb(None).await.unwrap();
        db.blob_backend = Some(backend.clone());
        let (_, drive) = db.setup("alice").await.unwrap();

        let (kept, shared, orphan) = (
            b"referenced file".as_slice(),
            b"two files, one object".as_slice(),
            b"destroyed file".as_slice(),
        );
        let mut files = Vec::new();
        for (name, bytes) in [("kept", kept), ("a", shared), ("b", shared), ("c", orphan)] {
            db.put_blob(blake3::hash(bytes).as_bytes(), bytes)
                .await
                .unwrap();
            let subject = db
                .create_resource(urls::FILE, &drive, name, None)
                .await
                .unwrap();
            let mut file = db.get_resource(&subject.as_str().into()).await.unwrap();
            file.set_unsafe(
                urls::BLOB.into(),
                Value::AtomicUrl(
                    format!("did:ad:blob:{}", blake3::hash(bytes).to_hex())
                        .as_str()
                        .into(),
                ),
            )
            .unwrap();
            db.add_resource_opts(&file, false, true, true)
                .await
                .unwrap();
            files.push(file.get_subject().clone());
        }
        // Not files: the probe `configure` writes, and a stray object.
        let marker = readiness_marker();
        db.put_blob(marker.as_bytes(), b"probe").await.unwrap();
        objects
            .put(&Path::from("files/README.txt"), "not ours".into())
            .await
            .unwrap();

        let listed = backend.list().await.unwrap();
        assert_eq!(
            listed.len(),
            4,
            "3 files + probe; the stray name is skipped"
        );
        let info = listed
            .iter()
            .find(|i| i.key == blake3::hash(orphan).as_bytes())
            .unwrap();
        assert_eq!(info.size, orphan.len() as u64);
        let age = atomic_lib::utils::now() - info.modified_ms.unwrap();
        assert!((0..60_000).contains(&age), "last-modified is the put time");
        assert!(backend
            .modified_ms(blake3::hash(orphan).as_bytes())
            .await
            .unwrap()
            .is_some());

        // Destroy one of the two files sharing an object, and the orphan's file.
        db.remove_resource(&files[1]).await.unwrap();
        db.remove_resource(&files[3]).await.unwrap();

        // Inside the grace period nothing is deleted.
        let report = run_gc(&db, Duration::from_secs(3600), false, true)
            .await
            .unwrap();
        assert_eq!((report.deleted, report.in_grace), (0, 1));
        // A dry run reports the orphan and deletes nothing.
        let report = run_gc(&db, Duration::ZERO, true, false).await.unwrap();
        assert_eq!(report.candidates.len(), 1);
        assert_eq!(report.candidate_bytes, orphan.len() as u64);
        assert!(db.has_blob(blake3::hash(orphan).as_bytes()).await.unwrap());

        // Deleting from an object store needs the operator's exclusivity flag.
        let refused = run_gc(&db, Duration::ZERO, false, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(refused.contains("ATOMIC_BLOB_GC_S3_EXCLUSIVE"), "{refused}");
        assert!(gc_delete_refusal(&db, false).is_some());
        assert!(gc_delete_refusal(&db, true).is_none());
        assert!(db.has_blob(blake3::hash(orphan).as_bytes()).await.unwrap());

        let report = run_gc(&db, Duration::ZERO, false, true).await.unwrap();
        assert_eq!((report.deleted, report.failed), (1, 0));
        assert_eq!(report.deleted_bytes, orphan.len() as u64);
        assert!(!db.has_blob(blake3::hash(orphan).as_bytes()).await.unwrap());
        for still_there in [kept, shared] {
            assert!(db
                .has_blob(blake3::hash(still_there).as_bytes())
                .await
                .unwrap());
        }
        assert!(db.has_blob(marker.as_bytes()).await.unwrap());
        assert!(objects.head(&Path::from("files/README.txt")).await.is_ok());
        // Deleting what is already gone is not an error.
        backend
            .delete(blake3::hash(orphan).as_bytes())
            .await
            .unwrap();
        // Nothing local was involved.
        assert_eq!(db.kv.len(Tree::Blobs).unwrap(), 0);

        // The last file referencing the shared object goes: now it is swept too.
        db.remove_resource(&files[2]).await.unwrap();
        assert_eq!(
            run_gc(&db, Duration::ZERO, false, true)
                .await
                .unwrap()
                .deleted,
            1
        );
    }

    #[tokio::test]
    async fn local_blob_store_needs_no_exclusivity_flag() {
        use std::time::Duration;
        let db = Db::init_redb(None).await.unwrap();
        let bytes = b"orphan in the local blob tree";
        db.put_blob(blake3::hash(bytes).as_bytes(), bytes)
            .await
            .unwrap();
        assert!(gc_delete_refusal(&db, false).is_none());
        let report = run_gc(&db, Duration::ZERO, false, false).await.unwrap();
        assert_eq!(report.deleted, 1);
    }

    #[tokio::test]
    async fn gc_sweeps_unreferenced_objects_in_memory_store() {
        exercise_gc(Arc::new(object_store::memory::InMemory::new())).await;
    }

    #[tokio::test]
    async fn gc_sweeps_unreferenced_objects_in_local_store() {
        let dir = tempfile::tempdir().unwrap();
        exercise_gc(Arc::new(
            object_store::local::LocalFileSystem::new_with_prefix(dir.path()).unwrap(),
        ))
        .await;
    }

    #[test]
    fn gc_durations_parse() {
        use std::time::Duration;
        assert_eq!(
            parse_duration("72h").unwrap(),
            Duration::from_secs(72 * 3600)
        );
        assert_eq!(parse_duration(" 90m ").unwrap(), Duration::from_secs(5400));
        assert_eq!(
            parse_duration("7d").unwrap(),
            Duration::from_secs(7 * 86_400)
        );
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
        assert!(parse_duration("soon").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("-1h").is_err());
        assert_eq!(
            parse_gc_interval("24h").unwrap(),
            Some(Duration::from_secs(86_400))
        );
        for off in ["0", "off", "OFF", "never", "false"] {
            assert_eq!(parse_gc_interval(off).unwrap(), None, "{off}");
        }
        assert!(parse_gc_interval("often").is_err());
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
