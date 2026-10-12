//! Mark-and-sweep garbage collection of blobs (planning/s3-blob-storage.md,
//! "GC / refcounting").
//!
//! Blobs are content-addressed (BLAKE3), so deleting a `File` never deletes its
//! bytes: another resource may reference the same hash, and a refcount kept
//! inline would not survive a crash, a sync or a concurrent destroy. Instead a
//! periodic pass computes what is referenced and removes the rest.
//!
//! **Mark.** [`Db::referenced_blob_hashes`] collects every 64-hex-digit token
//! found in the stored state that can name a blob:
//!
//! * every property value of every row in `Tree::Resources` except commits (so `File.blob`
//!   (`atomic:blob:<hash>`), `File.internalId`, every entry of `File.chunks`,
//!   and any other resource that mentions a blob hash, whatever its class);
//! * the `Tree::PluginMeta` records that own blobs, keys and values (website image assets
//!   `website/v1/<id>/assets/<hash>`, website deployments, plugin releases'
//!   `package`), plus the files and assets listed in each website deployment
//!   manifest, which is itself a blob.
//!
//! The rule is "when unsure, referenced": a token that merely looks like a hash
//! keeps a blob, never the opposite. Anything that fails to read or decode
//! aborts the whole pass before a single delete.
//!
//! **Sweep.** Every blob the backend lists that is not marked, not in
//! [`BlobGcOptions::keep`], and was last written at least
//! [`BlobGcOptions::grace`] ago is deleted. The grace period covers an upload
//! whose `File` commit has not landed yet. Blobs are listed *before* the mark
//! phase, and each candidate's age is re-read right before its delete, so a
//! re-upload that races the pass restarts the clock instead of being swept.
//!
//! Derived caches that nothing references (processed image renditions, keyed
//! by a synthetic hash) are collected like any other unreferenced blob once
//! the grace period passed; they are regenerated on the next request.
use super::{blob_backend::BlobInfo, encoding::decode_propvals, trees::Tree, Db};
use crate::{
    errors::AtomicResult,
    values::{SubResource, Value},
};
use std::{collections::HashSet, time::Duration};

pub type BlobHash = [u8; 32];

#[derive(Clone, Debug)]
pub struct BlobGcOptions {
    /// Blobs written more recently than this are never deleted.
    pub grace: Duration,
    /// Report what would be deleted; change nothing, not even metadata.
    pub dry_run: bool,
    /// Blobs to keep regardless of references (e.g. the S3 readiness marker).
    pub keep: HashSet<BlobHash>,
}

impl BlobGcOptions {
    pub fn new(grace: Duration) -> Self {
        Self {
            grace,
            dry_run: false,
            keep: HashSet::new(),
        }
    }

    pub fn dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    pub fn keep(mut self, keep: impl IntoIterator<Item = BlobHash>) -> Self {
        self.keep.extend(keep);
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlobGcReport {
    pub dry_run: bool,
    /// Blobs in the backend.
    pub scanned: usize,
    pub scanned_bytes: u64,
    /// Distinct hashes found by the mark phase.
    pub marked: usize,
    /// Blobs kept because they are referenced (or in `keep`).
    pub referenced: usize,
    /// Unreferenced but too young.
    pub in_grace: usize,
    /// Unreferenced local blobs with no recorded age. Stamped now (unless dry
    /// run), so they become eligible once the grace period has passed.
    pub unstamped: usize,
    /// Unreferenced and old enough: what a real run deletes.
    pub candidates: Vec<BlobInfo>,
    pub candidate_bytes: u64,
    pub deleted: usize,
    pub deleted_bytes: u64,
    /// Candidates whose age changed before the delete (re-uploaded meanwhile).
    pub revived: usize,
    /// Deletes (or age lookups) the backend refused; logged and skipped.
    pub failed: usize,
}

/// Add every run of exactly 64 hex digits in `text` to `out`.
pub(crate) fn scan_hashes(text: &[u8], out: &mut HashSet<BlobHash>) {
    let mut start: Option<usize> = None;
    for i in 0..=text.len() {
        let hex = text.get(i).is_some_and(u8::is_ascii_hexdigit);
        match (hex, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                start = None;
                if i - s == 64 {
                    let mut hash = [0u8; 32];
                    if hex::decode_to_slice(&text[s..i], &mut hash).is_ok() {
                        out.insert(hash);
                    }
                }
            }
            _ => {}
        }
    }
}

fn scan_sub_resource(sub: &SubResource, out: &mut HashSet<BlobHash>) {
    match sub {
        SubResource::Subject(subject) => scan_hashes(subject.as_str().as_bytes(), out),
        SubResource::Nested(propvals) => propvals.values().for_each(|v| scan_value(v, out)),
    }
}

fn scan_value(value: &Value, out: &mut HashSet<BlobHash>) {
    match value {
        // Binary CRDT payloads are base64 text, never a hex blob reference.
        Value::LoroDoc(_) | Value::Integer(_) | Value::Float(_) | Value::Boolean(_) => {}
        Value::ResourceArray(items) => items.iter().for_each(|i| scan_sub_resource(i, out)),
        Value::NestedResource(sub) => scan_sub_resource(sub, out),
        other => scan_hashes(other.to_string().as_bytes(), out),
    }
}

/// What follows the first occurrence of `needle` in `haystack`.
fn after<'a>(haystack: &'a [u8], needle: &[u8]) -> Option<&'a [u8]> {
    let at = haystack.windows(needle.len()).position(|w| w == needle)?;
    Some(&haystack[at + needle.len()..])
}

/// `Tree::PluginMeta` records that name blobs: website image assets, deployment
/// manifests and state (`website.rs`), and plugin releases' `package`
/// (`plugin_release.rs`).
const REFERENCING_PREFIXES: [&str; 2] = ["website/v1/", "plugin-release/v1/"];

/// Rows per page while walking a tree during the mark phase.
const MARK_PAGE: usize = 256;

impl Db {
    /// Visit every row of `tree` in key order, page by page. Unlike
    /// `KvStore::iter_tree` this reports read errors instead of skipping the
    /// row, which for the mark phase would mean deleting a referenced blob.
    async fn for_each_row(
        &self,
        tree: Tree,
        mut visit: impl FnMut(&[u8], &[u8]) -> AtomicResult<()>,
    ) -> AtomicResult<()> {
        let end = vec![0xFF; 1024];
        let mut start = Vec::new();
        loop {
            let page = self
                .kv
                .range_page(tree, start.clone(), end.clone(), MARK_PAGE)?;
            let Some((last, _)) = page.last() else {
                return Ok(());
            };
            start = last.clone();
            start.push(0);
            let full = page.len() == MARK_PAGE;
            for (key, value) in &page {
                visit(key, value)?;
            }
            if !full {
                return Ok(());
            }
            // Keep a long scan from monopolising the executor thread.
            tokio::task::yield_now().await;
        }
    }

    /// The mark phase: every blob hash the stored state refers to. See the
    /// module docs for what that includes. Errors mean "unknown", and callers
    /// must not delete anything on an error.
    pub async fn referenced_blob_hashes(&self) -> AtomicResult<HashSet<BlobHash>> {
        let mut out = HashSet::new();

        self.for_each_row(Tree::Resources, |key, value| {
            // Commits are history, not state: the genesis commit of a File
            // names its subject (`…/files/<hash>`) and outlives a destroy, so
            // counting it would keep every uploaded blob forever. A live
            // resource carries its own references in its row.
            if key.starts_with(crate::identifiers::ATOMIC_COMMIT_PREFIX.as_bytes())
                || key.starts_with(crate::identifiers::DID_AD_COMMIT_PREFIX.as_bytes())
            {
                return Ok(());
            }
            let propvals = decode_propvals(value).map_err(|e| {
                format!(
                    "blob GC aborted: resource {} cannot be read ({e})",
                    String::from_utf8_lossy(key)
                )
            })?;
            propvals.values().for_each(|v| scan_value(v, &mut out));
            Ok(())
        })
        .await?;

        // Plugin releases, website deployments and any other plugin-owned
        // record that names a blob. The blobs' own last-put times live in the
        // same tree and are not references.
        let mut manifests: HashSet<BlobHash> = HashSet::new();
        self.for_each_row(Tree::PluginMeta, |key, value| {
            // Only the records that own blobs. The rest of the tree is
            // bookkeeping that quotes subjects (the pending-search queue holds
            // `…/files/<hash>` of resources that no longer exist) or holds
            // secrets, and must not keep a blob alive.
            if !REFERENCING_PREFIXES
                .iter()
                .any(|prefix| key.starts_with(prefix.as_bytes()))
            {
                return Ok(());
            }
            scan_hashes(key, &mut out);
            scan_hashes(value, &mut out);
            // `website/v1/<project>/manifests/<deployment>`: the deployment id
            // is the hash of the manifest blob, which lists the page files and
            // image assets of that deployment.
            if let Some(deployment) = after(key, b"/manifests/") {
                scan_hashes(deployment, &mut manifests);
            }
            Ok(())
        })
        .await?;

        for manifest in manifests {
            // A listed manifest whose blob is gone cannot be read by anyone;
            // there is nothing left to protect through it. A backend error is
            // different: it says nothing, so abort.
            let Some(bytes) = self.get_blob(&manifest).await? else {
                tracing::warn!(
                    manifest = hex::encode(manifest),
                    "blob GC: website manifest blob is missing"
                );
                continue;
            };
            scan_hashes(&bytes, &mut out);
        }

        Ok(out)
    }

    /// Mark and sweep. See the module docs. An `Err` means nothing was
    /// deleted because the pass could not establish what is referenced (or
    /// could not list the backend).
    pub async fn gc_blobs(&self, opts: &BlobGcOptions) -> AtomicResult<BlobGcReport> {
        let backend = self.blob_store();
        let grace_ms = i64::try_from(opts.grace.as_millis()).unwrap_or(i64::MAX);
        let mut report = BlobGcReport {
            dry_run: opts.dry_run,
            ..Default::default()
        };

        // List first, then mark: a blob (re-)uploaded after the listing keeps
        // its fresh age out of our snapshot, which is why the age is read
        // again before each delete.
        let listed = backend.list().await?;
        let marked = self.referenced_blob_hashes().await?;
        report.marked = marked.len();

        let now = crate::utils::now();
        let mut unstamped: Vec<Vec<u8>> = Vec::new();
        for info in listed {
            report.scanned += 1;
            report.scanned_bytes += info.size;
            // A key that is not a BLAKE3 hash is not ours to judge.
            let Ok(hash) = BlobHash::try_from(info.key.as_slice()) else {
                report.referenced += 1;
                continue;
            };
            if marked.contains(&hash) || opts.keep.contains(&hash) {
                report.referenced += 1;
                continue;
            }
            match info.modified_ms {
                None => {
                    report.unstamped += 1;
                    unstamped.push(info.key);
                }
                Some(t) if now.saturating_sub(t) < grace_ms => report.in_grace += 1,
                Some(_) => {
                    report.candidate_bytes += info.size;
                    report.candidates.push(info);
                }
            }
        }

        if opts.dry_run {
            return Ok(report);
        }

        if !unstamped.is_empty() {
            // Not fatal: they stay unstamped and are skipped again next time.
            if let Err(e) = backend.record_first_seen(&unstamped).await {
                tracing::warn!("blob GC: could not record first-seen times: {e}");
            }
        }

        let candidates = report.candidates.clone();
        for (n, info) in candidates.iter().enumerate() {
            let name = hex::encode(&info.key);
            match backend.modified_ms(&info.key).await {
                // Gone already, or no age to judge by: leave it.
                Ok(None) => continue,
                Ok(Some(t)) if crate::utils::now().saturating_sub(t) < grace_ms => {
                    report.revived += 1;
                    continue;
                }
                Ok(Some(_)) => {}
                Err(e) => {
                    tracing::warn!(blob = name, "blob GC: could not read blob age: {e}");
                    report.failed += 1;
                    continue;
                }
            }
            match backend.delete(&info.key).await {
                Ok(()) => {
                    report.deleted += 1;
                    report.deleted_bytes += info.size;
                }
                Err(e) => {
                    tracing::warn!(blob = name, "blob GC: could not delete blob: {e}");
                    report.failed += 1;
                }
            }
            if n % 64 == 63 {
                tokio::task::yield_now().await;
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::blob_backend::{BlobBackend, BlobInfo, SEEN_PREFIX},
        urls,
        website::WebsitePackage,
        Db, Storelike,
    };
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    const HOUR: Duration = Duration::from_secs(3600);

    fn hash_of(bytes: &[u8]) -> BlobHash {
        *blake3::hash(bytes).as_bytes()
    }

    async fn db_with_drive() -> (Db, String) {
        let db = Db::init_redb(None).await.unwrap();
        let (_, drive) = db.setup("alice").await.unwrap();
        (db, drive)
    }

    /// A File resource whose `blob` points at `bytes`' hash, and the bytes.
    async fn add_file(db: &Db, drive: &str, name: &str, bytes: &[u8]) -> crate::Subject {
        db.put_blob(&hash_of(bytes), bytes).await.unwrap();
        reference_file(db, drive, name, bytes).await
    }

    /// A File resource pointing at `bytes`' hash without storing them.
    async fn reference_file(db: &Db, drive: &str, name: &str, bytes: &[u8]) -> crate::Subject {
        let hex = hex::encode(hash_of(bytes));
        let subject = db
            .create_resource(urls::FILE, drive, name, None)
            .await
            .unwrap();
        let mut file = db.get_resource(&subject.as_str().into()).await.unwrap();
        file.set_unsafe(
            urls::BLOB.into(),
            Value::AtomicUrl(crate::identifiers::blob_subject(&hex).into()),
        )
        .unwrap();
        db.add_resource_opts(&file, false, true, true)
            .await
            .unwrap();
        file.get_subject().clone()
    }

    /// Pretend the blob was last written `age` ago.
    fn backdate(db: &Db, bytes: &[u8], age: Duration) {
        let at = crate::utils::now() - age.as_millis() as i64;
        db.kv
            .insert(
                Tree::PluginMeta,
                format!("{SEEN_PREFIX}{}", hex::encode(hash_of(bytes))).as_bytes(),
                &at.to_be_bytes(),
            )
            .unwrap();
    }

    async fn stored(db: &Db, bytes: &[u8]) -> bool {
        db.has_blob(&hash_of(bytes)).await.unwrap()
    }

    #[test]
    fn scan_finds_exactly_64_hex_digits() {
        let hash = hash_of(b"x");
        let hex = hex::encode(hash);
        let mut found = HashSet::new();
        scan_hashes(
            format!("did:ad:blob:{hex},https://x/files/{}", hex.to_uppercase()).as_bytes(),
            &mut found,
        );
        assert_eq!(found, HashSet::from([hash]));

        let mut none = HashSet::new();
        scan_hashes(&hex.as_bytes()[1..], &mut none); // 63 digits
        scan_hashes(format!("{hex}0").as_bytes(), &mut none); // 65 digits
        scan_hashes(b"", &mut none);
        assert!(none.is_empty());

        let mut at_end = HashSet::new();
        scan_hashes(format!("blob:{hex}").as_bytes(), &mut at_end);
        assert_eq!(at_end.len(), 1);
    }

    #[tokio::test]
    async fn mark_covers_blob_internal_id_and_chunks() {
        let (db, drive) = db_with_drive().await;
        let (blob, internal, chunk_a, chunk_b) = (
            b"via blob".as_slice(),
            b"via internal id".as_slice(),
            b"chunk a".as_slice(),
            b"chunk b".as_slice(),
        );
        add_file(&db, &drive, "plain", blob).await;

        let subject = db
            .create_resource(urls::FILE, &drive, "legacy", None)
            .await
            .unwrap();
        let mut legacy = db.get_resource(&subject.as_str().into()).await.unwrap();
        legacy
            .set_unsafe(
                urls::INTERNAL_ID.into(),
                Value::String(hex::encode(hash_of(internal))),
            )
            .unwrap();
        db.add_resource_opts(&legacy, false, true, true)
            .await
            .unwrap();

        let subject = db
            .create_resource(urls::FILE, &drive, "chunked", None)
            .await
            .unwrap();
        let mut chunked = db.get_resource(&subject.as_str().into()).await.unwrap();
        chunked
            .set_unsafe(
                urls::CHUNKS.into(),
                Value::ResourceArray(
                    [chunk_a, chunk_b]
                        .iter()
                        .map(|c| {
                            SubResource::Subject(
                                crate::identifiers::blob_subject(&hex::encode(hash_of(c))).into(),
                            )
                        })
                        .collect(),
                ),
            )
            .unwrap();
        db.add_resource_opts(&chunked, false, true, true)
            .await
            .unwrap();

        let marked = db.referenced_blob_hashes().await.unwrap();
        for bytes in [blob, internal, chunk_a, chunk_b] {
            assert!(marked.contains(&hash_of(bytes)), "{:?}", bytes);
        }
        assert!(!marked.contains(&hash_of(b"never referenced")));
    }

    #[tokio::test]
    async fn orphan_is_swept_only_after_the_grace_period() {
        let (db, drive) = db_with_drive().await;
        let (kept, orphan) = (b"still a file".as_slice(), b"file was destroyed".as_slice());
        add_file(&db, &drive, "kept", kept).await;
        let gone = add_file(&db, &drive, "gone", orphan).await;
        db.remove_resource(&gone).await.unwrap();

        // Just uploaded: inside the grace period.
        let report = db.gc_blobs(&BlobGcOptions::new(HOUR)).await.unwrap();
        assert_eq!((report.scanned, report.in_grace, report.deleted), (2, 1, 0));
        assert!(stored(&db, orphan).await);

        // Old enough: swept. The referenced one stays, however old.
        backdate(&db, orphan, 2 * HOUR);
        backdate(&db, kept, 2 * HOUR);
        let report = db.gc_blobs(&BlobGcOptions::new(HOUR)).await.unwrap();
        assert_eq!(report.deleted, 1);
        assert_eq!(report.deleted_bytes, orphan.len() as u64);
        assert_eq!(report.referenced, 1);
        assert!(!stored(&db, orphan).await);
        assert!(stored(&db, kept).await);
        // Its last-put time goes with it.
        assert!(db
            .kv
            .get(
                Tree::PluginMeta,
                format!("{SEEN_PREFIX}{}", hex::encode(hash_of(orphan))).as_bytes()
            )
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn shared_hash_survives_until_the_last_file_is_gone() {
        let (db, drive) = db_with_drive().await;
        let bytes = b"same bytes uploaded twice".as_slice();
        let first = add_file(&db, &drive, "one", bytes).await;
        let second = reference_file(&db, &drive, "two", bytes).await;
        let grace0 = BlobGcOptions::new(Duration::ZERO);

        db.remove_resource(&first).await.unwrap();
        assert_eq!(db.gc_blobs(&grace0).await.unwrap().deleted, 0);
        assert!(stored(&db, bytes).await);

        db.remove_resource(&second).await.unwrap();
        assert_eq!(db.gc_blobs(&grace0).await.unwrap().deleted, 1);
        assert!(!stored(&db, bytes).await);
    }

    #[tokio::test]
    async fn unreadable_resource_aborts_before_any_delete() {
        let (db, _) = db_with_drive().await;
        let orphan = b"would be swept".as_slice();
        db.put_blob(&hash_of(orphan), orphan).await.unwrap();
        db.kv
            .insert(
                Tree::Resources,
                b"internal:/corrupt",
                b"\xc1 not msgpack propvals",
            )
            .unwrap();

        let err = db
            .gc_blobs(&BlobGcOptions::new(Duration::ZERO))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("internal:/corrupt"), "{err}");
        assert!(stored(&db, orphan).await);
    }

    /// Listing must complete: a backend that cannot list means no sweep.
    struct NoListing;
    #[async_trait]
    impl BlobBackend for NoListing {
        async fn get(&self, _: &[u8]) -> crate::errors::AtomicResult<Option<Vec<u8>>> {
            Ok(None)
        }
        async fn put(&self, _: &[u8], _: &[u8]) -> crate::errors::AtomicResult<()> {
            Ok(())
        }
        async fn size(&self, _: &[u8]) -> crate::errors::AtomicResult<Option<u64>> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn backend_without_gc_support_is_never_swept() {
        let mut db = Db::init_redb(None).await.unwrap();
        db.blob_backend = Some(Arc::new(NoListing));
        assert!(db
            .gc_blobs(&BlobGcOptions::new(Duration::ZERO))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn dry_run_reports_candidates_and_changes_nothing() {
        let (db, _) = db_with_drive().await;
        let orphan = b"orphan".as_slice();
        let legacy = b"stored before timestamps existed".as_slice();
        db.put_blob(&hash_of(orphan), orphan).await.unwrap();
        db.kv.insert(Tree::Blobs, &hash_of(legacy), legacy).unwrap();
        backdate(&db, orphan, 2 * HOUR);
        let rows = db.kv.len(Tree::PluginMeta).unwrap();

        let report = db
            .gc_blobs(&BlobGcOptions::new(HOUR).dry_run(true))
            .await
            .unwrap();
        assert!(report.dry_run);
        assert_eq!(report.candidates.len(), 1);
        assert_eq!(report.candidates[0].key, hash_of(orphan));
        assert_eq!(report.candidate_bytes, orphan.len() as u64);
        assert_eq!((report.deleted, report.unstamped), (0, 1));
        assert!(stored(&db, orphan).await);
        assert!(stored(&db, legacy).await);
        // Not even the first-seen stamp of the legacy blob was written.
        assert_eq!(db.kv.len(Tree::PluginMeta).unwrap(), rows);
    }

    #[tokio::test]
    async fn legacy_blobs_get_a_full_grace_period_from_the_first_pass() {
        let (db, _) = db_with_drive().await;
        let legacy = b"stored before timestamps existed".as_slice();
        db.kv.insert(Tree::Blobs, &hash_of(legacy), legacy).unwrap();

        // Pass one only stamps, even with a zero grace period.
        let report = db
            .gc_blobs(&BlobGcOptions::new(Duration::ZERO))
            .await
            .unwrap();
        assert_eq!((report.unstamped, report.deleted), (1, 0));
        assert!(stored(&db, legacy).await);

        // The clock has started: a long grace keeps it, a short one releases it.
        let report = db.gc_blobs(&BlobGcOptions::new(HOUR)).await.unwrap();
        assert_eq!((report.in_grace, report.deleted), (1, 0));
        let report = db
            .gc_blobs(&BlobGcOptions::new(Duration::ZERO))
            .await
            .unwrap();
        assert_eq!(report.deleted, 1);
        assert!(!stored(&db, legacy).await);
    }

    #[tokio::test]
    async fn rewriting_a_blob_restarts_its_grace_period() {
        let (db, _) = db_with_drive().await;
        let bytes = b"orphaned long ago, uploaded again just now".as_slice();
        db.put_blob(&hash_of(bytes), bytes).await.unwrap();
        backdate(&db, bytes, 100 * HOUR);
        db.put_blob(&hash_of(bytes), bytes).await.unwrap();

        let report = db.gc_blobs(&BlobGcOptions::new(HOUR)).await.unwrap();
        assert_eq!((report.in_grace, report.deleted), (1, 0));
        assert!(stored(&db, bytes).await);
    }

    #[tokio::test]
    async fn website_assets_and_deployment_files_are_referenced() {
        let (db, _) = db_with_drive().await;
        let image = b"optimized image bytes".as_slice();
        let hash = hex::encode(hash_of(image));
        let path = format!("assets/{hash}.webp");
        db.website_put_asset("site", &hash, image).await.unwrap();
        let package = WebsitePackage {
            version: 1,
            files: [("index.html".into(), format!("<img src=\"/{path}\">"))].into(),
            assets: [(path, hash)].into(),
            metadata: None,
        };
        db.website_upload("site", "drive", &package).await.unwrap();
        // manifest + one page file + the image
        assert_eq!(db.kv.len(Tree::Blobs).unwrap(), 3);

        let orphan = b"unrelated".as_slice();
        db.put_blob(&hash_of(orphan), orphan).await.unwrap();

        let report = db
            .gc_blobs(&BlobGcOptions::new(Duration::ZERO))
            .await
            .unwrap();
        assert_eq!((report.deleted, report.referenced), (1, 3));
        assert_eq!(db.kv.len(Tree::Blobs).unwrap(), 3);
        assert!(!stored(&db, orphan).await);
    }

    #[tokio::test]
    async fn plugin_release_packages_are_referenced() {
        use crate::db::plugin_release::PluginRelease;
        let (db, _) = db_with_drive().await;
        let package = b"zip bytes of a wasip2 plugin".as_slice();
        db.put_blob(&hash_of(package), package).await.unwrap();
        let mut release =
            PluginRelease::js(String::new(), serde_json::Value::Null, Default::default());
        release.package = Some(hex::encode(hash_of(package)));
        // Stored as the cache stores it; skips validation that is irrelevant here.
        db.kv
            .insert(
                Tree::PluginMeta,
                b"plugin-release/v1/blake3:test",
                &serde_json::to_vec(&release).unwrap(),
            )
            .unwrap();

        let report = db
            .gc_blobs(&BlobGcOptions::new(Duration::ZERO))
            .await
            .unwrap();
        assert_eq!((report.deleted, report.referenced), (0, 1));
        assert!(stored(&db, package).await);
    }

    #[tokio::test]
    async fn kept_hashes_survive_without_a_reference() {
        let (db, _) = db_with_drive().await;
        let marker = b"readiness marker".as_slice();
        db.put_blob(&hash_of(marker), marker).await.unwrap();
        let opts = BlobGcOptions::new(Duration::ZERO).keep([hash_of(marker)]);
        assert_eq!(db.gc_blobs(&opts).await.unwrap().deleted, 0);
        assert!(stored(&db, marker).await);
    }

    /// Fails to delete one blob, as an object store can.
    #[derive(Default)]
    struct FlakyBackend {
        blobs: Mutex<std::collections::BTreeMap<Vec<u8>, Vec<u8>>>,
        undeletable: Vec<u8>,
    }
    #[async_trait]
    impl BlobBackend for FlakyBackend {
        async fn get(&self, key: &[u8]) -> crate::errors::AtomicResult<Option<Vec<u8>>> {
            Ok(self.blobs.lock().unwrap().get(key).cloned())
        }
        async fn put(&self, key: &[u8], bytes: &[u8]) -> crate::errors::AtomicResult<()> {
            self.blobs
                .lock()
                .unwrap()
                .insert(key.to_vec(), bytes.to_vec());
            Ok(())
        }
        async fn size(&self, key: &[u8]) -> crate::errors::AtomicResult<Option<u64>> {
            Ok(self.blobs.lock().unwrap().get(key).map(|b| b.len() as u64))
        }
        async fn list(&self) -> crate::errors::AtomicResult<Vec<BlobInfo>> {
            Ok(self
                .blobs
                .lock()
                .unwrap()
                .iter()
                .map(|(key, bytes)| BlobInfo {
                    key: key.clone(),
                    size: bytes.len() as u64,
                    modified_ms: Some(0),
                })
                .collect())
        }
        async fn delete(&self, key: &[u8]) -> crate::errors::AtomicResult<()> {
            if key == self.undeletable {
                return Err("503 slow down".into());
            }
            self.blobs.lock().unwrap().remove(key);
            Ok(())
        }
        async fn modified_ms(&self, key: &[u8]) -> crate::errors::AtomicResult<Option<i64>> {
            Ok(self.blobs.lock().unwrap().contains_key(key).then_some(0))
        }
    }

    #[tokio::test]
    async fn backend_delete_errors_are_logged_and_skipped() {
        let (stuck, other) = (b"stuck".as_slice(), b"deletable".as_slice());
        let backend = Arc::new(FlakyBackend {
            undeletable: hash_of(stuck).to_vec(),
            ..Default::default()
        });
        let mut db = Db::init_redb(None).await.unwrap();
        db.blob_backend = Some(backend.clone());
        for bytes in [stuck, other] {
            db.put_blob(&hash_of(bytes), bytes).await.unwrap();
        }

        let report = db
            .gc_blobs(&BlobGcOptions::new(Duration::ZERO))
            .await
            .unwrap();
        assert_eq!((report.deleted, report.failed), (1, 1));
        assert_eq!(backend.blobs.lock().unwrap().len(), 1);
        assert!(stored(&db, stuck).await);
    }
}
