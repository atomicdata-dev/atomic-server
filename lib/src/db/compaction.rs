//! Startup store-size diagnostics and automatic compaction for the
//! file-backed redb store.
//!
//! redb never gives dead pages back to the filesystem on its own: every
//! overwrite and delete frees pages that later writes may reuse, but the
//! file only shrinks when the *tail* of it happens to be free, so a store
//! that has churned through many resources stays as large as its high-water
//! mark. `Database::create` then pays for that size on every boot (see
//! `planning/disk-storage-and-persistence-optimization.md`). This module
//! measures the file on open, says how much of it is dead, and reclaims it
//! when the policy says it is worth the one-off pause.
//!
//! Only the native file backend uses it: the WASM/OPFS store never reaches
//! `RedbStore::new_file`, and the sled backend has its own lifecycle.

use std::time::{Duration, Instant};

use redb::Database;
use serde::{Deserialize, Serialize};

use crate::errors::AtomicResult;

pub const MIB: u64 = 1024 * 1024;

/// Above this file size the open-time log line is a warning that names
/// `atomic-server compact`, whatever the reclaimable fraction: at 1 GiB the
/// open alone is measured in seconds on macOS.
pub const LARGE_STORE_WARN_BYTES: u64 = 1024 * MIB;

/// When `Db::init_redb_file` compacts the store before serving it.
///
/// Both thresholds must hold: a file smaller than `min_file_bytes` is cheap
/// to open however wasteful it is, and a large file whose free space is
/// below `min_reclaimable_fraction` would cost an O(file) compaction for
/// little gain (a store with steady churn always carries some free pages
/// that the next writes reuse).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CompactionPolicy {
    /// `false` skips the reclaimable-space measurement and the compaction.
    /// The file size and open duration are still logged.
    pub enabled: bool,
    /// Files below this size are never compacted automatically.
    pub min_file_bytes: u64,
    /// Compact when `free_bytes / file_bytes` reaches this (0.0 – 1.0).
    pub min_reclaimable_fraction: f64,
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            min_file_bytes: 256 * MIB,
            min_reclaimable_fraction: 0.30,
        }
    }
}

impl CompactionPolicy {
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            min_file_bytes: u64::MAX,
            min_reclaimable_fraction: 1.0,
        }
    }
}

/// Bytes the file occupies on disk, as opposed to its length. redb grows the
/// file with `set_len`, by doubling below 4 GiB and by whole regions above,
/// which leaves a sparse, never-written tail on every common filesystem.
/// That tail is headroom the next writes fill, not dead data, and the length
/// alone would call a freshly grown store half reclaimable. Dead pages were
/// written, so they do occupy blocks. Falls back to the length where the
/// platform reports no block count.
pub fn disk_usage(meta: &std::fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.blocks().saturating_mul(512).min(meta.len())
    }
    #[cfg(not(unix))]
    {
        meta.len()
    }
}

/// `(length, bytes on disk)` of `path`, both 0 when it cannot be read.
pub fn file_sizes(path: &std::path::Path) -> (u64, u64) {
    match std::fs::metadata(path) {
        Ok(meta) => (meta.len(), disk_usage(&meta)),
        Err(_) => (0, 0),
    }
}

/// What a redb file holds, measured right after open.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StoreFileStats {
    /// `metadata(path).len()`, including redb's sparse growth headroom.
    pub file_bytes: u64,
    /// See [`disk_usage`]; the size the thresholds are applied to.
    pub disk_bytes: u64,
    pub page_size: u64,
    /// Pages the allocator considers in use, including redb's own tables.
    pub allocated_pages: u64,
    pub leaf_pages: u64,
    pub branch_pages: u64,
    /// Bytes of keys and values (`DatabaseStats::stored_bytes`).
    pub stored_bytes: u64,
    /// Branch keys and other index overhead (`DatabaseStats::metadata_bytes`).
    pub metadata_bytes: u64,
    /// Slack inside allocated pages (`DatabaseStats::fragmented_bytes`).
    /// Compaction moves whole pages, so this is *not* reclaimable by it.
    pub fragmented_bytes: u64,
    /// `DatabaseStats` walks every B-tree page, so this is O(file) and
    /// worth knowing.
    pub measured_in: Duration,
}

impl StoreFileStats {
    /// Walks the whole store; see `measured_in`. redb exposes stats on a
    /// write transaction only; it is aborted, nothing is written.
    pub fn collect(db: &Database, path: &std::path::Path) -> AtomicResult<Self> {
        let (file_bytes, disk_bytes) = file_sizes(path);
        let t = Instant::now();
        let tx = db
            .begin_write()
            .map_err(|e| format!("redb stats tx: {e}"))?;
        let stats = tx.stats().map_err(|e| format!("redb stats: {e}"))?;
        tx.abort().map_err(|e| format!("redb stats abort: {e}"))?;
        Ok(Self {
            file_bytes,
            disk_bytes,
            page_size: stats.page_size() as u64,
            allocated_pages: stats.allocated_pages(),
            leaf_pages: stats.leaf_pages(),
            branch_pages: stats.branch_pages(),
            stored_bytes: stats.stored_bytes(),
            metadata_bytes: stats.metadata_bytes(),
            fragmented_bytes: stats.fragmented_bytes(),
            measured_in: t.elapsed(),
        })
    }

    pub fn allocated_bytes(&self) -> u64 {
        self.allocated_pages.saturating_mul(self.page_size)
    }

    /// Bytes on disk that no live page occupies: dead pages `compact()` can
    /// move out of the way and truncate.
    pub fn free_bytes(&self) -> u64 {
        self.disk_bytes.saturating_sub(self.allocated_bytes())
    }

    /// `free_bytes / disk_bytes`, 0.0 for an empty file.
    pub fn reclaimable_fraction(&self) -> f64 {
        if self.disk_bytes == 0 {
            0.0
        } else {
            self.free_bytes() as f64 / self.disk_bytes as f64
        }
    }
}

/// Why the startup policy did not compact.
#[derive(Debug, Clone, PartialEq)]
pub enum Skip {
    Disabled,
    /// The file is below `CompactionPolicy::min_file_bytes`.
    TooSmall,
    /// The reclaimable fraction is below the policy's threshold.
    NotWorthIt,
    /// Measuring or compacting failed; the store is still usable.
    Failed(String),
}

impl CompactionPolicy {
    /// Whether these stats meet both thresholds.
    pub fn decide(&self, stats: &StoreFileStats) -> Result<(), Skip> {
        if !self.enabled {
            return Err(Skip::Disabled);
        }
        if stats.disk_bytes < self.min_file_bytes {
            return Err(Skip::TooSmall);
        }
        if stats.reclaimable_fraction() < self.min_reclaimable_fraction {
            return Err(Skip::NotWorthIt);
        }
        Ok(())
    }
}

/// Outcome of one compaction. `Db::init_redb_file` stores the latest one
/// under `Tree::PluginMeta` (`RECORD_KEY`) so it can be read back after the
/// log line has scrolled away; `Db::last_compaction` returns it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompactionRecord {
    /// Unix time in milliseconds at which the compaction finished.
    pub compacted_at_ms: u64,
    /// File length before and after.
    pub bytes_before: u64,
    pub bytes_after: u64,
    /// Bytes on disk before and after (see [`disk_usage`]).
    pub disk_bytes_before: u64,
    pub disk_bytes_after: u64,
    /// `free_bytes` measured before compacting.
    pub free_bytes_before: u64,
    pub duration_ms: u64,
    /// `false` when redb found nothing to move (the file was already dense).
    pub did_compact: bool,
}

pub const RECORD_KEY: &[u8] = b"store_compaction_last";

/// `Database::compact` with an `AtomicResult`. The caller owns the only
/// handle, so no read transaction can be live.
pub fn compact_database(db: &mut Database) -> AtomicResult<bool> {
    db.compact()
        .map_err(|e| format!("Compaction failed: {e}").into())
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / MIB as f64
}

/// Log what the just-opened file looks like and compact it if the policy
/// says so. Never fails: a measurement or compaction error is a warning and
/// the store opens as it was. `open_duration` is how long `Database::create`
/// took, logged next to the size it scales with.
pub fn run_startup_policy(
    db: &mut Database,
    path: &std::path::Path,
    open_duration: Duration,
    policy: &CompactionPolicy,
) -> Result<CompactionRecord, Skip> {
    let (file_bytes, disk_bytes) = file_sizes(path);
    if disk_bytes >= LARGE_STORE_WARN_BYTES {
        tracing::warn!(
            "Store {} is {:.1} MiB on disk ({:.1} MiB long) and took {:?} to open; open time \
             grows with file size. `atomic-server compact` reclaims dead pages while the \
             server is stopped.",
            path.display(),
            mib(disk_bytes),
            mib(file_bytes),
            open_duration
        );
    } else {
        tracing::info!(
            "Store {} is {:.1} MiB on disk ({:.1} MiB long), opened in {:?}",
            path.display(),
            mib(disk_bytes),
            mib(file_bytes),
            open_duration
        );
    }

    if !policy.enabled {
        tracing::info!(
            "Automatic store compaction is disabled; skipping the reclaimable-space measurement"
        );
        return Err(Skip::Disabled);
    }
    // Measuring walks every page (a quarter second for a few MiB on a phone,
    // at every start). Below a quarter of the size floor neither a compaction
    // nor the "reclaimable but below the floor" hint can follow: its free
    // space cannot reach `min_file_bytes / 4`.
    if disk_bytes < policy.min_file_bytes / 4 {
        return Err(Skip::TooSmall);
    }

    let stats = match StoreFileStats::collect(db, path) {
        Ok(stats) => stats,
        Err(e) => {
            tracing::warn!("Could not measure the store file: {e}");
            return Err(Skip::Failed(e.to_string()));
        }
    };
    tracing::info!(
        "Store pages: {} allocated ({} leaf, {} branch) × {} B = {:.1} MiB live; \
         {:.1} MiB stored + {:.1} MiB metadata + {:.1} MiB fragmented; \
         {:.1} MiB ({:.0}%) reclaimable by compaction (measured in {:?})",
        stats.allocated_pages,
        stats.leaf_pages,
        stats.branch_pages,
        stats.page_size,
        mib(stats.allocated_bytes()),
        mib(stats.stored_bytes),
        mib(stats.metadata_bytes),
        mib(stats.fragmented_bytes),
        mib(stats.free_bytes()),
        100.0 * stats.reclaimable_fraction(),
        stats.measured_in
    );

    match policy.decide(&stats) {
        Ok(()) => {}
        Err(skip) => {
            if stats.free_bytes() >= policy.min_file_bytes / 4
                && stats.reclaimable_fraction() >= policy.min_reclaimable_fraction
            {
                // Big enough to matter and mostly dead, but under the size
                // floor: say so, once, in case the operator wants it now.
                tracing::info!(
                    "{:.1} MiB reclaimable but the store is below the {:.0} MiB automatic \
                     compaction floor; run `atomic-server compact` to reclaim it now",
                    mib(stats.free_bytes()),
                    mib(policy.min_file_bytes)
                );
            }
            return Err(skip);
        }
    }

    tracing::warn!(
        "Compacting store {} before serving: {:.1} MiB on disk of which {:.1} MiB ({:.0}%) is \
         reclaimable. This is O(file size); the server listens when it finishes. \
         Set ATOMIC_AUTO_COMPACT=false to skip.",
        path.display(),
        mib(disk_bytes),
        mib(stats.free_bytes()),
        100.0 * stats.reclaimable_fraction()
    );
    let t = Instant::now();
    let did_compact = match compact_database(db) {
        Ok(did) => did,
        Err(e) => {
            tracing::warn!(
                "Automatic store compaction failed; continuing with the store as it is: {e}"
            );
            return Err(Skip::Failed(e.to_string()));
        }
    };
    let duration = t.elapsed();
    let (bytes_after, disk_bytes_after) = file_sizes(path);
    let saved = disk_bytes.saturating_sub(disk_bytes_after);
    tracing::info!(
        "{} in {:?}: {:.1} MiB → {:.1} MiB on disk (saved {:.1} MiB, {:.0}%), \
         file length {:.1} MiB → {:.1} MiB",
        if did_compact {
            "Compacted store"
        } else {
            "Store already dense, nothing moved"
        },
        duration,
        mib(disk_bytes),
        mib(disk_bytes_after),
        mib(saved),
        if disk_bytes > 0 {
            100.0 * saved as f64 / disk_bytes as f64
        } else {
            0.0
        },
        mib(file_bytes),
        mib(bytes_after)
    );
    Ok(CompactionRecord {
        compacted_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        bytes_before: file_bytes,
        bytes_after,
        disk_bytes_before: disk_bytes,
        disk_bytes_after,
        free_bytes_before: stats.free_bytes(),
        duration_ms: duration.as_millis() as u64,
        did_compact,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(file_bytes: u64, allocated_pages: u64) -> StoreFileStats {
        StoreFileStats {
            file_bytes,
            disk_bytes: file_bytes,
            page_size: 4096,
            allocated_pages,
            leaf_pages: allocated_pages,
            branch_pages: 0,
            stored_bytes: 0,
            metadata_bytes: 0,
            fragmented_bytes: 0,
            measured_in: Duration::ZERO,
        }
    }

    #[test]
    fn free_bytes_is_file_minus_allocated_pages() {
        let s = stats(100 * 4096, 40);
        assert_eq!(s.allocated_bytes(), 40 * 4096);
        assert_eq!(s.free_bytes(), 60 * 4096);
        assert!((s.reclaimable_fraction() - 0.6).abs() < 1e-9);
        // A file shorter than its allocation (mid-write) never underflows.
        assert_eq!(stats(10, 40).free_bytes(), 0);
        assert_eq!(stats(0, 0).reclaimable_fraction(), 0.0);
    }

    #[test]
    fn sparse_growth_headroom_is_not_reclaimable() {
        // A file redb just doubled: 100 pages long, 40 live, the rest a
        // sparse tail. On disk it is only the written pages.
        let s = StoreFileStats {
            file_bytes: 100 * 4096,
            disk_bytes: 42 * 4096,
            ..stats(100 * 4096, 40)
        };
        assert_eq!(s.free_bytes(), 2 * 4096);
        assert!(s.reclaimable_fraction() < 0.05);
        assert_eq!(
            CompactionPolicy {
                enabled: true,
                min_file_bytes: 0,
                min_reclaimable_fraction: 0.30,
            }
            .decide(&s),
            Err(Skip::NotWorthIt)
        );
    }

    #[test]
    fn disk_usage_ignores_a_sparse_tail() {
        let dir = temp_store_dir("sparse");
        let path = dir.join("sparse.bin");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(64 * MIB).unwrap();
        drop(file);
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), 64 * MIB);
        // Tolerate a filesystem that cannot do sparse files, but on one
        // that can (every CI and dev box) the tail costs nothing.
        assert!(disk_usage(&meta) <= meta.len());
        if cfg!(unix) && disk_usage(&meta) < meta.len() {
            assert!(disk_usage(&meta) < MIB, "{}", disk_usage(&meta));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn policy_needs_both_thresholds() {
        let policy = CompactionPolicy {
            enabled: true,
            min_file_bytes: 100 * 4096,
            min_reclaimable_fraction: 0.5,
        };
        assert_eq!(policy.decide(&stats(100 * 4096, 40)), Ok(()));
        assert_eq!(
            policy.decide(&stats(99 * 4096, 1)),
            Err(Skip::TooSmall),
            "a small file is never compacted however wasteful"
        );
        assert_eq!(
            policy.decide(&stats(1000 * 4096, 600)),
            Err(Skip::NotWorthIt)
        );
        assert_eq!(
            CompactionPolicy::disabled().decide(&stats(1000 * 4096, 0)),
            Err(Skip::Disabled)
        );
    }

    fn temp_store_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "atomic-compaction-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("uploads")).unwrap();
        dir
    }

    async fn open(dir: &std::path::Path, policy: &CompactionPolicy) -> crate::Db {
        crate::Db::init_redb_file_with_policy(dir, None, &dir.join("uploads"), policy)
            .await
            .unwrap()
    }

    const RESOURCES: usize = 32;
    const ROUNDS: usize = 3;
    /// Throwaway resources per round; deleted at the end of the fill.
    const THROWAWAY: usize = 24;

    fn subject(i: usize) -> String {
        format!("did:ad:compaction-test-{i}")
    }

    /// The description written in `round`; the last round's value is what
    /// must survive compaction.
    fn payload(i: usize, round: usize) -> String {
        // Doubles per round so an overwrite never fits the block it frees,
        // the way a resource whose Loro snapshot grows with every edit
        // leaves the file.
        format!("r{i}-{round}-").repeat(512 << round)
    }

    /// Churn the store the way a long test session does: the kept
    /// resources are overwritten every round with a larger value, and a
    /// batch of throwaway resources is written between the rounds and
    /// deleted at the end. Their pages are freed mid-file, where redb's own
    /// tail truncation cannot reach them, so the file keeps its high-water
    /// size. Returns the file's `(length, bytes on disk)` after a clean close.
    /// Text that deflate cannot shrink: stored values are compressed, and a
    /// repeated string would leave no dead space to reclaim.
    fn noise(seed: usize, len: usize) -> String {
        let mut state = (seed as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (b'a' + (state % 26) as u8) as char
            })
            .collect()
    }

    async fn fill(dir: &std::path::Path) -> (u64, u64) {
        use crate::{urls, Resource, Storelike, Value};
        let store = open(dir, &CompactionPolicy::disabled()).await;
        let mut throwaways = Vec::new();
        for round in 0..ROUNDS {
            for j in 0..THROWAWAY {
                let subject = format!("did:ad:compaction-throwaway-{round}-{j}");
                let mut r = Resource::new(subject.clone());
                r.set_unsafe(
                    urls::DESCRIPTION.into(),
                    Value::String(noise(round * THROWAWAY + j, 18_000)),
                )
                .unwrap();
                // No index update: the test is about the file, and indexing
                // kilobytes of repeated text is most of the cost.
                store
                    .add_resource_opts(&r, false, false, true)
                    .await
                    .unwrap();
                throwaways.push(subject);
            }
            for i in 0..RESOURCES {
                let mut r = Resource::new(subject(i));
                r.set_unsafe(urls::DESCRIPTION.into(), Value::String(payload(i, round)))
                    .unwrap();
                store
                    .add_resource_opts(&r, false, false, true)
                    .await
                    .unwrap();
            }
        }
        for subject in &throwaways {
            store
                .remove_resource(&crate::Subject::from_raw(subject, None))
                .await
                .unwrap();
        }
        store.flush().unwrap();
        drop(store);
        file_sizes(&dir.join("atomic.redb"))
    }

    async fn assert_intact(store: &crate::Db) {
        use crate::{urls, Storelike};
        for i in 0..RESOURCES {
            let r = store
                .get_resource(&crate::Subject::from_raw(&subject(i), None))
                .await
                .unwrap();
            assert_eq!(
                r.get(urls::DESCRIPTION).unwrap().to_string(),
                payload(i, ROUNDS - 1),
                "resource {i} must read back its last value"
            );
        }
    }

    /// The whole startup path: a store bloated by overwrites is compacted
    /// when reopened through `Db::init_redb_file_with_policy`, shrinks,
    /// reads back every resource, and records what it did; the same file
    /// opened with the policy disabled is left alone.
    #[tokio::test(flavor = "multi_thread")]
    async fn startup_compaction_shrinks_a_bloated_store_and_keeps_every_resource() {
        let dir = temp_store_dir("startup");
        let (bloated, bloated_disk) = fill(&dir).await;
        {
            // A copy for the disabled case, so both branches see the same
            // bloat rather than one fill each.
            let untouched = temp_store_dir("disabled");
            std::fs::copy(dir.join("atomic.redb"), untouched.join("atomic.redb")).unwrap();
            let store = open(&untouched, &CompactionPolicy::disabled()).await;
            assert_eq!(store.last_compaction(), None);
            assert_intact(&store).await;
            drop(store);
            // The open still writes (bootstrap fingerprint, flush sentinel)
            // and redb may trim a few trailing free pages on those commits,
            // so the size can move by a page or two either way; what must
            // not have happened is the reclaim: the dead space is still there.
            let path = untouched.join("atomic.redb");
            let db = Database::create(&path).unwrap();
            let still = StoreFileStats::collect(&db, &path).unwrap();
            drop(db);
            assert!(
                still.reclaimable_fraction() >= 0.30,
                "a disabled policy must leave the dead space alone: {still:?}"
            );
            assert!(
                still.disk_bytes * 10 >= bloated_disk * 9,
                "{still:?} vs {bloated_disk}"
            );
            std::fs::remove_dir_all(&untouched).ok();
        }

        let policy = CompactionPolicy {
            enabled: true,
            // Far below the production floor: the test store is a few MiB.
            min_file_bytes: MIB,
            min_reclaimable_fraction: 0.30,
        };
        let store = open(&dir, &policy).await;
        let record = store
            .last_compaction()
            .expect("the startup policy must have compacted this store");
        assert!(record.did_compact, "{record:?}");
        assert_eq!(record.bytes_before, bloated);
        assert!(
            record.free_bytes_before * 10 >= record.disk_bytes_before * 3,
            "the fill must leave at least the 30% the policy asks for: {record:?}"
        );
        // Compaction moves live pages down and truncates the free tail; a
        // few pages of allocator metadata may not move, so demand most of
        // the free space back, not all of it.
        assert!(
            record.disk_bytes_before - record.disk_bytes_after >= record.free_bytes_before * 3 / 4,
            "compaction should reclaim most of the free space: {record:?}"
        );
        assert!(record.bytes_after < record.bytes_before, "{record:?}");
        assert_intact(&store).await;

        // The open that followed the compaction wrote to the store, and redb
        // grew the file's length again for that (a sparse tail). That is
        // headroom, not waste: the next open must not compact again, and
        // must still report the compaction that did run.
        drop(store);
        let store = open(&dir, &policy).await;
        assert_eq!(store.last_compaction(), Some(record));
        assert_intact(&store).await;
        drop(store);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A store far below the floor opens without the page walk that
    /// measures it (it cost a quarter second at every app start).
    #[test]
    fn a_small_store_is_not_measured() {
        let dir = temp_store_dir("small");
        let path = dir.join("small.redb");
        let mut db = Database::create(&path).unwrap();
        assert_eq!(
            run_startup_policy(&mut db, &path, Duration::ZERO, &CompactionPolicy::default()),
            Err(Skip::TooSmall)
        );
        drop(db);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn defaults_are_the_documented_ones() {
        let d = CompactionPolicy::default();
        assert!(d.enabled);
        assert_eq!(d.min_file_bytes, 256 * MIB);
        assert!((d.min_reclaimable_fraction - 0.30).abs() < 1e-9);
    }
}
