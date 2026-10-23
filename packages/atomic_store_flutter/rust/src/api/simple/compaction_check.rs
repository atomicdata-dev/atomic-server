//! How often an app start may check whether the store needs compacting.
//!
//! The library's startup policy measures the reclaimable space of every store
//! above a quarter of its 256 MiB floor by walking every page
//! (`StoreFileStats::collect`). On a 1 GB store that walk is 0.1 s from a
//! warm OS cache and about 1 s cold on a Mac, and it leaves the whole store in
//! redb's 1 GiB read cache: 870 MB RSS right after open, against 12 ms and
//! 11 MB without it (`lib/tests/stress_chats.rs`, `stress_reopen`). A phone
//! starts the app many times a day, and the space it could reclaim only
//! changes as fast as the store does, so the check runs at most once a week,
//! or sooner when the file grew by a quarter since the last one.

use std::path::{Path, PathBuf};

use atomic_lib::db::compaction::{file_sizes, CompactionPolicy};

/// Days between two checks of a store that did not grow.
const CHECK_EVERY_MS: i64 = 7 * 24 * 60 * 60 * 1000;

fn record_path(base_path: &Path) -> PathBuf {
    base_path.join("compaction-check")
}

/// `(checked_at_ms, disk_bytes)` of the last check, `None` when there was
/// none (or the record cannot be read).
fn last_check(base_path: &Path) -> Option<(i64, u64)> {
    let raw = std::fs::read_to_string(record_path(base_path)).ok()?;
    let mut parts = raw.split_whitespace();
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

/// Whether this start should run the startup compaction policy.
pub(crate) fn check_due(base_path: &Path, now_ms: i64) -> bool {
    let Some((checked_at, checked_bytes)) = last_check(base_path) else {
        return true;
    };
    let (_, disk_bytes) = file_sizes(&base_path.join("atomic.redb"));
    now_ms.saturating_sub(checked_at) >= CHECK_EVERY_MS
        || now_ms < checked_at
        || disk_bytes > checked_bytes.saturating_add(checked_bytes / 4)
}

/// The policy for this start: the library's default when a check is due,
/// otherwise none (the file is opened without the page walk).
pub(crate) fn startup_policy(base_path: &Path, now_ms: i64) -> CompactionPolicy {
    if check_due(base_path, now_ms) {
        CompactionPolicy::default()
    } else {
        CompactionPolicy::disabled()
    }
}

/// Remember that the store was checked now, at its current size.
pub(crate) fn record_check(base_path: &Path, now_ms: i64) {
    let (_, disk_bytes) = file_sizes(&base_path.join("atomic.redb"));
    let _ = std::fs::write(record_path(base_path), format!("{now_ms} {disk_bytes}\n"));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "atomic-compaction-check-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_check_is_due_once_a_week_or_when_the_store_grew() {
        let d = dir("due");
        let store = d.join("atomic.redb");
        std::fs::write(&store, vec![1u8; 400_000]).unwrap();
        let now = 1_000_000_000_000;
        assert!(check_due(&d, now), "never checked");

        record_check(&d, now);
        assert!(!check_due(&d, now + 60_000), "checked a minute ago");
        assert_eq!(startup_policy(&d, now + 60_000), CompactionPolicy::disabled());
        assert!(check_due(&d, now + CHECK_EVERY_MS), "a week later");
        assert!(check_due(&d, now - 1), "the clock went back");

        std::fs::write(&store, vec![1u8; 600_000]).unwrap();
        assert!(check_due(&d, now + 60_000), "grew by half");
        std::fs::remove_dir_all(d).ok();
    }
}
