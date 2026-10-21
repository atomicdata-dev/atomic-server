//! How much of the person's data this device holds, for the Sync screen's
//! "This device" card: the store's size on disk, and per drive the number of
//! resources and the bytes behind them. Everything is counted from the store,
//! nothing is estimated; what cannot be read is left out.
//!
//! Counting walks the drives' resources, so a host calls [`store_stats`] off its
//! UI thread and caches the answer for a short while.

use crate::{db::DriveUsage, errors::AtomicResult, Db};
use serde_json::{json, Value as Json};
use std::path::Path;

/// The bytes of every file under `dir` (the store file and anything beside
/// it), or `None` when it cannot be read. Does not follow symlinks.
pub fn dir_bytes(dir: &Path) -> Option<u64> {
    fn walk(dir: &Path, depth: usize) -> std::io::Result<u64> {
        let mut total = 0;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if meta.is_file() {
                total += meta.len();
            } else if meta.is_dir() && depth < 4 {
                total += walk(&entry.path(), depth + 1).unwrap_or(0);
            }
        }
        Ok(total)
    }
    walk(dir, 0).ok()
}

/// A drive's rows, biggest first; equal sizes keep a stable order by subject.
fn sorted(mut usage: Vec<DriveUsage>) -> Vec<DriveUsage> {
    usage.sort_by(|a, b| {
        (b.loro_bytes + b.blob_bytes)
            .cmp(&(a.loro_bytes + a.blob_bytes))
            .then_with(|| a.drive_subject.cmp(&b.drive_subject))
    });
    usage
}

/// `{disk_bytes?, resources, loro_bytes, blob_bytes, drives: [{subject, name,
/// resources, bytes, loro_bytes, blob_bytes}]}` for the drives of this agent
/// that this device holds. `dir` is the store's directory (for `disk_bytes`;
/// omitted when unknown). `drives` is biggest first.
pub async fn store_stats(store: &Db, dir: Option<&Path>) -> AtomicResult<Json> {
    // Only drives held here: asking for one that is not would go and fetch it.
    let mut held = Vec::new();
    for drive in store.list_drives().await? {
        if store.has_resource_locally(&drive.subject) && !held.contains(&drive.subject) {
            held.push(drive.subject);
        }
    }
    let usage = sorted(store.per_drive_usage(&held).await?);
    let (mut resources, mut loro, mut blob) = (0, 0, 0);
    let rows: Vec<Json> = usage
        .iter()
        .map(|d| {
            resources += d.resource_count;
            loro += d.loro_bytes;
            blob += d.blob_bytes;
            json!({
                "subject": d.drive_subject,
                "name": d.name.clone().unwrap_or_default(),
                "resources": d.resource_count,
                "bytes": d.loro_bytes + d.blob_bytes,
                "loro_bytes": d.loro_bytes,
                "blob_bytes": d.blob_bytes,
            })
        })
        .collect();
    let mut out = json!({
        "resources": resources,
        "loro_bytes": loro,
        "blob_bytes": blob,
        "drives": rows,
    });
    if let Some(bytes) = dir.and_then(dir_bytes) {
        out["disk_bytes"] = json!(bytes);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{host::test_support::Device, urls};

    #[tokio::test]
    async fn counts_two_drives_biggest_first() {
        let d = Device::new().await;
        let second = d.store.create_drive("Second").await.unwrap();
        // The second drive gets more content, so it must come first.
        for i in 0..5 {
            d.store
                .create_resource(urls::CLASS, &second, &format!("Thing {i}"), None)
                .await
                .unwrap();
        }
        d.store
            .create_resource(urls::CLASS, &d.drive, "One", None)
            .await
            .unwrap();

        let dir = std::env::temp_dir().join(format!("stats-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("atomic.redb"), vec![0u8; 1234]).unwrap();

        let stats = store_stats(&d.store, Some(&dir)).await.unwrap();
        let drives = stats["drives"].as_array().unwrap();
        assert_eq!(drives.len(), 2, "{stats}");
        assert_eq!(drives[0]["subject"], json!(second));
        assert!(drives[0]["resources"].as_u64().unwrap() >= 6);
        assert!(drives[1]["resources"].as_u64().unwrap() >= 2);
        assert!(drives.iter().all(|r| r["bytes"].as_u64().unwrap() > 0));
        assert!(drives[0]["bytes"].as_u64() >= drives[1]["bytes"].as_u64());
        let sum: u64 = drives
            .iter()
            .map(|r| r["resources"].as_u64().unwrap())
            .sum();
        assert_eq!(stats["resources"].as_u64().unwrap(), sum);
        assert_eq!(stats["disk_bytes"], json!(1234));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn no_directory_means_no_disk_size() {
        let d = Device::new().await;
        let stats = store_stats(&d.store, None).await.unwrap();
        assert!(stats.get("disk_bytes").is_none());
    }
}
