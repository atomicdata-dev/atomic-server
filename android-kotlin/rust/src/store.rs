//! Opening the store: once per process, never panicking, never deleting the
//! person's data. Copied from `flutter/rust/src/api/simple.rs` (see the crate
//! docs for why it is not shared).

use crate::{error::CoreResult, types::StoreRecovery};
use std::path::Path;

/// Open the store in `base_path`. A store that cannot be opened because the
/// file is damaged is renamed to `atomic.redb.corrupt-<ms>`, a repaired copy
/// (or, failing that, an empty store) takes its place and the recovery is
/// returned so the app can say so. Other errors (permissions, a full disk)
/// are returned as they are.
pub(crate) async fn open_native_store(
    base_path: &Path,
) -> CoreResult<(atomic_lib::Db, Option<StoreRecovery>)> {
    use atomic_lib::db::recovery;
    std::fs::create_dir_all(base_path)
        .map_err(|e| format!("Cannot create {}: {e}", base_path.display()))?;
    let db_path = base_path.join("atomic.redb");
    let before = recovery::inspect(&db_path).ok().flatten();
    let started = std::time::Instant::now();

    let (store, recovered) = match open_store_catching(base_path).await {
        Ok(store) => (store, None),
        Err(e) if recovery::is_damaged_store_error(&e) => {
            tracing::error!("The store could not be opened, setting it aside: {e} ({before:?})");
            let kept = recovery::set_aside(&db_path).map_err(|io| {
                format!("The store could not be opened ({e}) nor moved aside: {io}")
            })?;
            let mut repaired = match recovery::repair_copy(&kept, &db_path) {
                Ok(()) => true,
                Err(repair) => {
                    tracing::warn!("Repairing a copy of the store failed: {repair}");
                    false
                }
            };
            let store = match open_store_catching(base_path).await {
                Ok(store) => store,
                Err(again) if repaired => {
                    // Only the repaired copy goes; the original is `kept`.
                    tracing::warn!("The repaired store did not open either: {again}");
                    let _ = std::fs::remove_file(&db_path);
                    repaired = false;
                    open_store_catching(base_path).await?
                }
                Err(again) => return Err(again.into()),
            };
            let recovery = StoreRecovery {
                kept_path: kept.to_string_lossy().into_owned(),
                reason: e,
                repaired,
            };
            (store, Some(recovery))
        }
        Err(e) => return Err(e.into()),
    };
    tracing::info!(
        "store {} opened in {:?}; {}",
        db_path.display(),
        started.elapsed(),
        match &recovered {
            None => "no recovery needed".to_string(),
            Some(r) if r.repaired => format!("REPAIRED a damaged store, kept at {}", r.kept_path),
            Some(r) => format!("STARTED EMPTY, the damaged store is kept at {}", r.kept_path),
        }
    );
    Ok((store, recovered))
}

/// redb's read cache on a phone. Its default (1 GiB) keeps whatever was read,
/// up to the size of the store, in memory (870 MB of RSS after a full walk of
/// a 1 GB store); the lists and the search read little and repeatedly. The
/// same 48 MiB as the Flutter bridge.
pub(crate) const REDB_CACHE_BYTES: usize = 48 * 1024 * 1024;

/// `Db::init_redb_file_with_cache` with any panic inside it turned into a
/// "damaged" error: a panic must not escape to the app, which then never
/// draws. The startup compaction check runs at most once a week
/// ([`crate::compaction_check`]).
async fn open_store_catching(base_path: &Path) -> Result<atomic_lib::Db, String> {
    use futures::FutureExt;
    let uploads_path = base_path.join("uploads");
    let now = crate::state::now_ms();
    let policy = crate::compaction_check::startup_policy(base_path, now);
    let checks = policy.enabled;
    let opening = atomic_lib::Db::init_redb_file_with_cache(
        base_path,
        None,
        &uploads_path,
        &policy,
        Some(REDB_CACHE_BYTES),
    );
    match std::panic::AssertUnwindSafe(opening).catch_unwind().await {
        Ok(Ok(store)) => {
            if checks {
                crate::compaction_check::record_check(base_path, now);
            }
            Ok(store)
        }
        Ok(Err(e)) => Err(e.to_string()),
        Err(panic) => Err(format!(
            "The {}: panic while opening: {}",
            atomic_lib::db::recovery::DAMAGED_STORE,
            atomic_lib::db::recovery::panic_message(&panic)
        )),
    }
}

/// Make sure every stored resource is searchable: rebuilds once per install
/// (a marker records it), then drains resources filed for deferred indexing.
pub(crate) async fn catch_up_search_index(store: std::sync::Arc<atomic_lib::Db>) {
    let rebuilder = store.clone();
    let rebuilt = tokio::task::spawn_blocking(move || {
        atomic_lib::search::rebuild_search_index_once(&rebuilder, "kotlin-1")
    })
    .await;
    match rebuilt {
        Ok(Ok(true)) => tracing::info!("search index rebuilt"),
        Ok(Ok(false)) => {}
        Ok(Err(e)) => tracing::warn!("search index rebuild failed: {e}"),
        Err(e) => tracing::warn!("search index rebuild panicked: {e}"),
    }
    while let Ok(done) = atomic_lib::search::index_pending(&store, 500).await {
        if done == 0 {
            break;
        }
    }
}

/// Logging to logcat on Android, to stderr elsewhere. Safe to call twice.
pub(crate) fn init_logging() {
    #[cfg(target_os = "android")]
    {
        use tracing_subscriber::prelude::*;
        let _ = tracing_subscriber::registry()
            .with(tracing_android::layer("atomic").ok())
            .with(tracing_subscriber::filter::EnvFilter::new(
                "info,loro_internal=warn,swarm_discovery=error",
            ))
            .try_init();
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .try_init();
    }
}
