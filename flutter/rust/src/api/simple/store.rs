//! Opening, flushing and describing the local store.

use super::*;

/// Local-first Atomic Data SDK for Flutter.
///
/// API groups:
///   1. Database  — open_db()
///   2. Agent     — setup(), load_agent(), get_active_agent(), clear_agent()
///   3. Drive     — create_drive(), list_drives(), get_active_drive(), set_active_drive()
///   4. Resource  — create_resource(), set_property(), get_property()
///   5. History   — warm_resource_history(), get_resource_history()
///   6. Peer      — start_peer(), get_peer_id(), peer_announce(), peer_sync(), peer_discover_sync()
///
/// Networking (group 6) is explicit and opt-in. Nothing in groups 1-5 touches the network.

// ── 1. Database ────────────────────────────────────────────────────────────

/// Open a local database. Call on app start; a second call in the same
/// process (Android runs `main` again when it recreates the activity) keeps
/// the store that is already open.
///
/// Never panics and never deletes the user's data. A store that cannot be
/// opened because the file is damaged is renamed to
/// `atomic.redb.corrupt-<ms>`, a repaired copy (or, failing that, an empty
/// store) takes its place, and `store_recovery` tells the app so it can say
/// so. Other errors (permissions, a full disk) are returned as they are.
pub async fn open_db(path: String) -> Result<(), String> {
    // Set up log filtering — suppress noisy TLS/mDNS/iroh internals
    #[cfg(target_os = "android")]
    {
        use tracing_subscriber::prelude::*;
        let _ = tracing_subscriber::registry()
            .with(tracing_android::layer("atomic").unwrap())
            .with(tracing_subscriber::filter::EnvFilter::new(
                "info,swarm_discovery=error",
            ))
            .try_init();
    }

    #[cfg(not(target_arch = "wasm32"))]
    let _opening = state::OPEN_DB_LOCK.lock().await;
    if db().is_ok() {
        // A second store handle on the same file is what damaged stores on
        // Android (see `atomic_lib::db::recovery`).
        tracing::info!("open_db: the store is already open in this process; keeping it");
        return Ok(());
    }

    let (store, recovery, _fresh) = open_shared(std::path::Path::new(&path)).await?;
    if let Some(recovery) = recovery {
        #[cfg(not(target_arch = "wasm32"))]
        state::set_store_recovery(recovery);
        #[cfg(target_arch = "wasm32")]
        let _ = recovery;
    }

    set_db(store);
    #[cfg(not(target_arch = "wasm32"))]
    {
        state::set_store_dir(std::path::Path::new(&path));
        catch_up_search_index(db()?.clone()).await;
        crate::host::start_recents(std::path::Path::new(&path), db()?.clone());
    }
    Ok(())
}

/// The store at `path`, opened once per process: the `Db` another open of the
/// same file made is shared, never opened again. The caller holds
/// `state::OPEN_DB_LOCK` (not on wasm). The last value says the store was
/// opened by this call (and a damaged one set aside, in the second).
pub(crate) async fn open_shared(
    path: &std::path::Path,
) -> Result<(std::sync::Arc<atomic_lib::Db>, Option<StoreRecovery>, bool), String> {
    #[cfg(not(target_arch = "wasm32"))]
    let key = {
        let _ = std::fs::create_dir_all(path);
        std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    };
    #[cfg(target_arch = "wasm32")]
    let key = std::path::PathBuf::from("opfs:atomic.redb");

    if let Some(open) = state::registered_store(&key) {
        return Ok((open, None, false));
    }

    #[cfg(not(target_arch = "wasm32"))]
    let (store, recovery) = open_native_store(path).await?;
    #[cfg(target_arch = "wasm32")]
    let (store, recovery) = (
        atomic_lib::Db::init_redb_opfs(None, "atomic.redb")
            .await
            .map_err(err)?,
        None,
    );

    let store = std::sync::Arc::new(store);
    state::register_store(key, store.clone());
    Ok((store, recovery, true))
}

/// Set when the last `open_db` had to set a damaged store aside.
#[frb(sync)]
pub fn store_recovery() -> Option<StoreRecovery> {
    state::store_recovery()
}

/// What the host does in the background right now (sync runs, following and
/// catching up on drives, picture downloads, activity lookups and scans,
/// uploads), for a small "busy" mark. Cheap; poll it.
pub struct BackgroundActivity {
    pub total: u32,
    /// Running tasks by kind: `sync`, `drives`, `pictures`, `history`, `scan`,
    /// `upload`.
    pub by_kind: std::collections::HashMap<String, u32>,
    /// The last background failure, cleared by the next success.
    pub last_error: Option<String>,
    /// Unix ms of the last success.
    pub last_ok_ms: Option<i64>,
}

#[frb(sync)]
pub fn background_activity() -> BackgroundActivity {
    let s = atomic_lib::host::activity_status::snapshot();
    BackgroundActivity {
        total: s.total,
        by_kind: s.by_kind.into_iter().collect(),
        last_error: s.last_error,
        last_ok_ms: s.last_ok_ms,
    }
}

/// Make every write so far durable now. The app calls it when it goes to
/// the background, where Android may kill it without warning; the store
/// otherwise makes writes durable on a 100 ms tick.
pub fn flush_db() -> Result<(), String> {
    db()?.flush().map_err(err)
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn open_native_store(
    base_path: &std::path::Path,
) -> Result<(atomic_lib::Db, Option<StoreRecovery>), String> {
    use atomic_lib::db::recovery;
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
                Err(again) => return Err(again),
            };
            let recovery = StoreRecovery {
                kept_path: kept.to_string_lossy().into_owned(),
                reason: e,
                repaired,
            };
            (store, Some(recovery))
        }
        Err(e) => return Err(e),
    };

    let after = recovery::inspect(&db_path).ok().flatten();
    tracing::info!(
        "store self-check: {} opened in {:?}; before {}; now {}; {}",
        db_path.display(),
        started.elapsed(),
        describe_file(before),
        describe_file(after),
        match &recovered {
            None => "no recovery needed".to_string(),
            Some(r) if r.repaired => format!("REPAIRED a damaged store, kept at {}", r.kept_path),
            Some(r) => format!(
                "STARTED EMPTY, the damaged store is kept at {}",
                r.kept_path
            ),
        }
    );
    Ok((store, recovered))
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn describe_file(check: Option<atomic_lib::db::recovery::FileCheck>) -> String {
    match check {
        None => "no store file".into(),
        Some(c) => format!(
            "{} bytes, header describes {}{}{}",
            c.file_len,
            c.layout_len,
            if c.is_short() { " (SHORT)" } else { "" },
            if c.recovery_required {
                ", last run did not close it"
            } else {
                ", closed cleanly"
            }
        ),
    }
}

/// redb's read cache on a phone. Its default (1 GiB) keeps whatever was read,
/// up to the size of the store, in memory (870 MB of RSS after a full walk of
/// a 1 GB store); the lists and the search read little and repeatedly.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) const REDB_CACHE_BYTES: usize = 48 * 1024 * 1024;

/// `Db::init_redb_file` with any panic inside it turned into a "damaged"
/// error: a panic must not escape to the app, which then never draws.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn open_store_catching(base_path: &std::path::Path) -> Result<atomic_lib::Db, String> {
    use futures::FutureExt;
    let uploads_path = base_path.join("uploads");
    let now = state::now_ms();
    let policy = compaction_check::startup_policy(base_path, now);
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
                compaction_check::record_check(base_path, now);
            }
            Ok(store)
        }
        Ok(Err(e)) => Err(err(e)),
        Err(panic) => Err(format!(
            "The {}: panic while opening: {}",
            atomic_lib::db::recovery::DAMAGED_STORE,
            atomic_lib::db::recovery::panic_message(&panic)
        )),
    }
}

/// Make sure every stored resource is searchable. An index written by an older
/// build can lack resources that arrived by sync, and nothing else notices: the
/// library only rebuilds an empty index. Rebuilds once per install (a marker
/// records it, so later starts cost one key read), then drains resources filed
/// for deferred indexing.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn catch_up_search_index(store: std::sync::Arc<atomic_lib::Db>) {
    let rebuilder = store.clone();
    let rebuilt = tokio::task::spawn_blocking(move || {
        atomic_lib::search::rebuild_search_index_once(&rebuilder, "flutter-1")
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

#[frb(init)]
pub fn init_app() {
    // Before any TLS use: rustls panics without a process default when both of
    // its backends are compiled in (they are: ring and aws-lc-rs).
    #[cfg(not(target_family = "wasm"))]
    atomic_lib::client::install_default_crypto_provider();
    // Not `setup_default_user_utils`: that forwards the `log` crate to logcat
    // at Trace (rustls, reqwest and iroh wrote ~800 formatted lines per app
    // start) and sets RUST_BACKTRACE=1, which also makes every `anyhow` error
    // capture and print a stack (iroh makes them in its retry loops). Panics
    // keep their backtrace; library errors do not capture one.
    #[cfg(not(target_family = "wasm"))]
    if std::env::var_os("RUST_LIB_BACKTRACE").is_none() {
        std::env::set_var("RUST_LIB_BACKTRACE", "0");
    }
    flutter_rust_bridge::setup_backtrace();
    flutter_rust_bridge::setup_log_to_console(log::LevelFilter::Warn);

    // Initialize tracing → logcat on Android, stderr elsewhere. Loro logs
    // every encoded block at info.
    #[cfg(target_os = "android")]
    {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
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

/// What this build is, for the "This device" card: `{"version": …, "os": …,
/// "arch": …}` (the library's version and the platform it was built for).
#[frb(sync)]
pub fn device_info() -> String {
    serde_json::json!({
        "version": atomic_lib::VERSION,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
    })
    .to_string()
}

/// How much of the person's data this device holds: `{disk_bytes?, resources,
/// loro_bytes, blob_bytes, drives: [{subject, name, resources, bytes, …}]}`,
/// biggest drive first. Walks the drives' resources, so it runs on the async
/// pool, never the UI thread; the caller caches it.
pub async fn store_stats() -> Result<String, String> {
    let dir = state::store_dir();
    let stats = atomic_lib::host::store_stats::store_stats(db()?, dir.as_deref())
        .await
        .map_err(err)?;
    Ok(stats.to_string())
}
