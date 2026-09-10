//! App state, which is accessible from handlers
use std::sync::Arc;

use crate::{
    commit_monitor::CommitMonitor, config::Config, errors::AtomicServerResult,
    handlers::web_sockets::IndexStatusBroadcast, plugins,
};
use atomic_lib::commit::CommitResponse;

#[cfg(feature = "wasm-plugins")]
use crate::plugins::wasm;

/// The AppState contains all the relevant Context for the server.
/// This data object is available to all handlers and actors.
/// Contains the store, configuration and addresses for Actix Actors, such as for the [CommitMonitor].
/// It is generated using [init], which takes a [Config].
// This struct is cloned across all threads, so make sure the fields are thread safe.
// A good option here is to use Actors for things that can change (e.g. commit_monitor)
#[derive(Clone)]
pub struct AppState {
    /// Contains all the data
    pub store: atomic_lib::Db,
    /// App Configuration
    pub config: Config,
    /// The Actix Address of the CommitMonitor, which should receive updates when a commit is applied
    /// (and also hosts Loro ephemera / drive presence fan-out).
    pub commit_monitor: actix::Addr<CommitMonitor>,
    pub vector_search_state: crate::vector_search::VectorSearchState,
    pub index_status_broadcast: Arc<IndexStatusBroadcast>,
    /// Whether this node is managed (reports to a control plane). Set at runtime
    /// by an embedder hook (see `serve_with_hook`); surfaced via the managed
    /// manifest endpoint. Always false on self-hosted nodes.
    pub managed: Arc<std::sync::atomic::AtomicBool>,
    /// User-facing portal URL for a managed node, populated at runtime by the
    /// embedder's policy poll (empty on self-hosted nodes). Read by the managed
    /// manifest endpoint so the welcome screen can route account creation to the
    /// dashboard.
    pub managed_dashboard_url: Arc<std::sync::RwLock<Option<String>>>,
}

impl AppState {
    /// Shared runtime boundary for native adapters. Clones share this store's
    /// identity, event channels and durable data with the HTTP/WS adapter.
    pub fn node(&self) -> atomic_lib::runtime::AtomicNode {
        atomic_lib::runtime::AtomicNode::from_db(self.store.clone())
    }

    /// Creates the AppState (the server's context available in Handlers).
    /// Initializes or opens a store on disk.
    /// Creates a new agent, if necessary.
    pub async fn init(config: Config) -> AtomicServerResult<AppState> {
        tracing::info!("Initializing AppState");

        // We warn over here because tracing needs to be initialized first.
        if config.opts.slow_mode {
            tracing::warn!("Slow mode is enabled. This will introduce random delays in the server, to simulate a slow connection.");
        }
        if config.opts.development {
            tracing::warn!("Development mode is enabled. This will use staging environments for services like LetsEncrypt.");
        }

        let node = atomic_lib::runtime::AtomicNode::open_local(
            &config.store_path,
            &config.uploads_path,
            Some(config.get_origin()),
        )
        .await?;
        let mut store = node.db().clone();

        // Drop the persisted watched-query registry on startup. Every
        // entry was registered by a now-dead WS connection; live
        // subscribers re-register on reconnect. Without this, e2e
        // suites leak a unique filter per test (drives are unique)
        // and `check_if_atom_matches_watched_query_filters` walks a
        // growing pile of dead filters per commit, eventually pushing
        // rapid-save tests past their timeout. See
        // `Db::clear_watched_queries` for the full rationale.
        if let Err(e) = store.clear_watched_queries() {
            tracing::warn!("clear_watched_queries on startup failed: {e}");
        }

        // Register all built-in class extenders
        store.add_class_extender(plugins::chatroom::build_chatroom_extender())?;
        store.add_class_extender(plugins::chatroom::build_message_extender())?;
        store.add_endpoint(plugins::invite::invite_endpoint())?;
        store.add_class_extender(plugins::plugin::build_plugin_extender(
            config.plugin_path.clone(),
            config.plugin_cache_path.clone(),
            config.uploads_path.clone(),
        ))?;
        store.add_class_extender(plugins::files::build_file_extender(
            config.uploads_path.clone(),
        ))?;

        // Owned here rather than in the AppState literal below, because the
        // `/server` endpoint closes over them to report this node's status.
        let server_info = plugins::server_info::ServerInfo {
            managed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            managed_dashboard_url: Arc::new(std::sync::RwLock::new(None)),
            home_drive: config
                .opts
                .home_drive
                .as_deref()
                .map(str::trim)
                .filter(|d| !d.is_empty())
                .map(str::to_string),
            host_mode: config.host_mode.clone(),
        };

        // Register all built-in endpoints
        store.add_endpoint(plugins::server_info::server_info_endpoint(
            server_info.clone(),
        ))?;
        store.add_endpoint(plugins::versioning::version_endpoint())?;
        store.add_endpoint(plugins::versioning::all_versions_endpoint())?;
        store.add_endpoint(plugins::did::did_endpoint())?;
        store.add_endpoint(plugins::bind_drive::bind_drive_endpoint())?;
        store.add_endpoint(plugins::bookmark::bookmark_endpoint())?;
        store.add_endpoint(plugins::replicate::replicate_drive_endpoint())?;
        store.add_endpoint(plugins::files::upload_endpoint())?;
        store.add_endpoint(plugins::files::download_endpoint())?;
        store.add_endpoint(plugins::export::export_endpoint())?;
        store.add_endpoint(plugins::path::path_endpoint())?;
        store.add_endpoint(plugins::importer::import_endpoint())?;
        #[cfg(debug_assertions)]
        store.add_endpoint(plugins::prunetests::prune_tests_endpoint())?;
        store.add_endpoint(plugins::query::query_endpoint())?;
        store.add_endpoint(plugins::search::search_endpoint())?;
        #[cfg(feature = "vector-search")]
        store.add_endpoint(plugins::vector_search::vector_search_endpoint())?;

        // Get and register Wasm class extender plugins
        #[cfg(feature = "wasm-plugins")]
        {
            let extenders = wasm::load_wasm_class_extenders(
                &config.plugin_path,
                &config.plugin_cache_path,
                &store,
            )
            .await?;

            for extender in extenders {
                store.add_class_extender(extender)?;
            }
        }

        atomic_lib::runtime::AtomicNode::from_db(store.clone())
            .load_or_create_agent(&config.config_file_path, "server")
            .await?;

        let should_init = !&config.store_path.exists() || config.initialize;
        // If the store is empty, populate the core models (classes, properties, etc.).
        // We don't create a Drive here anymore; that's handled in the data-browser (new identity flow).
        if should_init {
            tracing::info!("Initialize: bootstrapping core models...");
            atomic_lib::populate::bootstrap(&store)
                .await
                .map_err(|e| format!("Failed to bootstrap store. {}", e))?;
        } else if config.repopulate_defaults {
            // Forced re-seed of the built-in base models + `lib/defaults/*.json`
            // into an already-seeded store, ignoring the defaults fingerprint.
            // Normally unnecessary: `Db` open (`bootstrap`) already re-seeds
            // whenever the embedded defaults changed since the store was last
            // seeded. Add-only either way — existing values are never
            // overwritten. Triggered by `ATOMIC_REPOPULATE_DEFAULTS=true`.
            tracing::info!("Repopulating built-in ontologies and default resources...");
            atomic_lib::populate::repopulate_defaults(&store)
                .await
                .map_err(|e| format!("Failed to repopulate defaults. {}", e))?;
        }

        // Who may put a *new* Drive here. Installed after populate so the scan
        // below sees every Drive already on disk, and before anything binds so
        // no request can slip in under the default open policy.
        crate::host_mode::install_policy(&store, &config.host_mode).await;

        match atomic_lib::envelopes::EnvelopeRetention::parse(&config.opts.envelope_retention) {
            Some(retention) => store.set_envelope_retention(retention),
            None => {
                return Err(format!(
                    "ATOMIC_ENVELOPE_RETENTION must be `latest` or `all`, got `{}`",
                    config.opts.envelope_retention
                )
                .into())
            }
        }

        let index_status_broadcast = Arc::new(IndexStatusBroadcast::new());
        let index_notifier: Arc<dyn Fn(&str, bool) + Send + Sync> = {
            let b = index_status_broadcast.clone();
            Arc::new(move |drive: &str, indexing: bool| {
                b.notify(drive, indexing);
            })
        };

        let vector_search_state =
            crate::vector_search::VectorSearchState::new(&config, Some(index_notifier))
                .await
                .map_err(|e| format!("Failed to start vector search service: {}", e))?;

        // Initialize commit monitor, which watches commits and sends these to the commit_monitor actor
        let commit_monitor = crate::commit_monitor::create_commit_monitor(
            store.clone(),
            vector_search_state.clone(),
        );

        let commit_monitor_clone = commit_monitor.clone();

        // This closure is called every time a Commit is created
        let send_commit = move |commit_response: &CommitResponse| {
            commit_monitor_clone.do_send(crate::actor_messages::CommitMessage {
                commit_response: commit_response.clone(),
            });
        };
        store.set_handle_commit(Box::new(send_commit));

        if should_init && vector_search_state.is_enabled() {
            tracing::info!("Adding all resources to vector search index");
            if let Err(e) = vector_search_state.add_all_resources(&store).await {
                tracing::error!("Failed to add all resources to vector search index: {}", e);
            }
        }
        Ok(AppState {
            store,
            config,
            commit_monitor,
            vector_search_state,
            index_status_broadcast,
            managed: server_info.managed,
            managed_dashboard_url: server_info.managed_dashboard_url,
        })
    }

    /// Is called when AppState goes out of scope (e.g. when the application closes)
    /// Cleanup code, writing buffers, committing changes, etc.
    fn exit(&self) -> AtomicServerResult<()> {
        // `flush_pending` is async; sync teardown (`exit`) runs outside/normal teardown contexts where we cannot safely call `Handle::block_on()`
        // — nesting Tokio block-on triggers panic ("cannot block_on runtime inside runtime").
        let vs = self.vector_search_state.clone();
        match std::thread::spawn(move || -> AtomicServerResult<()> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| {
                    format!(
                        "failed to build shutdown tokio runtime for vector flush: {}",
                        e
                    )
                })?;
            rt.block_on(vs.flush_pending())
        })
        .join()
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_panic) => Err("vector index flush thread panicked on shutdown".into()),
        }
    }
}

impl Drop for AppState {
    fn drop(&mut self) {
        if let Err(e) = self.exit() {
            tracing::error!("Error during AppState exit: {}", e);
        }
    }
}
