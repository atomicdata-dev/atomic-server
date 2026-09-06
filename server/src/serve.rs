use actix_cors::Cors;
use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    middleware, web, Error, HttpServer,
};
use atomic_lib::Storelike;
use tracing_actix_web::{DefaultRootSpanBuilder, RootSpanBuilder};

/// Custom span builder: uses "{method} {path}" when no route pattern is matched
/// (e.g. static files), so spans are legible in SigNoz instead of just "GET".
struct AtomicRootSpanBuilder;

impl RootSpanBuilder for AtomicRootSpanBuilder {
    fn on_request_start(request: &ServiceRequest) -> tracing::Span {
        if request.match_pattern().is_none() {
            let name = format!("{} {}", request.method(), request.path());
            return tracing::info_span!("HTTP request", "otel.name" = name, "http.method" = %request.method(), "http.target" = %request.path());
        }
        DefaultRootSpanBuilder::on_request_start(request)
    }

    fn on_request_end<B: MessageBody>(
        span: tracing::Span,
        outcome: &Result<ServiceResponse<B>, Error>,
    ) {
        DefaultRootSpanBuilder::on_request_end(span, outcome);
    }
}

use crate::errors::AtomicServerResult;

/// Clears and rebuilds the Store & Search indexes
async fn rebuild_indexes(
    appstate: &crate::appstate::AppState,
    mode: &crate::config::RebuildIndexMode,
) -> AtomicServerResult<()> {
    if matches!(
        mode,
        crate::config::RebuildIndexMode::All | crate::config::RebuildIndexMode::Atoms
    ) {
        let appstate_clone = appstate.clone();

        actix_web::rt::spawn(async move {
            appstate_clone
                .store
                .clear_index()
                .expect("Failed to clear value index");
            appstate_clone
                .store
                .build_index(true)
                .expect("Failed to build value index");
        });
    }

    if matches!(
        mode,
        crate::config::RebuildIndexMode::All | crate::config::RebuildIndexMode::Search
    ) {
        tracing::info!("Rebuilding full-text search index...");
        atomic_lib::search::build_search_index(&appstate.store)?;
    }

    if matches!(
        mode,
        crate::config::RebuildIndexMode::All | crate::config::RebuildIndexMode::Vector
    ) {
        #[cfg(not(feature = "vector-search"))]
        tracing::warn!(
            "Vector index rebuild requested but this build was compiled without the vector-search feature"
        );
        #[cfg(feature = "vector-search")]
        if appstate.vector_search_state.is_enabled() {
            tracing::info!("Removing existing vector search index...");
            // vector search index was already wiped in VectorSearchState::new if rebuild_indexes was passed

            appstate
                .vector_search_state
                .add_all_resources(&appstate.store)
                .await?;
        } else {
            tracing::warn!(
                "Vector index rebuild requested but vector search is disabled; pass --enable-vector-index too"
            );
        }
    }

    Ok(())
}

/// Removes all remote resources from the store.
async fn clear_remote_cache(appstate: &crate::appstate::AppState) -> AtomicServerResult<()> {
    tracing::info!("Removing remote resources...");
    let mut count = 0;
    let mut subjects_to_remove = Vec::new();
    for resource in appstate.store.all_resources(true) {
        let subject = resource.get_subject();
        if matches!(subject, atomic_lib::Subject::External(_)) {
            subjects_to_remove.push(subject.clone());
        }
    }

    for subject in subjects_to_remove {
        appstate.store.remove_resource(&subject).await?;
        let _ = appstate
            .vector_search_state
            .remove_resource(subject.as_str())
            .await;
        count += 1;
    }

    tracing::info!("Successfully removed {} remote resources.", count);
    Ok(())
}

/// Marker in the description of dev-drives (see
/// `browser/data-browser/src/hooks/useDevDrive.ts` /
/// `server/src/plugins/prunetests.rs`). Skipped during Pkarr announcement to
/// avoid broadcasting throwaway test drives to the DHT.
const DEV_DRIVE_MARKER: &str = "[atomic-data:dev-drive]";

/// Publish this server's Iroh NodeID to the pkarr DHT, one record per drive
/// it hosts. Pkarr keys the record by a keypair derived from the drive's DID
/// (see `atomic_lib::discovery::publish_node_id`), so clients resolving a
/// `?drive=did:ad:...` hint can find the node(s) hosting that specific drive.
///
/// Dev-drives are skipped (they accumulate by the hundreds during
/// development and publishing each is pure noise).
async fn announce_drives_pkarr(
    appstate: &crate::appstate::AppState,
    node_id: &str,
) -> Result<(), String> {
    use atomic_lib::Storelike;

    let mut published = 0;
    let mut skipped_dev = 0;
    for resource in appstate.store.all_resources(false) {
        if let Ok(classes_val) = resource.get(atomic_lib::urls::IS_A) {
            if let Ok(classes) = classes_val.to_subjects(None) {
                if !classes.contains(&atomic_lib::urls::DRIVE.to_string()) {
                    continue;
                }
            } else {
                continue;
            }
        } else {
            continue;
        }

        let is_dev = match resource.get(atomic_lib::urls::DESCRIPTION) {
            Ok(v) => v.to_string().contains(DEV_DRIVE_MARKER),
            Err(_) => false,
        };
        if is_dev {
            skipped_dev += 1;
            continue;
        }

        let drive_did = resource.get_subject().as_str();
        // Drives have did:ad:{genesis} subjects. The publish_node_id derivation
        // assumes exactly that shape — bail early for any other kind of drive
        // resource rather than producing a bad pkarr keypair.
        if !drive_did.starts_with("did:ad:")
            || drive_did.starts_with("did:ad:agent:")
            || drive_did.starts_with("did:ad:commit:")
        {
            continue;
        }

        match atomic_lib::discovery::publish_node_id(drive_did, node_id).await {
            Ok(_) => published += 1,
            Err(e) => tracing::warn!("Pkarr: failed for drive {drive_did}: {e}"),
        }
    }
    tracing::info!(
        "Pkarr: announced {} drives ({} dev-drives skipped)",
        published,
        skipped_dev
    );
    Ok(())
}

// Increase the maximum payload size (for POSTing a body, for example) to 50MB
const PAYLOAD_MAX: usize = 50_242_880;
const SERVER_VERSION_HEADER: &str = "X-Atomic-Server-Version";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Start the server
pub async fn serve(config: crate::config::Config) -> AtomicServerResult<()> {
    serve_with_hook(config, |_appstate| {}).await
}

/// Like [`serve`], but invokes `on_ready(&AppState)` once the store, indexes and
/// transports are up but before the HTTP server begins accepting connections.
/// Embedders (e.g. a managed-node wrapper) use this to install a sync policy and
/// spawn background tasks without forking the server. Self-hosted use goes
/// through [`serve`] with a no-op hook.
pub async fn serve_with_hook<F>(
    config: crate::config::Config,
    on_ready: F,
) -> AtomicServerResult<()>
where
    F: FnOnce(&crate::appstate::AppState),
{
    println!(
        "Atomic-server {} \nUse --help for instructions. Visit https://docs.atomicdata.dev and https://github.com/atomicdata-dev/atomic-server for more info.",
        env!("CARGO_PKG_VERSION")
    );

    // rustls 0.23 will not choose a CryptoProvider for itself when more than
    // one is compiled in, and both `ring` and `aws-lc-rs` reach us through the
    // dependency graph regardless of our own features. Without an explicit
    // choice, the first rustls call panics -- and the first rustls call is the
    // ACME path, so a server whose certificates have expired does not fail to
    // renew, it fails to BOOT. Staging died exactly this way (status 101 on
    // every restart until systemd gave up).
    //
    // Installed here rather than in bin.rs because the desktop app and the
    // managed-node wrapper embed this function instead of going through main().
    // Ignoring the error is intentional: it only reports that a provider was
    // already installed, which is the outcome we want anyway.
    #[cfg(feature = "rustls")]
    {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    // Sentry first, so the tracing layer below has a client to report to.
    // The guard is held until the end of this function; dropping it flushes.
    let _sentry_guard = crate::trace::init_sentry(&config);
    let tracing_chrome_flush_guard = crate::trace::init_tracing(&config);

    // Setup the database and more
    let appstate = crate::appstate::AppState::init(config.clone()).await?;

    // Start async processes
    if let Some(ref mode) = config.opts.rebuild_indexes {
        rebuild_indexes(&appstate, mode).await?;
    }
    if config.opts.clear_remote_cache {
        clear_remote_cache(&appstate).await?;
    }

    // Persist a configured device name so peers see something friendly in
    // their `HELLO` frames. Mirrors what the flutter app sets via its UI —
    // same DB key, same accessor — but driven from CLI/env so server
    // operators don't need a separate tool to brand a node.
    if let Some(name) = config
        .opts
        .device_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        atomic_lib::sync::peer::set_device_name(&appstate.store, name);
    }

    // Presence arriving from peers → the local websocket clients.
    //
    // Deliberately its own channel rather than `db_events`: presence must never
    // be written, and every consumer of a DbEvent writes or indexes. Cursor
    // positions merged into the CRDT would persist and sync forever.
    //
    // `addr: None` marks the update as relayed, which is what stops the
    // broadcaster sending it straight back out to peers — presence arrives at
    // cursor frequency, so an echo here would saturate the link far faster than
    // resource changes could.
    {
        let store = appstate.store.clone();
        let broadcaster = appstate.commit_monitor.clone();
        let mut rx = store.subscribe_ephemeral();
        actix_web::rt::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let subject = atomic_lib::Subject::from_raw(
                            &event.drive,
                            store.get_base_domain().as_deref(),
                        );
                        let agent = event.agent;
                        let update = event.payload;

                        // Each channel fans out to a different subscriber set,
                        // so a relayed frame has to re-enter through the same
                        // one it left by.
                        match event.kind {
                            atomic_lib::sync::protocol::ephemeral_kind::PRESENCE => {
                                broadcaster.do_send(crate::actor_messages::RemotePresenceUpdate {
                                    subject,
                                    agent,
                                    update,
                                });
                            }
                            atomic_lib::sync::protocol::ephemeral_kind::DOC => {
                                broadcaster.do_send(crate::actor_messages::LoroSyncUpdate {
                                    subject,
                                    agent,
                                    update,
                                    addr: None,
                                });
                            }
                            _ => {
                                broadcaster.do_send(crate::actor_messages::LoroEphemeralUpdate {
                                    subject,
                                    agent,
                                    update,
                                    addr: None,
                                });
                            }
                        }
                    }
                    // Presence is the first thing worth dropping under load, so
                    // lagging is expected and not an error: skip what was
                    // missed and carry on with the current cursors.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::debug!("[presence] dropped {n} frames under load");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    // Durable-flush tick. Per-commit writes use Durability::None (no fsync)
    // for throughput; this background flush makes them durable on a fixed
    // cadence (100ms), bounding crash data-loss to the interval while
    // amortizing a single fsync across every commit in the window. Runs on a
    // dedicated OS thread because the flush blocks on fsync, which would stall
    // a tokio worker.
    {
        let store = appstate.store.clone();
        std::thread::Builder::new()
            .name("durable-flush".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if let Err(e) = store.flush() {
                    tracing::warn!("periodic durable flush failed: {e}");
                }
            })
            .expect("spawn durable-flush thread");
    }

    // Start Iroh peer-to-peer transport
    let _iroh_router = {
        let store = appstate.store.clone();
        match crate::iroh_transport::start(store.clone()).await {
            Ok((node_id, router)) => {
                tracing::info!(
                    "Iroh transport ready as \"{}\". Connect with: did:ad:node:{node_id}",
                    atomic_lib::sync::peer::effective_device_name(&store)
                );

                // Announce this server's NodeID via pkarr relay, one record per
                // drive (see `announce_drives_pkarr`).
                let appstate_clone = appstate.clone();
                actix_web::rt::spawn(async move {
                    if let Err(e) =
                        announce_drives_pkarr(&appstate_clone, &node_id.to_string()).await
                    {
                        tracing::warn!("Pkarr announcement failed: {e}");
                    }
                });

                Some(router)
            }
            Err(e) => {
                tracing::warn!("Failed to start Iroh transport: {e}");
                None
            }
        }
    };

    // Catch up any drive the user asked us to replicate elsewhere. A target is
    // standing config, not a one-shot command, so anything committed while the
    // remote was unreachable is pushed now. This only ever contacts servers the
    // user explicitly named — a store with no targets does nothing at all, so it
    // is not a phone-home.
    let replication_store = appstate.store.clone();
    actix_web::rt::spawn(async move {
        crate::plugins::replicate::reconcile_replication_targets(&replication_store).await;
    });

    // Embedder hook: the store, indexes and transports are up, but the HTTP
    // server hasn't started accepting connections yet. A managed-node wrapper
    // (atomic-saas/managed-node) uses this to flip the `managed` flag, install
    // its sync admission policy, and spawn its control-plane tasks. The open
    // server passes a no-op (see `serve`), so it never phones home.
    on_ready(&appstate);

    let server = HttpServer::new(move || {
        let cors = Cors::permissive().expose_headers([SERVER_VERSION_HEADER]);

        actix_web::App::new()
            .app_data(web::PayloadConfig::new(PAYLOAD_MAX))
            .app_data(web::Data::new(appstate.clone()))
            .wrap(cors)
            // Attaches the request (method, url, headers) to any Sentry event
            // raised while handling it, and reports handler panics and 5xx
            // errors. No-op without a bound Sentry client.
            .wrap(sentry_actix::Sentry::new())
            .wrap(middleware::DefaultHeaders::new().add((SERVER_VERSION_HEADER, SERVER_VERSION)))
            .wrap(tracing_actix_web::TracingLogger::<AtomicRootSpanBuilder>::new())
            .wrap(middleware::Compress::default())
            // Here are the actual handlers / endpoints
            .configure(crate::routes::config_routes)
            .default_service(web::to(|| {
                tracing::error!("Wrong route, should not happen with normal requests");
                actix_web::HttpResponse::NotFound()
            }))
            .app_data(
                web::JsonConfig::default()
                    // register error_handler for JSON extractors.
                    .error_handler(crate::jsonerrors::json_error_handler),
            )
    });

    let protocol = if config.opts.https { "https" } else { "http" };
    let port = if config.opts.https {
        config.opts.port_https
    } else {
        config.opts.port
    };
    let mut message = format!(
        "{}\n\nVisit {}://{}:{}\n",
        BANNER, protocol, config.opts.domain, port
    );

    if config.opts.ip.is_unspecified() {
        message.push_str("\nAlso available on your local network at:\n");
        if let Ok(network_interfaces) = local_ip_address::list_afinet_netifas() {
            for (name, ip) in network_interfaces.iter() {
                if ip.is_ipv4() && !ip.is_loopback() {
                    message.push_str(&format!("- {}://{}:{} ({})\n", protocol, ip, port, name));
                }
            }
        }
        message.push('\n');
    } else {
        message.push('\n');
    }

    // Always say which it is. A node that silently changed who may write to it
    // would be worse than one that never gated at all.
    match config.host_mode.mode {
        crate::host_mode::HostMode::Owner => {
            message.push_str(&format!(
                "Only its owner can create new Drives here ({}).\n\n",
                config
                    .host_mode
                    .owner_agent
                    .as_deref()
                    .unwrap_or("no owner set")
            ));
        }
        crate::host_mode::HostMode::Open => {
            let reachability = config.reachability();

            if reachability.looks_exposed() && config.opts.host_mode.is_none() {
                let warning = crate::host_mode::exposure_warning(reachability);
                // Both, deliberately: the banner is what someone watching the
                // terminal sees, and the `warn!` is what survives into
                // journalctl for someone reading back later.
                tracing::warn!("{}", warning);
                message.push_str(&format!("{}\n\n", warning));
            } else {
                message.push_str("Anyone who can reach this node can create a Drive on it.\n\n");
            }
        }
    }

    if config.opts.https {
        if cfg!(feature = "https") {
            #[cfg(feature = "https")]
            {
                // If there is no certificate file, or the certs are too old, start HTTPS initialization
                {
                    if crate::https::should_renew_certs_check(&config)? {
                        crate::https::request_cert(&config).await?;
                    }
                }
                let https_config = crate::https::get_https_config(&config)
                    .expect("HTTPS TLS Configuration with Let's Encrypt failed.");
                let endpoint = format!("{}:{}", config.opts.ip, config.opts.port_https);
                tracing::info!("Binding HTTPS server to endpoint {}", endpoint);
                println!("{}", message);
                server
                    .bind_rustls_0_23(&endpoint, https_config)
                    .map_err(|e| format!("Cannot bind to endpoint {}: {}", &endpoint, e))?
                    .shutdown_timeout(TIMEOUT)
                    .run()
                    .await?;
            }
        } else {
            return Err("The HTTPS feature has been disabled for this build. Please compile atomic-server with the HTTP feature. `cargo install atomic-server`".into());
        }
    } else {
        let endpoint = format!("{}:{}", config.opts.ip, config.opts.port);
        tracing::info!("Binding HTTP server to endpoint {}", endpoint);
        println!("{}", message);
        server
            .bind(&format!("{}:{}", config.opts.ip, config.opts.port))
            .map_err(|e| format!("Cannot bind to endpoint {}: {}", &endpoint, e))?
            .shutdown_timeout(TIMEOUT)
            .run()
            .await?;
    }

    tracing::info!("Cleaning up");
    // Cleanup, runs when server is stopped
    // Note that more cleanup code is in Appstate::exit
    if let Some(guard) = tracing_chrome_flush_guard {
        guard.flush()
    }

    tracing::info!("Server stopped");
    Ok(())
}

/// Amount of seconds before server shuts down connections after SIGTERM signal
const TIMEOUT: u64 = 15;

const BANNER: &str = r#"
         __                  _
  ____ _/ /_____  ____ ___  (_)____      ________  ______   _____  _____
 / __ `/ __/ __ \/ __ `__ \/ / ___/_____/ ___/ _ \/ ___/ | / / _ \/ ___/
/ /_/ / /_/ /_/ / / / / / / / /__/_____(__  )  __/ /   | |/ /  __/ /
\__,_/\__/\____/_/ /_/ /_/_/\___/     /____/\___/_/    |___/\___/_/
"#;
