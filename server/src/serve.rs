use actix_cors::Cors;
use actix_web::{middleware, web, HttpServer};
use atomic_lib::Storelike;

use crate::errors::AtomicServerResult;

fn rebuild_index(appstate: &crate::appstate::AppState) -> AtomicServerResult<()> {
    let appstate_clone = appstate.clone();

    actix_web::rt::spawn(async move {
        tracing::warn!("Building value index... This could take a while, expect worse performance until 'Building value index finished'");
        appstate_clone
            .store
            .clear_index()
            .expect("Failed to clear value index");
        appstate_clone
            .store
            .build_index(true)
            .expect("Failed to build value index");
        tracing::info!("Building value index finished!");
    });
    tracing::info!("Removing existing search index...");
    appstate_clone
        .search_state
        .writer
        .write()
        .expect("Could not get a lock on search writer")
        .delete_all_documents()?;
    tracing::info!("Building search index...");
    crate::search::add_all_resources(&appstate_clone.search_state, &appstate.store)?;
    tracing::info!("Search index finished!");
    Ok(())
}

/// Start the server
pub async fn serve(config: crate::config::Config) -> AtomicServerResult<()> {
    println!("Atomic-server {} \nUse --help for instructions. Visit https://docs.atomicdata.dev and https://github.com/joepio/atomic-data-rust for more info.", env!("CARGO_PKG_VERSION"));
    let tracing_chrome_flush_guard = crate::trace::init_tracing(&config);

    // Setup the database and more
    let appstate = crate::appstate::init(config.clone())?;

    // Start async processes
    if config.opts.rebuild_index {
        rebuild_index(&appstate)?;
    }

    let server = HttpServer::new(move || {
        let cors = Cors::permissive();

        actix_web::App::new()
            .app_data(web::Data::new(appstate.clone()))
            .wrap(cors)
            .wrap(tracing_actix_web::TracingLogger::default())
            .wrap(middleware::Compress::default())
            // Here are the actual handlers / endpoints
            .configure(|app| crate::routes::config_routes(app, &appstate.config))
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

    let message = format!("{}\n\nVisit {}\n\n", BANNER, config.server_url);

    if config.opts.https {
        if cfg!(feature = "https") {
            #[cfg(feature = "https")]
            {
                // If there is no certificate file, or the certs are too old, start HTTPS initialization
                if crate::https::should_renew_certs_check(&config) {
                    crate::https::cert_init_server(&config).await?;
                }
                let https_config = crate::https::get_https_config(&config)
                    .expect("HTTPS TLS Configuration with Let's Encrypt failed.");
                let endpoint = format!("{}:{}", config.opts.ip, config.opts.port_https);
                tracing::info!("Binding HTTPS server to endpoint {}", endpoint);
                println!("{}", message);
                server
                    .bind_rustls(&endpoint, https_config)
                    .expect(&*format!("Cannot bind to endpoint {}", &endpoint))
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
            .expect(&*format!("Cannot bind to endpoint {}", &endpoint))
            .shutdown_timeout(TIMEOUT)
            .run()
            .await?;
    }
    tracing::info!("Cleaning up");

    // Cleanup, runs when server is stopped
    if let Some(guard) = tracing_chrome_flush_guard {
        guard.flush()
    }

    if cfg!(feature = "process-management") {
        #[cfg(feature = "process-management")]
        {
            crate::process::remove_pid(&config)?;
        }
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
