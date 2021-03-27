use actix_cors::Cors;
use actix_web::{middleware, web, App, HttpServer};
use std::{io, sync::Mutex};
mod appstate;
mod config;
mod content_types;
mod errors;
mod handlers;
mod helpers;
mod https;
mod jsonerrors;
mod render;
mod routes;
#[cfg(feature = "desktop")]
mod tray_icon;
mod views;

#[actix_rt::main]
async fn main() -> io::Result<()> {
    // Enable all logging
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    const VERSION: &str = env!("CARGO_PKG_VERSION");
    log::info!("Atomic-server {}. Visit https://atomicdata.dev and https://github.com/joepio/atomic for more information.", VERSION);

    // Read .env vars, https certs
    let config = config::init().expect("Error setting config");
    // Initialize DB and HTML templating engine
    let appstate = match appstate::init(config.clone()) {
        Ok(state) => state,
        Err(e) => {
            panic!("Error during appstate setup. {}", e)
        }
    };

    let server = HttpServer::new(move || {
        let data = web::Data::new(Mutex::new(appstate.clone()));
        // Allow requests from other domains
        let cors = Cors::permissive();

        App::new()
            .app_data(data)
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .configure(routes::config_routes)
            .app_data(
                web::JsonConfig::default()
                    // register error_handler for JSON extractors.
                    .error_handler(jsonerrors::json_error_handler),
            )
    });

    #[cfg(feature = "desktop")]
    tray_icon::tray_icon_process(config.clone());

    if config.https {
        // If there is no certificate file, or the certs are too old, start HTTPS initialization
        if std::fs::File::open(&config.cert_path).is_err() || crate::https::check_expiration_certs()
        {
            https::cert_init_server(&config).await.unwrap();
        }
        let https_config = crate::https::get_https_config(&config)
            .expect("HTTPS TLS Configuration with Let's Encrypt failed.");
        let endpoint = format!("{}:{}", config.ip, config.port_https);
        server
            .bind_rustls(&endpoint, https_config)
            .expect(&*format!("Cannot bind to endpoint {}", &endpoint))
            .run()
            .await?;
        Ok(())
    } else {
        let endpoint = format!("{}:{}", config.ip, config.port);
        server
            .bind(&format!("{}:{}", config.ip, config.port))
            .expect(&*format!("Cannot bind to endpoint {}", &endpoint))
            .run()
            .await?;
        Ok(())
    }
}
