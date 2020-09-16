use actix_web::{middleware, web, App, HttpServer};
use std::{io, sync::Mutex};
// use actix_web_middleware_redirect_https::RedirectHTTPS;
mod appstate;
mod config;
mod errors;
mod handlers;
mod helpers;
mod https;
mod content_types;
mod render;

#[actix_rt::main]
async fn main() -> io::Result<()> {
    // Enable all logging
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    let config = config::init();
    let appstate = appstate::init(config.clone()).expect("Failed to build appstate.");

    let server = HttpServer::new(move || {
        let data = web::Data::new(Mutex::new(appstate.clone()));
        App::new()
            .app_data(data)
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            // .wrap(actix_web_middleware_redirect_https::RedirectHTTPS::default())
            .service(actix_files::Files::new("/static", "static/").show_files_listing())
            .service(actix_files::Files::new("/.well-known", "static/well-known/").show_files_listing())
            .service(web::scope("/tpf").service(web::resource("").route(web::get().to(handlers::tpf::tpf))))
            .service(web::scope("/get").service(web::resource("").route(web::get().to(handlers::path::path))))
            .service(web::scope("/{path:[^{}]+}").service(web::resource("").route(web::get().to(handlers::resource::get_resource))))
            .service(web::scope("/").service(web::resource("").route(web::get().to(handlers::home::home))))
    });

    if config.https {
        // If there is no certificate file, start HTTPS initialization
        if std::fs::File::open(&config.cert_path).is_err() {
            https::cert_init_server(&config).await.unwrap();
        }
        let https_config = crate::https::get_https_config(&config)
            .expect("HTTPS TLS Configuration with Let's Encrypt failed.");
        let endpoint = format!("{}:{}", config.ip, config.port_https);
        server.bind_rustls(&endpoint, https_config).expect(&*format!("Cannot bind to endpoint {}", &endpoint))
            .run()
            .await?;
            Ok(())
    } else {
        let endpoint = format!("{}:{}", config.ip, config.port);
        server
            .bind(&format!("{}:{}", config.ip, config.port)).expect(&*format!("Cannot bind to endpoint {}", &endpoint))
            .run()
            .await?;
        Ok(())
    }
}
