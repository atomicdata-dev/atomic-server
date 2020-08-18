use actix_web::{middleware, web, App, HttpServer};
use std::{io, sync::Mutex};
use env_logger;

mod appstate;
mod config;
mod errors;
mod handlers;
mod content_types;

#[actix_rt::main]
async fn main() -> io::Result<()> {
    // On init, load the store (from disk)

    // Enable all logging
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    let config = config::init();
    let endpoint = format!("{}:{}", config.ip, config.port);
    let appstate = appstate::init(config.clone());

    HttpServer::new(move || {
        let data = web::Data::new(Mutex::new(appstate.clone()));
        App::new()
            .app_data(data.clone())
            .wrap(middleware::Logger::default())
            .service(actix_files::Files::new("/static", "static/").show_files_listing())
            .service(web::scope("/tpf").service(web::resource("").route(web::get().to(handlers::tpf::tpf))))
            .service(web::scope("/{path}").service(web::resource("").route(web::get().to(handlers::resource::get_resource))))
            .service(web::scope("/").service(web::resource("").route(web::get().to(handlers::home::home))))
    })
    .bind(&endpoint).expect(&*format!("Cannot bind to endpoint {}", &endpoint))
    .run()
    .await
}
