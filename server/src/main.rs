use crate::handlers::home::home;
use crate::handlers::resource::get_resource;
use actix_web::{middleware, web, App, HttpServer};
use std::{io, sync::Mutex};
use env_logger;

mod appstate;
mod errors;
mod handlers;

#[actix_rt::main]
async fn main() -> io::Result<()> {
    // On init, load the store (from disk)

    // Enable all logging
    std::env::set_var("RUST_LOG", "info");
    let endpoint = "127.0.0.1:1597";
    env_logger::init();

    HttpServer::new(|| {
        let appstate = appstate::init();
        let data = web::Data::new(Mutex::new(appstate.clone()));
        App::new()
            .app_data(data.clone())
            .wrap(middleware::Logger::default())
            // .wrap(middleware::Logger::new("%a %{User-Agent}i"))
            .service(actix_files::Files::new("/static", "static/").show_files_listing())
            .service(
                web::scope("/{path}").service(web::resource("").route(web::get().to(get_resource))),
            )
            .service(web::scope("/").service(web::resource("").route(web::get().to(home))))
    })
    .bind(endpoint)?
    .run()
    .await
}
