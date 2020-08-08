use actix_files as fs;
use actix_web::{web, App, HttpServer};
use crate::handlers::resource::get_resource;
use std::{io, sync::Mutex};

mod handlers;
mod errors;
mod log;
mod appstate;

#[actix_rt::main]
async fn main() -> io::Result<()> {
    // On init, load the store (from disk)

    std::env::set_var("RUST_LOG", "actix_web=info");
    let endpoint = "127.0.0.1:8080";

    println!("Starting server at: http://{}", endpoint);
    HttpServer::new(|| {
        let appstate = appstate::init();
        let data = web::Data::new(Mutex::new(appstate.clone()));
        App::new().app_data(data.clone())
        .service(fs::Files::new("static", ".").show_files_listing())
        .service(
            web::scope("/{path}").service(
                web::resource("").route(web::get().to(get_resource))
            ),
        )
    })
    .bind(endpoint)?
    .run()
    .await
}
