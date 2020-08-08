use actix_files as fs;
use actix_web::{web, App, HttpServer};
use atomic_lib::store;
use atomic_lib::store::Store;
use crate::handlers::resource::get_resource;
use dotenv::dotenv;
use std::{io, path::PathBuf, sync::Mutex};
use std::env;
use tera::Tera;

mod handlers;
mod errors;
mod log;

// Context for the server (not the request)
#[derive(Clone)]
pub struct AppState {
    store: Store,
    // Where the app is hosted (defaults to http://localhost:8080/)
    domain: String,
    tera: Tera,
}

// Creates the server context
fn init() -> AppState {
    dotenv().ok();
    let mut opt_path_store = None;
    let mut opt_domain = None;
    for (key, value) in env::vars() {
        match &*key {
            "ATOMIC_STORE_PATH" => {
                opt_path_store = Some(value);
            }
            "ATOMIC_DOMAIN" => {
                opt_domain = Some(value);
            }
            _ => {}
        }
    }
    let path_store = PathBuf::from(opt_path_store.expect("No ATOMIC_STORE_PATH env found"));
    let domain = opt_domain.expect("No ATOMIC_DOMAIN env found");
    let mut store = store::init();
    store::read_store_from_file(&mut store, &path_store).expect("Cannot read store");

    let tera = match Tera::new("src/templates/*.html") {
        Ok(t) => t,
        Err(e) => {
            println!("Parsing error(s): {}", e);
            ::std::process::exit(1);
        }
    };

    return AppState {
        store,
        domain,
        tera,
    };
}

#[actix_rt::main]
async fn main() -> io::Result<()> {
    // On init, load the store (from disk)

    std::env::set_var("RUST_LOG", "actix_web=info");
    let endpoint = "127.0.0.1:8080";

    println!("Starting server at: http://{}", endpoint);
    HttpServer::new(|| {
        let appstate = init();
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
