use atomic::store;
use atomic::store::Store;
use atomic::{errors::AppError, serialize};
use dotenv::dotenv;
use std::env;
use std::{io, path::PathBuf, sync::Mutex};
use actix_web::{
  web, App, HttpResponse, HttpServer, HttpRequest,
};
// Context for the server (not the request)
#[derive(Clone)]
pub struct Context {
    store: Store,
    domain: String,
}

// Creates the server context
fn init() -> Context {
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
    store::read_store_from_file(&mut store, &path_store);

    return Context { store, domain };
}

#[actix_rt::main]
async fn main() -> io::Result<()> {
    // On init, load the store (from disk)

    std::env::set_var("RUST_LOG", "actix_web=info");
    let endpoint = "127.0.0.1:8080";

    println!("Starting server at: {:?}", endpoint);
    HttpServer::new(|| {
        let context = init();
        let data = web::Data::new(Mutex::new(context.clone()));
        App::new()
            .app_data(data.clone())
            .service(web::scope("/{path}").service(
                web::resource("").route(web::get().to(get_resource))
            ))
    })
    .bind(endpoint)?
    .run()
    .await
}

pub async fn get_resource(
    _id: web::Path<String>,
    data: web::Data<Mutex<Context>>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    // Some logging, should be handled properly later.
    println!("{:?}", _id);
    println!("method: {:?}", req.method());
    let context = data.lock().unwrap();
    // This is how locally items are stored (which don't know their full subject URL) in Atomic Data
    let subject = format!("_:{}", _id);
let body = serialize::resource_to_ad3(&subject, &context.store, &context.domain)?;
    Ok(HttpResponse::Ok().body(body))
}
