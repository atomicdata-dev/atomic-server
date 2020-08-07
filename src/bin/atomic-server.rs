use actix_web::{web, App, http, HttpRequest, HttpResponse, HttpServer};
use atomic::store;
use atomic::store::{Store, Property};
use atomic::{errors::BetterResult, serialize};
use dotenv::dotenv;
use std::env;
use std::{io, path::PathBuf, sync::Mutex};
use tera::{Context as TeraCtx, Tera};
use std::path::Path;
use serde::Serialize;

// Context for the server (not the request)
#[derive(Clone)]
pub struct Context {
    store: Store,
    // Where the app is hosted (defaults to http://localhost:8080/)
    domain: String,
    tera: Tera,
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

    let tera = match Tera::new("src/templates/*.html") {
        Ok(t) => t,
        Err(e) => {
            println!("Parsing error(s): {}", e);
            ::std::process::exit(1);
        }
    };

    return Context {
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

    println!("Starting server at: {:?}", endpoint);
    HttpServer::new(|| {
        let context = init();
        let data = web::Data::new(Mutex::new(context.clone()));
        App::new().app_data(data.clone()).service(
            web::scope("/{path}").service(web::resource("").route(web::get().to(get_resource))),
        )
    })
    .bind(endpoint)?
    .run()
    .await
}
enum ContentType {
    JSON,
    HTML,
    AD3,
}

pub async fn get_resource(
    _id: web::Path<String>,
    data: web::Data<Mutex<Context>>,
    req: HttpRequest,
) -> BetterResult<HttpResponse> {
    let path = Path::new(_id.as_str());
    let id = path.file_stem().unwrap().to_str().unwrap();
    let content_type: ContentType = match path.extension() {
        Some(extension) => {
            match extension.to_str().unwrap() {
            "ad3" => ContentType::AD3,
            "json" => ContentType::JSON,
            "html" => ContentType::HTML,
            _ => ContentType::HTML,
            }
        }
        None => ContentType::HTML,
    } ;
    // Some logging, should be handled properly later.
    println!("{:?}", id);
    println!("method: {:?}", req.method());
    let context = data.lock().unwrap();
    // This is how locally items are stored (which don't know their full subject URL) in Atomic Data
    let subject = format!("_:{}", id);
    let mut builder = HttpResponse::Ok();
    match content_type {
        ContentType::JSON => {
            builder.set(
                http::header::ContentType::json()
            );
            let body = serialize::resource_to_json(&subject, &context.store, 1)?;
            Ok(builder.body(body))
        }
        ContentType::HTML => {
            builder.set(
                http::header::ContentType::html()
            );
            let mut tera_context = TeraCtx::new();
            let resource = context.store.get(&subject).unwrap();
            let mut propvals: Vec<PropVal> = Vec::new();

            #[derive(Serialize)]
            struct PropVal {
                property: Property,
                value: String,
            }
            for (property, value) in resource.iter() {
                let fullprop =  store::get_property(property, &context.store)?;
                let propval = PropVal {
                    property: fullprop,
                    value: value.into(),
                };
                println!("{:?}", propval.property.shortname);
                propvals.push(propval);
            }
            tera_context.insert("resource", &propvals);
            let body = context
                .tera
                .render("resource.html", &tera_context)
                .unwrap();
            Ok(builder.body(body))
        }
        ContentType::AD3 => {
            builder.set(
                http::header::ContentType::html()
            );
            let body = serialize::resource_to_ad3(&subject, &context.store, Some(&context.domain))?;
            Ok(builder.body(body))
        }
    }
}
