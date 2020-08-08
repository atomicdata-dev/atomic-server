use atomic_lib::store::Store;
use dotenv::dotenv;
use std::env;
use tera::Tera;
use std::{path::PathBuf};

// Context for the server (not the request)
#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    // Where the app is hosted (defaults to http://localhost:8080/)
    pub domain: String,
    pub tera: Tera,
}

// Creates the server context
pub fn init() -> AppState {
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
    let mut store = Store::init();
    store.read_store_from_file(&path_store).expect("Cannot read store");

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
