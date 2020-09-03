use crate::config::Config;
use atomic_lib::mapping::Mapping;
use atomic_lib::{Store, Storelike, Db};
use tera::Tera;

// Context for the server (not the request)
#[derive(Clone)]
pub struct AppState {
    pub store: Db,
    pub tera: Tera,
    pub mapping: Mapping,
    pub config: Config,
}

// Creates the server context
pub fn init(config: Config) -> AppState {
    // let mut store = Store::init();
    let mut store = Db::init(config.store_path.clone()).expect("Could not init store");

    let ad3 = include_str!("../../defaults/default_store.ad3");
    store
        .parse_ad3(&String::from(ad3))
        .expect("Error when parsing store");

    let mapping = Mapping::init();

    let tera = match Tera::new("src/templates/*.html") {
        Ok(t) => t,
        Err(e) => {
            println!("Parsing error(s): {}", e);
            ::std::process::exit(1);
        }
    };

    return AppState {
        store,
        config,
        mapping,
        tera,
    };
}
