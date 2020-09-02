use atomic_lib::Db;
use atomic_lib::mapping::Mapping;
use tera::Tera;
use crate::config::Config;

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
    let store = atomic_lib::Db::init(config.store_path.clone());

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
