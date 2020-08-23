use atomic_lib::store::Store;
use tera::Tera;
use crate::config::Config;

// Context for the server (not the request)
#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub tera: Tera,
    pub config: Config,
}

// Creates the server context
pub fn init(config: Config) -> AppState {
    let mut store = Store::init();

    if config.store_path.exists() {
        store.read_store_from_file(&config.store_path).expect("Cannot read store");
    } else {
        println!("No store found, initializing in {:?}", &config.store_path);
        store.load_default();
        store.write_store_to_disk(&config.store_path).expect("Could not create store");
    }

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
        tera,
    };
}
