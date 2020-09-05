use crate::{errors::BetterResult, config::Config};
use atomic_lib::{Storelike, mapping::Mapping};
use tera::Tera;

/// Context for the server (not an individual request)
#[derive(Clone)]
pub struct AppState {
    /// Contains all the data
    pub store: atomic_lib::Db,
    /// For rendering templates
    pub tera: Tera,
    /// For bookmarks (map URLs to Shortnames)
    pub mapping: Mapping,
    /// App Configuration
    pub config: Config,
}

/// Creates the server context.
/// Initializes a store.
pub fn init(config: Config) -> BetterResult<AppState> {
    let mut store = atomic_lib::Db::init(&config.store_path)?;
    let ad3 = include_str!("../../defaults/default_store.ad3");
    let atoms = atomic_lib::parse::parse_ad3(&String::from(ad3))?;
    store.add_atoms(atoms)?;

    let mapping = Mapping::init();

    let tera = Tera::new("templates/*.html")?;

    return Ok(AppState {
        store,
        config,
        mapping,
        tera,
    });
}
