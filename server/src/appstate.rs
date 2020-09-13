//! App state, which is accessible from handlers
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
    let mut store = atomic_lib::Db::init(&config.store_path, config.local_base_url.clone())?;
    store.populate()?;

    let mapping = Mapping::init();

    let tera = Tera::new("templates/*.html")?;

    Ok(AppState {
        store,
        config,
        mapping,
        tera,
    })
}
