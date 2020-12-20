//! App state, which is accessible from handlers
use crate::{config::Config, errors::BetterResult};
use atomic_lib::{mapping::Mapping, Storelike};
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
    let store = atomic_lib::Db::init(&config.store_path, config.local_base_url.clone())?;
    store.populate()?;
    let mapping = Mapping::init();
    let tera = Tera::new("templates/*.html")?;
    // Create a new identity if it does not yet exist.

    let path = atomic_lib::config::default_path()?;
    match atomic_lib::config::read_config(&path) {
        Ok(agent_config) => {
            store.get_resource(&agent_config.agent).unwrap_or_else(|_| {
                panic!(
                    "An agent is present in {:?}, but this agent is not present in the store",
                    path
                )
            });
        }
        Err(_) => {
            let agent = store.create_agent("root")?;
            let cfg = atomic_lib::config::Config {
                agent: agent.subject,
                server: config.local_base_url.clone(),
                private_key: agent.key,
            };
            atomic_lib::config::write_config(&path, cfg)?;
            log::info!("Agent created. Check newly created config file: {:?}", path);
        }
    }

    Ok(AppState {
        store,
        config,
        mapping,
        tera,
    })
}
