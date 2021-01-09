//! App state, which is accessible from handlers
use crate::{config::Config, errors::BetterResult};
use atomic_lib::{agents::Agent, mapping::Mapping, Storelike};
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

    let path = atomic_lib::config::default_path()?;
    // Create a new agent if it does not yet exist.
    match atomic_lib::config::read_config(&path) {
        Ok(agent_config) => {
            match store.get_resource(&agent_config.agent) {
                Ok(_) => {}
                Err(e) => {
                    if agent_config.agent.contains(&config.local_base_url) {
                        // If there is an agent in the config, but not in the store,
                        // That probably means that the DB has been erased and only the config file exists.
                        // This means that the Agent from the Config file should be recreated, using its private key.
                        log::info!("Agent not retrievable, but config was found. Recreating Agent in new store.");
                        let recreated_agent = Agent::new_from_private_key(
                            "root".into(),
                            &store,
                            agent_config.private_key,
                        );
                        store
                            .add_resource(&recreated_agent.to_resource(&store)?)?;
                    } else {
                        return Err(format!(
                            "An agent is present in {:?}, but this agent cannot be retrieved. Either make sure the agent is retrievable, or remove it from your config. {}",
                            path, e,
                        ).into())
                    }
                }
            };
        }
        Err(_) => {
            let agent = store.create_agent("root")?;
            let cfg = atomic_lib::config::Config {
                agent: agent.subject,
                server: config.local_base_url.clone(),
                private_key: agent.private_key,
            };
            atomic_lib::config::write_config(&path, cfg)?;
            log::info!("No existing config found. Newly created config file contains private key for new Agent: {:?}", path);
        }
    }

    Ok(AppState {
        store,
        config,
        mapping,
        tera,
    })
}
