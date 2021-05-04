//! App state, which is accessible from handlers
use crate::{config::Config, errors::BetterResult};
use atomic_lib::{agents::Agent, mapping::Mapping, Storelike};

/// Context for the server (not an individual request)
#[derive(Clone)]
pub struct AppState {
    /// Contains all the data
    pub store: atomic_lib::Db,
    /// For bookmarks (map URLs to Shortnames)
    pub mapping: Mapping,
    /// App Configuration
    pub config: Config,
}

/// Creates the server context.
/// Initializes a store.
pub fn init(config: Config) -> BetterResult<AppState> {
    // Opens or creates the database
    let store = atomic_lib::Db::init(&config.store_path, config.local_base_url.clone())?;
    // Maybe running populate every time is too much
    store.populate()?;
    // This may no longer be needed
    let mapping = Mapping::init();
    // Create a new agent if it does not yet exist.
    match atomic_lib::config::read_config(&config.config_file_path) {
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
                            &agent_config.private_key,
                        );
                        store.add_resource(&recreated_agent.to_resource(&store)?)?;
                        // Now let's add the agent as the Root user and provide write access
                        let mut drive = store.get_resource(store.get_base_url())?;
                        drive.set_propval(atomic_lib::urls::WRITE.into(), atomic_lib::Value::AtomicUrl(agent_config.agent), &store)?;
                    } else {
                        return Err(format!(
                            "An agent is present in {:?}, but this agent cannot be retrieved. Either make sure the agent is retrievable, or remove it from your config. {}",
                            config.config_file_path, e,
                        ).into());
                    }
                }
            };
        }
        Err(_) => {
            let agent = store.create_agent("root")?;
            let cfg = atomic_lib::config::Config {
                agent: agent.subject.clone(),
                server: config.local_base_url.clone(),
                private_key: agent.private_key,
            };
            let config_string = atomic_lib::config::write_config(&config.config_file_path, cfg)?;
            log::warn!("No existing config found, created a new Config at {:?}. Copy this to your client machine (running atomic-cli) to log in with these credentials. \n{}", &config.config_file_path, config_string);
        }
    }

    Ok(AppState {
        store,
        config,
        mapping,
    })
}
