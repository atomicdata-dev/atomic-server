//! App state, which is accessible from handlers
use crate::{config::Config, errors::BetterResult};
use atomic_lib::{
    agents::{generate_public_key, Agent},
    Storelike,
};

/// Context for the server (not an individual request)
#[derive(Clone)]
pub struct AppState {
    /// Contains all the data
    pub store: atomic_lib::Db,
    /// App Configuration
    pub config: Config,
}

/// Creates the server context.
/// Initializes a store on disk.
/// Creates a new agent, if neccessary.
pub fn init(config: Config) -> BetterResult<AppState> {
    let store = atomic_lib::Db::init(&config.store_path, config.local_base_url.clone())?;
    set_default_agent(&config, &store)?;
    // TODO: implement logic that checks if this is the first time that the server is started.
    let initial = true;
    if initial {
        store.populate()?;
        set_up_initial_invite(&store)?;
    }
    set_up_drive(&store)?;

    Ok(AppState { store, config })
}

/// Create a new agent if it does not yet exist.
fn set_default_agent(config: &Config, store: &impl Storelike) -> BetterResult<()> {
    let ag_cfg: atomic_lib::config::Config = match atomic_lib::config::read_config(
        &config.config_file_path,
    ) {
        Ok(agent_config) => {
            match store.get_resource(&agent_config.agent) {
                Ok(_) => agent_config,
                Err(e) => {
                    if agent_config.agent.contains(&config.local_base_url) {
                        // If there is an agent in the config, but not in the store,
                        // That probably means that the DB has been erased and only the config file exists.
                        // This means that the Agent from the Config file should be recreated, using its private key.
                        log::info!("Agent not retrievable, but config was found. Recreating Agent in new store.");
                        let recreated_agent = Agent::new_from_private_key(
                            "root".into(),
                            store,
                            &agent_config.private_key,
                        );
                        store.add_resource(&recreated_agent.to_resource(store)?)?;
                        agent_config
                    } else {
                        return Err(format!(
                            "An agent is present in {:?}, but this agent cannot be retrieved. Either make sure the agent is retrievable, or remove it from your config. {}",
                            config.config_file_path, e,
                        ).into());
                    }
                }
            }
        }
        Err(_) => {
            let agent = store.create_agent(Some("root"))?;
            let cfg = atomic_lib::config::Config {
                agent: agent.subject.clone(),
                server: config.local_base_url.clone(),
                private_key: agent
                    .private_key
                    .expect("No private key for agent. Check the config file."),
            };
            let config_string =
                atomic_lib::config::write_config(&config.config_file_path, cfg.clone())?;
            log::warn!("No existing config found, created a new Config at {:?}. Copy this to your client machine (running atomic-cli) to log in with these credentials. \n{}", &config.config_file_path, config_string);
            cfg
        }
    };

    let agent = Agent {
        subject: ag_cfg.agent.clone(),
        private_key: Some(ag_cfg.private_key.clone()),
        public_key: generate_public_key(&ag_cfg.private_key).public,
        created_at: 0,
        name: None,
    };
    log::info!("Setting default Agent {}...", &agent.subject);
    store.set_default_agent(agent);
    Ok(())
}

/// Creates the first Invitation that is opened by the user on the Home page.
fn set_up_initial_invite(store: &impl Storelike) -> BetterResult<()> {
    let subject = format!("{}/setup", store.get_base_url());
    log::info!("Creating initial Invite at {}...", subject);
    let mut invite = atomic_lib::Resource::new_instance(atomic_lib::urls::INVITE, store)?;
    invite.set_subject(subject);
    // This invite can be used only once
    invite.set_propval(
        atomic_lib::urls::USAGES_LEFT.into(),
        atomic_lib::Value::Integer(1),
        store,
    )?;
    invite.set_propval(
        atomic_lib::urls::WRITE_BOOL.into(),
        atomic_lib::Value::Boolean(true),
        store,
    )?;
    invite.set_propval(
        atomic_lib::urls::TARGET.into(),
        atomic_lib::Value::AtomicUrl(store.get_base_url().into()),
        store,
    )?;
    invite.save_locally(store)?;
    Ok(())
}

/// Get the Drive resource (base URL), set agent as the Root user, provide write access
fn set_up_drive(store: &impl Storelike) -> BetterResult<()> {
    log::info!("Setting rights to Drive...");
    // Now let's add the agent as the Root user and provide write access
    let mut drive = store.get_resource(store.get_base_url())?;
    let agents = vec![store.get_default_agent()?.subject];
    // TODO: add read rights to public, maybe
    drive.set_propval(atomic_lib::urls::WRITE.into(), agents.clone().into(), store)?;
    drive.set_propval(atomic_lib::urls::READ.into(), agents.into(), store)?;
    drive.save_locally(store)?;
    Ok(())
}
