//! App state, which is accessible from handlers
use crate::{
    commit_monitor::CommitMonitor, config::Config, errors::AtomicServerResult, search::SearchState,
};
use atomic_lib::{
    agents::{generate_public_key, Agent},
    Storelike,
};

/// Data object available to handlers and actors.
/// Contains the store, configuration and addresses for Actix Actors.
// This struct is cloned accross all threads, so make sure the fields are thread safe.
// A good option here is to use Actors for things that can change (e.g. commit_monitor)
#[derive(Clone)]
pub struct AppState {
    /// Contains all the data
    pub store: atomic_lib::Db,
    /// App Configuration
    pub config: Config,
    /// The Actix Address of the CommitMonitor, which should receive updates when a commit is applied
    pub commit_monitor: actix::Addr<CommitMonitor>,
    pub search_state: SearchState,
}

/// Creates the server context.
/// Initializes or opens a store on disk.
/// Initializes logging.
/// Creates a new agent, if neccessary.
pub fn init(config: Config) -> AtomicServerResult<AppState> {
    // Enable logging, but hide most tantivy logs
    std::env::set_var("RUST_LOG", "info,tantivy=warn");
    // Logs to the console. The tracing library allows for structured logging.
    tracing_subscriber::fmt::init();

    // use tracing_chrome::ChromeLayerBuilder;
    // use tracing_subscriber::{prelude::*, registry::Registry};

    // let (chrome_layer, _guard) = ChromeLayerBuilder::new().build();
    // tracing_subscriber::registry().with(chrome_layer).init();

    const VERSION: &str = env!("CARGO_PKG_VERSION");
    tracing::info!("Atomic-server {}. Use --help for more options. Visit https://docs.atomicdata.dev and https://github.com/joepio/atomic-data-rust.", VERSION);

    // Check if atomic-server is already running somwehere, and try to stop it. It's not a problem if things go wrong here, so errors are simply logged.
    let _ = crate::process::terminate_existing_processes(&config)
        .map_err(|e| tracing::error!("Could not check for running instance: {}", e));

    tracing::info!("Opening database at {:?}", &config.store_path);
    let store = atomic_lib::Db::init(&config.store_path, config.local_base_url.clone())?;
    if config.initialize {
        tracing::info!("Initialize: creating and populating new Database");
        atomic_lib::populate::populate_default_store(&store)
            .map_err(|e| format!("Failed to populate default store. {}", e))?;
        // Building the index here is needed to perform TPF queries on imported resources
        tracing::info!("Building index (this could take a few minutes for larger databases)");
        store.build_index(true)?;
        tracing::info!("Building index finished!");
    }
    tracing::info!("Setting default agent");
    set_default_agent(&config, &store)?;
    if config.initialize {
        tracing::info!("Running populate commands");
        atomic_lib::populate::create_drive(&store)
            .map_err(|e| format!("Failed to populate hierarchy. {}", e))?;
        atomic_lib::populate::set_drive_rights(&store, true)
            .map_err(|e| format!("Failed to set drive rights. {}", e))?;
        atomic_lib::populate::populate_collections(&store)
            .map_err(|e| format!("Failed to populate collections. {}", e))?;
        atomic_lib::populate::populate_endpoints(&store)
            .map_err(|e| format!("Failed to populate endpoints. {}", e))?;
        set_up_initial_invite(&store)?;
        // This means that editing the .env does _not_ grant you the rights to edit the Drive.
        tracing::info!("Setting rights to Drive {}", store.get_base_url());
    }

    // Initialize search constructs
    tracing::info!("Starting search service");
    let search_state = SearchState::new(&config)?;

    // Initialize commit monitor, which watches commits and sends these to the commit_monitor actor
    tracing::info!("Starting commit monitor");
    let commit_monitor = crate::commit_monitor::create_commit_monitor(
        store.clone(),
        search_state.clone(),
        config.clone(),
    );

    Ok(AppState {
        store,
        config,
        commit_monitor,
        search_state,
    })
}

/// Create a new agent if it does not yet exist.
fn set_default_agent(config: &Config, store: &impl Storelike) -> AtomicServerResult<()> {
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
                        tracing::info!("Agent not retrievable, but config was found. Recreating Agent in new store.");
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
        Err(_no_config) => {
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
            tracing::warn!("No existing config found, created a new Config at {:?}. Copy this to your client machine (running atomic-cli or atomic-data-browser) to log in with these credentials. \n{}", &config.config_file_path, config_string);
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
    tracing::info!("Default Agent is set: {}", &agent.subject);
    store.set_default_agent(agent);
    Ok(())
}

/// Creates the first Invitation that is opened by the user on the Home page.
fn set_up_initial_invite(store: &impl Storelike) -> AtomicServerResult<()> {
    let subject = format!("{}/setup", store.get_base_url());
    tracing::info!("Creating initial Invite at {}", subject);
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
    invite.set_propval(
        atomic_lib::urls::PARENT.into(),
        atomic_lib::Value::AtomicUrl(store.get_base_url().into()),
        store,
    )?;
    invite.set_propval(
        atomic_lib::urls::NAME.into(),
        atomic_lib::Value::String("Setup".into()),
        store,
    )?;
    invite.set_propval_string(
        atomic_lib::urls::DESCRIPTION.into(),
        "Use this Invite to create an Agent, or use an existing one. Accepting will grant your Agent the necessary rights to edit the data in your Atomic Server. This can only be used once. If you, for whatever reason, need a new `/setup` invite, you can pass the `--init` flag to `atomic-server`.",
        store,
    )?;
    invite.save_locally(store)?;
    Ok(())
}
