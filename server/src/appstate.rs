//! App state, which is accessible from handlers
use crate::{
    commit_monitor::CommitMonitor, config::Config, errors::AtomicServerResult, search::SearchState,
};
use atomic_lib::{
    agents::{generate_public_key, Agent},
    commit::CommitResponse,
    Storelike,
};

/// The AppState contains all the relevant Context for the server.
/// This data object is available to all handlers and actors.
/// Contains the store, configuration and addresses for Actix Actors, such as for the [CommitMonitor].
/// It is generated using [init], which takes a [Config].
// This struct is cloned across all threads, so make sure the fields are thread safe.
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

/// Creates the AppState (the server's context available in Handlers).
/// Initializes or opens a store on disk.
/// Creates a new agent, if necessary.
pub fn init(config: Config) -> AtomicServerResult<AppState> {
    tracing::info!("Initializing AppState");

    // Check if atomic-server is already running somewhere, and try to stop it. It's not a problem if things go wrong here, so errors are simply logged.
    if cfg!(feature = "process-management") {
        #[cfg(feature = "process-management")]
        {
            let _ = crate::process::terminate_existing_processes(&config)
                .map_err(|e| tracing::error!("Could not check for running instance: {}", e));
        }
    }

    tracing::info!("Opening database at {:?}", &config.store_path);
    let mut store = atomic_lib::Db::init(&config.store_path, config.server_url.clone())?;
    if config.initialize {
        tracing::info!("Initialize: creating and populating new Database");
        atomic_lib::populate::populate_default_store(&store)
            .map_err(|e| format!("Failed to populate default store. {}", e))?;
    }

    tracing::info!("Setting default agent");
    set_default_agent(&config, &store)?;

    // Initialize search constructs
    tracing::info!("Starting search service");
    let search_state =
        SearchState::new(&config).map_err(|e| format!("Failed to start search service: {}", e))?;

    // Initialize commit monitor, which watches commits and sends these to the commit_monitor actor
    tracing::info!("Starting commit monitor");
    let commit_monitor =
        crate::commit_monitor::create_commit_monitor(store.clone(), search_state.clone());

    let commit_monitor_clone = commit_monitor.clone();

    // This closure is called every time a Commit is created
    let send_commit = move |commit_response: &CommitResponse| {
        commit_monitor_clone.do_send(crate::actor_messages::CommitMessage {
            commit_response: commit_response.clone(),
        });
    };
    store.set_handle_commit(Box::new(send_commit));

    // If the user changes their server_url, the drive will not exist.
    // In this situation, we should re-build a new drive from scratch.
    if config.initialize || store.get_resource(&config.server_url).is_err() {
        tracing::info!(
            "Running initialization commands (first time startup, or you passed --initialize)"
        );

        atomic_lib::populate::populate_all(&store)?;
        // Building the index here is needed to perform Queries on imported resources
        let store_clone = store.clone();
        std::thread::spawn(move || {
            let res = store_clone.build_index(true);
            if let Err(e) = res {
                tracing::error!("Failed to build index: {}", e);
            }
        });

        set_up_initial_invite(&store)
            .map_err(|e| format!("Error while setting up initial invite: {}", e))?;
        // This means that editing the .env does _not_ grant you the rights to edit the Drive.
        tracing::info!("Setting rights to Drive {}", store.get_server_url());
    }

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
                    if agent_config.agent.contains(&config.server_url) {
                        // If there is an agent in the config, but not in the store,
                        // That probably means that the DB has been erased and only the config file exists.
                        // This means that the Agent from the Config file should be recreated, using its private key.
                        tracing::info!("Agent not retrievable, but config was found. Recreating Agent in new store.");
                        let recreated_agent = Agent::new_from_private_key(
                            "server".into(),
                            store,
                            &agent_config.private_key,
                        );
                        store.add_resource(&recreated_agent.to_resource()?)?;
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
            let agent = store.create_agent(Some("server"))?;
            let cfg = atomic_lib::config::Config {
                agent: agent.subject.clone(),
                server: config.server_url.clone(),
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
    let subject = format!("{}/setup", store.get_server_url());
    tracing::info!("Creating initial Invite at {}", subject);
    let mut invite = store.get_resource_new(&subject);
    invite.set_class(atomic_lib::urls::INVITE);
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
        atomic_lib::Value::AtomicUrl(store.get_server_url().into()),
        store,
    )?;
    invite.set_propval(
        atomic_lib::urls::PARENT.into(),
        atomic_lib::Value::AtomicUrl(store.get_server_url().into()),
        store,
    )?;
    invite.set_propval(
        atomic_lib::urls::NAME.into(),
        atomic_lib::Value::String("Setup".into()),
        store,
    )?;
    invite.set_propval_string(
        atomic_lib::urls::DESCRIPTION.into(),
        "Use this Invite to create an Agent, or use an existing one. Accepting will grant your Agent the necessary rights to edit the data in your Atomic Server. This can only be used once. If you, for whatever reason, need a new `/setup` invite, you can pass the `--initialize` flag to `atomic-server`.",
        store,
    )?;
    invite.save_locally(store)?;
    Ok(())
}
