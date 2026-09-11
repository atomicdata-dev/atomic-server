//! Shared native identity bootstrap for adapters; no server configuration or HTTP.
use super::AtomicNode;
use crate::{agents::Agent, config::SharedConfig, errors::AtomicResult, Storelike};

impl AtomicNode {
    /// Load this node's persisted identity, including legacy subject migration.
    /// Only a missing config creates a new identity. A damaged or unreadable
    /// existing config fails without overwriting it. Does not create a drive.
    pub async fn load_or_create_agent(
        &self,
        config_path: &std::path::Path,
        name: &str,
    ) -> AtomicResult<()> {
        let store = self.db();
        tracing::info!("Setting default agent");

        let agent = if config_path.try_exists()? {
            // An existing but damaged/unreadable file is not a fresh install.
            // Never replace its identity merely because parsing/loading failed.
            let agent_config = crate::config::read_config(Some(config_path))?;
            // Agent::from_secret owns legacy URL-to-DID migration for every
            // adapter; do not duplicate that conversion in runtime bootstrap.
            let agent = Agent::from_secret(&agent_config.shared.agent_secret)?;

            match store.get_resource(&agent.subject.clone()).await {
                Ok(_) => agent,
                Err(e) => {
                    if agent.subject.is_local() {
                        // If there is an agent in the config, but not in the store,
                        // That probably means that the DB has been erased and only the config file exists.
                        // This means that the Agent from the Config file should be recreated, using its private key.
                        tracing::info!("Agent not retrievable, but config was found. Recreating Agent in new store.");

                        let mut recreated_agent = Agent::new_from_private_key(
                            Some(name),
                            &agent.private_key.ok_or("No private key found")?,
                        )?;
                        recreated_agent.initial_drive = agent.initial_drive;
                        store.add_resource(&recreated_agent.to_resource()?).await?;

                        recreated_agent
                    } else {
                        return Err(format!(
                            "An agent is present in {:?}, but this agent cannot be retrieved. Either make sure the agent is retrievable, or remove it from your config. {}",
                            config_path, e,
                        ).into());
                    }
                }
            }
        } else {
            let agent = store.create_agent(Some(name)).await?;
            let cfg = crate::config::Config {
                shared: SharedConfig {
                    agent_secret: agent.build_secret()?,
                    initial_drive: agent.initial_drive.clone().map(|s| s.to_string()),
                },
                client: None,
            };

            cfg.save(config_path)?;

            // Never log the agent secret: on Android it would land in logcat
            // (bug reports, `adb logcat` history), and on servers in log
            // aggregators. The secret lives only in the config file.
            tracing::warn!(
                "No existing config found, created a new Config at {:?}. To sign in from another device, use the pairing/sign-in flow in the browser app, or copy the agent secret from that file.",
                config_path
            );

            agent
        };

        tracing::info!("Default Agent is set: {}", &agent.subject);
        store.set_default_agent(agent);
        Ok(())
    }
}
