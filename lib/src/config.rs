//! Configuration logic which can be used in both CLI and Server contexts
//! For serializaing, storing, and parsing the `~/.config/atomic/config.toml` file

use crate::{agents::Agent, errors::AtomicResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A set of options that are shared between CLI and Server contexts
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub shared: SharedConfig,
    pub client: Option<ClientConfig>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SharedConfig {
    /// Sudo agent on the server, also used as agent in the CLI. Usually lives on the server, but not necessarily so.
    pub agent_secret: String,
    /// The DID of the initial drive created for the base domain
    #[serde(rename = "initialDrive")]
    pub initial_drive: Option<String>,
}

/// Hand-written so the agent secret never reaches a log line through `{:?}`
/// (`Config` derives `Debug` and prints this).
impl std::fmt::Debug for SharedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedConfig")
            .field("agent_secret", &"[redacted]")
            .field("initial_drive", &self.initial_drive)
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientConfig {
    /// URL of Companion Atomic Server, where data is written to by default.
    pub server_url: String,
}

/// Returns the default path for the config file: `~/.config/atomic`
pub fn default_config_dir_path() -> AtomicResult<PathBuf> {
    if let Some(dirs) = directories::UserDirs::new() {
        let atomic_config_dir = dirs.home_dir().join(".config/atomic");
        return Ok(atomic_config_dir);
    }
    // Fallback for systems like Android where UserDirs might be None
    Ok(PathBuf::from(".config/atomic"))
}

/// Returns the default path for the config file: `~/.config/atomic/config.toml`
pub fn default_config_file_path() -> AtomicResult<PathBuf> {
    let mut default_dir = default_config_dir_path()?;
    default_dir.push("config.toml");
    Ok(default_dir)
}

/// Reads config file from a specified path
/// If you pass None, it will use the default config file path
pub fn read_config(path: Option<&Path>) -> AtomicResult<Config> {
    let default = default_config_file_path()?;
    let path = path.unwrap_or(&default);
    let config_string = std::fs::read_to_string(path)
        .map_err(|e| format!("Error reading config from {:?}. {}", path, e))?;
    let config = parse_and_migrate_if_needed(&config_string)
        .map_err(|e| format!("Could not parse toml in config file {:?}. {}", path, e))?;
    Ok(config)
}

/// Writes config file from a specified path.
/// Overwrites any existing config.
/// Creates the config directory if it does not exist.
fn write_config(path: &Path, config: Config) -> AtomicResult<String> {
    let out =
        toml::to_string_pretty(&config).map_err(|e| format!("Error serializing config. {}", e))?;

    let prefix = path
        .parent()
        .ok_or("Could not get parent dir of config file")?;
    std::fs::create_dir_all(prefix)
        .map_err(|e| format!("Could not create config directory {:?} . {}", prefix, e))?;

    std::fs::write(path, out.clone())
        .map_err(|e| format!("Error writing config file to {:?}. {}", path, e))?;
    // The file holds the agent's private key: owner-only, whatever the umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Could not restrict permissions of {:?}. {}", path, e))?;
    }
    Ok(out)
}

impl Config {
    pub fn save(&self, path: &Path) -> AtomicResult<()> {
        write_config(path, self.clone())?;
        Ok(())
    }

    pub fn to_string(&self) -> AtomicResult<String> {
        let out =
            toml::to_string_pretty(self).map_err(|e| format!("Error serializing config. {}", e))?;
        Ok(out)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ConfigV0 {
    agent: String,
    private_key: String,
    server: String,
}

fn parse_and_migrate_if_needed(config_str: &str) -> AtomicResult<Config> {
    // Try latest version first
    if let Ok(config) = toml::from_str::<Config>(config_str) {
        return Ok(config);
    }

    // Try v0 version
    if let Ok(config) = toml::from_str::<ConfigV0>(config_str) {
        return config_v0_to_v1(&config);
    }

    Err("Could not parse config".into())
}

fn config_v0_to_v1(config_v0: &ConfigV0) -> AtomicResult<Config> {
    let ConfigV0 {
        agent,
        private_key,
        server,
    } = config_v0;

    let new_agent = Agent::from_private_key_and_subject(private_key, agent)?;

    let config = Config {
        shared: SharedConfig {
            agent_secret: new_agent.build_secret()?,
            initial_drive: None,
        },
        client: Some(ClientConfig {
            server_url: server.clone(),
        }),
    };

    Ok(config)
}

#[cfg(test)]
mod test {
    use super::*;

    /// `{:?}` on a Config must never print the agent secret.
    #[test]
    fn debug_output_redacts_the_agent_secret() {
        let config = Config {
            shared: SharedConfig {
                agent_secret: "s3cret-agent-secret".into(),
                initial_drive: None,
            },
            client: None,
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("s3cret"), "{debug}");
        assert!(debug.contains("[redacted]"), "{debug}");
    }
}
