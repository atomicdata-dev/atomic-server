//! Configuration logic which can be used in both CLI and Server contexts
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use crate::errors::AtomicResult;

/// A set of options that are shared between CLI and Server contexts
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    /// URL of Companion Atomic Server, where data is written to by default.
    pub server: String,
    /// The current Agent (user) URL. Usually lives on the server, but not necessarily so.
    pub agent: String,
    /// Private key for the Agent, which is used to sign commits.
    pub private_key: String,
}

/// Returns the default path for the config file: `~/.config/atomic/config.toml`
pub fn default_path () -> AtomicResult<PathBuf> {
    Ok(dirs::home_dir().ok_or("Could not open home dir")?.join(".config/atomic/config.toml"))
}

/// Reads config file from a specified path
pub fn read_config(path: &PathBuf) -> AtomicResult<Config> {
    let config_string = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&config_string).unwrap();
    Ok(config)
}

/// Writes config file from a specified path
/// Overwrites any existing config
pub fn write_config(path: &PathBuf, config: Config) -> AtomicResult<()> {
    let out = toml::to_string_pretty(&config).map_err(|e|  format!("Error serializing config. {}", e))?;
    std::fs::write(path, out)?;
    Ok(())
}
