//! Configuration logic which can be used in both CLI and Server contexts
//! For serializaing, storing, and parsing the `~/.config/atomic/config.toml` file

use crate::errors::AtomicResult;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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

/// Returns the default path for the config file: `~/.config/atomic`
pub fn default_config_dir_path() -> AtomicResult<PathBuf> {
    if let Some(dirs) = directories::UserDirs::new() {
        let atomic_config_dir = dirs.home_dir().join(".config/atomic");
        return Ok(atomic_config_dir);
    }
    Err("No default config dir can be found, as no Home directory can be found on this operating system".into())
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
    let config: Config = toml::from_str(&config_string)
        .map_err(|e| format!("Could not parse toml in config file {:?}. {}", path, e))?;
    Ok(config)
}

/// Writes config file from a specified path.
/// Overwrites any existing config.
/// Creates the config directory if it does not exist.
pub fn write_config(path: &Path, config: Config) -> AtomicResult<String> {
    let out =
        toml::to_string_pretty(&config).map_err(|e| format!("Error serializing config. {}", e))?;

    let prefix = path
        .parent()
        .ok_or("Could not get parent dir of config file")?;
    std::fs::create_dir_all(prefix)
        .map_err(|e| format!("Could not create config directory {:?} . {}", prefix, e))?;

    std::fs::write(path, out.clone())
        .map_err(|e| format!("Error writing config file to {:?}. {}", path, e))?;
    Ok(out)
}
