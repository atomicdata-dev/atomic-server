//! Configuration logic which can be used in both CLI and Server contexts
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    /// Companion Atomic Server, where data is written by default.
    pub server: String,
    /// The current Agent (user) URL. Usually lives on the server, but not necessarily so.
    pub agent: String,
    /// Private key for the Agent, which is used to sign commits.
    pub private_key: String,
}

pub fn read_default() -> Config {
    let home = dirs::home_dir().expect("Could not open home dir").join(".config/atomic/config.toml");
    read_config(&home)
}

/// Reads config file from a specified path
pub fn read_config(path: &std::path::Path) -> Config {
    match std::fs::read_to_string(path) {
        Ok(config_string) => {
            let config: Config = toml::from_str(&config_string).unwrap();
            config
        }
        Err(_) => create_default_config("https://localhost"),
    }
}

/// Writes config file from a specified path
/// Overwrites any existing config
pub fn write_config(path: &std::path::Path, config: Config) {

    let out = toml::to_string_pretty(&config);
    std::fs::write
}


fn create_default_config(base_url: &str) -> Config {
    let keypair = crate::agents::generate_keypair();
    // TODO: This makes no sense, currenlty.
    Config {
        server: base_url.into(),
        agent: format!("{}/agents/root", base_url),
        private_key: keypair.private,
    }
}
