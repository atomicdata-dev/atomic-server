//! Setup on boot, reads .env values

use crate::errors::BetterResult;
use dotenv::dotenv;
use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

/// Configuration for the server.
/// These values are set when the server initializes, and do not change while running.
#[derive(Clone)]
pub struct Config {
    /// If you're running in Development mode.
    pub development: bool,
    /// Where the app is hosted (defaults to localhost).
    /// Without the port and schema values.
    pub domain: String,
    /// E.g. https://example.com
    pub local_base_url: String,
    /// The contact mail address for Let's Encrypt HTTPS setup
    pub email: Option<String>,
    /// The port where the HTTP app is available (defaults to 80)
    pub port: u32,
    /// The port where the HTTPS app is available (defaults to 443)
    pub port_https: u32,
    /// The IP address of the serer. (defaults to 0.0.0.0)
    pub ip: IpAddr,
    /// If we're using HTTPS or plaintext HTTP.
    /// Is disabled when using cert_init
    pub https: bool,
    // ===  PATHS  ===
    /// Path for atomic data config `~/.config/atomic/`. Used to construct most other paths.
    pub config_dir: PathBuf,
    /// Path where TLS key should be stored for HTTPS. (defaults to `~/.config/atomic/https/key.pem`)
    pub key_path: PathBuf,
    /// Path where TLS certificate should be stored for HTTPS. (defaults to `~/.config/atomic/https/cert.pem`)
    pub cert_path: PathBuf,
    /// Path where TLS certificates should be stored for HTTPS. (defaults to `~/.config/atomic/https`)
    pub https_path: PathBuf,
    /// Path where config.toml is located, which contains info about the Agent (defaults to `~/.config/atomic/config.toml`)
    pub config_file_path: PathBuf,
    /// Path where the public static files folder is located
    pub static_path: PathBuf,
    /// Path to where the store is located. (defaults to `~/.config/atomic/db`)
    pub store_path: PathBuf,
}

/// Creates the server config, reads .env values and sets defaults
pub fn init() -> BetterResult<Config> {
    dotenv().ok();
    let mut development = false;
    let mut domain = String::from("localhost");
    let mut https = false;
    let mut ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    let mut port = 80;
    let mut port_https = 443;
    let config_dir = atomic_lib::config::default_config_dir_path()?;
    let mut config_file_path = atomic_lib::config::default_config_file_path()?;
    let mut store_path = config_dir.clone();
    store_path.push("db");
    let mut https_path = config_dir.clone();
    https_path.push("https");
    let mut cert_path = config_dir.clone();
    cert_path.push("https/cert.pem");
    let mut key_path = config_dir.clone();
    key_path.push("https/key.pem");
    let mut email = None;
    for (key, value) in env::vars() {
        match &*key {
            "ATOMIC_CONFIG_PATH" => {
                config_file_path = value.parse().map_err(|e| {
                    format!(
                        "Could not parse ATOMIC_CONFIG_PATH. Is {} a valid path? {}",
                        value, e
                    )
                })?;
            }
            "ATOMIC_STORE_PATH" => {
                store_path = value.parse().map_err(|e| {
                    format!(
                        "Could not parse ATOMIC_STORE_PATH. Is {} a valid path? {}",
                        value, e
                    )
                })?;
            }
            "ATOMIC_DOMAIN" => {
                // Perhaps this should have some regex check
                domain = value;
            }
            "ATOMIC_DEVELOPMENT" => {
                development = value.parse().expect("ATOMIC_DEVELOPMENT is not a boolean");
            }
            "ATOMIC_PORT" => {
                port = value.parse().expect("ATOMIC_PORT is not a number");
            }
            "ATOMIC_PORT_HTTPS" => {
                port_https = value.parse().expect("ATOMIC_PORT_HTTPS is not a number");
            }
            "ATOMIC_IP" => {
                ip = value
                    .parse()
                    .expect("Could not parse ATOMIC_IP. Is it a valid IP address?");
            }
            "ATOMIC_EMAIL" => {
                email = Some(value);
            }
            "ATOMIC_HTTPS" => {
                https = value.parse().expect("ATOMIC_HTTPS is not a boolean");
            }
            _ => {}
        }
    }

    if https & email.is_none() {
        email = Some(promptly::prompt("What is your e-mail? This is required for getting an HTTPS certificate from Let'sEncrypt.").unwrap());
    }

    let schema = if https { "https" } else { "http" };
    let local_base_url = format!("{}://{}", schema, domain);

    let mut static_path = config_dir.clone();
    static_path.push("public");

    Ok(Config {
        cert_path,
        config_dir,
        config_file_path,
        email,
        development,
        domain,
        https,
        https_path,
        ip,
        key_path,
        port,
        port_https,
        local_base_url,
        store_path,
        static_path,
    })
}
