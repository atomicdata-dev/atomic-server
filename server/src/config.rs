use dotenv::dotenv;
use std::env;
use std::{path::PathBuf};
use std::net::{IpAddr, Ipv4Addr};
use dirs::home_dir;

/// Configuration for the server.
/// These values are set when the server initializes, and do not change while running.
#[derive(Clone)]
pub struct Config {
    pub development: bool,
    /// Where the app is hosted (defaults to localhost).
    /// Without the port and schema values.
    pub domain: String,
    /// E.g. https://example.com
    pub local_base_url: String,
    /// The contact mail address for Let's Encrypt HTTPS setup
    pub email: Option<String>,
    /// The port where the app is available (defaults to 80)
    pub port: u32,
    /// Where the .ad3 store is located
    pub store_path: PathBuf,
    /// The IP address of the serer. (defaults to 127.0.0.1)
    pub ip: IpAddr,
    /// If we're using SSL or plaintext HTTP.
    /// Is disabled when using cert_init
    pub https: bool,
    pub key_path: Option<String>,
    pub cert_path: Option<String>,
    /// This is only true when the Let's Encrypt initialization is running
    pub cert_init: bool,
}

/// Creates the server config, reads .env values and sets defaults
pub fn init() -> Config {
    dotenv().ok();
    let development = true;
    let mut domain = String::from("localhost");
    let cert_path = None;
    let key_path = None;
    let mut cert_init = false;
    let mut https = false;
    let mut ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let mut port = if https { 443 } else { 80 };
    let mut store_path = home_dir()
        .expect("Home dir could not be opened")
        .join(".config/atomic/db");
    let mut email = None;
    for (key, value) in env::vars() {
        match &*key {
            "ATOMIC_STORE_PATH" => {
                store_path = value.parse().expect("Could not parse ATOMIC_STORE_PATH. Is it a valid path?");
            }
            "ATOMIC_DOMAIN" => {
                domain = String::from(value);
            }
            "ATOMIC_PORT" => {
                port = value.parse().expect("ATOMIC_PORT is not a number");
            }
            "ATOMIC_IP" => {
                ip = value.parse().expect("Could not parse ATOMIC_IP. Is it a valid IP address?");
            }
            "ATOMIC_EMAIL" => {
                email = Some(String::from(value));
            }
            "ATOMIC_HTTPS" => {
                https = value.parse().expect("ATOMIC_HTTPS is not a boolean");
            }
            "ATOMIC_CERT_INIT" => {
                cert_init = value.parse().expect("ATOMIC_CERT_INIT is not a boolean");
            }
            _ => {}
        }
    }

    // Always disable HTTPS when initializing certificates
    if cert_init {
        https = false;
    }

    let schema = if https {"https"} else {"http"};
    let local_base_url = format!("{}://{}/", schema, domain);

    return Config {
        cert_init,
        cert_path,
        email,
        development,
        domain,
        https,
        ip,
        key_path,
        port,
        local_base_url,
        store_path,
    };
}
