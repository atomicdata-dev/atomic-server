use dotenv::dotenv;
use std::env;
use std::{path::PathBuf};
use std::net::{IpAddr, Ipv4Addr};
use dirs::home_dir;

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
    /// Where the .ad3 store is located
    pub store_path: PathBuf,
    /// The IP address of the serer. (defaults to 127.0.0.1)
    pub ip: IpAddr,
    /// If we're using SSL or plaintext HTTP.
    /// Is disabled when using cert_init
    pub https: bool,
    /// Path where ssl key should be stored for HTTPS. (defaults to .ssl/key.pem)
    pub key_path: String,
    /// Path where ssl certificate should be stored for HTTPS. (defaults to .ssl/cert.pem)
    pub cert_path: String,
    /// This is only true when the Let's Encrypt initialization is running
    pub cert_init: bool,
}

/// Creates the server config, reads .env values and sets defaults
pub fn init() -> Config {
    dotenv().ok();
    let development = false;
    let mut domain = String::from("localhost");
    let cert_path = String::from(".ssl/cert.pem");
    let key_path = String::from(".ssl/key.pem");
    let mut cert_init = false;
    let mut https = false;
    let mut ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let mut port = 80;
    let mut port_https = 443;
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
                // Perhaps this should have some regex check
                domain = value;
            }
            "ATOMIC_DEVELOPMENT" => {
                domain = value.parse().expect("ATOMIC_DEVELOPMENT is not a boolean");
            }
            "ATOMIC_PORT" => {
                port = value.parse().expect("ATOMIC_PORT is not a number");
            }
            "ATOMIC_PORT_HTTPS" => {
                port_https = value.parse().expect("ATOMIC_PORT_HTTPS is not a number");
            }
            "ATOMIC_IP" => {
                ip = value.parse().expect("Could not parse ATOMIC_IP. Is it a valid IP address?");
            }
            "ATOMIC_EMAIL" => {
                email = Some(value);
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

    Config {
        cert_init,
        cert_path,
        email,
        development,
        domain,
        https,
        ip,
        key_path,
        port,
        port_https,
        local_base_url,
        store_path,
    }
}
