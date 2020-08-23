use dotenv::dotenv;
use std::env;
use std::{path::PathBuf};
use std::net::{IpAddr, Ipv4Addr};

/// Config for the server.
/// These values should be set when the server initializes, and do not change while running.
#[derive(Clone)]
pub struct Config {
    // Where the app is hosted (defaults to http://localhost:8080/)
    pub domain: String,
    pub port: u32,
    pub store_path: PathBuf,
    pub ip: IpAddr,
}

/// Creates the server config, reads .env values and sets defaults
pub fn init() -> Config {
    dotenv().ok();
    let mut store_path = PathBuf::from("~/.atomic/default_store.ad3");
    let mut domain = String::from("http://localhost:8080/");
    let mut port = 8080;
    let mut ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
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
            _ => {}
        }
    }

    return Config {
        store_path,
        domain,
        port,
        ip,
    };
}
