//! Parse CLI options, setup on boot, read .env values

use crate::errors::BetterResult;
use clap::Parser;
use dotenv::dotenv;
use std::env;
use std::net::IpAddr;
use std::path::PathBuf;

/// Store and share Atomic Data! Visit https://atomicdata.dev for more info. Pass no subcommands to launch the server. The `.env` of your current directory will be read.
#[derive(Clone, Parser, Debug)]
#[clap(author = "Joep Meindertsma (joep@ontola.io)")]
pub struct Opts {
    /// The subcommand being run
    #[clap(subcommand)]
    pub command: Option<Command>,
    /// Recreates the `/setup` Invite for creating a new Root User. Also re-runs various populate commands, and re-builds the index
    #[clap(long)]
    pub initialize: bool,
    /// Re-creates the value index. Parses all the resources. Do this if your collections have issues.
    #[clap(long)]
    pub rebuild_index: bool,
    /// Use staging environments for services like LetsEncrypt
    #[clap(long, env = "ATOMIC_DEVELOPMENT")]
    pub development: bool,
    /// The origin domain where the app is hosted, without the port and schema values.
    #[clap(long, default_value = "localhost", env = "ATOMIC_DOMAIN")]
    pub domain: String,
    /// The contact mail address for Let's Encrypt HTTPS setup
    #[clap(long, env = "ATOMIC_EMAIL")]
    pub email: Option<String>,
    /// The port where the HTTP app is available
    #[clap(short, long, default_value = "80", env = "ATOMIC_PORT")]
    pub port: u32,
    /// The port where the HTTPS app is available
    #[clap(long, default_value = "443", env = "ATOMIC_PORT")]
    pub port_https: u32,
    /// The IP address of the server
    #[clap(long, default_value = "0.0.0.0", env = "ATOMIC_IP")]
    pub ip: IpAddr,
    /// If we're using HTTPS or plaintext HTTP.
    /// Is disabled when using cert_init
    #[clap(long, env = "ATOMIC_HTTPS")]
    pub https: bool,
    /// Endpoint where the front-end assets are hosted
    #[clap(
        long,
        default_value = "https://joepio.github.io/atomic-data-browser",
        env = "ATOMIC_ASSET_URL"
    )]
    pub asset_url: String,
    /// Custom JS script to include in the body of the HTML template
    #[clap(long, default_value = "", env = "ATOMIC_SCRIPT")]
    pub script: String,
    /// Path for atomic data config directory. Defaults to "~/.config/atomic/""
    #[clap(long, env = "ATOMIC_CONFIG_DIR")]
    pub config_dir: Option<PathBuf>,
}

#[derive(Parser, Clone, Debug)]
pub enum Command {
    /// Create and save a JSON-AD backup of the store.
    #[clap(name = "export")]
    Export(ExportOpts),
    /// Import a JSON-AD backup to the store. Overwrites existing Resources with same @id.
    #[clap(name = "import")]
    Import(ImportOpts),
    /// Creates a `.env` file in your current directory that shows various options that you can set.
    #[clap(name = "setup-env")]
    SetupEnv,
}

#[derive(Parser, Clone, Debug)]
pub struct ExportOpts {
    /// Where the exported file should be saved  "~/.config/atomic/backups/{date}.json"
    #[clap(short)]
    pub path: Option<PathBuf>,
    /// Do not export resources that are externally defined, which are cached by this Server.
    #[clap(long)]
    pub only_internal: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct ImportOpts {
    /// Where the file that should be imported is.
    #[clap(short)]
    pub path: PathBuf,
}

/// Start atomic-server, oi mate
#[derive(Parser, Clone, Debug)]
pub struct ServerOpts {}

/// Configuration for the server.
/// These values are set when the server initializes, and do not change while running.
#[derive(Clone)]
pub struct Config {
    /// Full domain + schema
    pub local_base_url: String,
    /// CLI + ENV options
    pub opts: Opts,
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
    /// init app
    pub initialize: bool,
}

/// Creates the server config, reads .env values and sets defaults
pub fn init() -> BetterResult<Config> {
    // Parse CLI options, .env values, set defaults
    let opts: Opts = Opts::parse();

    dotenv().ok();
    let config_dir = if let Some(dir) = &opts.config_dir {
        dir.clone()
    } else {
        atomic_lib::config::default_config_dir_path()?
    };
    let mut config_file_path = atomic_lib::config::default_config_file_path()?;
    let mut store_path = config_dir.clone();
    store_path.push("db");
    let mut https_path = config_dir.clone();
    https_path.push("https");
    let mut cert_path = config_dir.clone();
    cert_path.push("https/cert.pem");
    let mut key_path = config_dir.clone();
    key_path.push("https/key.pem");

    // Make sure to also edit the `default.env` if you introduce / change environment variables here.
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
            _ => {}
        }
    }

    let initialize = !std::path::Path::exists(&store_path) || opts.initialize;

    if opts.https & opts.email.is_none() {
        return Err(
            "The email parameter is required for getting an HTTPS certificate from Let'sEncrypt."
                .into(),
        );
        // email = Some(promptly::prompt("What is your e-mail? This is required for getting an HTTPS certificate from Let'sEncrypt.").unwrap());
    }

    let schema = if opts.https { "https" } else { "http" };
    // I'm not convinced that this is the best way to do this.
    let local_base_url = if opts.https && opts.port_https == 443 || !opts.https && opts.port == 80 {
        format!("{}://{}", schema, opts.domain)
    } else {
        format!("{}://{}:{}", schema, opts.domain, opts.port)
    };

    let mut static_path = config_dir.clone();
    static_path.push("public");

    Ok(Config {
        initialize,
        opts,
        cert_path,
        config_dir,
        config_file_path,
        https_path,
        key_path,
        local_base_url,
        static_path,
        store_path,
    })
}
