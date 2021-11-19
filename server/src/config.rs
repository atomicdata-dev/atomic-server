//! Parse CLI options, setup on boot, read .env values

use clap::Parser;
use dotenv::dotenv;
use std::env;
use std::path::PathBuf;

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
    pub opts: crate::cli::Opts,
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
    /// Path to where the search index for tantivy full text search is located  (defaults to `~/.config/atomic/search_index`)
    pub search_index_path: PathBuf,
    /// If true, the initialization scripts will be ran (create first Drive, Agent, indexing, etc)
    pub initialize: bool,
}

/// Creates the server config, reads .env values and sets defaults
pub fn init() -> crate::AtomicServerResult<Config> {
    // Parse .env file (do this before parsing the CLI opts)
    dotenv().ok();

    // Parse CLI options, .env values, set defaults
    let opts: crate::cli::Opts = crate::cli::Opts::parse();

    let config_dir = if let Some(dir) = &opts.config_dir {
        dir.clone()
    } else {
        atomic_lib::config::default_config_dir_path()?
    };
    let mut config_file_path = config_dir.join("config.toml");
    let mut store_path = config_dir.clone();
    store_path.push("db");
    let mut https_path = config_dir.clone();
    https_path.push("https");
    let mut search_index_path = config_dir.clone();
    search_index_path.push("search_index");
    let mut cert_path = config_dir.clone();
    cert_path.push("https/cert.pem");
    let mut key_path = config_dir.clone();
    key_path.push("https/key.pem");

    // Make sure to also edit the `default.env` if you introduce / change environment variables here.
    for (key, value) in env::vars() {
        match &*key {
            "ATOMIC_CONFIG_FILE_PATH" => {
                config_file_path = value.parse().map_err(|e| {
                    format!(
                        "Could not parse ATOMIC_CONFIG_FILE_PATH. Is {} a valid path? {}",
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
        search_index_path,
    })
}
