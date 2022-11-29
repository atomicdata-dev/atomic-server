//! Parse CLI options, setup on boot, read .env values

use crate::errors::AtomicServerResult;
use clap::Parser;
use dotenv::dotenv;
use std::env;
use std::net::IpAddr;
use std::path::PathBuf;

/// Store and share Atomic Data! Visit https://atomicdata.dev for more info. Pass no subcommands to launch the server. The `.env` of your current directory will be read.
#[derive(Clone, Parser, Debug)]
#[clap(about, author, version)]
pub struct Opts {
    /// The subcommand being run
    #[clap(subcommand)]
    pub command: Option<Command>,

    /// Recreates the `/setup` Invite for creating a new Root User. Also re-runs various populate commands, and re-builds the index
    #[clap(long, env = "ATOMIC_INITIALIZE")]
    pub initialize: bool,

    /// Re-builds the indexes. Parses all the resources.
    /// Do this when updating requires it, or if you have issues with Collections / Queries / Search.
    #[clap(long, env = "ATOMIC_REBUILD_INDEX")]
    pub rebuild_indexes: bool,

    /// Use staging environments for services like LetsEncrypt
    #[clap(long, env = "ATOMIC_DEVELOPMENT")]
    pub development: bool,

    /// The origin domain where the app is hosted, without the port and schema values.
    #[clap(long, default_value = "localhost", env = "ATOMIC_DOMAIN")]
    pub domain: String,

    // 9.883 is decimal for the `⚛` character.
    /// The port where the HTTP app is available. Set to 80 if you want this to be available on the network.
    #[clap(short, long, default_value = "9883", env = "ATOMIC_PORT")]
    pub port: u32,

    /// The port where the HTTPS app is available. Set to 443 if you want this to be available on the network.
    #[clap(
        long,
        default_value = "9884",
        env = "ATOMIC_PORT_HTTPS",
        requires = "https"
    )]
    pub port_https: u32,

    /// The IP address of the server. Set to :: if you want this to be available to other devices on your network.
    #[clap(long, default_value = "::", env = "ATOMIC_IP")]
    pub ip: IpAddr,

    /// Use HTTPS instead of HTTP.
    /// Will get certificates from LetsEncrypt fully automated.
    #[clap(long, env = "ATOMIC_HTTPS")]
    pub https: bool,

    /// Initializes DNS-01 challenge for LetsEncrypt. Use this if you want to use subdomains.
    #[clap(long, env = "ATOMIC_HTTPS_DNS", requires = "https")]
    pub https_dns: bool,

    /// The contact mail address for Let's Encrypt HTTPS setup
    #[clap(long, env = "ATOMIC_EMAIL")]
    pub email: Option<String>,

    /// Custom JS script to include in the body of the HTML template
    #[clap(long, default_value = "", env = "ATOMIC_SCRIPT")]
    pub script: String,

    /// Path for atomic data config directory. Defaults to "~/.config/atomic/""
    #[clap(long, env = "ATOMIC_CONFIG_DIR")]
    pub config_dir: Option<PathBuf>,

    /// Path for atomic data store folder. Contains your Store, uploaded files and more. Default value depends on your OS.
    #[clap(long, env = "ATOMIC_DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    /// CAUTION: Skip authentication checks, making all data publicly readable. Improves performance.

    #[clap(long, env = "ATOMIC_PUBLIC_MODE")]
    pub public_mode: bool,

    /// The full URL of the server. It should resolve to the home page. Set this if you use an external server or tunnel, instead of directly exposing atomic-server. If you leave this out, it will be generated from `domain`, `port` and `http` / `https`.
    #[clap(long, env = "ATOMIC_SERVER_URL")]
    pub server_url: Option<String>,

    /// How much logs you want. Also influences what is sent to your trace service, if you've set one (e.g. OpenTelemetry)
    #[clap(value_enum, long, default_value = "info", env = "RUST_LOG")]
    pub log_level: LogLevel,

    /// How you want to trace what's going on with the server. Useful for monitoring performance and errors in production.
    /// Combine with `log_level` to get more or less data (`trace` is the most verbose)
    #[clap(value_enum, long, env = "ATOMIC_TRACING", default_value = "stdout")]
    pub trace: Tracing,

    /// Add this if you want so send e-mails (e.g. on user registration)
    #[clap(long, env = "ATOMIC_SMTP_HOST")]
    pub smpt_host: Option<String>,

    /// Useful for debugging e-mails during development, or if your SMTP server has an unconventional port number.
    #[clap(long, env = "ATOMIC_SMTP_PORT", default_value = "25")]
    pub smpt_port: u16,

    /// If you want to parse options from a specific .env file. By default reads the `./.env` file.
    #[clap(long)]
    pub env_file: Option<PathBuf>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Tracing {
    /// Log to STDOUT in your terminal
    Stdout,
    /// Create a file in the current directory with tracing data, that can be opened with the chrome://tracing/ URL
    Chrome,
    /// Log to a local OpenTelemetry service (e.g. Jaeger), using default ports
    Opentelemetry,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum LogLevel {
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Parser, Clone, Debug)]
pub enum Command {
    /// Create and save a JSON-AD backup of the store.
    #[clap(name = "export")]
    Export(ExportOpts),
    /// Import a JSON-AD file or stream to the store. By default creates Commits for all changes, maintaining version history. Use --force to allow importing other types of files.
    #[clap(name = "import", trailing_var_arg = true)]
    Import(ImportOpts),
    /// Creates a `.env` file in your current directory that shows various options that you can set.
    #[clap(name = "generate-dotenv")]
    CreateDotEnv,
    /// Returns the currently selected options, based on the passed flags and parsed environment variables.
    #[clap(name = "show-config")]
    ShowConfig,
    /// Danger! Removes all data from the store.
    #[clap(name = "reset")]
    Reset,
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
    /// Path of the file to be imported.
    #[clap(long)]
    pub file: PathBuf,
    /// The URL of the  Importer (parent) Resource to be used.
    /// This will set the hierarchical location of the imported items.
    /// If not passed, the default Importer `/import` will be used.
    #[clap(long)]
    pub parent: Option<String>,
    /// Skip checks, allows for importing things like Commits.
    #[clap(long)]
    pub force: bool,
}

/// Start atomic-server, oi mate
#[derive(Parser, Clone, Debug)]
pub struct ServerOpts {}

/// Configuration for the server.
/// These values are set when the server initializes, and do not change while running.
/// These are constructed from [Opts], which in turn are constructed from CLI arguments and ENV variables.
#[derive(Clone, Debug)]
pub struct Config {
    /// Full domain + schema, e.g. `https://example.com`. Is either generated from `domain` and `schema`, or is the `custom_server_url`.
    pub server_url: String,
    /// CLI + ENV options
    pub opts: Opts,
    // ===  PATHS  ===
    /// Path for atomic data config. Used to construct most other paths.
    pub config_dir: PathBuf,
    /// Path where TLS key should be stored for HTTPS.
    pub key_path: PathBuf,
    /// Path where TLS certificate should be stored for HTTPS.
    pub cert_path: PathBuf,
    /// Path where TLS certificates should be stored for HTTPS.
    pub https_path: PathBuf,
    /// Path where config.toml is located, which contains info about the Agent
    pub config_file_path: PathBuf,
    /// Path where the public static files folder is located
    pub static_path: PathBuf,
    /// Path to where the store / database is located.
    pub store_path: PathBuf,
    /// Path to where the uploaded files are stored.
    pub uploads_path: PathBuf,
    /// Path to where the search index for tantivy full text search is located
    pub search_index_path: PathBuf,
    /// If true, the initialization scripts will be ran (create first Drive, Agent, indexing, etc)
    pub initialize: bool,
}

/// Parse .env and CLI options
pub fn read_opts() -> Opts {
    // Parse .env file (do this before parsing the CLI opts)
    dotenv().ok();

    // Parse CLI options, .env values, set defaults
    let mut opts = Opts::parse();
    if let Some(env_path) = &opts.env_file {
        dotenv::from_path(env_path)
            .unwrap_or_else(|_| panic!("Env file not found: {} ", env_path.display()));
        // Parse the opts again so the CLI opts override the .env file
        opts = Opts::parse();
    }
    opts
}

/// Creates the server config, reads .env values and sets defaults
pub fn build_config(opts: Opts) -> AtomicServerResult<Config> {
    // Directories & file system
    let project_dirs = directories::ProjectDirs::from("", "", "atomic-data")
        .expect("Could not find Project directories on your OS");

    // Persistent user data
    let data_dir = opts
        .data_dir
        .clone()
        .unwrap_or_else(|| project_dirs.data_dir().to_owned());
    let mut store_path = data_dir.clone();
    store_path.push("store");

    let mut uploads_path = data_dir.clone();
    uploads_path.push("uploads");

    let mut static_path = data_dir;
    static_path.push("static");

    // Config data
    let config_dir = if let Some(dir) = &opts.config_dir {
        dir.clone()
    } else {
        atomic_lib::config::default_config_dir_path()?
    };
    let mut config_file_path = config_dir.join("config.toml");

    let mut https_path = config_dir.clone();
    https_path.push("https");

    let mut cert_path = config_dir.clone();
    cert_path.push("https/cert.pem");

    let mut key_path = config_dir.clone();
    key_path.push("https/key.pem");

    // Cache data

    let cache_dir = project_dirs.cache_dir();

    let mut search_index_path = cache_dir.to_owned();
    search_index_path.push("search_index");

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
            "The `--email` flag (or ATOMIC_EMAIL env) is required for getting an HTTPS certificate from letsencrypt.org."
                .into(),
        );
    }

    let schema = if opts.https { "https" } else { "http" };

    // This logic could be a bit too complicated, but I'm not sure on how to make this simpler.
    let server_url = if let Some(addr) = opts.server_url.clone() {
        addr
    } else if opts.https && opts.port_https == 443 || !opts.https && opts.port == 80 {
        format!("{}://{}", schema, opts.domain)
    } else {
        format!("{}://{}:{}", schema, opts.domain, opts.port)
    };

    Ok(Config {
        initialize,
        opts,
        cert_path,
        config_dir,
        config_file_path,
        https_path,
        key_path,
        server_url,
        static_path,
        store_path,
        search_index_path,
        uploads_path,
    })
}
