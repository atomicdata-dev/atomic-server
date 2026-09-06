//! Parse CLI options, setup on boot, read .env values

use crate::errors::AtomicServerResult;
use clap::Parser;
use dotenv::dotenv;
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

    /// Forces a re-import of the built-in ontologies and default server resources, ignoring the defaults fingerprint. Add-only (existing values are kept). Normally unnecessary: the store re-seeds itself on open whenever the built-in defaults changed.
    #[clap(long, env = "ATOMIC_REPOPULATE_DEFAULTS")]
    pub repopulate_defaults: bool,

    /// Re-builds the indexes. Parses all the resources.
    /// Do this when updating requires it, or if you have issues with Collections / Queries / Search.
    #[clap(value_enum, long, env = "ATOMIC_REBUILD_INDEX")]
    pub rebuild_indexes: Option<RebuildIndexMode>,

    /// Use staging environments for services like LetsEncrypt
    #[clap(long, env = "ATOMIC_DEVELOPMENT")]
    pub development: bool,

    /// Which signed commit envelopes this node keeps per resource: `latest`
    /// (the envelope that produced the current state; the default) or `all`
    /// (every envelope, so History shows a verified signer per change).
    #[clap(long, default_value = "latest", env = "ATOMIC_ENVELOPE_RETENTION")]
    pub envelope_retention: String,

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

    /// Path for the atomic data cache folder. Contains search index, temp files and more. Default value depends on your OS.
    #[clap(long, env = "ATOMIC_CACHE_DIR")]
    pub cache_dir: Option<PathBuf>,

    /// CAUTION: Skip authentication checks, making all data publicly readable. Improves performance.
    #[clap(long, env = "ATOMIC_PUBLIC_MODE")]
    pub public_mode: bool,

    /// How much logs you want. Also influences what is sent to your trace service, if you've set one (e.g. OpenTelemetry)
    #[clap(value_enum, long, default_value = "info", env = "RUST_LOG")]
    pub log_level: LogLevel,

    /// How you want to trace what's going on with the server. Useful for monitoring performance and errors in production.
    /// Combine with `log_level` to get more or less data (`trace` is the most verbose)
    #[clap(value_enum, long, env = "ATOMIC_TRACING", default_value = "stdout")]
    pub trace: Tracing,

    /// Sentry DSN for error reporting. When set, panics and `error!`-level
    /// tracing events are sent to Sentry, with HTTP request context and
    /// recent log lines as breadcrumbs. Leave unset to disable entirely.
    /// `SENTRY_ENVIRONMENT` (e.g. `staging`, `production`) and
    /// `SENTRY_RELEASE` are read from the environment as well.
    #[clap(long, env = "SENTRY_DSN")]
    pub sentry_dsn: Option<String>,

    /// Sentry DSN for the bundled data-browser front-end. Injected into the
    /// served HTML so the browser reports its own errors. Separate from
    /// `--sentry-dsn` because browser DSNs are public. Leave unset to serve
    /// a front-end that never contacts Sentry (the default).
    #[clap(long, env = "SENTRY_DSN_BROWSER")]
    pub sentry_dsn_browser: Option<String>,

    /// Introduces random delays in the server, to simulate a slow connection. Useful for testing.
    #[clap(long, env = "ATOMIC_SLOW_MODE")]
    pub slow_mode: bool,
    /// Removes all remote resources from the store.
    #[clap(long, env = "ATOMIC_CLEAR_REMOTE_CACHE")]
    pub clear_remote_cache: bool,

    /// The base domain for multi-tenant hosting.
    /// If set, the server will allow serving subdomains of this domain (e.g. *.atomicserver.eu).
    #[clap(long, env = "ATOMIC_BASE_DOMAIN")]
    pub base_domain: Option<String>,

    /// Serve one Drive as this server's front page.
    ///
    /// Set this to a Drive's subject (e.g. `internal:/` for the Drive at the
    /// server root, or a `did:ad:drive:...`) and visiting `/` opens that Drive
    /// directly — for signed-out visitors too. This is what you want when the
    /// server hosts a single site or wiki that the public should just see.
    ///
    /// Unset by default. Without it, `/` sends visitors without an Agent to the
    /// sign-in / welcome flow, which is the right behaviour for a multi-tenant
    /// server where the root is not a Drive, or not one everybody may read.
    ///
    /// The value is injected into the served HTML, so the browser routes to it
    /// on the first render without an extra request. Make sure the Drive is
    /// readable by the public Agent, or signed-out visitors will get an
    /// authorization error instead of the front page.
    #[clap(long, env = "ATOMIC_HOME_DRIVE")]
    pub home_drive: Option<String>,

    /// Friendly display name exchanged with other Atomic nodes on peer sync
    /// (`HELLO` frame). Pure display — never used for authorization. Defaults
    /// to the OS hostname if unset, then to "Unknown" if that fails.
    #[clap(long, env = "ATOMIC_DEVICE_NAME")]
    pub device_name: Option<String>,

    /// Who may create a **new** Drive on this node.
    ///
    /// `open` (the default) lets anyone who can reach the server create an
    /// account and store their data here. That is right for localhost and for a
    /// node you deliberately share with others; on a public address it is an
    /// open registration form for space on your disk.
    ///
    /// `owner` allows only the Agent named in `--owner-agent`. Reading what you
    /// shared, invited collaborators, and your own other devices are unaffected.
    ///
    /// Left unset, naming an `--owner-agent` selects `owner`.
    #[clap(value_enum, long, env = "ATOMIC_HOST_MODE")]
    pub host_mode: Option<crate::host_mode::HostMode>,

    /// The Agent ID that owns this node, e.g. `did:ad:agent:...`.
    ///
    /// The public ID only — never the secret. This node does not sign as you; it
    /// only recognises you. Copy it from Settings in any Atomic client, or from
    /// the `subject` field of your saved secret.
    #[clap(long, env = "ATOMIC_OWNER_AGENT")]
    pub owner_agent: Option<String>,
    /// Use the GPU (if available) for processing vector search embeddings.
    #[clap(long, env = "ATOMIC_GPU_INDEXING")]
    pub gpu_indexing: bool,

    /// OpenRouter API key for remote embeddings instead of local fastembed.
    #[clap(long, env = "OPENROUTER_API_KEY")]
    pub openrouter_api_key: Option<String>,

    /// OpenRouter embedding model id (required when `OPENROUTER_API_KEY` is set).
    #[clap(long, env = "OPENROUTER_EMBEDDING_MODEL")]
    pub openrouter_embedding_model: Option<String>,

    /// Optional embedding vector dimensions for OpenRouter (JSON `dimensions` field; not all models honor it). Empty string is treated as unset.
    #[clap(long, env = "OPENROUTER_EMBEDDING_DIMENSIONS")]
    pub openrouter_embedding_dimensions: Option<String>,

    /// Opt in to vector embedding models and Lance index builds for semantic search.
    /// Off by default: loading embedding models and indexing every write has a real
    /// performance cost, so it should be a deliberate choice rather than the default.
    #[clap(long, env = "ATOMIC_ENABLE_VECTOR_INDEX")]
    pub enable_vector_index: bool,

    /// Deprecated: vector indexing is now off by default. Kept only so existing
    /// scripts/deployments that pass this flag keep working; it is a no-op unless
    /// combined with `--enable-vector-index`, in which case it forces indexing off again.
    #[clap(long, env = "ATOMIC_SKIP_VECTOR_INDEX")]
    pub skip_vector_index: bool,
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

#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
pub enum RebuildIndexMode {
    All,
    Atoms,
    Vector,
    Search,
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
    /// Compact the on-disk redb file (rebuilds page layout, truncates
    /// dead-page tail). Slow — typically minutes on a multi-GB store —
    /// but makes future boots dramatically faster because the open-time
    /// `fsync` cost scales with file size. Server MUST be stopped:
    /// redb takes an exclusive file lock and will fail otherwise.
    #[clap(name = "compact")]
    Compact,
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
    pub plugin_path: PathBuf,
    /// Path to where the uploaded files are stored.
    pub uploads_path: PathBuf,
    /// Unused. Previously the Tantivy mmap directory; FTS now lives in the KV store.
    pub search_index_path: PathBuf,
    /// Path to where the vector search index for polarisdb is located
    pub vector_search_index_path: PathBuf,
    pub plugin_cache_path: PathBuf,
    /// If true, the initialization scripts will be ran (create first Drive, Agent, indexing, etc)
    pub initialize: bool,
    /// The base domain for multi-tenant hosting.
    pub base_domain: Option<String>,
    /// If true, runs `populate_all` on startup without full initialize (no index rebuild).
    pub repopulate_defaults: bool,
    /// Use the GPU (if available) for processing vector search embeddings.
    pub gpu_indexing: bool,

    /// OpenRouter API key for remote embeddings (empty strings are treated as unset).
    pub openrouter_api_key: Option<String>,
    /// OpenRouter embedding model id (required when `openrouter_api_key` is set).
    pub openrouter_embedding_model: Option<String>,
    /// Optional embedding dimensions for OpenRouter.
    pub openrouter_embedding_dimensions: Option<u32>,
    /// When true, vector models are not loaded and indexing is a no-op.
    pub skip_vector_index: bool,
    /// Who may enroll a new Drive here. Resolved once at boot from explicit
    /// configuration; see [`crate::host_mode`] for why it is never guessed.
    pub host_mode: crate::host_mode::HostModeConfig,
}

impl Config {
    /// Returns the origin URL (scheme + domain + port) based on the configuration.
    pub fn get_origin(&self) -> String {
        let proto = if self.opts.https { "https" } else { "http" };
        let host = &self.opts.domain;
        let port = if self.opts.https {
            if self.opts.port_https == 443 {
                "".into()
            } else {
                format!(":{}", self.opts.port_https)
            }
        } else if self.opts.port == 80 {
            "".into()
        } else {
            format!(":{}", self.opts.port)
        };
        format!("{}://{}{}", proto, host, port)
    }

    /// Returns the base domain of the server (e.g. "atomicdata.dev").
    pub fn get_base_domain(&self) -> Option<String> {
        self.base_domain.clone()
    }

    /// Signals that this node was set up to be reached from outside. Used only
    /// to decide whether an Open node is warned at boot — never to pick the
    /// mode, which [`crate::host_mode`] explains at length.
    pub fn reachability(&self) -> crate::host_mode::Reachability {
        let port = if self.opts.https {
            self.opts.port_https
        } else {
            self.opts.port
        };

        crate::host_mode::Reachability {
            https: self.opts.https,
            public_domain: crate::host_mode::domain_looks_public(&self.opts.domain),
            web_port: matches!(port, 80 | 443),
        }
    }
}

/// True when the store path is under a throwaway test directory (e.g. `./.temp/...`).
fn store_path_looks_like_test_harness(store_path: &std::path::Path) -> bool {
    store_path.components().any(|c| c.as_os_str() == ".temp")
}

/// Parse .env and CLI options
pub fn read_opts() -> Opts {
    // Parse .env file (do this before parsing the CLI opts)

    match dotenv() {
        Ok(_) => println!(".env file found and parsed"),
        Err(_e) => (),
    }

    // Parse CLI options, .env values, set defaults
    Opts::parse()
}

pub fn build_temp_config(random_id: &str) -> AtomicServerResult<Config> {
    let opts = Opts::parse_from([
        "atomic-server",
        "--initialize",
        "--data-dir",
        &format!("./.temp/{}/db", random_id),
        "--config-dir",
        &format!("./.temp/{}/config", random_id),
        "--cache-dir",
        &format!("./.temp/{}/cache", random_id),
    ]);

    build_config(opts)
}

/// Creates the server config, reads .env values and sets defaults
pub fn build_config(opts: Opts) -> AtomicServerResult<Config> {
    // Directories & file system
    // Only resolve platform-specific dirs when not explicitly set (avoids panic on Android)
    let get_project_dirs = || directories::ProjectDirs::from("", "", "atomic-data");

    // Persistent user data
    let data_dir = match opts.data_dir.clone() {
        Some(dir) => dir,
        None => get_project_dirs()
            .map(|d| d.data_dir().to_owned())
            .unwrap_or_else(|| PathBuf::from("atomic-data/data")),
    };
    let mut store_path = data_dir.clone();
    store_path.push("store");

    let mut plugin_path = data_dir.clone();
    plugin_path.push("plugins");

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
    let config_file_path = config_dir.join("config.toml");

    let mut https_path = config_dir.clone();
    https_path.push("https");

    let mut cert_path = config_dir.clone();
    cert_path.push("https/cert.pem");

    let mut key_path = config_dir.clone();
    key_path.push("https/key.pem");

    // Cache data

    let cache_dir = match opts.cache_dir.clone() {
        Some(dir) => dir,
        None => get_project_dirs()
            .map(|d| d.cache_dir().to_owned())
            .unwrap_or_else(|| PathBuf::from("atomic-data/cache")),
    };

    let mut search_index_path = cache_dir.clone();
    search_index_path.push("search_index");

    let mut vector_search_index_path = cache_dir.clone();
    vector_search_index_path.push("vector_search_index");

    let mut plugin_cache_path = cache_dir.clone();
    plugin_cache_path.push("plugin_cache");

    // Keep search/vector indexes beside throwaway test stores so parallel `cargo test`
    // runs do not share the production cache dir (Tantivy lock contention, Lance dim mismatch).
    if opts.cache_dir.is_none() && store_path_looks_like_test_harness(&store_path) {
        let test_root = store_path
            .parent()
            .expect("test store path should have a parent directory");
        search_index_path = test_root.join("search_index");
        vector_search_index_path = test_root.join("vector_search_index");
    }

    let initialize = !std::path::Path::exists(&store_path) || opts.initialize;
    let repopulate_defaults = opts.repopulate_defaults;

    if opts.https & opts.email.is_none() {
        return Err(
            "The `--email` flag (or ATOMIC_EMAIL env) is required for getting an HTTPS certificate from letsencrypt.org."
                .into(),
        );
    }

    // Resolved before anything binds: Owner mode with an unusable owner must
    // fail here, not after the socket is open. Mirrors the `--https` without
    // `--email` refusal above.
    let host_mode = crate::host_mode::resolve(opts.host_mode, opts.owner_agent.as_deref())?;

    let base_domain = opts.base_domain.clone();

    let gpu_indexing = opts.gpu_indexing;

    let openrouter_api_key = opts.openrouter_api_key.clone().filter(|s| !s.is_empty());
    let openrouter_embedding_model = opts
        .openrouter_embedding_model
        .clone()
        .filter(|s| !s.is_empty());
    let openrouter_embedding_dimensions = match opts.openrouter_embedding_dimensions.as_deref() {
        None | Some("") => None,
        Some(s) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.parse().map_err(|_| {
                    "OPENROUTER_EMBEDDING_DIMENSIONS must be a non-negative integer if set"
                })?)
            }
        }
    };

    let skip_vector_index = !opts.enable_vector_index
        || opts.skip_vector_index
        || cfg!(test)
        || store_path_looks_like_test_harness(&store_path);

    Ok(Config {
        host_mode,
        initialize,
        repopulate_defaults,
        gpu_indexing,
        openrouter_api_key,
        openrouter_embedding_model,
        openrouter_embedding_dimensions,
        skip_vector_index,
        opts,
        cert_path,
        config_dir,
        config_file_path,
        https_path,
        key_path,
        plugin_path,
        static_path,
        store_path,
        search_index_path,
        vector_search_index_path,
        plugin_cache_path,
        uploads_path,
        base_domain,
    })
}
