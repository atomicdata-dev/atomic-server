use clap::Parser;
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
    #[clap(long, env = "ATOMIC_INITIALIZE")]
    pub initialize: bool,
    /// Re-creates the value index. Parses all the resources. Do this if your collections have issues.
    #[clap(long, env = "ATOMIC_REBUILD_INDEX")]
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
    /// Use HTTPS instead of HTTP.
    /// Will get certificates from LetsEncrypt.
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
    /// CAUTION: Makes data public on the `/search` endpoint. When enabled, it allows POSTing to the /search endpoint and returns search results as single triples, without performing authentication checks. See https://github.com/joepio/atomic-data-rust/blob/master/server/rdf-search.md
    #[clap(long, env = "ATOMIC_RDF_SEARCH")]
    pub rdf_search: bool,
    /// By default, Atomic-Server keeps previous verions of resources indexed in Search. When enabling this flag, previous versions of resources are removed from the search index when their values are updated.
    #[clap(long, env = "ATOMIC_REMOVE_PREVIOUS_SEARCH")]
    pub remove_previous_search: bool,
    /// CAUTION: Skip authentication checks, making all data public. Improves performance.
    #[clap(long, env = "ATOMIC_PUBLIC_MODE")]
    pub public_mode: bool,
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
