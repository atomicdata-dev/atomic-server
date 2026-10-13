use atomic_lib::agents::Agent;
use atomic_lib::config::ClientConfig;
use atomic_lib::config::Config;
use atomic_lib::mapping::Mapping;
use atomic_lib::serialize::Format;
use atomic_lib::{errors::AtomicResult, Storelike};
use clap::{crate_version, Parser, Subcommand, ValueEnum};
use colored::*;
use dirs::home_dir;
use std::{path::PathBuf, sync::Mutex};

mod commit;
mod connect;
mod get;
mod new;
mod print;
mod schema;
mod search;

#[derive(Parser)]
#[command(
    name = "atomic-cli",
    version = crate_version!(),
    author = "Joep Meindertsma <joep@ontola.io>",
    about = "Create, share, fetch and model Atomic Data!",
    after_help = "Visit https://atomicdata.dev for more info",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Clone)]
enum Commands {
    /// Create a Resource
    New {
        /// The URL or shortname of the Class that should be created
        #[arg(required = true)]
        class: String,
    },
    /// Get a Resource or Value by using Atomic Paths
    #[command(after_help = "\
        Traverses a Path and prints the resulting Resource or Value. \n\n\
        Examples: \n\n\
        $ atomic get class https://atomicdata.dev/properties/description\n\
        $ atomic get class description\n\
        $ atomic get https://example.com \n\n\
        Visit https://docs.atomicdata.dev/core/paths.html for more info about paths. \
    ")]
    Get {
        /// The subject URL
        #[arg(required = true)]
        subject: String,

        /// Serialization format
        #[arg(long, value_enum, default_value = "pretty")]
        as_: SerializeOptions,
    },
    /// Update a single Atom. Creates both the Resource if they don't exist. Overwrites existing.
    Set {
        /// Subject URL or bookmark of the resource
        #[arg(required = true)]
        subject: String,

        /// Property URL or shortname of the property
        #[arg(required = true)]
        property: String,

        /// String representation of the Value to be changed
        #[arg(required = true)]
        value: String,
    },
    /// Remove a single Atom from a Resource.
    Remove {
        /// Subject URL or bookmark of the resource
        #[arg(required = true)]
        subject: String,

        /// Property URL or shortname of the property to be deleted
        #[arg(required = true)]
        property: String,
    },
    /// Edit a single Atom from a Resource using your text editor.
    Edit {
        /// Subject URL or bookmark of the resource
        #[arg(required = true)]
        subject: String,

        /// Property URL or shortname of the property to be edited
        #[arg(required = true)]
        property: String,
    },
    /// Permanently removes a Resource.
    Destroy {
        /// Subject URL or bookmark of the resource to be destroyed
        #[arg(required = true)]
        subject: String,
    },
    /// Full text search
    Search {
        /// The search query
        #[arg(required = true)]
        query: String,
        /// Subject URL of the parent Resource to filter by
        #[arg(long)]
        parent: Option<String>,
        /// Server URL to search on
        /// Will query this + `/search` if provided.
        /// Defaults to the server in the config.
        #[arg(long)]
        server: Option<String>,
        /// Serialization format
        #[arg(long, value_enum, default_value = "pretty")]
        as_: SerializeOptions,
    },
    /// Make a schema file a real ontology, and pin its property IDs in a lockfile
    #[command(after_help = "\
        Reads a JSON Schema or an ontology JSON ({ shortname, classes }). \n\n\
        Examples: \n\n\
        $ atomic-cli schema push shop.schema.json --parent <drive subject>\n\
        $ atomic-cli schema lock shop.schema.json --ontology <ontology subject>\n\
        $ atomic-cli schema check shop.schema.json \n\n\
        The lockfile is written next to the schema file as <file>.lock.json. \
    ")]
    Schema {
        #[command(subcommand)]
        command: SchemaCommands,
    },
    /// List all bookmarks
    List,
    /// Validates the store
    #[command(hide = true)]
    Validate,
    /// Print the current agent
    Agent,
    /// Connect this machine with its own key, approved in the app. Your agent
    /// secret is never needed.
    #[command(after_help = "\
        Makes a key on this machine and prints a link to your Atomic app. There \
        you pick which drives it may reach and whether it may edit, and click \
        Allow. Revoke it any time under Connected apps in your account settings.\
    ")]
    Connect {
        /// The server your drives live on, e.g. https://atomicdata.dev
        #[arg(long)]
        server: Option<String>,
        /// Where the app runs, for the approval link. Defaults to --server.
        #[arg(long)]
        app: Option<String>,
        /// The name you see in the app. Defaults to "atomic-cli on <host>".
        #[arg(long)]
        name: Option<String>,
        /// Ask for edit rights too. You still decide in the app.
        #[arg(long)]
        write: bool,
    },
}

#[derive(Subcommand, Clone)]
enum SchemaCommands {
    /// Create or update the ontology on the configured server, and write the lockfile
    Push {
        /// A JSON Schema or an ontology JSON file
        #[arg(required = true)]
        file: PathBuf,
        /// Subject of the resource (usually a drive) that holds the ontology.
        /// Defaults to the initial drive in the config.
        #[arg(long)]
        parent: Option<String>,
        /// The ontology's shortname. Defaults to the one in the file.
        #[arg(long)]
        shortname: Option<String>,
        /// Lockfile path. Defaults to <file>.lock.json
        #[arg(long)]
        lockfile: Option<PathBuf>,
        /// Push even if the lockfile no longer matches the schema (new properties are made)
        #[arg(long)]
        accept_changes: bool,
    },
    /// Offline: write the lockfile for an ontology whose subject you already know
    Lock {
        /// A JSON Schema or an ontology JSON file
        #[arg(required = true)]
        file: PathBuf,
        /// Subject of the Ontology resource
        #[arg(long, required = true)]
        ontology: String,
        /// The ontology's shortname. Defaults to the one in the file.
        #[arg(long)]
        shortname: Option<String>,
        /// Lockfile path. Defaults to <file>.lock.json
        #[arg(long)]
        lockfile: Option<PathBuf>,
    },
    /// Offline: fail if the lockfile no longer matches the schema
    Check {
        /// A JSON Schema or an ontology JSON file
        #[arg(required = true)]
        file: PathBuf,
        /// The ontology's shortname. Defaults to the one in the file.
        #[arg(long)]
        shortname: Option<String>,
        /// Lockfile path. Defaults to <file>.lock.json
        #[arg(long)]
        lockfile: Option<PathBuf>,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum SerializeOptions {
    Pretty,
    Json,
    JsonAd,
    NTriples,
}

impl From<SerializeOptions> for Format {
    fn from(val: SerializeOptions) -> Self {
        match val {
            SerializeOptions::Pretty => Format::Pretty,
            SerializeOptions::Json => Format::Json,
            SerializeOptions::JsonAd => Format::JsonAd,
            SerializeOptions::NTriples => Format::NTriples,
        }
    }
}

#[allow(dead_code)]
/// The Context contains all the data for executing a single CLI command, such as the passed arguments and the in memory store.
pub struct Context {
    store: atomic_lib::Store,
    mapping: Mutex<Mapping>,
    matches: Commands,
    config_folder: PathBuf,
    user_mapping_path: PathBuf,
    /// A set of configuration options that are required for writing data on some server
    write: Mutex<Option<Config>>,
}

impl Context {
    /// Returns the config (agent, key) from the user config dir
    pub fn read_config(&self) -> Config {
        if let Some(write_ctx) = self.write.lock().unwrap().as_ref() {
            return write_ctx.clone();
        };
        let write_ctx =
            set_agent_config().expect("Issue while generating write context / agent configuration");
        self.write.lock().unwrap().replace(write_ctx.clone());
        let agent = Agent::from_secret(&write_ctx.shared.agent_secret).unwrap();
        self.store.set_default_agent(agent);
        self.store
            .set_base_url(&write_ctx.client.clone().unwrap().server_url);

        write_ctx
    }
}

/// Reads config files for writing data, or promps the user if they don't yet exist
fn set_agent_config() -> CLIResult<Config> {
    let agent_config_path = atomic_lib::config::default_config_file_path()?;
    match atomic_lib::config::read_config(Some(&agent_config_path)) {
        Ok(found) => {
            prompt_for_missing_config_values(&found)?;
            Ok(found)
        }
        Err(_e) => {
            Err(format!(
                "No config found at {:?}. Run `atomic-cli connect --server <your server>` to connect this machine.",
                agent_config_path
            )
            .into())
        }
    }
}

fn prompt_for_missing_config_values(config: &Config) -> AtomicResult<Config> {
    if config.client.is_none() {
        println!("No server url found in config.");
        let server = promptly::prompt("What's the base url of your Atomic Server?")
            .map_err(|e| format!("Invalid input: {}", e))?;
        let config = Config {
            client: Some(ClientConfig { server_url: server }),
            ..config.clone()
        };
        config.save(&atomic_lib::config::default_config_file_path()?)?;

        return Ok(config);
    }

    Ok(config.clone())
}

#[tokio::main]
async fn main() -> AtomicResult<()> {
    let cli = Cli::parse();

    let config_folder = home_dir()
        .expect("Home dir could not be opened. We need this to store some configuration files.")
        .join(".config/atomic/");

    // The mapping holds shortnames and URLs for quick CLI usage
    let mut mapping: Mapping = Mapping::init();
    let user_mapping_path = config_folder.join("mapping.amp");
    if !user_mapping_path.exists() {
        mapping.populate()?;
    } else {
        mapping.read_mapping_from_file(&user_mapping_path)?;
    }

    // Initialize an in-memory store
    let store = atomic_lib::Store::init().await?;
    // Add some default data / common properties to speed things up
    store.populate().await?;

    let mut context = Context {
        mapping: Mutex::new(mapping),
        store,
        matches: cli.command,
        config_folder,
        user_mapping_path,
        write: Mutex::new(None),
    };

    match exec_command(&mut context).await {
        Ok(r) => r,
        Err(e) => {
            eprint!("{}", e);
            std::process::exit(1);
        }
    };

    Ok(())
}

async fn exec_command(context: &mut Context) -> AtomicResult<()> {
    let command = context.matches.clone();

    match command {
        Commands::Destroy { subject } => {
            commit::destroy(context, &subject).await?;
        }
        #[cfg(feature = "native")]
        Commands::Edit { subject, property } => {
            commit::edit(context, &subject, &property).await?;
        }
        #[cfg(not(feature = "native"))]
        Commands::Edit { .. } => {
            return Err("Feature not available. Compile with `native` feature.".into());
        }
        Commands::Get { subject, as_ } => {
            get::get_resource(context, &subject, &as_).await?;
        }
        Commands::List => {
            list(context);
        }
        Commands::New { class } => {
            new::new(context, &class).await?;
        }
        Commands::Remove { subject, property } => {
            commit::remove(context, &subject, &property).await?;
        }
        Commands::Set {
            subject,
            property,
            value,
        } => {
            commit::set(context, &subject, &property, &value).await?;
        }
        Commands::Schema { command } => match command {
            SchemaCommands::Push {
                file,
                parent,
                shortname,
                lockfile,
                accept_changes,
            } => {
                schema::push(context, &file, parent, shortname, lockfile, accept_changes).await?;
            }
            SchemaCommands::Lock {
                file,
                ontology,
                shortname,
                lockfile,
            } => {
                let path = schema::lock(&file, &ontology, shortname, lockfile)?;
                println!("Lockfile written to {}", path.display());
            }
            SchemaCommands::Check {
                file,
                shortname,
                lockfile,
            } => {
                schema::check(&file, shortname, lockfile)?;
                println!("{}", "Lockfile matches the schema".green());
            }
        },
        Commands::Search {
            query,
            parent,
            server,
            as_,
        } => {
            search::search(context, query, parent, server, &as_).await?;
        }
        Commands::Validate => {
            validate(context).await;
        }
        Commands::Connect {
            server,
            app,
            name,
            write,
        } => {
            connect_command(context, server, app, name, write).await?;
        }
        Commands::Agent => {
            let config = context.read_config();
            let agent = Agent::from_secret(&config.shared.agent_secret).unwrap();
            println!("{}", agent.subject);
        }
    };
    Ok(())
}

async fn connect_command(
    context: &mut Context,
    server: Option<String>,
    app: Option<String>,
    name: Option<String>,
    write: bool,
) -> AtomicResult<()> {
    let path = atomic_lib::config::default_config_file_path()?;
    if path.exists() {
        // The same file can hold a local server's own agent: never replace it
        // without asking.
        let replace: bool = promptly::prompt_default(
            format!("{:?} already exists. Replace it with the new key?", path),
            false,
        )
        .map_err(|e| format!("Invalid input: {}", e))?;
        if !replace {
            return Err("Kept the existing config.".into());
        }
    }
    let server = match server {
        Some(s) => s,
        None => promptly::prompt("What's the base url of your Atomic Server?")
            .map_err(|e| format!("Invalid input: {}", e))?,
    };
    let name = name.unwrap_or_else(|| {
        let host = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_default();
        if host.is_empty() {
            "atomic-cli".into()
        } else {
            format!("atomic-cli on {host}")
        }
    });
    let config = connect::connect(
        &context.store,
        connect::ConnectOpts {
            server,
            app,
            name,
            write,
        },
    )
    .await?;
    config.save(&path)?;
    println!(
        "\nConnected. The key is stored in {:?}.\nRevoke it any time under Connected apps in your account settings.",
        path
    );
    Ok(())
}

/// List all bookmarks
fn list(context: &mut Context) {
    let mut string = String::new();
    for (shortname, url) in context.mapping.lock().unwrap().clone().into_iter() {
        string.push_str(&format!(
            "{0: <15}{1: <10} \n",
            shortname.blue().bold(),
            url
        ));
    }
    println!("{}", string)
}

/// Validates the store
async fn validate(context: &mut Context) {
    let reportstring = context.store.validate().await.to_string();
    println!("{}", reportstring);
}

pub type CLIResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;
