use atomic_lib::serialize::Format;
use atomic_lib::{agents::generate_public_key, mapping::Mapping};
use atomic_lib::{agents::Agent, config::Config};
use atomic_lib::{errors::AtomicResult, Storelike};
use clap::{crate_version, Parser, Subcommand, ValueEnum};
use colored::*;
use dirs::home_dir;
use std::{cell::RefCell, path::PathBuf, sync::Mutex};

mod commit;
mod new;
mod path;
mod print;
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
        /// The subject URL, shortname or path to be fetched
        #[arg(required = true, num_args = 1..)]
        path: Vec<String>,

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
    },
    /// List all bookmarks
    List,
    /// Validates the store
    #[command(hide = true)]
    Validate,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum SerializeOptions {
    Pretty,
    Json,
    NTriples,
}

impl From<&SerializeOptions> for Format {
    fn from(val: &SerializeOptions) -> Self {
        match val {
            SerializeOptions::Pretty => Format::Pretty,
            SerializeOptions::Json => Format::Json,
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
    write: RefCell<Option<Config>>,
}

impl Context {
    /// Returns the config (agent, key) from the user config dir
    pub fn read_config(&self) -> Config {
        if let Some(write_ctx) = self.write.borrow().as_ref() {
            return write_ctx.clone();
        };
        let write_ctx =
            set_agent_config().expect("Issue while generating write context / agent configuration");
        self.write.borrow_mut().replace(write_ctx.clone());
        self.store.set_default_agent(Agent {
            subject: write_ctx.agent.clone(),
            private_key: Some(write_ctx.private_key.clone()),
            created_at: atomic_lib::utils::now(),
            name: None,
            public_key: generate_public_key(&write_ctx.private_key).public,
        });
        write_ctx
    }
}

/// Reads config files for writing data, or promps the user if they don't yet exist
fn set_agent_config() -> CLIResult<Config> {
    let agent_config_path = atomic_lib::config::default_config_file_path()?;
    match atomic_lib::config::read_config(Some(&agent_config_path)) {
        Ok(found) => Ok(found),
        Err(_e) => {
            println!(
                "No config found at {:?}. Let's create one!",
                &agent_config_path
            );
            let server: String = promptly::prompt("What's the base url of your Atomic Server?")?;
            let agent = promptly::prompt("What's the URL of your Agent?")?;
            let private_key = promptly::prompt("What's the private key of this Agent?")?;
            let config = atomic_lib::config::Config {
                server,
                agent,
                private_key,
            };
            atomic_lib::config::write_config(&agent_config_path, config.clone())?;
            println!("New config file created at {:?}", agent_config_path);
            Ok(config)
        }
    }
}

fn main() -> AtomicResult<()> {
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
    let store = atomic_lib::Store::init()?;
    // Add some default data / common properties to speed things up
    store.populate()?;

    let mut context = Context {
        mapping: Mutex::new(mapping),
        store,
        matches: cli.command,
        config_folder,
        user_mapping_path,
        write: RefCell::new(None),
    };

    match exec_command(&mut context) {
        Ok(r) => r,
        Err(e) => {
            eprint!("{}", e);
            std::process::exit(1);
        }
    };

    Ok(())
}

fn exec_command(context: &mut Context) -> AtomicResult<()> {
    let command = context.matches.clone();

    match command {
        Commands::Destroy { subject } => {
            commit::destroy(context, &subject)?;
        }
        Commands::Edit { subject, property } => {
            #[cfg(feature = "native")]
            {
                commit::edit(context, &subject, &property)?;
            }
            #[cfg(not(feature = "native"))]
            {
                return Err("Feature not available. Compile with `native` feature.".into());
            }
        }
        Commands::Get { path, as_ } => {
            path::get_path(context, &path, &as_)?;
        }
        Commands::List => {
            list(context);
        }
        Commands::New { class } => {
            new::new(context, &class)?;
        }
        Commands::Remove { subject, property } => {
            commit::remove(context, &subject, &property)?;
        }
        Commands::Set {
            subject,
            property,
            value,
        } => {
            commit::set(context, &subject, &property, &value)?;
        }
        Commands::Search { query } => {
            search::search(context, query)?;
        }
        Commands::Validate => {
            validate(context);
        }
    };
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
fn validate(context: &mut Context) {
    let reportstring = context.store.validate().to_string();
    println!("{}", reportstring);
}

pub type CLIResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;
