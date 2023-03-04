use atomic_lib::{agents::generate_public_key, mapping::Mapping};
use atomic_lib::{agents::Agent, config::Config};
use atomic_lib::{errors::AtomicResult, Storelike};
use clap::{crate_version, Arg, ArgMatches, Command};
use colored::*;
use dirs::home_dir;
use std::{cell::RefCell, path::PathBuf, sync::Mutex};

use crate::print::SERIALIZE_OPTIONS;

mod commit;
mod new;
mod path;
mod print;

#[allow(dead_code)]
/// The Context contains all the data for executing a single CLI command, such as the passed arguments and the in memory store.
pub struct Context {
    store: atomic_lib::Store,
    mapping: Mutex<Mapping>,
    matches: ArgMatches,
    config_folder: PathBuf,
    user_mapping_path: PathBuf,
    /// A set of configuration options that are required for writing data on some server
    write: RefCell<Option<Config>>,
}

impl Context {
    /// Sets an agent
    pub fn get_write_context(&self) -> Config {
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
    match atomic_lib::config::read_config(&agent_config_path) {
        Ok(found) => Ok(found),
        Err(_e) => {
            println!(
                "No config found at {:?}. Let's create one!",
                &agent_config_path
            );
            let server = promptly::prompt("What's the base url of your Atomic Server?")?;
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
    let matches = Command::new("atomic-cli")
        .version(crate_version!())
        .author("Joep Meindertsma <joep@ontola.io>")
        .about("Create, share, fetch and model Atomic Data!")
        .after_help("Visit https://atomicdata.dev for more info")
        .arg_required_else_help(true)
        .subcommand(
            Command::new("new").about("Create a Resource")
            .arg(
                Arg::new("class")
                    .help("The URL or shortname of the Class that should be created")
                    .required(true),
            )
        )
        .subcommand(
            Command::new("get")
                    .about("Get a Resource or Value by using Atomic Paths.",
                    )
                    .after_help("\
                    Traverses a Path and prints the resulting Resource or Value. \n\n\
                    Examples: \n\n\
                    $ atomic get class https://atomicdata.dev/properties/description\n\
                    $ atomic get class description\n\
                    $ atomic get https://example.com \n\n\
                    Visit https://docs.atomicdata.dev/core/paths.html for more info about paths. \
                    ")
                .arg(Arg::new("path")
                    .help("\
                    The subject URL, shortname or path to be fetched. \
                    Use quotes for paths. \
                    You can use Bookmarks instead of a full subject URL. \
                    ",
                    )
                    .required(true)
                    .num_args(1..)
                )
                .arg(Arg::new("as")
                    .long("as")
                    .value_parser(SERIALIZE_OPTIONS)
                    .default_value("pretty")
                    .help("Serialization format")
                    .num_args(1)
                )
        )
        .subcommand(
            Command::new("set")
                .about("Update a single Atom. Creates both the Resource if they don't exist. Overwrites existing.")
                .arg(Arg::new("subject")
                    .help("Subject URL or bookmark of the resource")
                    .required(true)
                )
                .arg(Arg::new("property")
                    .help("Property URL or shortname of the property")
                    .required(true)
                )
                .arg(Arg::new("value")
                    .help("String representation of the Value to be changed")
                    .required(true)
                )
        )
        .subcommand(
            Command::new("remove")
                .about("Remove a single Atom from a Resource.")
                .arg(Arg::new("subject")
                    .help("Subject URL or bookmark of the resource")
                    .required(true)
                )
                .arg(Arg::new("property")
                    .help("Property URL or shortname of the property to be deleted")
                    .required(true)
                )
        )
        .subcommand(
            Command::new("edit")
                .about("Edit a single Atom from a Resource using your text editor.")
                .arg(Arg::new("subject")
                    .help("Subject URL or bookmark of the resource")
                    .required(true)
                )
                .arg(Arg::new("property")
                    .help("Property URL or shortname of the property to be edited")
                    .required(true)
                )
        )
        .subcommand(
            Command::new("destroy")
                .about("Permanently removes a Resource.")
                .arg(Arg::new("subject")
                    .help("Subject URL or bookmark of the resource to be destroyed")
                    .required(true)
                )
        )
        .subcommand(Command::new("list").about("List all bookmarks"))
        .subcommand(Command::new("validate").about("Validates the store").hide(true))
        .get_matches();

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
        matches,
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
    match context.matches.subcommand_name() {
        Some("destroy") => {
            commit::destroy(context)?;
        }
        Some("edit") => {
            #[cfg(feature = "native")]
            {
                commit::edit(context)?;
            }
            #[cfg(not(feature = "native"))]
            {
                return Err("Feature not available. Compile with `native` feature.".into());
            }
        }
        Some("get") => {
            path::get_path(context)?;
        }
        Some("list") => {
            list(context);
        }
        Some("new") => {
            new::new(context)?;
        }
        Some("remove") => {
            commit::remove(context)?;
        }
        Some("set") => {
            commit::set(context)?;
        }
        Some("validate") => {
            validate(context);
        }
        Some(cmd) => {
            return Err(format!("{} is not a valid command. Run atomic --help", cmd).into())
        }
        None => println!("Run atomic --help for available commands"),
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
