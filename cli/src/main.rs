use atomic_lib::mapping::Mapping;
use atomic_lib::{errors::AtomicResult, Storelike};
use clap::{crate_version, App, AppSettings, Arg, ArgMatches, SubCommand};
use colored::*;
use dirs::home_dir;
use path::SERIALIZE_OPTIONS;
use std::{path::PathBuf, sync::Mutex};

mod commit;
mod delta;
mod new;
mod path;

#[allow(dead_code)]
pub struct Context<'a> {
    store: atomic_lib::Store,
    mapping: Mutex<Mapping>,
    matches: ArgMatches<'a>,
    config_folder: PathBuf,
    user_mapping_path: PathBuf,
    write: Option<WriteContext>,
}

impl Context<'_> {
    pub fn get_write_context(&self) -> WriteContext {
        match self.write {
            Some(_) => {
                self.write.clone().unwrap()
            }
            None => {
                panic!("No write context set");
            }
        }
    }
}

#[derive(Clone)]
pub struct WriteContext {
    /// URL of the Atomic Server to write to
    base_url: String,
    /// URL of the Author of Commits
    author_subject: String,
    /// Private key of the Author of Commits
    author_private_key: String,
}

fn main() -> AtomicResult<()> {
    let matches = App::new("atomic")
        .version(crate_version!())
        .author("Joep Meindertsma <joep@ontola.io>")
        .about("Create, share, fetch and model linked atomic data!")
        .after_help("Visit https://github.com/joepio/atomic for more info")
        .setting(AppSettings::ArgRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("new").about("Create a Resource")
            .arg(
                Arg::with_name("class")
                    .help("The URL or shortname of the Class that should be created")
                    .required(true),
            )
        )
        .subcommand(
            SubCommand::with_name("get")
                    .about("Traverses a Path and prints the resulting Resource or Value.",
                    )
                    .after_help("\
                    Traverses a Path and prints the resulting Resource or Value. \
                    Examples: \natomic get \"class description\"\natomic get \"https://example.com\"\n\
                    Visit https://docs.atomicdata.dev/core/paths.html for more info about paths. \
                    ")
                .arg(Arg::with_name("path")
                    .help("\
                    The subject URL, shortname or path to be fetched. \
                    Use quotes for paths. \
                    You can use Bookmarks instead of a full subject URL. \
                    ",
                    )
                    .required(true)
                )
                .arg(Arg::with_name("as")
                    .long("as")
                    .possible_values(&SERIALIZE_OPTIONS)
                    .default_value("pretty")
                    .help(&*format!("Serialization option ({:#?})", SERIALIZE_OPTIONS))
                    .takes_value(true)
                )
        )
        .subcommand(
            SubCommand::with_name("tpf")
                    .about("Finds Atoms using Triple Pattern Fragments",
                    )
                    .after_help("\
                    Filter the store by <subject> <property> and <value>. \
                    Use a dot to indicate that you don't need to filter. \
                    ")
                .arg(Arg::with_name("subject")
                    .help("The subject URL or bookmark to be filtered by. Use a dot '.' to indicate 'any'.")
                    .required(true)
                )
                .arg(Arg::with_name("property")
                    .help("The property URL or bookmark to be filtered by. Use a dot '.' to indicate 'any'.")
                    .required(true)
                )
                .arg(Arg::with_name("value")
                    .help("The value URL or bookmark to be filtered by. Use a dot '.' to indicate 'any'.")
                    .required(true)
                )
        )
        .subcommand(
            SubCommand::with_name("set")
                .about("Update an Atom's value. Writes a commit to the store using the current Agent.")
                .arg(Arg::with_name("subject")
                    .help("Subject URL or bookmark of the resourece")
                    .required(true)
                )
                .arg(Arg::with_name("property")
                    .help("Property URL or shortname of the property")
                    .required(true)
                )
                .arg(Arg::with_name("value")
                    .help("String representation of the Value to be changed")
                    .required(true)
                )
        )
        .subcommand(
            SubCommand::with_name("remove")
                .about("Remove a single Atom from a Resource. Writes a commit to the store using the current Agent.")
                .arg(Arg::with_name("subject")
                    .help("Subject URL or bookmark of the resource")
                    .required(true)
                )
                .arg(Arg::with_name("property")
                    .help("Property URL or shortname of the property to be deleted")
                    .required(true)
                )
        )
        .subcommand(
            SubCommand::with_name("destroy")
                .about("Permanently removes a Resource. Writes a commit to the store using the current Agent.")
                .arg(Arg::with_name("subject")
                    .help("Subject URL or bookmark of the resource to be destroyed")
                    .required(true)
                )
        )
        .subcommand(
            SubCommand::with_name("delta")
                    .about("Update the store using an single Delta. Deprecated in favor of `set`, `remove` and `",
                    )
                .arg(Arg::with_name("method")
                    .help("Method URL or bookmark, describes how the resource will be changed. Only suppports Insert at the time")
                    .required(true)
                )
                .arg(Arg::with_name("subject")
                    .help("Subject URL or bookmark of the thing to be changed")
                    .required(true)
                )
                .arg(Arg::with_name("property")
                    .help("Property URL or bookmark of the thing that needs to be updated")
                    .required(true)
                )
                .arg(Arg::with_name("value")
                    .help("The new Value serialized as a a string")
                    .required(true)
                )
        )
        .subcommand(SubCommand::with_name("list").about("List all bookmarks"))
        .subcommand(SubCommand::with_name("populate").about("Adds the default Atoms to the store"))
        .subcommand(SubCommand::with_name("validate").about("Validates the store"))
        .get_matches();

    let config_folder = home_dir()
        .expect("Home dir could not be opened. We need this to store data.")
        .join(".config/atomic/");

    // The mapping holds shortnames and URLs for quick CLI usage
    let mut mapping: Mapping = Mapping::init();
    let user_mapping_path = config_folder.join("mapping.amp");
    if !user_mapping_path.exists() {
        mapping.populate()?;
    } else {
        mapping.read_mapping_from_file(&user_mapping_path)?;
    }

    let _use_db = false;

    if _use_db {
        // Currenlty uses the Sled store, just like the server.
        // Unfortunately, these can't be used at the same time!
        // let user_store_path = config_folder.join("db");
        // let store_path = &user_store_path;
        // let store = atomic_lib::Db::init(store_path).expect("Failed opening store. Is another program using it?");
    }
    let store = atomic_lib::Store::init();

    let agent_config_path = atomic_lib::config::default_path()?;
    let agent_config = atomic_lib::config::read_config(&agent_config_path)?;
    let write_context = WriteContext {
        base_url: agent_config.server,
        author_private_key: agent_config.private_key,
        author_subject: agent_config.agent,
    };

    let mut context = Context {
        // TODO: This should be configurable
        mapping: Mutex::new(mapping),
        store,
        matches,
        config_folder,
        user_mapping_path,
        write: Some(write_context),
    };

    exec_command(&mut context)?;
    Ok(())
}

fn exec_command(context: &mut Context) -> AtomicResult<()> {
    match context.matches.subcommand_name() {
        Some("new") => {
            new::new(context)?;
        }
        Some("list") => {
            list(context);
        }
        Some("get") => {
            path::get_path(context)?;
        }
        Some("tpf") => {
            tpf(context)?;
        }
        Some("delta") => {
            delta::delta(context)?;
        }
        Some("set") => {
            commit::set(context)?;
        }
        Some("remove") => {
            commit::remove(context)?;
        }
        Some("destroy") => {
            commit::destroy(context)?;
        }
        Some("populate") => {
            populate(context)?;
        }
        Some("validate") => {
            validate(context)?;
        }
        Some(cmd) => println!("{} is not a valid command. Run atomic --help", cmd),
        None => println!("Run atomic --help for available commands"),
    };
    Ok(())
}

/// List all bookmarks
fn list(context: &mut Context) {
    let mut string = String::new();
    for (shortname, url) in context.mapping.lock().unwrap().clone().into_iter() {
        string.push_str(&*format!(
            "{0: <15}{1: <10} \n",
            shortname.blue().bold(),
            url
        ));
    }
    println!("{}", string)
}

/// Prints a resource to the terminal with readble formatting and colors
fn pretty_print_resource(url: &str, store: &mut dyn Storelike) -> AtomicResult<()> {
    let mut output = String::new();
    let resource = store.get_resource_string(url)?;
    for (prop_url, val) in resource {
        let prop_shortname = store.property_url_to_shortname(&prop_url)?;
        output.push_str(&*format!(
            "{0: <15}{1: <10} \n",
            prop_shortname.blue().bold(),
            val
        ));
    }
    output.push_str(&*format!("{0: <15}{1: <10} \n", "url".blue().bold(), url));
    println!("{}", output);
    Ok(())
}

/// Triple Pattern Fragment Query
fn tpf(context: &mut Context) -> AtomicResult<()> {
    let subcommand_matches = context.matches.subcommand_matches("tpf").unwrap();
    let subject = tpf_value(subcommand_matches.value_of("subject").unwrap());
    let property = tpf_value(subcommand_matches.value_of("property").unwrap());
    let value = tpf_value(subcommand_matches.value_of("value").unwrap());
    let found_atoms = context
        .store
        .tpf(subject, property, value)
        .expect("TPF failed");
    let serialized = atomic_lib::serialize::serialize_atoms_to_ad3(found_atoms)?;
    println!("{}", serialized);
    Ok(())
}

fn tpf_value(string: &str) -> Option<&str> {
    if string == "." {
        None
    } else {
        Some(string)
    }
}

/// Adds the default store to the store
fn populate(context: &mut Context) -> AtomicResult<()> {
    context.store.populate()?;
    println!("Succesfully added default Atoms to the store. Run `atomic-cli tpf . . .` to list them all!");
    Ok(())
}

/// Validates the store
fn validate(context: &mut Context) -> AtomicResult<()> {
    let reportstring = context.store.validate().to_string();
    println!("{}", reportstring);
    Ok(())
}
