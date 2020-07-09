use clap::{App, Arg, SubCommand, ArgMatches};
use promptly::{prompt_opt};
use regex::Regex;
use serde_json::de::from_str;
use std::{collections::HashMap, path::{PathBuf}};
use uuid;
use colored::*;
use dirs::home_dir;

mod mapping;
mod store;

struct Model {
    requires: Vec<Property>,
    recommends: Vec<Property>,
    shortname: String,
    description: String,
    /// URL
    subject: String,
}

struct Property {
    data_type: String,
    shortname: String,
    identifier: String,
}

/// The in-memory store of data, containing the Resources, Properties and Classes
type Store = HashMap<String, Resource>;

/// The first string represents the URL of the Property, the second one its Value.
type Resource = HashMap<String, String>;

struct Context<'a> {
    store: Store,
    mapping: mapping::Mapping,
    matches: ArgMatches<'a>,
    config_folder: PathBuf,
    user_store_path: PathBuf,
    user_mapping_path: PathBuf,
}

fn main() {
    let matches = App::new("atomic")
        .version("0.1.1")
        .author("Joep Meindertsma <joep@ontola.io>")
        .about("Create, share, fetch and model linked atomic data!")
        .subcommand(
            SubCommand::with_name("new")
                .about("Create a Resource")
                .arg(
                    Arg::with_name("class")
                        .help("The URL or shortname of the Class that should be created"),
                ),
        )
        .subcommand(
            SubCommand::with_name("get")
                .about("Fetches and shows a Resource")
                .arg(
                    Arg::with_name("subject")
                        .help("The subject URL or shortname to be fetched"),
                ),
        )
        .subcommand(
            SubCommand::with_name("list")
                .about("List all bookmarks")
        )
        .get_matches();

    let config_folder = home_dir().expect("Home dir could not be opened").join(".config/atomic/");
    let user_mapping_path = config_folder.join("mapping.amp");
    let default_mapping_path = PathBuf::from("./default_mapping.amp");
    let mut mapping_path = &default_mapping_path;
    if user_mapping_path.exists() {
        mapping_path = &user_mapping_path;
    }
    let mapping = mapping::read_mapping_from_file(&mapping_path);

    let default_store_path = PathBuf::from("./default_store.ad3");
    let user_store_path = config_folder.join("store.ad3");
    let mut store_path = &default_store_path;

    if user_store_path.exists() {
        store_path = &user_store_path;
    }

    let mut store: Store = HashMap::new();
    // The store contains the classes and properties
    store = store::read_store_from_file(&mut store, &store_path).clone();

    let mut context = Context {
        mapping,
        store,
        matches,
        config_folder,
        user_store_path: user_store_path.clone(),
        user_mapping_path: user_mapping_path.clone(),
    };

    match context.matches.subcommand_name() {
        Some("new") => {
            new(&mut context);
        }
        Some("list") => {
            list(&mut context);
        }
        Some(cmd) => {println!("{} is not a valid command. Run atomic --help", cmd)}
        None => {println!("Run atomic --help for available commands")}
    }

}

fn list(context: &mut Context) {
    let mut string = String::new();
    for (shortname, url) in context.mapping.iter() {
        string.push_str(&*format!("{0: <15}{1: <10} \n", shortname.blue().bold(), url));
    }
    println!("{}", string)
}

fn new(context: &mut Context) {
    let class_input = context.matches.subcommand_matches("new")
        .expect("Add a class").value_of("class").expect("Add a class value");
    let class_url = context.mapping.get(class_input)
        .expect(&*format!("Could not find class {} in mapping", class_input));
    // let class_url = "https://example.com/Person";
    let model = get_model(class_url.into(), &mut context.store);
    println!("Enter a new {}: {}", model.shortname, model.description);

    let mut new_resource: Resource = HashMap::new();

    new_resource.insert(
        "https://atomicdata.dev/properties/isA".into(),
        String::from(&model.subject),
    );

    for field in model.requires {
        let mut input = prompt_field(&field, false);
        loop {
            if let Some(i) = input {
                new_resource.insert(field.identifier, i.clone());
                break
            } else {
                println!("Required field, please enter a value.");
                input = prompt_field(&field, false);
            }
        }
    }

    for field in model.recommends {
        let input = prompt_field(&field, true);
        if let Some(i) = input {
            new_resource.insert(field.identifier, i.clone());
        }
    }

    let subject = format!("https://example.com/{}", uuid::Uuid::new_v4());
    println!("Resource created with URL: {}", &subject);

    prompt_bookmark(&mut context.mapping, &subject);

    // Add created_instance to store
    context.store.insert(subject, new_resource);
    // Publish new resource to IPFS
    // TODO!
    // Save the store locally
    store::write_store_to_disk(&context.store, &context.user_store_path);
    mapping::write_mapping_to_disk(&context.mapping, &context.user_mapping_path);
}

// Checks the property and its datatype, and issues a prompt that performs validation.
fn prompt_field(property: &Property, optional: bool) -> Option<String> {
    let mut input: Option<String> = None;
    let mut msg_appendix = "";
    if optional {
        msg_appendix = " (optional)";
    }
    let msg = format!("{}{}", &property.shortname, msg_appendix );
    match property.data_type.as_str() {
        urls::STRING => {
            input = prompt_opt(&msg).unwrap();
        }
        urls::INTEGER => {
            let number: Option<u32> = prompt_opt(&msg).unwrap();
            match number {
                Some(nr) => {
                    input = Some(nr.to_string());
                }
                None => (),
            }
        }
        urls::RESOURCE_ARRAY => {
            loop {
                let message = format!("{} - Add the URLs or Shortnames, separated by spacebars", &msg);
                let option_string: Option<String> = prompt_opt(message).unwrap();
                match option_string {
                    Some(string) => {
                        let string_items = string.split(" ");
                        let mut urls: Vec<String> = Vec::new();
                        let length = string_items.clone().count();
                        for item in string_items.into_iter() {
                            match mapping::try_mapping_or_url(&item.into()) {
                                Some(url) => {
                                    urls.push(url);
                                }
                                None => {
                                    println!("{} is not a valid URL, try again", item);
                                    continue;
                                }
                            }
                            println!("item: {}", item)
                        }
                        println!("urls: {:?}", urls);
                        if length == urls.len() {
                            break
                        }
                    }
                    None => {
                        break
                    },
                }
            }
        }
        _ => panic!("Unknown datatype: {}", property.data_type),
    };
    return input;
}

pub mod urls {
    // Classes
    pub const CLASS: &str = "https://atomicdata.dev/classes/Class";
    pub const PROPERTY: &str = "https://atomicdata.dev/classes/Property";
    pub const DATATYPE_CLASS: &str = "https://atomicdata.dev/classes/Datatype";

    // Properties
    pub const SHORTNAME: &str = "https://atomicdata.dev/properties/shortname";
    pub const DESCRIPTION: &str = "https://atomicdata.dev/properties/description";
    // ... for Properties
    pub const IS_A: &str = "https://atomicdata.dev/properties/isA";
    pub const DATATYPE_PROP: &str = "https://atomicdata.dev/properties/datatype";
    // ... for Classes
    pub const REQUIRES: &str = "https://atomicdata.dev/properties/requires";
    pub const RECOMMENDS: &str = "https://atomicdata.dev/properties/recommends";

    // Datatypes
    pub const STRING: &str = "https://atomicdata.dev/datatypes/string";
    pub const SLUG: &str = "https://atomicdata.dev/datatypes/slug";
    pub const ATOMIC_URL: &str = "https://atomicdata.dev/datatypes/atomicURL";
    pub const INTEGER: &str = "https://atomicdata.dev/datatypes/integer";
    pub const RESOURCE_ARRAY: &str = "https://atomicdata.dev/datatypes/resourceArray";
    pub const BOOLEAN: &str = "https://atomicdata.dev/datatypes/boolean";
}

/// Retrieves a model from the store by subject URL and converts it into a model useful for forms
fn get_model(subject: String, store: &mut Store) -> Model {
    // The string representation of the model
    let model_strings = store.get(&subject).expect("Model not found");
    let shortname = model_strings
        .get(urls::SHORTNAME)
        .expect("Model has no shortname");
    let description = model_strings
        .get(urls::DESCRIPTION)
        .expect("Model has no description");
    let requires_string = model_strings.get(urls::REQUIRES).expect("No required props");
    let recommends_string = model_strings
        .get(urls::RECOMMENDS)
        .expect("No recommended props");
    let requires: Vec<Property> = get_properties(requires_string.into(), &store);
    let recommends: Vec<Property> = get_properties(recommends_string.into(), &store);

    fn get_properties(resource_array: String, store: &Store) -> Vec<Property> {
        let mut properties: Vec<Property> = vec![];
        let string_vec: Vec<String> = from_str(&*resource_array).unwrap();
        for prop_url in string_vec {
            let property_resource = store.get(&*prop_url).expect(&*format!("Model not found {}", &*prop_url));
            let property = Property {
                data_type: property_resource
                    .get(urls::DATATYPE_PROP)
                    .expect("Datatype not found")
                    .into(),
                shortname: property_resource
                    .get(urls::SHORTNAME)
                    .expect("Shortname not found")
                    .into(),
                identifier: prop_url.into(),
            };
            properties.push(property)
        }
        return properties;
    }

    let model = Model {
        requires,
        recommends,
        shortname: shortname.into(),
        subject,
        description: description.into(),
    };

    return model;
}

fn prompt_bookmark(mapping: &mut mapping::Mapping, subject: &String) {
    let re = Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").unwrap();
    let mut shortname: Option<String> = prompt_opt(format!("Local Bookmark (optional) for {}", subject)).unwrap();
    loop {
        match shortname {
            Some(sn) => {
                if mapping.contains_key(&*sn) {
                    let msg = format!(
                        "You're already using that shortname for {:?}, try something else",
                        mapping.get(&*sn).unwrap()
                    );
                    shortname = prompt_opt(msg).unwrap();
                } else if re.is_match(&*sn) {
                    &mut mapping.insert(sn, String::from(subject));
                    break;
                } else {
                    shortname =
                        prompt_opt("Not a valid bookmark, only use letters, numbers, and '-'")
                            .unwrap();
                }
            }
            None => {
                break
            }
        }
    }
}
