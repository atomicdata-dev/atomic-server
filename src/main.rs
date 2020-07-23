use clap::{App, Arg, ArgMatches, SubCommand};
use colored::*;
use dirs::home_dir;
use promptly::prompt_opt;
use regex::Regex;
use serde_json::de::from_str;
use std::{collections::HashMap, path::PathBuf};
use uuid;

mod mapping;
mod store;
mod serialization;

struct Model {
    requires: Vec<Property>,
    recommends: Vec<Property>,
    shortname: String,
    description: String,
    /// URL
    subject: String,
}

struct Property {
    // URL of the class
    class_type: Option<String>,
    // URL of the datatype
    data_type: String,
    shortname: String,
    identifier: String,
    description: String,
}

/// The in-memory store of data, containing the Resources, Properties and Classes
type Store = HashMap<String, Resource>;

/// The first string represents the URL of the Property, the second one its Value.
type Resource = HashMap<String, String>;

pub struct Context<'a> {
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
            SubCommand::with_name("new").about("Create a Resource").arg(
                Arg::with_name("class")
                    .help("The URL or shortname of the Class that should be created"),
            ),
        )
        .subcommand(
            SubCommand::with_name("get")
                .about("Fetches and shows a Resource")
                .arg(Arg::with_name("path").help("The subject URL, shortname or path to be fetched")),
        )
        .subcommand(SubCommand::with_name("list").about("List all bookmarks"))
        .get_matches();

    let config_folder = home_dir()
        .expect("Home dir could not be opened")
        .join(".config/atomic/");
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
        Some("get") => {
            get(&mut context);
        }
        Some(cmd) => println!("{} is not a valid command. Run atomic --help", cmd),
        None => println!("Run atomic --help for available commands"),
    }
}

fn list(context: &mut Context) {
    let mut string = String::new();
    for (shortname, url) in context.mapping.iter() {
        string.push_str(&*format!(
            "{0: <15}{1: <10} \n",
            shortname.blue().bold(),
            url
        ));
    }
    println!("{}", string)
}

fn get(context: &mut Context) {
    let path_string = context
    .matches
    .subcommand_matches("get")
    .unwrap()
    .value_of("path")
    .expect("Add a URL, shortname or path");

    store::get_path(path_string, &context.store, &context.mapping);
}

fn new(context: &mut Context) {
    let class_input = context
        .matches
        .subcommand_matches("new")
        .expect("Add a class")
        .value_of("class")
        .expect("Add a class value");
    let class_url = context
        .mapping
        .get(class_input)
        .expect(&*format!("Could not find class {} in mapping", class_input));
    // let class_url = "https://example.com/Person";
    let model = get_model(class_url.into(), &mut context.store);
    println!("Enter a new {}: {}", model.shortname, model.description);
    prompt_instance(context, &model);
}

/// Lets the user enter an instance of an Atomic Class through multiple prompts
/// Returns the Resource, its URL and its Bookmark
fn prompt_instance(context: &mut Context, model: &Model) -> (Resource, String, Option<String>) {
    let mut new_resource: Resource = HashMap::new();

    new_resource.insert(
        "https://atomicdata.dev/properties/isA".into(),
        String::from(&model.subject),
    );

    for field in &model.requires {
        println!("{}: {}", field.shortname, field.description);
        let mut input = prompt_field(&field, false, context);
        loop {
            if let Some(i) = input {
                new_resource.insert(field.identifier.clone(), i.clone());
                break;
            } else {
                println!("Required field, please enter a value.");
                input = prompt_field(&field, false, context);
            }
        }
    }

    for field in &model.recommends {
        println!("{}: {}", field.shortname, field.description);
        let input = prompt_field(&field, true, context);
        if let Some(i) = input {
            new_resource.insert(field.identifier.clone(), i.clone());
        }
    }

    let subject = format!("https://example.com/{}", uuid::Uuid::new_v4());
    println!("{} created with URL: {}", &model.shortname, &subject);

    let map = prompt_bookmark(&mut context.mapping, &subject);

    // Add created_instance to store
    context.store.insert(subject.clone(), new_resource.clone());
    // Publish new resource to IPFS
    // TODO!
    // Save the store locally
    store::write_store_to_disk(&context.store, &context.user_store_path);
    mapping::write_mapping_to_disk(&context.mapping, &context.user_mapping_path);
    return (new_resource, subject, map);
}

// Checks the property and its datatype, and issues a prompt that performs validation.
fn prompt_field(property: &Property, optional: bool, context: &mut Context) -> Option<String> {
    let mut input: Option<String> = None;
    let mut msg_appendix = "";
    if optional {
        msg_appendix = " (optional)";
    } else {
        msg_appendix = " (required)";
    }
    // let msg = format!("{}{}", &property.shortname, msg_appendix);
    match property.data_type.as_str() {
        urls::STRING => {
            let msg = format!("string{}", msg_appendix);
            input = prompt_opt(&msg).unwrap();
            return input;
        }
        urls::SLUG => {
            let msg = format!("slug{}", msg_appendix);
            input = prompt_opt(&msg).unwrap();
            let re = Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").unwrap();
            match input {
                Some(slug) => {
                    if re.is_match(&*slug) {
                        return Some(slug);
                    }
                    println!("Only letters, numbers and dashes - no spaces or special characters.");
                    return None
                }
                None => (),
            }
            return input;
        }
        urls::INTEGER => {
            let msg = format!("integer{}", msg_appendix);
            let number: Option<u32> = prompt_opt(&msg).unwrap();
            match number {
                Some(nr) => {
                    input = Some(nr.to_string());
                }
                None => (),
            }
        }
        urls::ATOMIC_URL => {
            let msg = format!("URL{}", msg_appendix);
            let url: Option<String> = prompt_opt(msg).unwrap();
            // If a classtype is present, the given URL must be an instance of that Class
            let classtype = &property.class_type;
            if classtype.is_some() {
                let class = get_model(String::from(classtype.as_ref().unwrap()), &context.store);
                println!("Enter the URL or shortname of a {}", class.description)
            }
            match url {
                Some(u) => {
                    // TODO: Check if string or if map
                    input = mapping::try_mapping_or_url(&u, &context.mapping);
                    return input
                }
                None => (),
            };
        }
        urls::RESOURCE_ARRAY => loop {
            let msg = format!(
                "resource array - Add the URLs or Shortnames, separated by spacebars{}", msg_appendix);
            let option_string: Option<String> = prompt_opt(msg).unwrap();
            match option_string {
                Some(string) => {
                    let string_items = string.split(" ");
                    let mut urls: Vec<String> = Vec::new();
                    let length = string_items.clone().count();
                    for item in string_items.into_iter() {
                        match mapping::try_mapping_or_url(&item.into(), &context.mapping) {
                            Some(url) => {
                                urls.push(url);
                            }
                            None => {
                                println!("{} is not a valid URL or known Shortname, so let's create a new Resource:", item, );
                                // TODO: This currently creates Property instances, but this should depend on the class!
                                let (_resource, url, _shortname) = prompt_instance(
                                    context,
                                    &get_model(urls::PROPERTY.into(), &context.store),
                                );
                                urls.push(url);
                                continue;
                            }
                        }
                    }
                    if length == urls.len() {
                        input = Some(serde_json::to_string(&urls).unwrap());
                        break;
                    }
                }
                None => break,
            }
        },
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
    pub const CLASSTYPE_PROP: &str = "https://atomicdata.dev/properties/classtype";
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
fn get_model(subject: String, store: &Store) -> Model {
    // The string representation of the model
    let model_strings = store.get(&subject).expect("Model not found");
    let shortname = model_strings
        .get(urls::SHORTNAME)
        .expect("Model has no shortname");
    let description = model_strings
        .get(urls::DESCRIPTION)
        .expect("Model has no description");
    let requires_string = model_strings
        .get(urls::REQUIRES);
    let recommends_string = model_strings
        .get(urls::RECOMMENDS);

    let mut requires: Vec<Property> = Vec::new();
    let mut recommends: Vec<Property> = Vec::new();
    if requires_string.is_some() {
        requires = get_properties(requires_string.unwrap().into(), &store);
    }
    if recommends_string.is_some() {
        recommends = get_properties(recommends_string.unwrap().into(), &store);
    }

    fn get_properties(resource_array: String, store: &Store) -> Vec<Property> {
        let mut properties: Vec<Property> = vec![];
        let string_vec: Vec<String> = from_str(&*resource_array).unwrap();
        for prop_url in string_vec {
            let property_resource = store
                .get(&*prop_url)
                .expect(&*format!("Model not found {}", &*prop_url));
            let property = Property {
                data_type: property_resource
                    .get(urls::DATATYPE_PROP)
                    .expect("Datatype not found")
                    .into(),
                shortname: property_resource
                    .get(urls::SHORTNAME)
                    .expect("Shortname not found")
                    .into(),
                description: property_resource
                    .get(urls::DESCRIPTION)
                    .expect("Description not found")
                    .into(),
                class_type: property_resource
                    .get(urls::CLASSTYPE_PROP)
                    .map(|s| s.clone()),
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

// Asks for and saves the bookmark. Returns the shortname.
fn prompt_bookmark(mapping: &mut mapping::Mapping, subject: &String) -> Option<String> {
    let re = Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").unwrap();
    let mut shortname: Option<String> =
        prompt_opt(format!("Local Bookmark (optional)")).unwrap();
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
                    &mut mapping.insert(String::from(&sn), String::from(subject));
                    return Some(String::from(&sn));
                } else {
                    shortname =
                        prompt_opt("Not a valid bookmark, only use letters, numbers, and '-'")
                            .unwrap();
                }
            }
            None => return None,
        }
    }
}
