use clap::{App, AppSettings,Arg, ArgMatches, SubCommand};
use colored::*;
use dirs::home_dir;
use promptly::prompt_opt;
use regex::Regex;
use serde_json::de::from_str;
use std::{collections::HashMap, path::PathBuf};
use atomic::store::{self, Store, Resource, Property, DataType};
use atomic::urls;
use atomic::mapping;
use atomic::serialize;
use uuid;

struct Model {
    requires: Vec<Property>,
    recommends: Vec<Property>,
    shortname: String,
    description: String,
    /// URL
    subject: String,
}

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
        .version("0.4.2")
        .author("Joep Meindertsma <joep@ontola.io>")
        .about("Create, share, fetch and model linked atomic data!")
        .after_help("Visit https://github.com/joepio/atomic-cli for more info")
        .setting(AppSettings::ArgRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("new").about("Create a Resource").arg(
                Arg::with_name("class")
                    .help("The URL or shortname of the Class that should be created"),
            ),
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
                    You can use Bookmarks instead of a full subjet URL. \
                    ",
                    )
                    .required(true)
                )
                .arg(Arg::with_name("as")
                    .long("as")
                    .help("Serialization option (pretty=default, json, ad3)")
                    .takes_value(true)
                )
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

    let mut store: Store = store::init();
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
    let subcommand_matches = context
        .matches
        .subcommand_matches("get")
        .unwrap();
    let path_string = subcommand_matches.value_of("path")
        .expect("Add a URL, shortname or path");
    let serialization: Option<serialize::SerialializationFormats> = match subcommand_matches.value_of("as") {
        Some("json") => Some(serialize::SerialializationFormats::JSON),
        Some("ad3") => Some(serialize::SerialializationFormats::AD3),
        Some(format) => {
            panic!("As {} not supported. Try 'json' or 'ad3'.", format);
        }
        None => None
    };

    // Returns a URL or Value
    let result = store::get_path(path_string, &context.store, &context.mapping);
    match result {
        Ok(res) => {
            match res {
                store::PathReturn::Subject(url) => {
                    match serialization {
                        Some(serialize::SerialializationFormats::JSON) => {
                            let out = serialize::resource_to_json(&url, &context.store, 1).unwrap();
                            println!("{}", out);
                        }
                        Some(serialize::SerialializationFormats::AD3) => {
                            let out = serialize::resource_to_ad3(&url, &context.store, None).unwrap();
                            println!("{}", out);
                        }
                        None => {
                            pretty_print_resource(&url, &context.store);
                        }
                    }
                }
                store::PathReturn::Atom(atom) => {
                    println!("{:?}", atom.native_value)
                }
            }
        }
        Err(e) => {
            eprintln!("{}", e);
        }
    }
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
    let msg_appendix;
    if optional {
        msg_appendix = " (optional)";
    } else {
        msg_appendix = " (required)";
    }
    match &property.data_type {
        DataType::String => {
            let msg = format!("string{}", msg_appendix);
            input = prompt_opt(&msg).unwrap();
            return input;
        }
        DataType::Slug => {
            let msg = format!("slug{}", msg_appendix);
            input = prompt_opt(&msg).unwrap();
            let re = Regex::new(store::SLUG_REGEX).unwrap();
            match input {
                Some(slug) => {
                    if re.is_match(&*slug) {
                        return Some(slug);
                    }
                    println!("Only letters, numbers and dashes - no spaces or special characters.");
                    return None;
                }
                None => (return None),
            }
        }
        DataType::Integer => {
            let msg = format!("integer{}", msg_appendix);
            let number: Option<u32> = prompt_opt(&msg).unwrap();
            match number {
                Some(nr) => {
                    input = Some(nr.to_string());
                }
                None => (return None),
            }
        }
        DataType::Date => {
            let msg = format!("date YY-MM-DDDD{}", msg_appendix);
            let date: Option<String> = prompt_opt(&msg).unwrap();
            let re = Regex::new(store::DATE_REGEX).unwrap();
            match date {
                Some(date_val) => loop {
                    if re.is_match(&*date_val) {
                        return Some(date_val);
                    }
                    println!("Not a valid date.");
                },
                None => (return None),
            }
        }
        DataType::AtomicUrl => loop {
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
                    match input {
                        Some(url) => return Some(url),
                        None => {
                            println!("Shortname not found, try again.");
                            return None;
                        }
                    }
                }
                None => (),
            };
        },
        DataType::ResourceArray => loop {
            let msg = format!(
                "resource array - Add the URLs or Shortnames, separated by spacebars{}",
                msg_appendix
            );
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
        DataType::MDString => { todo!() }
        DataType::Timestamp => { todo!() }
        DataType::Unsupported(unsup) => {
            panic!("Unsupported datatype: {:?}", unsup)
        }
    };
    return input;
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
    let requires_string = model_strings.get(urls::REQUIRES);
    let recommends_string = model_strings.get(urls::RECOMMENDS);

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
            properties.push(store::get_property(&prop_url, &store).unwrap());
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
    let re = Regex::new(store::SLUG_REGEX).unwrap();
    let mut shortname: Option<String> = prompt_opt(format!("Local Bookmark (optional)")).unwrap();
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

/// Prints a resource to the terminal with readble formatting and colors
fn pretty_print_resource(url: &String, store: &Store) {
    let mut output = String::new();
    for (prop_url, val) in store.get(url).unwrap() {
        let prop_shortname = store::property_url_to_shortname(prop_url, store).unwrap();
        output.push_str(&*format!(
            "{0: <15}{1: <10} \n",
            prop_shortname.blue().bold(),
            val
        ));
    }
    output.push_str(&*format!("{0: <15}{1: <10} \n", "url".blue().bold(), url));
    println!("{}", output)
}
