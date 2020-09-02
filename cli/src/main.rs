use atomic_lib::errors::AtomicResult;
use atomic_lib::mapping::{self, Mapping};
use atomic_lib::serialize;
use atomic_lib::storelike::{self, Class, Property, Storelike};
use atomic_lib::urls;
use atomic_lib::values::DataType;
use atomic_lib::{Resource, Store, Value};
use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use colored::*;
use dirs::home_dir;
use promptly::prompt_opt;
use regex::Regex;
use serialize::serialize_atoms_to_ad3;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{path::PathBuf};

#[allow(dead_code)]
pub struct Context<'a> {
    store: Store,
    mapping: Mapping,
    matches: ArgMatches<'a>,
    config_folder: PathBuf,
    user_store_path: PathBuf,
    user_mapping_path: PathBuf,
}

fn main() {
    let matches = App::new("atomic")
        .version("0.9.0")
        .author("Joep Meindertsma <joep@ontola.io>")
        .about("Create, share, fetch and model linked atomic data!")
        .after_help("Visit https://github.com/joepio/atomic-cli for more info")
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
                    .help("Serialization option (pretty=default, json, ad3)")
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
        .subcommand(SubCommand::with_name("list").about("List all bookmarks"))
        .get_matches();

    let config_folder = home_dir()
        .expect("Home dir could not be opened")
        .join(".config/atomic/");
    let user_mapping_path = config_folder.join("mapping.amp");
    let default_mapping_path = PathBuf::from("../defaults/default_mapping.amp");
    let mut mapping_path = &default_mapping_path;
    if user_mapping_path.exists() {
        mapping_path = &user_mapping_path;
    }
    let mut mapping: Mapping = Mapping::init();
    mapping.read_mapping_from_file(&mapping_path).unwrap();

    let default_store_path = PathBuf::from("../defaults/default_store.ad3");
    let user_store_path = config_folder.join("store.ad3");
    let mut store_path = &default_store_path;

    let mut store: Store = Store::init();
    if user_store_path.exists() {
        store_path = &user_store_path;
    } else {
        println!("No store found, initializing in {:?}", &user_store_path);
        store.load_default();
        store
            .write_store_to_disk(&user_store_path)
            .expect("Could not create store");
    }

    // The store contains the classes and properties
    store
        .read_store_from_file(&store_path)
        .expect("Does it work");

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
        Some("tpf") => {
            tpf(&mut context);
        }
        Some(cmd) => println!("{} is not a valid command. Run atomic --help", cmd),
        None => println!("Run atomic --help for available commands"),
    }
}

fn list(context: &mut Context) {
    let mut string = String::new();
    for (shortname, url) in context.mapping.clone().into_iter() {
        string.push_str(&*format!(
            "{0: <15}{1: <10} \n",
            shortname.blue().bold(),
            url
        ));
    }
    println!("{}", string)
}

fn get(context: &mut Context) {
    let subcommand_matches = context.matches.subcommand_matches("get").unwrap();
    let path_string = subcommand_matches
        .value_of("path")
        .expect("Add a URL, shortname or path");
    let serialization: Option<serialize::SerialializationFormats> =
        match subcommand_matches.value_of("as") {
            Some("json") => Some(serialize::SerialializationFormats::JSON),
            Some("ad3") => Some(serialize::SerialializationFormats::AD3),
            Some(format) => {
                panic!("As {} not supported. Try 'json' or 'ad3'.", format);
            }
            None => None,
        };

    // Returns a URL or Value
    let result = &context.store.get_path(path_string, &context.mapping);
    match result {
        Ok(res) => match res {
            storelike::PathReturn::Subject(url) => match serialization {
                Some(serialize::SerialializationFormats::JSON) => {
                    let out = &context.store.resource_to_json(&url, 1).unwrap();
                    println!("{}", out);
                }
                Some(serialize::SerialializationFormats::AD3) => {
                    let out = &context.store.resource_to_ad3(&url, None).unwrap();
                    println!("{}", out);
                }
                None => {
                    pretty_print_resource(&url, &context.store).unwrap();
                }
            },
            storelike::PathReturn::Atom(atom) => match serialization {
                Some(serialize::SerialializationFormats::JSON) => {
                    println!("{}", atom.value);
                }
                Some(serialize::SerialializationFormats::AD3) => {
                    println!("{}", atom.value);
                }
                None => println!("{:?}", &atom.native_value),
            },
        },
        Err(e) => {
            eprintln!("{}", e);
        }
    }
}

fn new(context: &mut Context) {
    let class_input = context
        .matches
        .subcommand_matches("new")
        .unwrap()
        .value_of("class")
        .expect("Add a class value");

    let class_url = context
        .mapping
        .try_mapping_or_url(&class_input.into())
        .unwrap();
    let model = context.store.get_class(&class_url);
    println!("Enter a new {}: {}", model.shortname, model.description);
    prompt_instance(context, &model, None).unwrap();
}

/// Lets the user enter an instance of an Atomic Class through multiple prompts
/// Adds the instance to the store, and writes to disk.
/// Returns the Resource, its URL and its Bookmark.
fn prompt_instance(
    context: &mut Context,
    class: &Class,
    preffered_shortname: Option<String>,
) -> AtomicResult<(Resource, String, Option<String>)> {
    // Not sure about the best way t
    // The Path is the thing at the end of the URL, from the domain
    // Here I set some (kind of) random numbers.
    // I think URL generation could be better, though. Perhaps use a
    let path = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();

    let mut subject = format!("_:{}", path);
    if preffered_shortname.is_some() {
        subject = format!("_:{}-{}", path, preffered_shortname.clone().unwrap());
    }

    let mut new_resource: Resource = Resource::new(subject.clone());

    new_resource.insert(
        "https://atomicdata.dev/properties/isA".into(),
        Value::ResourceArray(Vec::from([class.subject.clone().into()])),
    )?;

    for field in &class.requires {
        if field.subject == atomic_lib::urls::SHORTNAME && preffered_shortname.clone().is_some() {
            new_resource.insert_string(
                field.subject.clone(),
                &preffered_shortname.clone().unwrap(),
                &mut context.store,
            )?;
            println!("Shortname set to {}", preffered_shortname.clone().unwrap().bold().green());
            continue;
        }
        println!("{}: {}", field.shortname.bold().blue(), field.description);
        // In multiple Properties, the shortname field is required.
        // A preferred shortname can be passed into this function
        let mut input = prompt_field(&field, false, context)?;
        loop {
            if let Some(i) = input {
                new_resource.insert_string(field.subject.clone(), &i, &mut context.store)?;
                break;
            } else {
                println!("Required field, please enter a value.");
                input = prompt_field(&field, false, context)?;
            }
        }
    }

    for field in &class.recommends {
        println!("{}: {}", field.shortname, field.description);
        let input = prompt_field(&field, true, context)?;
        if let Some(i) = input {
            new_resource.insert_string(field.subject.clone(), &i, &mut context.store)?;
        }
    }

    println!("{} created with URL: {}", &class.shortname, &subject.clone());

    let map = prompt_bookmark(&mut context.mapping, &subject);

    // Add created_instance to store
    context
        .store
        .add_resource_string(new_resource.subject().clone(), new_resource.to_plain())
        .unwrap();
    // Publish new resource to IPFS
    // TODO!
    // Save the store locally
    context
        .store
        .write_store_to_disk(&context.user_store_path)
        .expect("Could not write to disk");
    context
        .mapping
        .write_mapping_to_disk(&context.user_mapping_path);
    return Ok((new_resource, subject, map));
}

// Checks the property and its datatype, and issues a prompt that performs validation.
fn prompt_field(property: &Property, optional: bool, context: &mut Context) -> AtomicResult<Option<String>> {
    let mut input: Option<String> = None;
    let msg_appendix;
    if optional {
        msg_appendix = " (optional)";
    } else {
        msg_appendix = " (required)";
    }
    match &property.data_type {
        DataType::String | DataType::Markdown => {
            let msg = format!("string{}", msg_appendix);
            input = prompt_opt(&msg).unwrap();
            return Ok(input);
        }
        DataType::Slug => {
            let msg = format!("slug{}", msg_appendix);
            input = prompt_opt(&msg).unwrap();
            let re = Regex::new(atomic_lib::values::SLUG_REGEX).unwrap();
            match input {
                Some(slug) => {
                    if re.is_match(&*slug) {
                        return Ok(Some(slug));
                    }
                    println!("Only letters, numbers and dashes - no spaces or special characters.");
                    return Ok(None);
                }
                None => (return Ok(None)),
            }
        }
        DataType::Integer => {
            let msg = format!("integer{}", msg_appendix);
            let number: Option<u32> = prompt_opt(&msg).unwrap();
            match number {
                Some(nr) => {
                    input = Some(nr.to_string());
                }
                None => (return Ok(None)),
            }
        }
        DataType::Date => {
            let msg = format!("date YY-MM-DDDD{}", msg_appendix);
            let date: Option<String> = prompt_opt(&msg).unwrap();
            let re = Regex::new(atomic_lib::values::DATE_REGEX).unwrap();
            match date {
                Some(date_val) => loop {
                    if re.is_match(&*date_val) {
                        return Ok(Some(date_val));
                    }
                    println!("Not a valid date.");
                },
                None => (return Ok(None)),
            }
        }
        DataType::AtomicUrl => loop {
            let msg = format!("URL{}", msg_appendix);
            let url: Option<String> = prompt_opt(msg).unwrap();
            // If a classtype is present, the given URL must be an instance of that Class
            let classtype = &property.class_type;
            if classtype.is_some() {
                let class = context
                    .store
                    .get_class(&String::from(classtype.as_ref().unwrap()));
                println!("Enter the URL or shortname of a {}", class.description)
            }
            match url {
                Some(u) => {
                    // TODO: Check if string or if map
                    input = context.mapping.try_mapping_or_url(&u);
                    match input {
                        Some(url) => return Ok(Some(url)),
                        None => {
                            println!("Shortname not found, try again.");
                            return Ok(None);
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
                        match context.mapping.try_mapping_or_url(&item.into()) {
                            Some(url) => {
                                urls.push(url);
                            }
                            None => {
                                println!("Define the Property named {}", item.bold().green(), );
                                // TODO: This currently creates Property instances, but this should depend on the class!
                                let (_resource, url, _shortname) = prompt_instance(
                                    context,
                                    &context.store.get_class(&urls::PROPERTY.into()),
                                    Some(item.into()),
                                )?;
                                urls.push(url);
                                continue;
                            }
                        }
                    }
                    if length == urls.len() {
                        input = Some(atomic_lib::serialize::serialize_json_array(&urls).unwrap());
                        break;
                    }
                }
                None => break,
            }
        },
        DataType::Timestamp => todo!(),
        DataType::Unsupported(unsup) => panic!("Unsupported datatype: {:?}", unsup),
    };
    return Ok(input);
}

// Asks for and saves the bookmark. Returns the shortname.
fn prompt_bookmark(mapping: &mut mapping::Mapping, subject: &String) -> Option<String> {
    let re = Regex::new(atomic_lib::values::SLUG_REGEX).unwrap();
    let mut shortname: Option<String> = prompt_opt(format!("Local Bookmark (optional)")).unwrap();
    loop {
        match shortname.as_ref() {
            Some(sn) => {
                if mapping.contains_key(sn) {
                    let msg = format!(
                        "You're already using that shortname for {:?}, try something else",
                        mapping.get(sn).unwrap()
                    );
                    shortname = prompt_opt(msg).unwrap();
                } else if re.is_match(&sn.as_str()) {
                    &mut mapping.insert(String::from(sn), String::from(subject));
                    return Some(String::from(sn));
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
fn pretty_print_resource(url: &String, store: &Store) -> AtomicResult<()> {
    let mut output = String::new();
    let resource = store.get_string_resource(url).ok_or(format!("Not found: {}", url))?;
    for (prop_url, val) in resource {
        let prop_shortname = store.property_url_to_shortname(&prop_url).unwrap();
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

fn tpf(context: &mut Context) {
    let subcommand_matches = context.matches.subcommand_matches("tpf").unwrap();
    let subject = tpf_value(subcommand_matches.value_of("subject").unwrap());
    let property = tpf_value(subcommand_matches.value_of("property").unwrap());
    let value = tpf_value(subcommand_matches.value_of("value").unwrap());
    let found_atoms = context.store.tpf(subject, property, value);
    let serialized = serialize_atoms_to_ad3(found_atoms);
    println!("{}", serialized.unwrap())
}

fn tpf_value(string: &str) -> Option<String> {
    if string == "." {
        return None;
    } else {
        return Some(string.into());
    }
}
