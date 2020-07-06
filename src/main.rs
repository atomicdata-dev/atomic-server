use clap::{App, Arg, SubCommand, ArgMatches};
use promptly::{prompt, prompt_opt};
use regex::Regex;
use serde_json::de::from_str;
use std::{collections::HashMap, fs, path::Path};
use uuid;
struct Model {
    requires: Vec<Property>,
    recommends: Vec<Property>,
    shortname: String,
    /// URL
    subject: String,
}

struct Property {
    data_type: String,
    shortname: String,
    identifier: String,
}

/// Maps shortanmes to URLs
type Mapping = HashMap<String, String>;

/// The in-memory store of data, containing the Resources, Properties and Classes
type Store = HashMap<String, Resource>;

/// The first string represents the URL of the Property, the second one its Value.
type Resource = HashMap<String, String>;

struct Context<'a> {
    store: Store,
    mapping: Mapping,
    matches: ArgMatches<'a>,
}

fn main() {
    let matches = App::new("Atomicli")
        .version("0.1")
        .author("Joep Meindertsma <joep@ontola.io>")
        .about("Create, share and standardize linked atomic data!")
        .subcommand(
            SubCommand::with_name("new")
                .about("Create a Resource")
                .arg(
                    Arg::with_name("class")
                        .help("Select the class URL or shortname"),
                ),
        )
        .get_matches();

    // Reads the shortname + URL map
    let mut mapping = read_mapping_from_file();
    let mut store: Store = HashMap::new();
    // The store contains the classes and properties
    read_store_from_file(&mut store);

    let mut context = Context {
        mapping,
        store,
        matches,
    };

    match context.matches.subcommand_name() {
        Some("new") => {
            new(&mut context);
        }
        Some(cmd) => {println!("cmd: {}", cmd)}
        None => {println!("no command...")}
    }

}

fn new(context: &mut Context) {
    if let class = context.matches.subcommand_matches("new").unwrap().value_of("class").unwrap() {
        println!("{:?}", class );
    };
    let model = get_model("https://example.com/Person".into(), &mut context.store);

    let mut new_resource: Resource = HashMap::new();

    new_resource.insert(
        "https://atomicdata.dev/properties/isA".into(),
        String::from(&model.subject),
    );

    for field in model.requires {
        new_resource.insert(field.identifier, prompt(field.shortname).unwrap());
    }

    for field in model.recommends {
        let mut input: Option<String> = None;
        let msg = format!("{} (optional)", &field.shortname);
        match field.data_type.as_str() {
            URL::STRING => {
                input = prompt_opt(&msg).unwrap();
            }
            URL::INTEGER => {
                let number: Option<u32> = prompt_opt(&msg).unwrap();
                match number {
                    Some(nr) => {
                        input = Some(nr.to_string());
                    }
                    None => (),
                }
            }
            _ => panic!("Unknown datatype: {}", field.data_type),
        };
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
    write_store_to_disk(&context.store);
    write_mapping_to_disk(&context.mapping);
}

pub mod URL {
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
        .get(URL::SHORTNAME)
        .expect("Model has no shortname");
    let requires_string = model_strings.get(URL::REQUIRES).expect("No required props");
    let recommends_string = model_strings
        .get(URL::RECOMMENDS)
        .expect("No recommended props");
    let requires: Vec<Property> = get_properties(requires_string.into(), &store);
    let recommends: Vec<Property> = get_properties(recommends_string.into(), &store);

    fn get_properties(resource_array: String, store: &Store) -> Vec<Property> {
        let mut properties: Vec<Property> = vec![];
        let string_vec: Vec<String> = from_str(&*resource_array).unwrap();
        for prop_url in string_vec {
            let property_resource = store.get(&*prop_url).expect("Model not found");
            let property = Property {
                data_type: property_resource
                    .get(URL::DATATYPE_PROP)
                    .expect("Datatype not found")
                    .into(),
                shortname: property_resource
                    .get(URL::SHORTNAME)
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
    };

    return model;
}

fn read_mapping_from_file() -> Mapping {
    let mut mapping: Mapping = HashMap::new();
    let default_mapping_path = Path::new("./default_mapping.amp");
    let user_mapping_path = Path::new("./user_mapping.amp");
    let mut mapping_path = default_mapping_path;

    if user_mapping_path.exists() {
        mapping_path = user_mapping_path;
    }

    match std::fs::read_to_string(mapping_path) {
        Ok(contents) => {
            for line in contents.lines() {
                match line.chars().next() {
                    Some('#') => {}
                    Some(' ') => {}
                    Some(_) => {
                        let split: Vec<&str> = line.split("=").collect();
                        if split.len() == 2 {
                            &mapping.insert(String::from(split[0]), String::from(split[1]));
                        } else {
                            println!("Error reading line {:?} in {:?}", line, mapping_path);
                        };
                    }
                    None => {}
                };
            }
        }
        Err(_) => panic!("error reading mapping file {:?}", mapping_path),
    }
    return mapping;
}

/// Reads the .ad3 (Atomic Data Triples) graph from this directory
fn read_store_from_file(store: &mut Store) -> &Store {
    let default_store_path = Path::new("./default_store.ad3");
    let user_store_path = Path::new("./user_store.ad3");
    let mut store_path = default_store_path;

    if user_store_path.exists() {
        store_path = user_store_path;
    }

    match std::fs::read_to_string(store_path) {
        Ok(contents) => {
            for line in contents.lines() {
                match line.chars().next() {
                    // These are comments
                    Some('#') => {}
                    Some(' ') => {}
                    // That's an array, awesome
                    Some('[') => {
                        let string_vec: Vec<String> =
                            from_str(line).expect(&*format!("Parsing error in {:?}", store_path));
                        if string_vec.len() != 3 {
                            panic!(format!("Wrong length of array in {:?} at line {:?}: wrong length of array, should be 3", store_path, line))
                        }
                        let subject = &string_vec[0];
                        let property = &string_vec[1];
                        let value = &string_vec[2];
                        match &mut store.get_mut(&*subject) {
                            Some(existing) => {
                                existing.insert(property.into(), value.into());
                            }
                            None => {
                                let mut resource: Resource = HashMap::new();
                                resource.insert(property.into(), value.into());
                                store.insert(subject.into(), resource);
                            }
                        }
                    }
                    Some(_) => println!("Parsing error in {:?} at {:?}", store_path, line),
                    None => {}
                };
            }
        }
        Err(_) => panic!("Parsing error..."),
    }

    return store;
}

fn write_store_to_disk(store: &Store) {
    let user_store_path = "./user_store.ad3";
    let mut file_string: String = String::new();
    for (subject, resource) in store {
        for (property, value) in resource {
            // let ad3_atom = format!("[\"{}\",\"{}\",\"{}\"]\n", subject, property, value.replace("\"", "\\\""));
            let mut ad3_atom =
                serde_json::to_string(&vec![subject, property, value]).expect("Can't serialize");
            ad3_atom.push_str("\n");
            &file_string.push_str(&*ad3_atom);
        }
        // file_string.push(ch);
    }
    fs::write(user_store_path, file_string).expect("Unable to write file");
}

fn write_mapping_to_disk(mapping: &Mapping) {
    let user_mapping_path = "./user_mapping.amp";
    let mut file_string: String = String::new();
    for (key, url) in mapping {
        let map = format!("{}={}\n", key, url);
        &file_string.push_str(&*map);
    }
    fs::write(user_mapping_path, file_string).expect("Unable to write file");
}

fn prompt_bookmark(mapping: &mut Mapping, subject: &String) {
    let re = Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").unwrap();
    let mut shortname: Option<String> = prompt_opt("Local Bookmark (optional)").unwrap();
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
            None => {}
        }
    }
}
