// Store - this is an in-memory store of Atomic data.
// Currently, it writes everything as .ad3 (NDJSON arrays) to disk, but this should change later on.
// Perhaps we'll use some database, or something very specific to rust: https://github.com/TheNeikos/rustbreak

use crate::errors::Result;
use crate::mapping;
use crate::{serialize::deserialize_json_array, urls};
use mapping::Mapping;
use regex::Regex;
use serde_json::from_str;
use std::{collections::HashMap, fs, path::PathBuf};

/// The first string represents the URL of the Property, the second one its Value.
pub type Resource = HashMap<String, String>;

pub struct Property {
    // URL of the class
    pub class_type: Option<String>,
    // URL of the datatype
    pub data_type: DataType,
    pub shortname: String,
    pub identifier: String,
    pub description: String,
}

#[derive(Debug)]
pub enum DataType {
    AtomicUrl,
    Date,
    Integer,
    MDString,
    ResourceArray,
    Slug,
    String,
    Timestamp,
    Unsupported(String),
}

#[derive(Debug)]
pub enum Value {
    AtomicUrl(String),
    Date(String),
    Integer(i32),
    MDString(String),
    ResourceArray(Vec<String>),
    Slug(String),
    String(String),
    Timestamp(i64),
    UnkownValue(UnkownValue),
}

#[derive(Debug)]
pub struct UnkownValue {
    pub value: String,
    // URL of the datatype
    pub datatype: String,
}

pub struct Atom {
    pub subject: String,
    pub property: String,
    pub value: String,
    pub native_value: Value,
}

/// The in-memory store of data, containing the Resources, Properties and Classes
pub type Store = HashMap<String, Resource>;

pub fn init() -> Store {
    return HashMap::new();
}

/// Reads an .ad3 (Atomic Data Triples) graph and adds it to the store
pub fn read_store_from_file<'a>(store: &'a mut Store, path: &'a PathBuf) -> &'a Store {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            for line in contents.lines() {
                match line.chars().next() {
                    // These are comments
                    Some('#') => {}
                    Some(' ') => {}
                    // That's an array, awesome
                    Some('[') => {
                        let string_vec: Vec<String> =
                            from_str(line).expect(&*format!("Parsing error in {:?}", path));
                        if string_vec.len() != 3 {
                            panic!(format!("Wrong length of array in {:?} at line {:?}: wrong length of array, should be 3", path, line))
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
                    Some(_) => println!("Parsing error in {:?} at {:?}", path, line),
                    None => {}
                };
            }
        }
        Err(err) => panic!(format!("Parsing error... {}", err)),
    }

    return store;
}

/// Serializes the current store and saves to path
pub fn write_store_to_disk(store: &Store, path: &PathBuf) {
    let mut file_string: String = String::new();
    for (subject, resource) in store {
        // TODO: use resource_to_ad3()
        for (property, value) in resource {
            // let ad3_atom = format!("[\"{}\",\"{}\",\"{}\"]\n", subject, property, value.replace("\"", "\\\""));
            let mut ad3_atom =
                serde_json::to_string(&vec![subject, property, value]).expect("Can't serialize");
            ad3_atom.push_str("\n");
            &file_string.push_str(&*ad3_atom);
        }
        // file_string.push(ch);
    }
    fs::create_dir_all(path.parent().expect("Could not find parent folder"))
        .expect("Unable to create dirs");
    fs::write(path, file_string).expect("Unable to write file");
}

pub fn property_url_to_shortname(url: &String, store: &Store) -> Result<String> {
    let property_resource = store
        .get(url)
        .ok_or(format!("Could not find property for {}", url))?
        .get(urls::SHORTNAME)
        .ok_or(format!("Could not get shortname prop for {}", url))?;

    return Ok(property_resource.into());
}

pub fn get_property(url: &String, store: &Store) -> Result<Property> {
    let property_resource = store.get(url).ok_or("Property not found")?;
    let property = Property {
        data_type: match_datatype(property_resource
            .get(urls::DATATYPE_PROP)
            .ok_or(format!("Datatype not found for property {}", url))?
            .into()),
        shortname: property_resource
            .get(urls::SHORTNAME)
            .ok_or(format!("Shortname not found for property {}", url))?
            .into(),
        description: property_resource
            .get(urls::DESCRIPTION)
            .ok_or(format!("Description not found for property {}", url))?
            .into(),
        class_type: property_resource
            .get(urls::CLASSTYPE_PROP)
            .map(|s| s.clone()),
        identifier: url.into(),
    };

    return Ok(property);
}

// A path can return one of many things
pub enum PathReturn {
    Subject(String),
    Atom(Atom),
}

/// Accepts an Atomic Path string, returns the result value (resource or property value)
/// https://docs.atomicdata.dev/core/paths.html
/// Todo: return something more useful, give more context.
pub fn get_path(atomic_path: &str, store: &Store, mapping: &Mapping) -> Result<PathReturn> {
    // The first item of the path represents the starting Resource, the following ones are traversing the graph / selecting properties.
    let path_items: Vec<&str> = atomic_path.split(' ').collect();
    // For the first item, check the user mapping
    let id_url: String = mapping::try_mapping_or_url(&String::from(path_items[0]), mapping)
        .ok_or(&*format!("No url found for {}", path_items[0]))?;
    if path_items.len() == 1 {
        return Ok(PathReturn::Subject(id_url));
    }
    // The URL of the next resource
    let mut subject = id_url;
    // Set the currently selectred resource parent, which starts as the root of the search
    let mut resource: Option<&Resource> = store.get(&subject);
    // During each of the iterations of the loop, the scope changes.
    // Try using pathreturn...
    let mut current: PathReturn = PathReturn::Subject(subject.clone());
    // Loops over every item in the list, traverses the graph
    // Skip the first one, for that is the subject (i.e. first parent) and not a property
    for item in path_items[1..].iter().cloned() {
        // In every iteration, the subject, property_url and current should be set.
        // Ignore double spaces
        if item == "" {
            continue;
        }
        // If the item is a number, assume its indexing some array
        match item.parse::<u32>() {
            Ok(i) => match current {
                PathReturn::Atom(atom) => {
                    let array_string = resource
                        .ok_or("Resource not found")?
                        .get(&atom.property)
                        .ok_or("Property not found")?;
                    let vector: Vec<String> =
                        from_str(array_string).expect("Failed to parse array");
                    if vector.len() <= i as usize {
                        eprintln!(
                            "Too high index ({}) for array with length {}",
                            i,
                            array_string.len()
                        );
                    }
                    let url = &vector[i as usize];

                    subject = url.clone();
                    resource = store.get(url);
                    current = PathReturn::Subject(url.clone());
                    continue;
                }
                PathReturn::Subject(_) => return Err("You can't do an index on a resource, only on arrays.".into()),
            },
            Err(_) => {}
        };
        // Since the selector isn't an array index, we can assume it's a property URL
        let property_url;
        // Get the shortname or use the URL
        if mapping::is_url(&String::from(item)) {
            property_url = Some(String::from(item));
        } else {
            // Traverse relations, don't use mapping here, but do use classes
            property_url = Some(property_shortname_to_url(
                &String::from(item),
                resource.ok_or("Relation not found")?,
                &store,
            )?);
        }
        // Set the parent for the next loop equal to the next node.
        let value = Some(resource
            .expect("Resource not found")
            .get(&property_url.clone().unwrap())
            .unwrap().clone());
        current = PathReturn::Atom(
            Atom {
                subject: subject.clone(),
                property: property_url.clone().unwrap(),
                value: value.clone().unwrap(),
                native_value: get_native_value(
                    &value.clone().unwrap(),
                    &property_url.clone().unwrap(),
                    store
                )?,
            }
        )
    }
    return Ok(current);
}

pub fn property_shortname_to_url(
    shortname: &String,
    resource: &Resource,
    store: &Store,
) -> Result<String> {
    for (prop_url, _value) in resource.iter() {
        let prop_resource = store
            .get(&*prop_url)
            .ok_or(format!("Property '{}' not found", prop_url))?;
        let prop_shortname = prop_resource
            .get(urls::SHORTNAME)
            .ok_or(format!("Property shortname for '{}' not found", prop_url))?;
        if prop_shortname == shortname {
            return Ok(prop_url.clone());
        }
    }
    return Err(format!("Could not find shortname {}", shortname).into());
}

pub fn validate_store(store: &Store) -> Result<String> {
    todo!();
    for (url, properties) in store.iter() {
        // Are all property URLs accessible?
        // Do the datatypes of the properties match the datatypes of the
        // if they are instances of a class, do they have the required fields?
        println!("{:?}: {:?}", url, properties);
    }
    return Err("Whoops".into());
}

pub const SLUG_REGEX: &str = r"^[a-z0-9]+(?:-[a-z0-9]+)*$";
pub const DATE_REGEX: &str = r"^\d{4}\-(0[1-9]|1[012])\-(0[1-9]|[12][0-9]|3[01])$";

// Returns an enum of the native value.
// Validates the contents.
pub fn get_native_value(value: &String, property_url: &String, store: &Store) -> Result<Value> {
    let prop = get_property(property_url, store)?;
    match prop.data_type {
        DataType::Integer => {
            let val: i32 = value.parse()?;
            return Ok(Value::Integer(val));
        }
        DataType::String => return Ok(Value::String(value.clone())),
        DataType::MDString => return Ok(Value::MDString(value.clone())),
        DataType::Slug => {
            let re = Regex::new(SLUG_REGEX).unwrap();
            if re.is_match(&*value) {
                return Ok(Value::Slug(value.clone()));
            }
            return Err(format!("Not a valid slug: {}", value).into())
        },
        DataType::AtomicUrl => {
            let re = Regex::new(DATE_REGEX).unwrap();
            if re.is_match(&*value) {
                return Ok(Value::Date(value.clone()));
            }
            return Err(format!("Not a valid Atomic URL: {}", value).into())
        },
        DataType::ResourceArray => {
            let vector: Vec<String> = deserialize_json_array(value).unwrap();
            return Ok(Value::ResourceArray(vector))
        },
        DataType::Date => {
            let re = Regex::new(DATE_REGEX).unwrap();
            if re.is_match(&*value) {
                return Ok(Value::Date(value.clone()));
            }
            return Err(format!("Not a valid date: {}", value).into())
        },
        DataType::Timestamp => {
            let val: i64 = value.parse()?;
            return Ok(Value::Timestamp(val));
        },
        DataType::Unsupported(unsup_url) => {
            return Ok(Value::UnkownValue(UnkownValue {
                value: value.into(),
                datatype: unsup_url.into(),
            }))
        }
    };
}

pub fn match_datatype(string: &String) -> DataType {
    match string.as_str() {
        urls::INTEGER => DataType::Integer,
        urls::STRING => DataType::String,
        urls::MDSTRING => DataType::MDString,
        urls::SLUG => DataType::Slug,
        urls::ATOMIC_URL => DataType::AtomicUrl,
        urls::RESOURCE_ARRAY => DataType::ResourceArray,
        urls::DATE => DataType::Date,
        urls::TIMESTAMP => DataType::Timestamp,
        unsupported_datatype => {
            return DataType::Unsupported(string.into())
        }
    }
}
