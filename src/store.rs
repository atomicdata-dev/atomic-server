// Store - this is an in-memory store of Atomic data.
// Currently, it writes everything as .ad3 (NDJSON arrays) to disk, but this should change later on.
// Perhaps we'll use some database, or something very specific to rust: https://github.com/TheNeikos/rustbreak

use crate::errors::Result;
use crate::mapping;
use crate::urls;
use mapping::Mapping;
use serde_json::from_str;
use std::{collections::HashMap, fs, path::PathBuf};

/// The first string represents the URL of the Property, the second one its Value.
pub type Resource = HashMap<String, String>;

pub struct Property {
    // URL of the class
    pub class_type: Option<String>,
    // URL of the datatype
    pub data_type: String,
    pub shortname: String,
    pub identifier: String,
    pub description: String,
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
        data_type: property_resource
            .get(urls::DATATYPE_PROP)
            .ok_or(format!("Datatype not found for property {}", url))?
            .into(),
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

    return Ok(property)
}

/// Accepts an Atomic Path string, returns the result value
/// https://docs.atomicdata.dev/core/paths.html
/// Todo: return something more useful, give more context.
pub fn get_path(atomic_path: &str, store: &Store, mapping: &Mapping) -> Result<String> {
    // The first item of the path represents the starting Resource, the following ones are traversing the graph / selecting properties.
    let path_items: Vec<&str> = atomic_path.split(' ').collect();
    // For the first item, check the user mapping
    let id_url = mapping::try_mapping_or_url(&String::from(path_items[0]), mapping)
        .ok_or(&*format!("No url found for {}", path_items[0]))?;
    if path_items.len() == 1 {
        return Ok(id_url);
    }
    // Set a parent, which starts as the root of the search
    let mut parent = store.get(&id_url);
    // The URL of the next resource
    let mut found_property_url = id_url;
    // Loops over every item in the list, traverses the graph
    // Skip the first one, for that is the subject (i.e. first parent) and not a property
    for item in path_items[1..].iter().cloned() {
        // Get the shortname or use the URL
        if mapping::is_url(&String::from(item)) {
            // found_value = current_resource.get(item).expect(&*format!("property '{}' not found", item)).clone();
            found_property_url = item.into();
        } else {
            // Traverse relations, don't use mapping here, but do use classes
            let property_url = property_shortname_to_url(
                &String::from(item),
                parent.ok_or("Relation not found")?,
                &store,
            )?;
            found_property_url = property_url;
        }
        // Set the parent for the next loop equal to the next node.
        let value = parent.unwrap().get(&found_property_url).unwrap();
        match store.get(value) {
            Some(resource) => {
                parent = Some(resource);
            }
            None => {
                // If the value is something different than a resolvable URL, don't do anything
            }
        }
    }
    let value = parent
        .ok_or(format!("Resource not found: {:?}", &parent))?
        .get(&found_property_url)
        .ok_or(format!("Property not found: {:?}", &found_property_url))?;
    return Ok(value.into());
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
