use crate::{Resource, Store};
use std::{path::PathBuf, fs, collections::HashMap, error::Error};
use serde_json::from_str;
use crate::mapping;
use crate::urls;
use mapping::{try_mapping_or_url, Mapping};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

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
      for (property, value) in resource {
          // let ad3_atom = format!("[\"{}\",\"{}\",\"{}\"]\n", subject, property, value.replace("\"", "\\\""));
          let mut ad3_atom =
              serde_json::to_string(&vec![subject, property, value]).expect("Can't serialize");
          ad3_atom.push_str("\n");
          &file_string.push_str(&*ad3_atom);
      }
      // file_string.push(ch);
  }
  fs::create_dir_all(path.parent().expect("Could not find parent folder")).expect("Unable to create dirs");
  fs::write(path, file_string).expect("Unable to write file");
}

/// Accepts an Atomic Path string, returns the result
/// https://docs.atomicdata.dev/core/paths.html
pub fn get_path(atomic_path: &str, store: &Store, mapping: &Mapping) -> String {
    // The first item of the path represents the starting Resource, the following ones are traversing the graph / selecting properties.
    let path_items: Vec<&str> = atomic_path.split(' ').collect();
    let mut current_resource;
    // For the first item, check the user mapping
    let id_url = mapping::try_mapping_or_url(&String::from(path_items[0]), mapping)
        .expect(&*format!("No url found for {}", path_items[0]));
    current_resource = store.get(&id_url).expect("not found");
    // Loops over every item in the list, traverses the graph
    // Skip the first one
    for item in path_items[1..].iter().cloned() {
        // Get the shortname or use the URL
        if mapping::is_url(&String::from(item)) {
            let next_item = current_resource.get(item).expect(&*format!("property '{}' not found", item));
        } else {
            // Traverse relations, don't use mapping here, but do use classes
            let property_url = &resolve_property_shortname(&String::from(item), current_resource, &store)
                .expect(&*format!("URL not found for {}", item));
            current_resource = store.get(property_url)
                .expect(&*format!("Resource not found not found for {}", property_url))
        }
        store.get(&String::from(item));
    }
    println!("{:?}", current_resource);
    return String::from("SomeResult")
}

pub fn resolve_property_shortname(shortname: &String, resource: &Resource, store: &Store) -> Result<String> {
    // Find first class of resource
    // Get classes array
    let classes_resource_array: Vec<String> = from_str(resource.get(urls::IS_A).ok_or("Resource has no isA relation")?)?;

    // Iterate over the classes
    for class_url in classes_resource_array {
        let class_resource = store.get(&*class_url).ok_or("Class not found")?;
        let recommended_props: Vec<String> = from_str(class_resource.get(urls::RECOMMENDS).ok_or("No recommended props in class")?)?;
        let required_props: Vec<String> = from_str(class_resource.get(urls::REQUIRES).ok_or("No required props in class")?)?;
        let all_prop_urls: Vec<String> = [recommended_props, required_props].concat();
        // Iterate over both recommended and required resources, and check their shortnames
        for prop_url in all_prop_urls {
            let prop_resource = store.get(&*prop_url).ok_or("Class not found")?;
            let prop_shortname = prop_resource.get(urls::SHORTNAME).ok_or("Class not found")?;
            if prop_shortname == shortname {
                return Ok(prop_url)
            }
        }
        return Err(format!("no match... class: {}, shortname: {}", class_url, shortname).into())
    }
    // Iterate over all required & recommended properties
    // Did you find the shortname? Nice, return it.
    return Err("Should not end here...".into())
}
