use crate::{Resource, Store};
use std::{path::PathBuf, fs, collections::HashMap};
use serde_json::from_str;

/// Reads an .ad3 (Atomic Data Triples) graph
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
