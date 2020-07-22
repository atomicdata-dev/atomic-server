use crate::Context;
use std::{collections::HashMap, fs, path::PathBuf};

/// Maps shortanmes to URLs
pub type Mapping = HashMap<String, String>;

pub fn try_mapping_or_url(mapping_or_url: &String, mapping: &Mapping) -> Option<String> {
    let maybe = mapping.get(mapping_or_url);
    match maybe {
        Some(hit) => return Some(hit.clone()),
        None => {
            // Currently only accept HTTP(S) protocol
            if is_url(mapping_or_url) {
                return Some(mapping_or_url.clone());
            }
            return None;
        }
    }
}

pub fn read_mapping_from_file(path: &PathBuf) -> Mapping {
    let mut mapping: Mapping = HashMap::new();
    match std::fs::read_to_string(path) {
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
                            println!("Error reading line {:?} in {:?}", line, path);
                        };
                    }
                    None => {}
                };
            }
        }
        Err(_) => panic!("Error reading mapping file {:?}", path),
    }
    return mapping;
}

pub fn write_mapping_to_disk(mapping: &Mapping, path: &PathBuf) {
    let mut file_string: String = String::new();
    for (key, url) in mapping {
        let map = format!("{}={}\n", key, url);
        &file_string.push_str(&*map);
    }
    fs::create_dir_all(path.parent().expect("Could not find parent folder"))
        .expect("Unable to create dirs");
    fs::write(path, file_string).expect("Unable to write file");
}

/// Check if something is a shortname or URL
pub fn is_url(string: &String) -> bool {
    string.starts_with("http")
}
