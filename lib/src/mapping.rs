//! # Mappings
//! Because writing full URLs is error prone and time consuming, we map URLs to shortnames.
//! These are often user-specific.
//! This section provides tools to store, share and resolve these Mappings.

use crate::errors::AtomicResult;
use std::{collections::HashMap, fs, path::PathBuf};
use std::collections::hash_map::IntoIter;
/// Maps shortanmes (bookmarks) to URLs
#[derive(Clone)]
pub struct Mapping {
    hashmap: HashMap<String, String>,
}

impl Mapping {
    pub fn init() -> Mapping {
        let hashmap: HashMap<String, String> = HashMap::new();

        Mapping {
            hashmap
        }
    }

    /// Checks if the input string is a Mapping or a valid URL.
    /// If it is neither, a None is returned.
    pub fn try_mapping_or_url(&self, mapping_or_url: &String) -> Option<String> {
        match self.get(mapping_or_url) {
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

    /// Add a new bookmark to the store
    pub fn insert(&mut self, shortname: String, url: String){
        self.hashmap.insert(shortname, url);
    }

    /// Checks if the bookmark exists, returns it
    pub fn get(&self, bookmark: &String) -> Option<&String> {
        self.hashmap.get(bookmark)
    }

    /// Reads an .amp (atomic mapping) file.
    /// This is a simple .ini-like text file that maps shortnames to URLs.
    /// The left-hand should contain the shortname, the right-hand the URL.
    /// Ignores # comments and empty lines
    pub fn read_mapping_from_file(&mut self, path: &PathBuf) -> AtomicResult<()> {
        for line in std::fs::read_to_string(path)?.lines() {
            match line.chars().next() {
                Some('#') => {}
                Some(' ') => {}
                Some(_) => {
                    let split: Vec<&str> = line.split("=").collect();
                    if split.len() == 2 {
                        &self.hashmap.insert(String::from(split[0]), String::from(split[1]));
                    } else {
                        return Err(format!("Error reading line {:?} in {:?}", line, path).into());
                    };
                }
                None => {}
            };
        }
        return Ok(());
    }

    /// Check if the bookmark shortname is present
    pub fn contains_key(&self, key: &String) -> bool {
        return self.hashmap.contains_key(key)
    }

    /// Serializes the mapping and stores it to the path
    pub fn write_mapping_to_disk(&self, path: &PathBuf) {
        let mut file_string: String = String::new();
        for (key, url) in self.hashmap.clone().iter() {
            let map = format!("{}={}\n", key, url);
            &file_string.push_str(&*map);
        }
        fs::create_dir_all(path.parent().expect("Could not find parent folder"))
            .expect("Unable to create dirs");
        fs::write(path, file_string).expect("Unable to write file");
    }
}

/// Check if something is a URL
pub fn is_url(string: &String) -> bool {
    string.starts_with("http") || string.starts_with("_:")
}

impl IntoIterator for Mapping {
    type Item = (String, String);
    type IntoIter = IntoIter<String, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.hashmap.into_iter()
    }
}
