//! Because writing full URLs is error prone and time consuming, we map URLs to shortnames.
//! These are often user-specific.
//! This section provides tools to store, share and resolve these Mappings.

use crate::errors::AtomicResult;
use std::collections::hash_map::IntoIter;
use std::{collections::HashMap, fs, path::Path};
/// Maps shortanmes (bookmarks) to URLs
#[derive(Clone)]
pub struct Mapping {
    hashmap: HashMap<String, String>,
}

impl Mapping {
    pub fn init() -> Mapping {
        let hashmap: HashMap<String, String> = HashMap::new();

        Mapping { hashmap }
    }

    /// Checks if the input string is a Mapping or a valid URL.
    /// Returns Some if it is valid.
    /// If it is neither, a None is returned.
    pub fn try_mapping_or_url(&self, mapping_or_url: &str) -> Option<String> {
        match self.get(mapping_or_url) {
            Some(hit) => Some(hit.into()),
            None => {
                // Currently only accept HTTP(S) protocol
                if is_url(mapping_or_url) {
                    return Some(mapping_or_url.into());
                }
                None
            }
        }
    }

    /// Add a new bookmark to the store
    pub fn insert(&mut self, shortname: String, url: String) {
        self.hashmap.insert(shortname, url);
    }

    /// Checks if the bookmark exists, returns it
    pub fn get(&self, bookmark: &str) -> Option<&String> {
        self.hashmap.get(bookmark)
    }

    /// Reads an .amp (atomic mapping) file from your disk.
    pub fn read_mapping_from_file(&mut self, path: &Path) -> AtomicResult<()> {
        let mapping_string = std::fs::read_to_string(path)?;
        self.parse_mapping(&mapping_string)?;
        Ok(())
    }

    /// Reads an .amp (atomic mapping) file.
    /// This is a simple .ini-like text file that maps shortnames to URLs.
    /// The left-hand should contain the shortname, the right-hand the URL.
    /// Ignores # comments and empty lines.
    /// Stores after parsing to the Mapping struct.
    pub fn parse_mapping(&mut self, mapping_string: &str) -> AtomicResult<()> {
        for line in mapping_string.lines() {
            match line.chars().next() {
                Some('#') => {}
                Some(' ') => {}
                Some(_) => {
                    let split: Vec<&str> = line.split('=').collect();
                    if split.len() == 2 {
                        self.hashmap
                            .insert(String::from(split[0]), String::from(split[1]));
                    } else {
                        return Err(format!("Error reading line {:?}", line).into());
                    };
                }
                None => {}
            };
        }
        Ok(())
    }

    /// Check if the bookmark shortname is present
    pub fn contains_key(&self, key: &str) -> bool {
        self.hashmap.contains_key(key)
    }

    /// Serializes the mapping and stores it to the path
    pub fn write_mapping_to_disk(&self, path: &Path) {
        let mut file_string: String = String::new();
        for (key, url) in self.hashmap.clone().iter() {
            let map = format!("{}={}\n", key, url);
            file_string.push_str(&map);
        }
        fs::create_dir_all(path.parent().expect("Cannot create above root"))
            .expect("Unable to create dirs");
        fs::write(path, file_string).expect("Unable to write file");
    }

    pub fn populate(&mut self) -> AtomicResult<()> {
        let mapping = include_str!("../defaults/default_mapping.amp");
        self.parse_mapping(mapping)?;
        Ok(())
    }
}

/// Check if something is a URL
pub fn is_url(string: &str) -> bool {
    // TODO: Probably delete this second one, might break some tests though.
    string.starts_with("http") || string.starts_with("_:")
}

impl IntoIterator for Mapping {
    type Item = (String, String);
    type IntoIter = IntoIter<String, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.hashmap.into_iter()
    }
}
