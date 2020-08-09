//! # Mappings
//! Because writing full URLs is error prone and time consuming, we map URLs to shortnames.
//! These are often user-specific.
//! This section provides tools to store, share and resolve these Mappings.

use crate::errors::Result;
use std::{collections::HashMap, fs, path::PathBuf};

/// Maps shortanmes to URLs
pub type Mapping = HashMap<String, String>;

/// Checks if the input string is a Mapping or a valid URL.
/// If it is neither, a None is returned.
pub fn try_mapping_or_url(mapping_or_url: &String, mapping: &Mapping) -> Option<String> {
    match mapping.get(mapping_or_url) {
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

/// Reads an .amp (atomic mapping) file.
/// This is a simple .ini-like text file that maps shortnames to URLs.
/// The left-hand should contain the shortname, the right-hand the URL.
/// Ignores # comments and empty lines
pub fn read_mapping_from_file(path: &PathBuf) -> Result<Mapping> {
    let mut mapping: Mapping = HashMap::new();
    for line in std::fs::read_to_string(path)?.lines() {
        match line.chars().next() {
            Some('#') => {}
            Some(' ') => {}
            Some(_) => {
                let split: Vec<&str> = line.split("=").collect();
                if split.len() == 2 {
                    &mapping.insert(String::from(split[0]), String::from(split[1]));
                } else {
                    return Err(format!("Error reading line {:?} in {:?}", line, path).into());
                };
            }
            None => {}
        };
    }
    return Ok(mapping);
}

/// Serializes the mapping and stores it to the path
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

/// Check if something is a URL
pub fn is_url(string: &String) -> bool {
    string.starts_with("http")
}
