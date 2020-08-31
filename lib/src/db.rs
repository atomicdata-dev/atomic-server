//! Persistent store, stores to disk.
//! Uses Sled - an embedded database.

use crate::storelike::Storelike;
use std::collections::HashMap;
use sled;

struct Db {
  tree: sled::Db,
}

impl Db {
  // Creates a new store at the specified path
  pub fn init(&mut self, path: std::path::PathBuf) -> Db {
    let tree = sled::open(path).expect("open");
    return Db {
      tree,
    };
  }
}

impl Storelike for Db {
    fn get_string_resource(&self, resource_url: &String) -> Option<crate::storelike::ResourceString> {
        let result = self.tree.get(resource_url).unwrap().unwrap();
        // self.tree.
        let fake = HashMap::new();
        Some(fake)
    }
}
