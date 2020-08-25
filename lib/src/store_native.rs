//! Store - this is an in-memory store of Atomic data.
//! This provides many methods for finding, changing, serializing and parsing Atomic Data.
//! Currently, it can only persist its data as .ad3 (Atomic Data Triples) to disk.
//! A more robust persistent storage option will be used later, such as: https://github.com/TheNeikos/rustbreak

use crate::errors::Result;
use crate::Resource;
use std::collections::HashMap;

/// In-memory store of data, containing the Atoms with native, validated Values
#[derive(Clone)]
pub struct StoreNative {
    // The store currently holds two stores - that is not ideal
    resources: HashMap<String, Resource>,
}

impl StoreNative {
    /// Create an empty Store. This is where you start.
    ///
    /// # Example
    /// let store = Store::init();
    pub fn init() -> StoreNative {
        return StoreNative {
            resources: HashMap::new(),
        };
    }

    pub fn add_resource(&mut self, resource: Resource) -> Result<()> {
        self.resources.insert(resource.subject().clone(), resource);
        Ok(())
    }

    pub fn get(&self, resource_url: &String) -> Option<&Resource> {
        return self.resources.get(resource_url);
    }
}
