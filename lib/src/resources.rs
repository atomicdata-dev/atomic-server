use crate::errors::AtomicResult;
use crate::values::Value;
use crate::Store;
use crate::Storelike;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// A resource is a set of Atoms that shares a single Subject
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resource {
    propvals: PropVals,
    subject: String,
}

/// Maps Property URLs to their values
type PropVals = HashMap<String, Value>;

impl Resource {
    /// Create a new, empty Resource.
    pub fn new(subject: String) -> Resource {
        let properties: PropVals = HashMap::new();
        return Resource {
            propvals: properties,
            subject,
        };
    }

    /// Get a value by property URL
    pub fn get(&self, property_url: &String) -> AtomicResult<&Value> {
        return Ok(self.propvals.get(property_url).ok_or(format!(
            "Property {} for resource {} not found",
            property_url, self.subject
        ))?);
    }

    /// Gets a value by its shortname
    pub fn get_shortname(&self, shortname: &String, store: &Store) -> AtomicResult<&Value> {
        for (url, _val) in self.propvals.iter() {
            match store.get_property(url) {
                Ok(prop) => {
                    if &prop.shortname == shortname {
                        return Ok(self.get(url)?)
                    }
                }
                Err(_) => {}
            }

        }
        return Err("No match".into())
    }

    /// Insert a Property/Value combination.
    /// Overwrites existing Property/Value.
    /// Validates the datatype.
    pub fn insert_string(
        &mut self,
        property_url: String,
        value: &String,
        store: &Store,
    ) -> AtomicResult<()> {
        let fullprop = &store.get_property(&property_url)?;
        let val = Value::new(value, &fullprop.data_type)?;
        self.propvals.insert(property_url, val);
        Ok(())
    }

    /// Inserts a Property/Value combination.
    /// Overwrites existing.
    pub fn insert(&mut self, property: String, value: Value) -> AtomicResult<()> {
        self.propvals.insert(property, value);
        Ok(())
    }

    pub fn set_subject(&mut self, url: String) {
        self.subject = url;
    }

    pub fn subject(&self) -> &String {
        &self.subject
    }

    /// Converts a resource to a string only HashMap
    pub fn to_plain(&self) -> HashMap<String, String> {
        let mut hashmap: HashMap<String, String> = HashMap::new();
        for (prop, val) in &mut self.propvals.clone().into_iter() {
            hashmap.insert(prop, val.to_string());
        }
        hashmap
    }
}
