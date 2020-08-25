use crate::errors::Result;
use crate::values::Value;
use crate::Store;
use std::collections::HashMap;

/// A resource is a set of Atoms that shares a single Subject
#[derive(Clone, Debug)]
pub struct Resource {
    properties: Properties,
    subject: String,
}

/// Maps Property URLs to their values
type Properties = HashMap<String, Value>;

impl Resource {
    /// Create a new, empty Resource.
    pub fn new(subject: String) -> Resource {
        let properties: Properties = HashMap::new();
        return Resource {
            properties,
            subject,
        };
    }

    /// Get a value by property URL
    pub fn get(&self, property_url: &String) -> Result<&Value> {
        return Ok(self.properties.get(property_url).ok_or(format!(
            "Property {} for resource {} not found",
            property_url, self.subject
        ))?);
    }

    /// Insert a Property/Value combination.
    /// Overwrites existing Property/Value.
    /// Validates the datatype.
    pub fn insert_string(
        &mut self,
        property_url: String,
        value: &String,
        store: &Store,
    ) -> Result<()> {
        let fullprop = &store.get_property(&property_url)?;
        let val = Value::new(value, &fullprop.data_type)?;
        self.properties.insert(property_url, val);
        Ok(())
    }

    /// Inserts a Property/Value combination.
    /// Overwrites existing.
    pub fn insert(&mut self, property: String, value: Value) -> Result<()> {
        self.properties.insert(property, value);
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
        for (prop, val) in &mut self.properties.clone().into_iter() {
            hashmap.insert(prop, val.to_string());
        }
        hashmap
    }
}
