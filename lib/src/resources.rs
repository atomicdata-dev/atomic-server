use crate::errors::AtomicResult;
use crate::values::Value;
use crate::{mapping::is_url, storelike::{Property, Class}, Atom, Storelike};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A resource is a set of Atoms that shares a single Subject
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resource {
    propvals: PropVals,
    subject: String,
    // The isA relationship of the resource
    // Useful for quick access to shortnames and datatypes
    // Should be an empty vector if it's checked, should be None if unknown
    classes: Option<Vec<Class>>,
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
            classes: None,
        };
    }

    pub fn new_from_resource_string(
        subject: String,
        resource_string: &ResourceString,
        store: &dyn Storelike,
    ) -> AtomicResult<Resource> {
        let mut res = Resource::new(subject);
        for (prop_string, val_string) in resource_string {
            let propertyfull = store.get_property(prop_string).expect("Prop not found");
            let fullvalue = Value::new(val_string, &propertyfull.data_type)?;
            res.insert(prop_string.clone(), fullvalue)?;
        }
        Ok(res)
    }

    /// Get a value by property URL
    pub fn get(&self, property_url: &str) -> AtomicResult<&Value> {
        return Ok(self.propvals.get(property_url).ok_or(format!(
            "Property {} for resource {} not found",
            property_url, self.subject
        ))?);
    }

    /// Gets a value by its shortname
    // Todo: should use both the Classes AND the existing props
    pub fn get_shortname(&self, shortname: &str, store: &dyn Storelike) -> AtomicResult<&Value> {
        // If there is a class
        for (url, _val) in self.propvals.iter() {
            match store.get_property(url) {
                Ok(prop) => {
                    if &prop.shortname == shortname {
                        return Ok(self.get(url)?);
                    }
                }
                Err(_) => {}
            }
        }

        return Err("No match".into());
    }

    /// Tries to resolve the shortname to a URL.
    // Currently assumes that classes have been set before.
    pub fn resolve_shortname(
        &mut self,
        shortname: &str,
        store: &dyn Storelike,
    ) -> AtomicResult<Option<Property>> {
        if self.classes.is_none() {
            self.classes = Some(store.get_classes_for_subject(self.subject())?);
        }
        let classes = self.classes.clone().unwrap();
        // Loop over all Requires and Recommends props
        for class in classes {
            for required_prop in class.requires {
                if required_prop.shortname == shortname {
                    return Ok(Some(required_prop));
                }
            }
            for recommended_prop in class.recommends {
                if recommended_prop.shortname == shortname {
                    return Ok(Some(recommended_prop));
                }
            }
        }
        return Ok(None);
    }

    /// Insert a Property/Value combination.
    /// Overwrites existing Property/Value.
    /// Validates the datatype.
    pub fn insert_string(
        &mut self,
        property_url: String,
        value: &String,
        store: &dyn Storelike,
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

    /// Sets a property / value combination.
    /// Property can be a shortname (e.g. 'description' instead of the full URL), if the Resource has a Class.
    /// Validates the datatype.
    pub fn set_prop(&mut self, property: &str, value: &str, store: &mut dyn Storelike) -> AtomicResult<()> {
        let fullprop = if is_url(property) {
            store.get_property(property)?
        } else {
            self.resolve_shortname(property, store)?.unwrap()
        };
        let fullval = Value::new(value, &fullprop.data_type)?;
        self.insert(fullprop.subject, fullval)?;
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

/// A plainstring hashmap, which represents an (unvalidated?) Atomic Resource.
/// The key string represents the URL of the Property, the value one its Values.
pub type ResourceString = HashMap<String, String>;

pub fn resourcestring_to_atoms(subject: &str, resource: ResourceString) -> Vec<Atom> {
    let mut vec = Vec::new();
    for (prop, val) in resource.iter() {
        vec.push(Atom::new(subject, prop, val));
    }
    vec
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::{urls, parse::parse_ad3};

    fn init_store() -> Store {
        let string =
            String::from("[\"_:test\",\"https://atomicdata.dev/properties/shortname\",\"hi\"]");
        let mut store = Store::init();
        store.populate().unwrap();
        let atoms = parse_ad3(&string).unwrap();
        store.add_atoms(atoms).unwrap();
        return store;
    }

    #[test]
    fn get_and_set_resource_props() {
        let mut store = init_store();
        let mut resource = store.get_resource(urls::CLASS).unwrap();
        assert!(resource.get_shortname("shortname", &store).unwrap().to_string() == "class");
        resource.set_prop("shortname", "something-valid", &mut store).unwrap();
        assert!(resource.get_shortname("shortname", &store).unwrap().to_string() == "something-valid");
        resource.set_prop("shortname", "should not contain spaces", &mut store).unwrap_err();
    }

}
