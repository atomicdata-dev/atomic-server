//! Store - this is an in-memory store of Atomic data.
//! This provides many methods for finding, changing, serializing and parsing Atomic Data.
//! Currently, it can only persist its data as .ad3 (Atomic Data Triples) to disk.
//! A more robust persistent storage option will be used later, such as: https://github.com/TheNeikos/rustbreak

use crate::errors::Result;
use crate::mutations;
use crate::values::{DataType, Value};
use crate::{
    atoms::Atom,
    storelike::{ResourceString, Storelike},
};
use serde_json::from_str;
use std::{collections::HashMap, fs, path::PathBuf};

/// The in-memory store of data, containing the Resources, Properties and Classes
#[derive(Clone)]
pub struct Store {
    // The store currently holds two stores - that is not ideal
    hashmap: HashMap<String, ResourceString>,
    log: mutations::Log,
}

impl Store {
    /// Create an empty Store. This is where you start.
    ///
    /// # Example
    /// let store = Store::init();
    pub fn init() -> Store {
        return Store {
            hashmap: HashMap::new(),
            log: Vec::new(),
        };
    }

    /// Replaces existing resource with the contents
    /// Accepts a simple nested string only hashmap
    /// Adds to hashmap and to the resource store
    pub fn add_resource(&mut self, subject: String, resource: ResourceString) -> Result<()> {
        self.hashmap.insert(subject.clone(), resource.clone());
        return Ok(());
    }

    /// Parses an Atomic Data Triples (.ad3) string and adds the Atoms to the store.
    /// Allows comments and empty lines.
    pub fn parse_ad3<'a, 'b>(&mut self, string: &'b String) -> Result<()> {
        let mut atoms: Vec<Atom> = Vec::new();
        for line in string.lines() {
            match line.chars().next() {
                // These are comments
                Some('#') => {}
                Some(' ') => {}
                // That's an array, awesome
                Some('[') => {
                    let string_vec: Vec<String> =
                        from_str(line).expect(&*format!("Parsing error in {:?}", line));
                    if string_vec.len() != 3 {
                        return Err(format!("Wrong length of array at line {:?}: wrong length of array, should be 3", line).into());
                    }
                    let subject = &string_vec[0];
                    let property = &string_vec[1];
                    let value = &string_vec[2];
                    atoms.push(Atom::new(subject.clone(), property.clone(), value.clone()));
                }
                Some(char) => {
                    return Err(
                        format!("Parsing error at {:?}, cannot start with {}", line, char).into(),
                    )
                }
                None => {}
            };
        }
        self.add_atoms(atoms)?;
        return Ok(());
    }

    /// Reads an .ad3 (Atomic Data Triples) graph and adds it to the store
    pub fn read_store_from_file<'a>(&mut self, path: &'a PathBuf) -> Result<()> {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                self.parse_ad3(&contents)?;
                Ok(())
            }
            Err(err) => Err(format!("Parsing error: {}", err).into()),
        }
    }

    /// Serializes the current store and saves to path
    pub fn write_store_to_disk(&self, path: &PathBuf) -> Result<()> {
        let mut file_string: String = String::new();
        for (subject, _) in self.hashmap.iter() {
            let resourcestring = self.resource_to_ad3(&subject, None)?;
            &file_string.push_str(&*resourcestring);
        }
        fs::create_dir_all(path.parent().expect("Could not find parent folder"))
            .expect("Unable to create dirs");
        fs::write(path, file_string).expect("Unable to write file");
        return Ok(());
    }

    /// Gets a resource where with Values instead of strings
    pub fn get_native(&self) {}

    // Returns an enum of the native value.
    // Validates the contents.
    pub fn get_native_value(value: &String, datatype: &DataType) -> Result<Value> {
        Value::new(value, datatype)
    }

    pub fn resource_to_ad3(&self, subject: &String, domain: Option<&String>) -> Result<String> {
        let mut string = String::new();
        let resource = self
            .get_string_resource(subject)
            .ok_or("Resource not found")?;
        let mut mod_subject = subject.clone();
        // Replace local schema with actual local domain
        if subject.starts_with("_:") && domain.is_some() {
            // Remove first two characters
            let mut chars = subject.chars();
            chars.next();
            chars.next();
            mod_subject = format!("{}{}", &domain.unwrap(), &chars.as_str());
        }
        for (property, value) in resource {
            let mut ad3_atom = serde_json::to_string(&vec![&mod_subject, &property, &value])
                .expect("Can't serialize");
            ad3_atom.push_str("\n");
            &string.push_str(&*ad3_atom);
        }
        return Ok(string);
    }

    /// Checks Atomic Data in the store for validity.
    /// Returns an Error if it is not valid.
    ///
    /// Validates:
    ///
    /// - [X] If the Values can be parsed using their Datatype (e.g. if Integers are integers)
    /// - [X] If all required fields of the class are present
    /// - [ ] If the URLs are publicly accessible and return the right type of data
    /// - [ ] Returns a report with multiple options
    #[allow(dead_code, unreachable_code)]
    pub fn validate_store(&self) -> Result<()> {
        for (subject, resource) in self.hashmap.iter() {
            println!("Subject: {:?}", subject);
            println!("Resource: {:?}", resource);

            let mut found_props: Vec<String> = Vec::new();

            for (prop_url, value) in resource {
                let property = self.get_property(prop_url)?;

                Value::new(value, &property.data_type)?;
                found_props.push(prop_url.clone());
                // println!("{:?}: {:?}", prop_url, value);
            }
            let classes = self.get_classes_for_subject(subject)?;
            for class in classes {
                println!("Class: {:?}", class.shortname);
                println!("Found: {:?}", found_props);
                for required_prop in class.requires {
                    println!("Required: {:?}", required_prop.shortname);
                    if !found_props.contains(&required_prop.subject) {
                        return Err(format!(
                            "Missing requried property {} in {} because of class {}",
                            &required_prop.shortname, subject, class.subject,
                        )
                        .into());
                    }
                }
            }
            println!("{:?} Valid", subject);
        }
        return Ok(());
    }

    /// Triple Pattern Fragments interface.
    /// Use this for most queries, e.g. finding all items with some property / value combination.
    /// Returns an empty array if nothing is found.
    ///
    /// # Example
    ///
    /// For example, if I want to view all Resources that are instances of the class "Property", I'd do:
    ///
    /// ```
    /// let mut store = atomic_lib::Store::init();
    /// store.load_default();
    /// let atoms = store.tpf(
    ///     None,
    ///     Some(String::from("https://atomicdata.dev/properties/isA")),
    ///     Some(String::from("[\"https://atomicdata.dev/classes/Class\"]"))
    /// );
    /// assert!(atoms.len() == 3)
    /// ```
    pub fn tpf(
        &self,
        q_subject: Option<String>,
        q_property: Option<String>,
        q_value: Option<String>,
    ) -> Vec<Atom> {
        let mut vec: Vec<Atom> = Vec::new();

        let hassub = q_subject.is_some();
        let hasprop = q_property.is_some();
        let hasval = q_value.is_some();

        // Simply return all the atoms
        if !hassub && !hasprop && !hasval {
            for (sub, resource) in self.hashmap.iter() {
                for (property, value) in resource {
                    vec.push(Atom::new(sub.into(), property.into(), value.into()))
                }
            }
            return vec;
        }

        // Find atoms matching the TPF query in a single resource
        let mut find_in_resource = |subj: &String, resource: &ResourceString| {
            for (prop, val) in resource.iter() {
                if hasprop && q_property.as_ref().unwrap() == prop {
                    if hasval {
                        if val == q_value.as_ref().unwrap() {
                            vec.push(Atom::new(subj.into(), prop.into(), val.into()))
                        }
                    } else {
                        vec.push(Atom::new(subj.into(), prop.into(), val.into()))
                    }
                } else if hasval && q_value.as_ref().unwrap() == val {
                    vec.push(Atom::new(subj.into(), prop.into(), val.into()))
                }
            }
        };

        match q_subject {
            Some(sub) => match self.get_string_resource(&sub) {
                Some(resource) => {
                    find_in_resource(&sub, &resource);
                    return vec;
                }
                None => {
                    return vec;
                }
            },
            None => {
                for (subj, properties) in self.hashmap.iter() {
                    find_in_resource(subj, properties);
                }
                return vec;
            }
        }
    }

    /// Loads the default Atomic Store, containing the Properties, Datatypes and Clasess for Atomic Schema.
    pub fn load_default(&mut self) {
        let ad3 = include_str!("../../defaults/default_store.ad3");
        self.parse_ad3(&String::from(ad3)).unwrap();
    }
}

impl Storelike for Store {
    fn add_atoms(&mut self, atoms: Vec<Atom>) -> Result<()> {
        for atom in atoms {
            match self.hashmap.get_mut(&atom.subject) {
                Some(resource) => {
                    resource.insert(atom.property, atom.value);
                }
                None => {
                    let mut resource: ResourceString = HashMap::new();
                    resource.insert(atom.property, atom.value);
                    self.hashmap.insert(atom.subject, resource);
                }
            }
        }
        return Ok(());
    }

    fn get_string_resource(&self, resource_url: &String) -> Option<ResourceString> {
        match self.hashmap.get(resource_url) {
            Some(result) => Some(result.clone()),
            None => None,
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::urls;

    fn init_store() -> Store {
        let string =
            String::from("[\"_:test\",\"https://atomicdata.dev/properties/shortname\",\"hi\"]");
        let mut store = Store::init();
        store.load_default();
        // Run parse...
        store.parse_ad3(&string).unwrap();
        return store;
    }

    #[test]
    fn get() {
        let store = init_store();
        // Get our resource...
        let my_resource = store.get_string_resource(&"_:test".into()).unwrap();
        // Get our value by filtering on our property...
        let my_value = my_resource
            .get("https://atomicdata.dev/properties/shortname")
            .unwrap();
        println!("My value: {}", my_value);
        assert!(my_value == "hi");
    }

    #[test]
    fn validate() {
        let store = init_store();
        store.validate_store().unwrap();
    }

    #[test]
    #[should_panic]
    fn validate_invalid() {
        let mut store = init_store();
        let invalid_ad3 =
            // should be array, is string
            String::from("[\"_:test\",\"https://atomicdata.dev/properties/requires\",\"Test\"]");
        store.parse_ad3(&invalid_ad3).unwrap();
        store.validate_store().unwrap();
    }

    #[test]
    fn serialize() {
        let store = init_store();
        store
            .resource_to_json(&String::from(urls::CLASS), 1)
            .unwrap();
    }
}
