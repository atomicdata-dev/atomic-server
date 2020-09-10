//! Store - this is an in-memory store of Atomic data.
//! This provides many methods for finding, changing, serializing and parsing Atomic Data.
//! Currently, it can only persist its data as .ad3 (Atomic Data Triples) to disk.
//! A more robust persistent storage option will be used later, such as: https://github.com/TheNeikos/rustbreak

use crate::errors::AtomicResult;
use crate::mutations;
use crate::{
    atoms::Atom,
    storelike::{ResourceCollection, Storelike},
    ResourceString,
};
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
        Store {
            hashmap: HashMap::new(),
            log: Vec::new(),
        }
    }

    /// Reads an .ad3 (Atomic Data Triples) graph and adds it to the store
    pub fn read_store_from_file<'a>(&mut self, path: &'a PathBuf) -> AtomicResult<()> {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let atoms = crate::parse::parse_ad3(&contents)?;
                self.add_atoms(atoms)?;
                Ok(())
            }
            Err(err) => Err(format!("Parsing error: {}", err).into()),
        }
    }

    /// Serializes the current store and saves to path
    pub fn write_store_to_disk(&self, path: &PathBuf) -> AtomicResult<()> {
        let mut file_string: String = String::new();
        for (subject, _) in self.all_resources()? {
            let resourcestring = self.resource_to_ad3(subject, None)?;
            file_string.push_str(&*resourcestring);
        }
        fs::create_dir_all(path.parent().expect("Could not find parent folder"))
            .expect("Unable to create dirs");
        fs::write(path, file_string).expect("Unable to write file");
        Ok(())
    }
}

impl Storelike for Store {
    fn add_atoms(&mut self, atoms: Vec<Atom>) -> AtomicResult<()> {
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
        Ok(())
    }

    fn add_resource_string(
        &mut self,
        subject: String,
        resource: &ResourceString,
    ) -> AtomicResult<()> {
        self.hashmap.insert(subject, resource.clone());
        Ok(())
    }

    fn all_resources(&self) -> AtomicResult<ResourceCollection> {
        let res = self.hashmap.clone().into_iter().collect();
        Ok(res)
    }

    fn get_resource_string(&self, resource_url: &str) -> AtomicResult<ResourceString> {
        match self.hashmap.get(resource_url) {
            Some(result) => Ok(result.clone()),
            None => {
                Ok(self.fetch_resource(resource_url)?)
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{parse::parse_ad3, urls};

    fn init_store() -> Store {
        let string =
            String::from("[\"_:test\",\"https://atomicdata.dev/properties/shortname\",\"hi\"]");
        let mut store = Store::init();
        store.populate().unwrap();
        let atoms = parse_ad3(&string).unwrap();
        store.add_atoms(atoms).unwrap();
        store
    }

    #[test]
    fn get() {
        let store = init_store();
        let my_resource = store.get_resource_string("_:test").unwrap();
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
            // 'requires' should be an array, but is a string
            String::from("[\"_:test\",\"https://atomicdata.dev/properties/requires\",\"Test\"]");
        let atoms = parse_ad3(&invalid_ad3).unwrap();
        store.add_atoms(atoms).unwrap();
        store.validate_store().unwrap();
    }

    #[test]
    fn get_full_resource_and_shortname() {
        let store = init_store();
        let resource = store.get_resource(urls::CLASS).unwrap();
        let shortname = resource
            .get_shortname("shortname", &store)
            .unwrap()
            .to_string();
        assert!(shortname == "class");
    }

    #[test]
    fn serialize() {
        let store = init_store();
        store
            .resource_to_json(&String::from(urls::CLASS), 1, true)
            .unwrap();
    }

    #[test]
    fn path() {
        let store = init_store();
        let res = store.get_path("https://atomicdata.dev/classes/Class shortname", None).unwrap();
        match res {
            crate::storelike::PathReturn::Subject(_) => {
                panic!("Should be an Atom")
            }
            crate::storelike::PathReturn::Atom(atom) => {
                assert!(atom.value == "class");
            }
        }
        let res = store.get_path("https://atomicdata.dev/classes/Class requires 0", None).unwrap();
        match res {
            crate::storelike::PathReturn::Subject(sub) => {
                assert!(sub == urls::SHORTNAME);
            }
            crate::storelike::PathReturn::Atom(_) => {
                panic!("Should be an Subject")
            }
        }
    }
}
