//! In-memory store of Atomic data.
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
use std::{collections::HashMap, fs, path::PathBuf, sync::Arc, sync::Mutex};

/// The in-memory store of data, containing the Resources, Properties and Classes
#[derive(Clone)]
pub struct Store {
    // The store currently holds two stores - that is not ideal
    hashmap: Arc<Mutex<HashMap<String, ResourceString>>>,
    log: mutations::Log,
}

impl Store {
    /// Create an empty Store. This is where you start.
    ///
    /// # Example
    /// let store = Store::init();
    pub fn init() -> Store {
        Store {
            hashmap: Arc::new(Mutex::new(HashMap::new())),
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
    pub fn write_store_to_disk(&mut self, path: &PathBuf) -> AtomicResult<()> {
        let mut file_string: String = String::new();
        for (subject, _) in self.all_resources() {
            let resourcestring = self.get_resource(&subject)?.to_ad3()?;
            file_string.push_str(&*resourcestring);
        }
        fs::create_dir_all(path.parent().expect("Could not find parent folder"))
            .expect("Unable to create dirs");
        fs::write(path, file_string).expect("Unable to write file");
        Ok(())
    }
}

impl Storelike for Store {
    fn add_atoms(&self, atoms: Vec<Atom>) -> AtomicResult<()> {
        let mut hm = self.hashmap.lock().unwrap();
        for atom in atoms {
            match hm.get_mut(&atom.subject) {
                Some(resource) => {
                    resource.insert(atom.property, atom.value);
                }
                None => {
                    let mut resource: ResourceString = HashMap::new();
                    resource.insert(atom.property, atom.value);
                    hm.insert(atom.subject, resource);
                }
            }
        }
        Ok(())
    }

    fn add_resource_string(&self, subject: String, resource: &ResourceString) -> AtomicResult<()> {
        self.hashmap
            .lock()
            .unwrap()
            .insert(subject, resource.clone());
        Ok(())
    }

    fn all_resources(&self) -> ResourceCollection {
        self.hashmap.lock().unwrap().clone().into_iter().collect()
    }

    fn get_base_url(&self) -> String {
        // TODO Should be implemented later when companion functionality is here
        // https://github.com/joepio/atomic/issues/6
        "https://localhost/".into()
    }

    fn get_resource_string(&self, resource_url: &str) -> AtomicResult<ResourceString> {
        let resource: Option<ResourceString> = match self.hashmap.lock().unwrap().get(resource_url)
        {
            Some(result) => return Ok(result.clone()),
            None => None,
        };
        match resource {
            Some(_) => Err("This is not possible.".into()),
            None => Ok(self.fetch_resource(resource_url)?),
        }
    }

    fn remove_resource(&self, subject: &str) {
        self.hashmap.lock().unwrap().remove_entry(subject);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{parse::parse_ad3, urls};

    fn init_store() -> Store {
        let string =
            String::from("[\"_:test\",\"https://atomicdata.dev/properties/shortname\",\"hi\"]");
        let store = Store::init();
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
        assert!(store.validate().is_valid())
    }

    #[test]
    fn validate_invalid() {
        let store = init_store();
        let invalid_ad3 =
            // 'requires' should be an array, but is a string
            String::from("[\"_:test\",\"https://atomicdata.dev/properties/requires\",\"Test\"]");
        let atoms = parse_ad3(&invalid_ad3).unwrap();
        store.add_atoms(atoms).unwrap();
        let report = store.validate();
        assert!(!report.is_valid());
    }

    #[test]
    fn get_full_resource_and_shortname() {
        let store = init_store();
        let resource = store.get_resource(urls::CLASS).unwrap();
        let shortname = resource.get_shortname("shortname").unwrap().to_string();
        assert!(shortname == "class");
    }

    #[test]
    fn serialize() {
        let store = init_store();
        let subject = urls::CLASS;
        let resource = store
            .get_resource(subject)
            .unwrap();
        resource.to_json(&store,  1, true).unwrap();
    }

    #[test]
    fn tpf() {
        let store = init_store();
        // All atoms
        let atoms = store.tpf(None, None, None).unwrap();
        assert!(atoms.len() > 10);
        // Find by subject
        let atoms = store.tpf(Some(urls::CLASS), None, None).unwrap();
        assert!(atoms.len() == 5);
        // Find by value
        let atoms = store.tpf(None, None, Some("class")).unwrap();
        assert!(atoms[0].subject == urls::CLASS);
        assert!(atoms.len() == 1);
        // Find by property and value
        let atoms = store
            .tpf(None, Some(urls::SHORTNAME), Some("class"))
            .unwrap();
        assert!(atoms[0].subject == urls::CLASS);
        assert!(atoms.len() == 1);
        // Find item in array
        let atoms = store
            .tpf(None, Some(urls::IS_A), Some(urls::CLASS))
            .unwrap();
        assert!(atoms.len() > 3);
    }

    #[test]
    fn path() {
        let store = init_store();
        let res = store
            .get_path("https://atomicdata.dev/classes/Class shortname", None)
            .unwrap();
        match res {
            crate::storelike::PathReturn::Subject(_) => panic!("Should be an Atom"),
            crate::storelike::PathReturn::Atom(atom) => {
                assert!(atom.value == "class");
            }
        }
        let res = store
            .get_path("https://atomicdata.dev/classes/Class requires 0", None)
            .unwrap();
        match res {
            crate::storelike::PathReturn::Subject(sub) => {
                assert!(sub == urls::SHORTNAME);
            }
            crate::storelike::PathReturn::Atom(_) => panic!("Should be an Subject"),
        }
    }

    #[test]
    fn get_external_resource() {
        let store = Store::init();
        // If nothing happens - this is deadlock.
        store.get_resource_string(urls::CLASS).unwrap();
    }

    #[test]
    fn get_extended_resource() {
        let store = Store::init();
        store.populate().unwrap();
        let resource = store.get_resource_extended("https://atomicdata.dev/classes").unwrap();
        resource.get(urls::COLLECTION_MEMBERS).unwrap();
    }

    #[test]
    #[should_panic]
    fn path_fail() {
        let store = init_store();
        store
            .get_path(
                "https://atomicdata.dev/classes/Class requires isa description",
                None,
            )
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn path_fail2() {
        let store = init_store();
        store
            .get_path(
                "https://atomicdata.dev/classes/Class requires requires",
                None,
            )
            .unwrap();
    }
}
