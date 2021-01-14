//! In-memory store of Atomic data.
//! This provides many methods for finding, changing, serializing and parsing Atomic Data.
//! Currently, it can only persist its data as .ad3 (Atomic Data Triples) to disk.
//! A more robust persistent storage option will be used later, such as: https://github.com/TheNeikos/rustbreak

use crate::{Resource, errors::AtomicResult};
use crate::{
    atoms::Atom,
    storelike::{ResourceCollection, Storelike},
};
use std::{collections::HashMap, fs, path::PathBuf, sync::Arc, sync::Mutex};

/// The in-memory store of data, containing the Resources, Properties and Classes
#[derive(Clone)]
pub struct Store {
    // The store currently holds two stores - that is not ideal
    hashmap: Arc<Mutex<HashMap<String, Resource>>>,
    default_agent: Arc<Mutex<Option<crate::agents::Agent>>>,
}

impl Store {
    /// Creates an empty Store.
    /// Run `.populate()` to get useful standard models loaded into your store.
    pub fn init() -> AtomicResult<Store> {
        let store = Store {
            hashmap: Arc::new(Mutex::new(HashMap::new())),
            default_agent: Arc::new(Mutex::new(None)),
        };
        crate::populate::populate_base_models(&store)?;
        Ok(store)
    }

    /// Reads an .ad3 (Atomic Data Triples) graph and adds it to the store
    pub fn read_store_from_file(&self, path: &PathBuf) -> AtomicResult<()> {
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
        for resource in self.all_resources() {
            file_string.push_str(&*resource.to_ad3()?);
        }
        fs::create_dir_all(path.parent().expect("Could not find parent folder"))
            .expect("Unable to create dirs");
        fs::write(path, file_string).expect("Unable to write file");
        Ok(())
    }
}

impl Storelike for Store {

    fn add_atoms(&self, atoms: Vec<Atom>) -> AtomicResult<()> {
        // Start with a nested HashMap, containing only strings.
        let mut map: HashMap<String, Resource> = HashMap::new();
        for atom in atoms {
            match map.get_mut(&atom.subject) {
                // Resource exists in map
                Some(resource) => {
                    resource.set_propval_string(atom.property, &atom.value, self)?;
                }
                // Resource does not exist
                None => {
                    let mut resource = Resource::new(atom.subject.clone());
                    resource.set_propval_string(atom.property, &atom.value, self)?;
                    map.insert(atom.subject, resource);
                }
            }
        }
        for (_subject, resource) in map.iter() {
            self.add_resource(resource)?
        }
        Ok(())
    }

    /// Adds a Resource to the store.
    /// Replaces existing resource with the contents.
    /// In most cases, you should use `.commit()` instead.
    fn add_resource(&self, resource: &Resource) -> AtomicResult<()> {
        resource.check_required_props(self)?;
        self.add_resource_unsafe(resource)?;
        Ok(())
    }

    fn add_resource_unsafe(&self, resource: &crate::Resource) -> AtomicResult<()> {
        self.hashmap
            .lock()
            .unwrap()
            .insert(resource.get_subject().into(), resource.clone());
        Ok(())
    }

    fn all_resources(&self) -> ResourceCollection {
        let mut all = Vec::new();
        for (_subject, resource) in self.hashmap.lock().unwrap().clone().into_iter() {
            all.push(resource)
        }
        all
    }

    fn get_base_url(&self) -> String {
        // TODO Should be implemented later when companion functionality is here
        // https://github.com/joepio/atomic/issues/6
        "http://localhost".into()
    }

    fn get_default_agent(&self) -> AtomicResult<crate::agents::Agent> {
        match self.default_agent.lock().unwrap().to_owned() {
            Some(agent) => Ok(agent),
            None => Err("No default agent has been set.".into()),
        }
    }

    fn get_resource(&self, subject: &str) -> AtomicResult<Resource> {
        if let Some(resource) = self.hashmap.lock().unwrap().get(subject) {
            return Ok(resource.clone())
        }
        self.handle_not_found(subject)
    }

    fn remove_resource(&self, subject: &str) {
        self.hashmap.lock().unwrap().remove_entry(subject);
    }

    fn set_default_agent(&self, agent: crate::agents::Agent) {
        self.default_agent.lock().unwrap().replace(agent);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{parse::parse_ad3, urls};

    fn init_store() -> Store {
        let string =
            String::from("[\"_:test\",\"https://atomicdata.dev/properties/shortname\",\"hi\"]");
        let store = Store::init().unwrap();
        store.populate().unwrap();
        let atoms = parse_ad3(&string).unwrap();
        store.add_atoms(atoms).unwrap();
        store
    }

    #[test]
    fn populate_base_models() {
        let store = Store::init().unwrap();
        crate::populate::populate_base_models(&store).unwrap();
        let property=  store.get_property(urls::DESCRIPTION).unwrap();
        assert_eq!(property.shortname, "description")
    }

    #[test]
    fn single_get_empty_server_to_class() {
        let store = Store::init().unwrap();
        crate::populate::populate_base_models(&store).unwrap();
        // Should fetch the agent class, since it's not in the store
        let agent=  store.get_class(urls::AGENT).unwrap();
        assert_eq!(agent.shortname, "agent")
    }

    #[test]
    fn get() {
        let store = init_store();
        let my_resource = store.get_resource("_:test").unwrap();
        let my_value = my_resource
            .get("https://atomicdata.dev/properties/shortname")
            .unwrap();
        println!("My value: {}", my_value);
        assert!(my_value.to_string() == "hi");
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
        store.add_atoms(atoms).unwrap_err();
        // Throws an error before we even need to validate. Which is good. Maybe the validate function should accept something different.
        // let report = store.validate();
        // assert!(!report.is_valid());
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
        let subject = urls::CLASS;
        let resource = store.get_resource(subject).unwrap();
        resource.to_json(&store, 1, true).unwrap();
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
        let store = Store::init().unwrap();
        store.populate().unwrap();
        // If nothing happens - this night be deadlock.
        store.get_resource(urls::CLASS).unwrap();
    }

    #[test]
    fn get_extended_resource() {
        let store = Store::init().unwrap();
        store.populate().unwrap();
        let resource = store
            .get_resource_extended("https://atomicdata.dev/classes")
            .unwrap();
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

    #[test]
    fn populate_collections() {
        let store = init_store();
        let collections_collection_url = format!("{}/collections", store.get_base_url());
        let my_resource = store
            .get_resource_extended(&collections_collection_url)
            .unwrap();
        let my_value = my_resource.get(urls::COLLECTION_MEMBER_COUNT).unwrap();
        println!("My value: {}", my_value);
        assert!(my_value.to_string() == "5");
    }
}
