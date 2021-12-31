//! In-memory store of Atomic data.
//! This provides many methods for finding, changing, serializing and parsing Atomic Data.

use crate::{
    atoms::Atom,
    storelike::{ResourceCollection, Storelike},
};
use crate::{errors::AtomicResult, Resource};
use std::{collections::HashMap, sync::Arc, sync::Mutex};

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
}

impl Storelike for Store {
    fn add_atoms(&self, atoms: Vec<Atom>) -> AtomicResult<()> {
        // Start with a nested HashMap, containing only strings.
        let mut map: HashMap<String, Resource> = HashMap::new();
        for atom in atoms {
            match map.get_mut(&atom.subject) {
                // Resource exists in map
                Some(resource) => {
                    resource.set_propval(atom.property, atom.value, self)?;
                }
                // Resource does not exist
                None => {
                    let mut resource = Resource::new(atom.subject.clone());
                    resource.set_propval(atom.property, atom.value, self)?;
                    map.insert(atom.subject, resource);
                }
            }
        }
        for (_subject, resource) in map.iter() {
            self.add_resource(resource)?
        }
        Ok(())
    }

    fn add_resource_opts(
        &self,
        resource: &Resource,
        check_required_props: bool,
        update_index: bool,
        overwrite_existing: bool,
    ) -> AtomicResult<()> {
        if check_required_props {
            resource.check_required_props(self)?;
        }
        if !overwrite_existing {
            let subject = resource.get_subject();
            if let Some(_r) = self.hashmap.lock().unwrap().get(subject) {
                return Err(format!("{} already present, will not overwrite.", subject).into());
            }
        }
        let _ = update_index;
        // This store has no index, so we don't need to update it.
        self.hashmap
            .lock()
            .unwrap()
            .insert(resource.get_subject().into(), resource.clone());
        Ok(())
    }

    // TODO: Fix this for local stores, include external does not make sense here
    fn all_resources(&self, _include_external: bool) -> ResourceCollection {
        let mut all = Vec::new();
        for (_subject, resource) in self.hashmap.lock().unwrap().clone().into_iter() {
            all.push(resource)
        }
        all
    }

    fn get_server_url(&self) -> &str {
        // TODO Should be implemented later when companion functionality is here
        // https://github.com/joepio/atomic/issues/6
        "http://localhost"
    }

    fn get_default_agent(&self) -> AtomicResult<crate::agents::Agent> {
        match self.default_agent.lock().unwrap().to_owned() {
            Some(agent) => Ok(agent),
            None => Err("No default agent has been set.".into()),
        }
    }

    fn get_resource(&self, subject: &str) -> AtomicResult<Resource> {
        if let Some(resource) = self.hashmap.lock().unwrap().get(subject) {
            return Ok(resource.clone());
        }
        self.handle_not_found(subject, "Not found in HashMap.".into())
    }

    fn remove_resource(&self, subject: &str) -> AtomicResult<()> {
        self.hashmap
            .lock()
            .unwrap()
            .remove_entry(subject)
            .ok_or(format!(
                "Resource {} could not be deleted, because it is not found",
                subject
            ))?;
        Ok(())
    }

    fn set_default_agent(&self, agent: crate::agents::Agent) {
        self.default_agent.lock().unwrap().replace(agent);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::urls;

    fn init_store() -> Store {
        let store = Store::init().unwrap();
        store.populate().unwrap();
        store
    }

    #[test]
    fn populate_base_models() {
        let store = Store::init().unwrap();
        crate::populate::populate_base_models(&store).unwrap();
        let property = store.get_property(urls::DESCRIPTION).unwrap();
        assert_eq!(property.shortname, "description")
    }

    #[test]
    fn single_get_empty_server_to_class() {
        let store = Store::init().unwrap();
        crate::populate::populate_base_models(&store).unwrap();
        // Should fetch the agent class, since it's not in the store
        let agent = store.get_class(urls::AGENT).unwrap();
        assert_eq!(agent.shortname, "agent")
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
        resource.to_json_ad().unwrap();
    }

    #[test]
    fn tpf() {
        let store = init_store();
        // All atoms
        let atoms = store.tpf(None, None, None, true).unwrap();
        assert!(atoms.len() > 10);
        // Find by subject
        let atoms = store.tpf(Some(urls::CLASS), None, None, true).unwrap();
        assert_eq!(atoms.len(), 6);
        // Find by value
        let atoms = store.tpf(None, None, Some("class"), true).unwrap();
        assert_eq!(atoms[0].subject, urls::CLASS);
        assert_eq!(atoms.len(), 1);
        // Find by property and value
        let atoms = store
            .tpf(None, Some(urls::SHORTNAME), Some("class"), true)
            .unwrap();
        assert!(atoms[0].subject == urls::CLASS);
        assert!(atoms.len() == 1);
        // Find item in array
        let atoms = store
            .tpf(None, Some(urls::IS_A), Some(urls::CLASS), true)
            .unwrap();
        assert!(atoms.len() > 3);
    }

    #[test]
    fn path() {
        let store = init_store();
        let res = store
            .get_path("https://atomicdata.dev/classes/Class shortname", None, None)
            .unwrap();
        match res {
            crate::storelike::PathReturn::Subject(_) => panic!("Should be an Atom"),
            crate::storelike::PathReturn::Atom(atom) => {
                assert_eq!(atom.value.to_string(), "class");
            }
        }
        let res = store
            .get_path(
                "https://atomicdata.dev/classes/Class requires 0",
                None,
                None,
            )
            .unwrap();
        match res {
            crate::storelike::PathReturn::Subject(sub) => {
                assert_eq!(sub, urls::SHORTNAME);
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
    #[should_panic]
    fn path_fail() {
        let store = init_store();
        store
            .get_path(
                "https://atomicdata.dev/classes/Class requires isa description",
                None,
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
                None,
            )
            .unwrap();
    }
}
