//! Persistent, ACID compliant, threadsafe to-disk store.
//! Powered by Sled - an embedded database.

use crate::{errors::AtomicResult, storelike::Storelike, urls, Atom, Resource, Value};
use sled;

#[derive(Clone)]
pub struct Db {
    tree: sled::Db,
}

impl Db {
    // Creates a new store at the specified path
    pub fn init(path: std::path::PathBuf) -> Db {
        let tree = sled::open(path).expect("open");

        // add a test resource
        let mut resource = crate::Resource::new("_:test".into());
        resource
            .insert(
                urls::DESCRIPTION.into(),
                Value::from(String::from("Test value!")),
            )
            .unwrap();
        let binser = bincode::serialize(&resource).unwrap();

        tree.insert("_:test", binser).unwrap();

        return Db { tree };
    }

    /// Adds a Resource to the store
    pub fn add_resource(&mut self, resource: &Resource) -> AtomicResult<()> {
        let binser = bincode::serialize(resource)?;
        self.tree.insert("_:test", binser)?;
        Ok(())
    }

    /// Fetch a single resource from the store
    pub fn get_resource(&self, resource_url: &String) -> Option<Resource> {
        let binresource = self.tree.get(&*resource_url).unwrap();
        match binresource {
            Some(found) => {
                let resource: crate::Resource = bincode::deserialize(&found).unwrap();
                return Some(resource);
            }
            None => None,
        }
    }
}

impl Storelike for Db {
    fn add_atoms(&mut self, atoms: Vec<Atom>) -> AtomicResult<()> {
        for atom in atoms {
            // So this is not possible.
            // The store will have no properties on initialization, so it will crash.
            let value = Value::new(&atom.value, &self.get_property(&atom.property)?.data_type)?;
            match self.get_resource(&atom.subject).as_mut() {
                Some(resource) => {
                    // Overwrites existing properties
                    resource.insert(atom.property, value)?;
                    self.add_resource(resource)?;
                }
                None => {
                    let mut resource = Resource::new(atom.subject.clone());
                    resource.insert(atom.property.clone(), value)?;
                    self.add_resource(&resource)?;
                }
            }
        }
        Ok(())
    }

    fn add_resource_string(
        &mut self,
        subject: String,
        resource: crate::storelike::ResourceString,
    ) -> AtomicResult<()> {
        todo!()
    }

    fn get_string_resource(
        &self,
        resource_url: &String,
    ) -> Option<crate::storelike::ResourceString> {
        match self.get_resource(resource_url) {
            Some(resource) => Some(resource.to_plain()),
            None => None,
        }
    }

    fn tpf(
        &self,
        q_subject: Option<String>,
        q_property: Option<String>,
        q_value: Option<String>,
    ) -> Vec<Atom> {
        todo!()
    }
}
