//! Persistent, ACID compliant, threadsafe to-disk store.
//! Powered by Sled - an embedded database.

use crate::{
    errors::AtomicResult,
    storelike::{ResourceString, Storelike},
    Atom, Resource,
};
use sled;
use std::collections::HashMap;

#[derive(Clone)]
pub struct Db {
    tree: sled::Db,
}

impl Db {
    // Creates a new store at the specified path
    pub fn init(path: std::path::PathBuf) -> Db {
        let tree = sled::open(path).expect("open");
        return Db { tree };
    }
}

impl Storelike for Db {
    fn add_atoms(&mut self, atoms: Vec<Atom>) -> AtomicResult<()> {
        for atom in atoms {
            match self.get_resource_string(&atom.subject).as_mut() {
                Some(resource) => {
                    // Overwrites existing properties
                    resource.insert(atom.property, atom.value);
                    self.add_resource_string(atom.subject, &resource)?;
                }
                None => {
                    let mut resource: ResourceString = HashMap::new();
                    resource.insert(atom.property.clone(), atom.value);
                    self.add_resource_string(atom.subject, &resource)?;
                }
            }
        }
        Ok(())
    }

    fn add_resource(&mut self, resource: &Resource) -> AtomicResult<()> {
        self.add_resource_string(resource.subject().clone(), &resource.to_plain())?;
        Ok(())
    }

    fn add_resource_string(
        &mut self,
        subject: String,
        resource: &ResourceString,
    ) -> AtomicResult<()> {
        let binser = bincode::serialize(resource)?;
        self.tree.insert(subject, binser)?;
        Ok(())
    }

    fn get_resource_string(&self, resource_url: &String) -> Option<ResourceString> {
        match self.tree.get(resource_url).expect("cant even access store") {
            Some(res_bin) => {
                let resource: ResourceString = bincode::deserialize(&res_bin).expect("Can't deserialize resource. Your database may be corrupt!");
                Some(resource)
            }
            None => None
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
