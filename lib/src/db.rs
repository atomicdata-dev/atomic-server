//! Persistent, ACID compliant, threadsafe to-disk store.
//! Powered by Sled - an embedded database.

use crate::{
    errors::AtomicResult,
    storelike::{Storelike, ResourceCollection},
    resources::ResourceString,
    Atom, Resource,
};
use sled;

/// The Db is a persistent on-disk Atomic Data store.
/// It's an implementation of Storelike.
#[derive(Clone)]
pub struct Db {
    // The Key-Value store that contains all data.
    // Resources can be found using their Subject.
    // Try not to use this directly, but use the Trees.
    db: sled::Db,
    // Stores all resources. The Key is a string, the value a ResourceString. Both must be serialized using bincode.
    resources: sled::Tree,
    // Stores all Atoms. The key is the atom.value, the value a vector of Atoms.
    index_vals: sled::Tree,
    index_props: sled::Tree,
}

impl Db {
    // Creates a new store at the specified path
    pub fn init(path: &std::path::PathBuf) -> AtomicResult<Db> {
        let db = sled::open(path)?;
        let resources = db.open_tree("resources")?;
        let index_props = db.open_tree("index_props")?;
        let index_vals = db.open_tree("index_vals")?;
        Ok(Db {
            db,
            resources,
            index_vals,
            index_props,
        })
    }

    // fn index_value_add(&mut self, atom: Atom) -> AtomicResult<()> {
    //     todo!();
    // }

    // fn index_value_remove(&mut self, atom: Atom) -> AtomicResult<()> {
    //     todo!();
    // }
}

impl Storelike for Db {
    fn add_atoms(&mut self, atoms: Vec<Atom>) -> AtomicResult<()> {
        for atom in atoms {
            self.add_atom(atom)?;
        }
        self.db.flush()?;
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
        let res_bin = bincode::serialize(resource)?;
        let sub_bin = bincode::serialize(&subject)?;
        self.resources.insert(sub_bin, res_bin)?;
        // Note that this does not do anything with indexes, so it might have to be replaced!
        Ok(())
    }

    fn get_resource_string(&self, resource_url: &String) -> AtomicResult<ResourceString> {
        match self
            .resources
            .get(bincode::serialize(resource_url).expect("Can't deserialize subject"))
            .expect("cant even access store")
        {
            Some(res_bin) => {
                let resource: ResourceString = bincode::deserialize(&res_bin)
                    .expect("Can't deserialize resource. Your database may be corrupt!");
                Ok(resource)
            }
            None => {
                match self.fetch_resource(resource_url) {
                    Ok(got) => Ok(got),
                    Err(e) => {
                        return Err(format!("Failed to retrieve {} from the web: {}", resource_url, e).into())
                    },
                }
            },
        }
    }

    fn all_resources(&self) -> AtomicResult<ResourceCollection> {
        let mut resources: ResourceCollection = Vec::new();
        for item in self.resources.into_iter() {
            let (subject_bin, resource_bin) = item?;
            let subby: String = bincode::deserialize(&subject_bin)?;
            let resource: ResourceString = bincode::deserialize(&resource_bin)?;
            resources.push((subby, resource));
        }
        Ok(resources)
    }
}
