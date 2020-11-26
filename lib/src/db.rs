//! Persistent, ACID compliant, threadsafe to-disk store.
//! Powered by Sled - an embedded database.

use crate::{
    errors::AtomicResult,
    resources::PropVals,
    resources::ResourceString,
    storelike::{ResourceCollection, Storelike},
    Atom, Resource,
};

/// The Db is a persistent on-disk Atomic Data store.
/// It's an implementation of Storelike.
#[derive(Clone)]
pub struct Db {
    // The Key-Value store that contains all data.
    // Resources can be found using their Subject.
    // Try not to use this directly, but use the Trees.
    db: sled::Db,
    // Stores all resources. The Key is the Subject as a string, the value a PropVals. Both must be serialized using bincode.
    resources: sled::Tree,
    // Stores all Atoms. The key is the atom.value, the value a vector of Atoms.
    index_vals: sled::Tree,
    index_props: sled::Tree,
    /// The base_url is the domain where the db will be hosted, e.g. http://localhost/
    base_url: String,
}

impl Db {
    /// Creates a new store at the specified path.
    /// The base_url is the domain where the db will be hosted, e.g. http://localhost/
    /// It is used for distinguishing locally defined items from externally defined ones.
    pub fn init<P: AsRef<std::path::Path>>(path: P, base_url: String) -> AtomicResult<Db> {
        let db = sled::open(path)?;
        let resources = db.open_tree("resources")?;
        let index_props = db.open_tree("index_props")?;
        let index_vals = db.open_tree("index_vals")?;
        let store = Db {
            db,
            resources,
            index_vals,
            index_props,
            base_url,
        };
        Ok(store)
    }

    // fn index_value_add(&mut self, atom: Atom) -> AtomicResult<()> {
    //     todo!();
    // }

    // fn index_value_remove(&mut self, atom: Atom) -> AtomicResult<()> {
    //     todo!();
    // }

    fn set_propvals(&self, subject: &str, propvals: &PropVals) -> AtomicResult<()> {
        let resource_bin = bincode::serialize(propvals)?;
        let subject_bin = bincode::serialize(subject)?;
        self.resources.insert(subject_bin, resource_bin)?;
        Ok(())
    }

    /// Finds resource by Subject, return PropVals HashMap
    /// Deals with the binary API of Sled
    fn get_propvals(&self, subject: &str) -> AtomicResult<PropVals> {
        let subject_binary = bincode::serialize(subject)
            .map_err(|e| format!("Can't serialize {}: {}", subject, e))?;
        let propval_maybe = self
            .resources
            .get(subject_binary)
            .map_err(|e| format!("Can't open {} from store: {}", subject, e))?;
        match propval_maybe.as_ref() {
            Some(binpropval) => {
                let propval: PropVals = bincode::deserialize(binpropval).map_err(|e| format!("{} {}", DB_CORRUPT_MSG, e))?;
                Ok(propval)
            },
            None => Err("Not found".into()),
        }
    }
}

impl Storelike for Db {
    fn add_atoms(&self, atoms: Vec<Atom>) -> AtomicResult<()> {
        for atom in atoms {
            self.add_atom(atom)?;
        }
        self.db.flush()?;
        Ok(())
    }

    /// Adds a single atom to the store
    /// If the resource already exists, it will be inserted into it.
    /// Existing data will be overwritten.
    /// If the resource does not exist, it will be created.
    fn add_atom(&self, atom: Atom) -> AtomicResult<()> {
        let mut resource: PropVals = match self.get_propvals(&atom.subject) {
            Ok(r) => r,
            Err(_) => PropVals::new(),
        };

        resource.insert(atom.property, atom.value.into());
        self.set_propvals(&atom.subject, &resource)?;
        Ok(())
    }

    fn add_resource(&self, resource: &Resource) -> AtomicResult<()> {
        self.set_propvals(resource.get_subject(), &resource.get_propvals())?;
        Ok(())
    }

    fn add_resource_string(
        &self,
        subject: String,
        resource_string: &ResourceString,
    ) -> AtomicResult<()> {
        let resource =
            crate::resources::Resource::new_from_resource_string(subject, resource_string, self)?;
        self.add_resource(&resource)?;
        // Note that this does not do anything with indexes, so it might have to be replaced!
        Ok(())
    }

    fn get_base_url(&self) -> String {
        self.base_url.clone()
    }

    fn get_resource_string(&self, resource_url: &str) -> AtomicResult<ResourceString> {
        let propvals = self.get_propvals(resource_url);
        match propvals {
            Ok(propvals) => {
                let resource = crate::resources::propvals_to_resourcestring(propvals);
                Ok(resource)
            }
            Err(_e) => {
                if resource_url.starts_with(&self.base_url) {
                    return Err(format!(
                        "Failed to retrieve {}, does not exist locally",
                        resource_url
                    )
                    .into());
                }

                match self.fetch_resource(resource_url) {
                    Ok(got) => Ok(got),
                    Err(e) => Err(format!(
                        "Failed to retrieve {} from the web: {}",
                        resource_url, e
                    )
                    .into()),
                }
            }
        }
    }

    fn all_resources(&self) -> ResourceCollection {
        let mut resources: ResourceCollection = Vec::new();
        for item in self.resources.into_iter() {
            let (subject, resource_bin) = item.expect(DB_CORRUPT_MSG);
            let subject: String = bincode::deserialize(&subject).expect(DB_CORRUPT_MSG);
            let propvals: PropVals = bincode::deserialize(&resource_bin).expect(DB_CORRUPT_MSG);
            let resource: ResourceString = crate::resources::propvals_to_resourcestring(propvals);
            resources.push((subject, resource));
        }
        resources
    }

    fn remove_resource(&self, subject: &str) {
        // This errors when the resource is not present.
        // https://github.com/joepio/atomic/issues/46
        let _discard_error = self.db
            .remove(bincode::serialize(subject).unwrap())
            .ok();
    }
}

const DB_CORRUPT_MSG: &str = "Could not deserialize item from database. DB is possibly corrupt, could be due to update. Restore to a previous version, export / serialize the data and import your data.";

#[cfg(test)]
mod test {
    use super::*;

    /// Creates new temporary database, populates it, removes previous one
    fn init() -> Db {
        let tmp_dir_path = "tmp/db";
        std::fs::remove_dir_all(tmp_dir_path).unwrap();
        let store = Db::init(tmp_dir_path, "https://localhost/".into()).unwrap();
        store.populate().unwrap();
        store
    }

    #[test]
    fn basic() {
        let store = init();
        // Let's parse this AD3 string.
        let ad3 =
            r#"["https://localhost/test","https://atomicdata.dev/properties/description","Test"]"#;
        // The parser returns a Vector of Atoms
        let atoms = crate::parse::parse_ad3(&ad3).unwrap();
        // Add the Atoms to the Store
        store.add_atoms(atoms).unwrap();
        // Get our resource...
        let my_resource = store.get_resource("https://localhost/test").unwrap();
        // Get our value by filtering on our property...
        let my_value = my_resource
            .get("https://atomicdata.dev/properties/description")
            .unwrap();
        assert!(my_value.to_string() == "Test");
        // We can also use the shortname of description
        let my_value_from_shortname = my_resource.get_shortname("description").unwrap();
        assert!(my_value_from_shortname.to_string() == "Test");
        // We can find any Atoms matching some value using Triple Pattern Fragments:
        let found_atoms = store.tpf(None, None, Some("Test")).unwrap();
        assert!(found_atoms.len() == 1);
        assert!(found_atoms[0].value == "Test");

        // We can also create a new Resource, linked to the store.
        // Note that since this store only exists in memory, it's data cannot be accessed from the internet.
        // Let's make a new Property instance!
        let mut new_property =
            crate::Resource::new_instance("https://atomicdata.dev/classes/Property", &store)
                .unwrap();
        // And add a description for that Property
        new_property
            .set_by_shortname("description", "the age of a person")
            .unwrap();
        // Changes are only applied to the store after calling `.save()`
        new_property.save().unwrap();
        // The modified resource is saved to the store after this

        // A subject URL has been created automatically.
        let subject = new_property.get_subject();
        let fetched_new_resource = store.get_resource(subject).unwrap();
        let description_val = fetched_new_resource
            .get_shortname("description")
            .unwrap()
            .to_string();
        println!("desc {}", description_val);
        assert!(description_val == "the age of a person");
    }
}
