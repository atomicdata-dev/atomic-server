//! Persistent, ACID compliant, threadsafe to-disk store.
//! Powered by Sled - an embedded database.

use std::{collections::HashMap, sync::{Arc, Mutex}};

use crate::{
    errors::AtomicResult,
    resources::PropVals,
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
    default_agent: Arc<Mutex<Option<crate::agents::Agent>>>,
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
        let db = sled::open(path).map_err(|e|format!("Failed creating DB at this location. {}", e))?;
        let resources = db.open_tree("resources").map_err(|e|format!("Failed building resources. Your DB might be corrupt. Go back to a previous version and export your data. {}", e))?;
        let index_props = db.open_tree("index_props")?;
        let index_vals = db.open_tree("index_vals")?;
        let store = Db {
            db,
            default_agent: Arc::new(Mutex::new(None)),
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

    /// Internal method for fetching Resource data.
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
                let propval: PropVals = bincode::deserialize(binpropval)
                    .map_err(|e| format!("{} {}", DB_CORRUPT_MSG, e))?;
                Ok(propval)
            }
            None => Err(format!("Resource {} not found", subject).into()),
        }
    }
}

impl Storelike for Db {

    fn add_atoms(&self, atoms: Vec<Atom>) -> AtomicResult<()> {
        // Start with a nested HashMap, containing only strings.
        let mut map: HashMap<String, Resource> = HashMap::new();
        for atom in atoms {
            match map.get_mut(&atom.subject) {
                // Resource exists in map
                Some(resource) => {
                    resource.set_propval_string(atom.property.clone(), &atom.value, self).map_err(|e| format!("Failed adding attom {}. {}", atom, e))?;
                }
                // Resource does not exist
                None => {
                    let mut resource = Resource::new(atom.subject.clone());
                    resource.set_propval_string(atom.property.clone(), &atom.value, self).map_err(|e| format!("Failed adding attom {}. {}", atom, e))?;
                    map.insert(atom.subject, resource);
                }
            }
        }
        for (_subject, resource) in map.iter() {
            self.add_resource(resource)?
        }
        self.db.flush()?;
        Ok(())
    }

    fn add_resource(&self, resource: &Resource) -> AtomicResult<()> {
        // This only works if no external functions rely on using add_resource for atom-like operations!
        // However, add_atom uses set_propvals, which skips the validation.
        resource.check_required_props(self)?;
        self.set_propvals(resource.get_subject(), &resource.get_propvals())
    }

    fn add_resource_unsafe(&self, resource: &Resource) -> AtomicResult<()> {
        self.set_propvals(resource.get_subject(), &resource.get_propvals())
    }

    fn get_base_url(&self) -> String {
        self.base_url.clone()
    }

    fn get_default_agent(&self) -> AtomicResult<crate::agents::Agent> {
        match self.default_agent.lock().unwrap().to_owned() {
            Some(agent) => Ok(agent),
            None => Err("No default agent has been set.".into()),
        }
    }

    fn get_resource(&self, subject: &str) -> AtomicResult<Resource> {
        let propvals = self.get_propvals(subject);

        match propvals {
            Ok(propvals) => {
                let resource = crate::resources::Resource::from_propvals(propvals, subject.into());
                Ok(resource)
            }
            Err(_e) => {
                self.handle_not_found(subject)
            }
        }
    }

    fn all_resources(&self) -> ResourceCollection {
        let mut resources: ResourceCollection = Vec::new();
        for item in self.resources.into_iter() {
            let (subject, resource_bin) = item.expect(DB_CORRUPT_MSG);
            let subject: String = bincode::deserialize(&subject).expect(DB_CORRUPT_MSG);
            let propvals: PropVals = bincode::deserialize(&resource_bin).expect(DB_CORRUPT_MSG);
            let resource = Resource::from_propvals(propvals, subject);
            resources.push(resource);
        }
        resources
    }

    fn set_default_agent(&self, agent: crate::agents::Agent) {
        self.default_agent.lock().unwrap().replace(agent);
    }

    fn remove_resource(&self, subject: &str) {
        // This errors when the resource is not present.
        // https://github.com/joepio/atomic/issues/46
        let _discard_error = self.db.remove(bincode::serialize(subject).unwrap()).ok();
    }
}

const DB_CORRUPT_MSG: &str = "Could not deserialize item from database. DB is possibly corrupt, could be due to update. Restore to a previous version, export / serialize the data and import your data.";

#[cfg(test)]
mod test {
    use super::*;
    use ntest::timeout;

    /// Creates new temporary database, populates it, removes previous one
    fn init() -> Db {
        let tmp_dir_path = "tmp/db";
        let _try_remove_existing = std::fs::remove_dir_all(tmp_dir_path);
        let store = Db::init(tmp_dir_path, "https://localhost/".into()).unwrap();
        store.populate().unwrap();
        let agent = store.create_agent("name").unwrap();
        store.set_default_agent(agent);
        store
    }

    /// TODO: find bug!
    /// For some reason, this one keeps going on forever.
    /// It calles create_agent before populating, and keeps requesting stuff.
    fn _init_faulty() -> Db {
        let tmp_dir_path = "tmp/db";
        let _try_remove_existing = std::fs::remove_dir_all(tmp_dir_path);
        let store = Db::init(tmp_dir_path, "https://localhost/".into()).unwrap();
        let agent = store.create_agent("name").unwrap();
        store.populate().unwrap();
        store.set_default_agent(agent);
        store
    }

    #[test]
    #[timeout(30000)]
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
        let my_value_from_shortname = my_resource.get_shortname("description", &store).unwrap();
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
            .set_propval_shortname("description", "the age of a person", &store)
            .unwrap();
        new_property
            .set_propval_shortname("shortname", "age", &store)
            .unwrap();
        new_property
            .set_propval_shortname("datatype", crate::urls::INTEGER, &store)
            .unwrap();
        // Changes are only applied to the store after saving them explicitly.
        new_property.save(&store).unwrap();
        // The modified resource is saved to the store after this

        // A subject URL has been created automatically.
        let subject = new_property.get_subject();
        let fetched_new_resource = store.get_resource(subject).unwrap();
        let description_val = fetched_new_resource
            .get_shortname("description", &store)
            .unwrap()
            .to_string();
        println!("desc {}", description_val);
        assert!(description_val == "the age of a person");
    }
}
