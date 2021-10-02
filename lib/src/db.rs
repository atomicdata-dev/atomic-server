//! Persistent, ACID compliant, threadsafe to-disk store.
//! Powered by Sled - an embedded database.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use crate::{
    datatype::DataType,
    errors::AtomicResult,
    resources::PropVals,
    storelike::{ResourceCollection, Storelike},
    Atom, Resource, Value,
};

/// Inside the index_vals, each value is mapped to this type.
/// The String on the left represents a Property URL, and the second one is the set of subjects.
pub type PropSubjectMap = HashMap<String, HashSet<String>>;

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
    /// The base_url is the domain where the db will be hosted, e.g. http://localhost/
    base_url: String,
}

impl Db {
    /// Creates a new store at the specified path, or opens the store if it already exists.
    /// The base_url is the domain where the db will be hosted, e.g. http://localhost/
    /// It is used for distinguishing locally defined items from externally defined ones.
    pub fn init<P: AsRef<std::path::Path>>(path: P, base_url: String) -> AtomicResult<Db> {
        let db = sled::open(path).map_err(|e|format!("Failed opening DB at this location. Is another instance of Atomic Server running? {}", e))?;
        let resources = db.open_tree("resources").map_err(|e|format!("Failed building resources. Your DB might be corrupt. Go back to a previous version and export your data. {}", e))?;
        let index_vals = db.open_tree("index_vals")?;
        let store = Db {
            db,
            default_agent: Arc::new(Mutex::new(None)),
            resources,
            index_vals,
            base_url,
        };
        crate::populate::populate_base_models(&store)?;
        Ok(store)
    }

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
                let propval: PropVals = bincode::deserialize(binpropval).map_err(|e| {
                    format!(
                        "Deserialize propval error: {} {}",
                        corrupt_db_message(subject),
                        e
                    )
                })?;
                Ok(propval)
            }
            None => Err(format!("Resource {} not found", subject).into()),
        }
    }

    /// Search for a value, get a PropSubjectMap. If it does not exist, create a new one.
    fn get_prop_subject_map(&self, string_val: &str) -> AtomicResult<PropSubjectMap> {
        let prop_sub_map = self
            .index_vals
            .get(string_val)
            .map_err(|e| format!("Can't open {} from value index: {}", string_val, e))?;
        match prop_sub_map.as_ref() {
            Some(binpropval) => {
                let psm: PropSubjectMap = bincode::deserialize(binpropval).map_err(|e| {
                    format!(
                        "Deserialize PropSubjectMap error: {} {}",
                        corrupt_db_message(&string_val),
                        e
                    )
                })?;
                Ok(psm)
            }
            None => {
                let psm: PropSubjectMap = PropSubjectMap::new();
                Ok(psm)
            }
        }
    }

    /// Returns true if the index has been built.
    pub fn has_index(&self) -> bool {
        !self.index_vals.is_empty()
    }

    fn set_prop_subject_map(&self, string_val: &str, psm: &PropSubjectMap) -> AtomicResult<()> {
        let psm_binary = bincode::serialize(psm)
            .map_err(|e| format!("Can't serialize value {}: {}", string_val, e))?;
        self.index_vals.insert(string_val, psm_binary)?;
        Ok(())
    }

    /// Removes all values from the index.
    pub fn clear_index(&self) -> AtomicResult<()> {
        self.index_vals.clear()?;
        Ok(())
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
                    resource
                        .set_propval_string(atom.property.clone(), &atom.value.to_string(), self)
                        .map_err(|e| format!("Failed adding attom {}. {}", atom, e))?;
                }
                // Resource does not exist
                None => {
                    let mut resource = Resource::new(atom.subject.clone());
                    resource
                        .set_propval_string(atom.property.clone(), &atom.value.to_string(), self)
                        .map_err(|e| format!("Failed adding attom {}. {}", atom, e))?;
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

    // This only adds ResourceArrays and AtomicURLs at this moment, which means that many values cannot be accessed in the TPF query (thus, collections)
    fn add_atom_to_index(&self, atom: &Atom) -> AtomicResult<()> {
        let vec = match atom.value.clone() {
            Value::ResourceArraySubjects(v) => v,
            Value::AtomicUrl(v) => vec![v],
            _other => return Ok(()),
        };

        for val in vec {
            let mut map = self.get_prop_subject_map(&val)?;

            let mut set = match map.get_mut(&atom.property) {
                Some(vals) => vals.to_owned(),
                None => HashSet::new(),
            };

            set.insert(atom.subject.clone());
            map.insert(atom.property.clone(), set);

            self.set_prop_subject_map(&val, &map)?;
        }
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

    fn remove_atom_from_index(&self, atom: &Atom) -> AtomicResult<()> {
        let vec = match atom.value.clone() {
            Value::ResourceArraySubjects(v) => v,
            other => vec![other.to_string()],
        };

        for val in vec {
            let mut map = self.get_prop_subject_map(&val)?;

            let mut set = match map.get_mut(&atom.property) {
                Some(vals) => vals.to_owned(),
                None => HashSet::new(),
            };

            set.remove(&atom.subject);
            map.insert(atom.property.clone(), set);

            self.set_prop_subject_map(&val, &map)?;
        }
        Ok(())
    }

    fn get_base_url(&self) -> &str {
        &self.base_url
    }

    // Since the DB is often also the server, this should make sense.
    // Some edge cases might appear later on (e.g. a slave DB that only stores copies?)
    fn get_self_url(&self) -> Option<String> {
        Some(self.get_base_url().into())
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
            Err(e) => self.handle_not_found(subject, e),
        }
    }

    fn get_resource_extended(&self, subject: &str) -> AtomicResult<Resource> {
        // This might add a trailing slash
        let mut url = url::Url::parse(subject)?;
        let clone = url.clone();
        let query_params = clone.query_pairs();
        url.set_query(None);
        let mut removed_query_params = url.to_string();

        // Remove trailing slash
        if removed_query_params.ends_with('/') {
            removed_query_params.pop();
        }

        // Check if the subject matches one of the endpoints
        // TODO: do this on initialize, not on request!
        let endpoints = crate::endpoints::default_endpoints();
        let mut endpoint_resource = None;
        endpoints.into_iter().for_each(|endpoint| {
            if url.path().starts_with(&endpoint.path) {
                endpoint_resource = Some((endpoint.handle)(clone.clone(), self))
            }
        });

        if let Some(resource) = endpoint_resource {
            let mut resource_updated = resource?;
            // Extended resources must always return the requested subject as their own subject
            resource_updated.set_subject(subject.into());
            return Ok(resource_updated);
        }

        let mut resource = self.get_resource(&removed_query_params)?;
        // make sure the actual subject matches the one requested
        resource.set_subject(subject.into());
        // If a certain class needs to be extended, add it to this match statement
        for class in resource.get_classes(self)? {
            match class.subject.as_ref() {
                crate::urls::COLLECTION => {
                    return crate::collections::construct_collection(
                        self,
                        query_params,
                        &mut resource,
                    )
                }
                crate::urls::INVITE => {
                    return crate::plugins::invite::construct_invite_redirect(
                        self,
                        query_params,
                        &mut resource,
                        subject,
                    )
                }
                crate::urls::DRIVE => return crate::hierarchy::add_children(self, &mut resource),
                _ => {}
            }
        }
        Ok(resource)
    }

    fn all_resources(&self, include_external: bool) -> ResourceCollection {
        let mut resources: ResourceCollection = Vec::new();
        let self_url = self
            .get_self_url()
            .expect("No self URL set, is required in DB");
        for item in self.resources.into_iter() {
            let (subject, resource_bin) = item.expect(DB_CORRUPT_MSG);
            let subject: String = bincode::deserialize(&subject).expect(DB_CORRUPT_MSG);
            if !include_external && !subject.starts_with(&self_url) {
                continue;
            }
            let propvals: PropVals = bincode::deserialize(&resource_bin)
                .unwrap_or_else(|e| panic!("{}. {}", corrupt_db_message(&subject), e));
            let resource = Resource::from_propvals(propvals, subject);
            resources.push(resource);
        }
        resources
    }

    fn populate(&self) -> AtomicResult<()> {
        // populate_base_models should be run in init, instead of here, since it will result in infinite loops without
        crate::populate::populate_default_store(self)?;
        // This is a potentially expensive operation, but is needed to make TPF queries work with the models created in here
        self.build_index(true)?;
        crate::populate::populate_hierarchy(self)?;
        crate::populate::populate_collections(self)?;
        crate::populate::populate_endpoints(self)?;
        Ok(())
    }

    fn remove_resource(&self, subject: &str) -> AtomicResult<()> {
        // This errors when the resource is not present.
        // https://github.com/joepio/atomic/issues/46
        let binary_subject = bincode::serialize(subject).unwrap();
        let found = self.resources.remove(&binary_subject)?;
        if found.is_none() {
            return Err(format!(
                "Resource {} could not be deleted, because it was not found in the store.",
                subject
            )
            .into());
        }
        Ok(())
    }

    fn set_default_agent(&self, agent: crate::agents::Agent) {
        self.default_agent.lock().unwrap().replace(agent);
    }

    // TPF implementation that used the index_value cache, far more performant than the StoreLike implementation
    fn tpf(
        &self,
        q_subject: Option<&str>,
        q_property: Option<&str>,
        q_value: Option<&str>,
        // Whether resources from outside the store should be searched through
        include_external: bool,
    ) -> AtomicResult<Vec<Atom>> {
        let mut vec: Vec<Atom> = Vec::new();

        let hassub = q_subject.is_some();
        let hasprop = q_property.is_some();
        let hasval = q_value.is_some();

        // Simply return all the atoms
        if !hassub && !hasprop && !hasval {
            for resource in self.all_resources(include_external) {
                for (property, value) in resource.get_propvals() {
                    vec.push(Atom::new(
                        resource.get_subject().clone(),
                        property.clone(),
                        value.clone(),
                    ))
                }
            }
            return Ok(vec);
        }

        // If the value is a resourcearray, check if it is inside
        let val_equals = |val: &str| {
            let q = q_value.unwrap();
            val == q || {
                if val.starts_with('[') {
                    match crate::parse::parse_json_array(val) {
                        Ok(vec) => return vec.contains(&q.into()),
                        Err(_) => return val == q,
                    }
                }
                false
            }
        };

        // Find atoms matching the TPF query in a single resource
        let mut find_in_resource = |resource: &Resource| {
            let subj = resource.get_subject();
            for (prop, val) in resource.get_propvals().iter() {
                if hasprop && q_property.as_ref().unwrap() == prop {
                    if hasval {
                        if val_equals(&val.to_string()) {
                            vec.push(Atom::new(subj.into(), prop.into(), val.clone()))
                        }
                        break;
                    } else {
                        vec.push(Atom::new(subj.into(), prop.into(), val.clone()))
                    }
                    break;
                } else if hasval && !hasprop && val_equals(&val.to_string()) {
                    vec.push(Atom::new(subj.into(), prop.into(), val.clone()))
                }
            }
        };

        match q_subject {
            Some(sub) => match self.get_resource(&sub) {
                Ok(resource) => {
                    if hasprop | hasval {
                        find_in_resource(&resource);
                        Ok(vec)
                    } else {
                        resource.to_atoms()
                    }
                }
                Err(_) => Ok(vec),
            },
            None => {
                if hasval {
                    let spm = self.get_prop_subject_map(q_value.unwrap())?;
                    if hasprop {
                        if let Some(set) = spm.get(q_property.unwrap()) {
                            let base = self.get_base_url();
                            for subj in set {
                                if !include_external && !subj.starts_with(base) {
                                    continue;
                                }
                                let property_full = self.get_property(q_property.unwrap())?;
                                let mut datatype = property_full.data_type;
                                // The value index stores only single subjects, not arrays.
                                // However, this also means that it is not possible to find the actual _value_ of a thing
                                // So for arrays, we simply return AtomicURLs.
                                if datatype == DataType::ResourceArray {
                                    datatype = DataType::AtomicUrl
                                }
                                let atom = Atom::new(
                                    subj.into(),
                                    q_property.unwrap().into(),
                                    Value::new(q_value.unwrap(), &datatype)?,
                                );
                                vec.push(atom);
                            }
                        }
                    } else {
                        for (prop, set) in spm.iter() {
                            for subj in set {
                                let property_full = self.get_property(prop)?;
                                let atom = Atom::new(
                                    subj.into(),
                                    prop.into(),
                                    Value::new(q_value.unwrap(), &property_full.data_type)?,
                                );
                                vec.push(atom);
                            }
                        }
                    }
                    return Ok(vec);
                }
                // TODO: Add an index for searching only by property
                for resource in self.all_resources(include_external) {
                    find_in_resource(&resource);
                }
                Ok(vec)
            }
        }
    }
}

fn corrupt_db_message(subject: &str) -> String {
    return format!("Could not deserialize item {} from database. DB is possibly corrupt, could be due to an update or a lack of migrations. Restore to a previous version, export / serialize your data and import your data again.", subject);
}

const DB_CORRUPT_MSG: &str = "Could not deserialize item from database. DB is possibly corrupt, could be due to an update or a lack of migrations. Restore to a previous version, export / serialize your data and import your data again.";

#[cfg(test)]
pub mod test {
    use crate::urls;

    use super::*;
    use ntest::timeout;

    /// Creates new temporary database, populates it, removes previous one.
    /// Can only be run one thread at a time, because it requires a lock on the DB file.
    fn init() -> Db {
        let tmp_dir_path = "tmp/db";
        let _try_remove_existing = std::fs::remove_dir_all(tmp_dir_path);
        let store = Db::init(tmp_dir_path, "https://localhost".into()).unwrap();
        let agent = store.create_agent(None).unwrap();
        store.set_default_agent(agent);
        store.populate().unwrap();
        store
    }

    /// Share the Db instance between tests. Otherwise, all tests try to init the same location on disk and throw errors.
    use lazy_static::lazy_static; // 1.4.0
    use std::sync::Mutex;
    lazy_static! {
        pub static ref DB: Mutex<Db> = Mutex::new(init());
    }

    #[test]
    #[timeout(30000)]
    fn basic() {
        let store = DB.lock().unwrap().clone();
        // We can create a new Resource, linked to the store.
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
        new_property.save_locally(&store).unwrap();
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

        // Try removing something
        store.get_resource(crate::urls::CLASS).unwrap();
        store.remove_resource(crate::urls::CLASS).unwrap();
        // Should throw an error, because can't remove non-existent resource
        store.remove_resource(crate::urls::CLASS).unwrap_err();
        // Should throw an error, because resource is deleted
        store.get_propvals(crate::urls::CLASS).unwrap_err();

        assert!(store.all_resources(false).len() < store.all_resources(true).len());
    }

    #[test]
    fn populate_collections() {
        let store = DB.lock().unwrap().clone();
        let subjects: Vec<String> = store
            .all_resources(false)
            .into_iter()
            .map(|r| r.get_subject().into())
            .collect();
        println!("{:?}", subjects);
        let collections_collection_url = format!("{}/collections", store.get_base_url());
        let my_resource = store
            .get_resource_extended(&collections_collection_url)
            .unwrap();
        let my_value = my_resource
            .get(crate::urls::COLLECTION_MEMBER_COUNT)
            .unwrap();
        println!("My value: {}", my_value);
        assert!(my_value.to_int().unwrap() > 11);
    }

    #[test]
    /// Check if the cache is working
    fn add_atom_to_index() {
        let store = DB.lock().unwrap().clone();
        let subject = urls::CLASS.into();
        let property: String = urls::PARENT.into();
        let val_string = urls::AGENT;
        let value = Value::new(val_string, &DataType::AtomicUrl).unwrap();
        // This atom should normally not exist - Agent is not the parent of Class.
        let atom = Atom::new(subject, property.clone(), value);
        store.add_atom_to_index(&atom).unwrap();
        let found_no_external = store
            .tpf(None, Some(&property), Some(val_string), false)
            .unwrap();
        // Don't find the atom if no_external is true.
        assert_eq!(found_no_external.len(), 0);
        let found_external = store
            .tpf(None, Some(&property), Some(val_string), true)
            .unwrap();
        // If we see the atom, it's in the index.
        assert_eq!(found_external.len(), 1);
    }

    #[test]
    /// Check if a resource is properly removed from the DB after a delete command
    fn destroy_resource_and_check_collection() {
        let store = DB.lock().unwrap().clone();
        let agents_url = format!("{}/agents", store.get_base_url());
        let agents_collection_1 = store.get_resource_extended(&agents_url).unwrap();
        let agents_collection_count_1 = agents_collection_1
            .get(crate::urls::COLLECTION_MEMBER_COUNT)
            .unwrap()
            .to_int()
            .unwrap();
        assert_eq!(
            agents_collection_count_1, 1,
            "The Agents collection is not one (we assume there is one agent already present from init)"
        );

        let mut resource = crate::agents::Agent::new(None, &store)
            .unwrap()
            .to_resource(&store)
            .unwrap();
        resource.save_locally(&store).unwrap();
        let agents_collection_2 = store.get_resource_extended(&agents_url).unwrap();
        let agents_collection_count_2 = agents_collection_2
            .get(crate::urls::COLLECTION_MEMBER_COUNT)
            .unwrap()
            .to_int()
            .unwrap();
        assert_eq!(
            agents_collection_count_2, 2,
            "The Resource was not found in the collection."
        );

        resource.destroy(&store).unwrap();
        let agents_collection_3 = store.get_resource_extended(&agents_url).unwrap();
        let agents_collection_count_3 = agents_collection_3
            .get(crate::urls::COLLECTION_MEMBER_COUNT)
            .unwrap()
            .to_int()
            .unwrap();
        assert_eq!(
            agents_collection_count_3, 1,
            "The collection count did not decrease after destroying the resource."
        );
    }
}
