//! Persistent, ACID compliant, threadsafe to-disk store.
//! Powered by Sled - an embedded database.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use crate::{
    endpoints::{default_endpoints, Endpoint},
    errors::{AtomicError, AtomicResult},
    resources::PropVals,
    storelike::{Query, QueryResult, ResourceCollection, Storelike},
    Atom, Resource, Value,
};

use self::query_index::{
    add_atoms_to_index, check_if_atom_matches_watched_collections, query_indexed, update_member,
    watch_collection, IndexAtom, QueryFilter,
};

mod query_index;

/// Inside the reference_index, each value is mapped to this type.
/// The String on the left represents a Property URL, and the second one is the set of subjects.
pub type PropSubjectMap = HashMap<String, HashSet<String>>;

/// The Db is a persistent on-disk Atomic Data store.
/// It's an implementation of [Storelike].
/// It uses [sled::Tree] as a Key Value store.
/// It builds a value index for performant [Query]s.
/// It stores [Resource]s as [PropVals]s by their subject as key.
#[derive(Clone)]
pub struct Db {
    /// The Key-Value store that contains all data.
    /// Resources can be found using their Subject.
    /// Try not to use this directly, but use the Trees.
    db: sled::Db,
    default_agent: Arc<Mutex<Option<crate::agents::Agent>>>,
    /// Stores all resources. The Key is the Subject as a string, the value a [PropVals]. Both must be serialized using bincode.
    resources: sled::Tree,
    /// Index for all AtommicURLs, indexed by their Value. Used to speed up TPF queries. See [key_for_reference_index]
    reference_index: sled::Tree,
    /// Stores the members of Collections, easily sortable.
    /// See [collections_index]
    members_index: sled::Tree,
    /// A list of all the Collections currently being used. Is used to update `members_index`.
    /// See [collections_index]
    watched_queries: sled::Tree,
    /// The address where the db will be hosted, e.g. http://localhost/
    server_url: String,
    /// Endpoints are checked whenever a resource is requested. They calculate (some properties of) the resource and return it.
    endpoints: Vec<Endpoint>,
}

impl Db {
    /// Creates a new store at the specified path, or opens the store if it already exists.
    /// The server_url is the domain where the db will be hosted, e.g. http://localhost/
    /// It is used for distinguishing locally defined items from externally defined ones.
    pub fn init(path: &std::path::Path, server_url: String) -> AtomicResult<Db> {
        let db = sled::open(path).map_err(|e|format!("Failed opening DB at this location: {:?} . Is another instance of Atomic Server running? {}", path, e))?;
        let resources = db.open_tree("resources").map_err(|e|format!("Failed building resources. Your DB might be corrupt. Go back to a previous version and export your data. {}", e))?;
        let reference_index = db.open_tree("reference_index")?;
        let members_index = db.open_tree("members_index")?;
        let watched_queries = db.open_tree("watched_queries")?;
        let store = Db {
            db,
            default_agent: Arc::new(Mutex::new(None)),
            resources,
            reference_index,
            members_index,
            server_url,
            watched_queries,
            endpoints: default_endpoints(),
        };
        crate::populate::populate_base_models(&store)
            .map_err(|e| format!("Failed to populate base models. {}", e))?;
        Ok(store)
    }

    /// Internal method for fetching Resource data.
    #[tracing::instrument(skip(self))]
    fn set_propvals(&self, subject: &str, propvals: &PropVals) -> AtomicResult<()> {
        let resource_bin = bincode::serialize(propvals)?;
        let subject_bin = bincode::serialize(subject)?;
        self.resources.insert(subject_bin, resource_bin)?;
        Ok(())
    }

    /// Finds resource by Subject, return PropVals HashMap
    /// Deals with the binary API of Sled
    #[tracing::instrument(skip(self))]
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
            None => Err(AtomicError::not_found(format!(
                "Resource {} not found",
                subject
            ))),
        }
    }

    /// Returns true if the index has been built.
    pub fn has_index(&self) -> bool {
        !self.reference_index.is_empty()
    }

    /// Removes all values from the index.
    pub fn clear_index(&self) -> AtomicResult<()> {
        self.reference_index.clear()?;
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
    #[tracing::instrument(skip(self))]
    fn add_atom_to_index(&self, atom: &Atom) -> AtomicResult<()> {
        let values_vec = match &atom.value {
            // This results in wrong indexing, as some subjects will be numbers.
            Value::ResourceArray(_v) => atom.values_to_subjects()?,
            Value::AtomicUrl(v) => vec![v.into()],
            _other => return Ok(()),
        };

        for val_subject in values_vec {
            // https://github.com/joepio/atomic-data-rust/issues/282
            // The key is a newline delimited string, with the following format:
            let index_atom = query_index::IndexAtom {
                value: val_subject,
                property: atom.property.clone(),
                subject: atom.subject.clone(),
            };

            // It's OK if this overwrites a value
            let _existing = self
                .reference_index
                .insert(key_for_reference_index(&index_atom).as_bytes(), b"")?;

            // Also update the members index to keep collections performant
            query_index::check_if_atom_matches_watched_collections(self, &index_atom, false)
                .map_err(|e| {
                    format!("Failed to check_if_atom_matches_watched_collections. {}", e)
                })?;
        }
        Ok(())
    }

    #[tracing::instrument(skip(self, resource), fields(sub = %resource.get_subject()))]
    fn add_resource_opts(
        &self,
        resource: &Resource,
        check_required_props: bool,
        update_index: bool,
        overwrite_existing: bool,
    ) -> AtomicResult<()> {
        // This only works if no external functions rely on using add_resource for atom-like operations!
        // However, add_atom uses set_propvals, which skips the validation.
        let existing = self.get_propvals(resource.get_subject()).ok();
        if !overwrite_existing && existing.is_some() {
            return Err(format!(
                "Failed to add: '{}', already exists, should not be overwritten.",
                resource.get_subject()
            )
            .into());
        }
        if check_required_props {
            resource.check_required_props(self)?;
        }
        if update_index {
            if let Some(pv) = existing {
                let subject = resource.get_subject();
                for (prop, val) in pv.iter() {
                    // Possible performance hit - these clones can be replaced by modifying remove_atom_from_index
                    let remove_atom = crate::Atom::new(subject.into(), prop.into(), val.clone());
                    self.remove_atom_from_index(&remove_atom).map_err(|e| {
                        format!("Failed to remove atom to index {}. {}", remove_atom, e)
                    })?;
                }
            }
            for a in resource.to_atoms()? {
                self.add_atom_to_index(&a)
                    .map_err(|e| format!("Failed to add atom to index {}. {}", a, e))?;
            }
        }
        self.set_propvals(resource.get_subject(), resource.get_propvals())
    }

    #[tracing::instrument(skip(self))]
    fn remove_atom_from_index(&self, atom: &Atom) -> AtomicResult<()> {
        let vec = match atom.value.to_owned() {
            Value::ResourceArray(_v) => atom.values_to_subjects()?,
            Value::AtomicUrl(subject) => vec![subject],
            _other => return Ok(()),
        };

        for val in vec {
            let index_atom = IndexAtom {
                value: val,
                property: atom.property.clone(),
                subject: atom.subject.clone(),
            };

            self.reference_index
                .remove(&key_for_reference_index(&index_atom).as_bytes())?;

            check_if_atom_matches_watched_collections(self, &index_atom, true)?;
        }
        Ok(())
    }

    fn get_server_url(&self) -> &str {
        &self.server_url
    }

    // Since the DB is often also the server, this should make sense.
    // Some edge cases might appear later on (e.g. a slave DB that only stores copies?)
    fn get_self_url(&self) -> Option<String> {
        Some(self.get_server_url().into())
    }

    fn get_default_agent(&self) -> AtomicResult<crate::agents::Agent> {
        match self.default_agent.lock().unwrap().to_owned() {
            Some(agent) => Ok(agent),
            None => Err("No default agent has been set.".into()),
        }
    }

    #[tracing::instrument(skip(self))]
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

    #[tracing::instrument(skip(self))]
    fn get_resource_extended(
        &self,
        subject: &str,
        skip_dynamic: bool,
        for_agent: Option<&str>,
    ) -> AtomicResult<Resource> {
        tracing::trace!("get_resource_extended: {}", subject);
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
        for endpoint in self.endpoints.iter() {
            if url.path().starts_with(&endpoint.path) {
                // Not all Endpoitns have a hanlde function.
                // If there is none, return the endpoint plainly.
                let mut resource = if let Some(handle) = endpoint.handle {
                    // Call the handle function for the endpoint, if it exists.
                    (handle)(clone.clone(), self, for_agent).map_err(|e| {
                        format!("Error handling {} Endpoint: {}", endpoint.shortname, e)
                    })?
                } else {
                    endpoint.to_resource(self)?
                };
                // Extended resources must always return the requested subject as their own subject
                resource.set_subject(subject.into());
                return Ok(resource.to_owned());
            }
        }

        let mut resource = self.get_resource(&removed_query_params)?;

        // make sure the actual subject matches the one requested
        resource.set_subject(subject.into());

        if let Some(agent) = for_agent {
            crate::hierarchy::check_read(self, &resource, agent)?;
        }

        // Whether the resource has dynamic properties
        let mut has_dynamic = false;
        // If a certain class needs to be extended, add it to this match statement
        for class in resource.get_classes(self)? {
            match class.subject.as_ref() {
                crate::urls::COLLECTION => {
                    has_dynamic = true;
                    if !skip_dynamic {
                        return crate::collections::construct_collection_from_params(
                            self,
                            query_params,
                            &mut resource,
                            for_agent,
                        );
                    }
                }
                crate::urls::INVITE => {
                    has_dynamic = true;
                    if !skip_dynamic {
                        return crate::plugins::invite::construct_invite_redirect(
                            self,
                            query_params,
                            &mut resource,
                            subject,
                        );
                    }
                }
                crate::urls::DRIVE => {
                    has_dynamic = true;
                    if !skip_dynamic {
                        return crate::hierarchy::add_children(self, &mut resource);
                    }
                }
                _ => {}
            }
        }

        // This lets clients know that the resource may have dynamic properties that are currently not included
        if has_dynamic && skip_dynamic {
            resource.set_propval(
                crate::urls::INCOMPLETE.into(),
                crate::Value::Boolean(true),
                self,
            )?;
        }
        Ok(resource)
    }

    /// Search the Store, returns the matching subjects.
    /// The second returned vector should be filled if query.include_resources is true.
    /// Tries `query_cache`, which you should implement yourself.
    #[tracing::instrument(skip(self))]
    fn query(&self, q: &Query) -> AtomicResult<QueryResult> {
        if let Ok(Some(res)) = query_indexed(self, q) {
            // Yay, we have a cache hit!
            return Ok(res);
        }

        // No cache hit, perform the query
        let mut atoms = self.tpf(
            None,
            q.property.as_deref(),
            q.value.as_deref(),
            q.include_external,
        )?;

        // Retry the same query!
        if let Ok(Some(res)) = query_indexed(self, q) {
            // Yay, we have a cache hit!
            return Ok(res);
        }

        let mut subjects = Vec::new();
        let mut resources = Vec::new();
        for atom in atoms.iter() {
            // These nested resources are not fully calculated - they will be presented as -is
            subjects.push(atom.subject.clone());
            // We need the Resources if we want to sort by a non-subject value
            if q.include_nested || q.sort_by.is_some() {
                match self.get_resource_extended(&atom.subject, true, q.for_agent.as_deref()) {
                    Ok(resource) => {
                        resources.push(resource);
                    }
                    Err(e) => match e.error_type {
                        crate::AtomicErrorType::NotFoundError => {}
                        crate::AtomicErrorType::UnauthorizedError => {}
                        crate::AtomicErrorType::OtherError => {
                            return Err(
                                format!("Error when getting resource in collection: {}", e).into()
                            )
                        }
                    },
                }
            }
        }

        if let Some(sort) = &q.sort_by {
            resources.
        }

        let q_filter: QueryFilter = q.into();

        add_atoms_to_index(self, &atoms, &q_filter)?;
        // Maybe make this optional?
        watch_collection(self, &q_filter)?;

        Ok((subjects, resources))
    }

    #[tracing::instrument(skip(self))]
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
        crate::populate::populate_default_store(self)
            .map_err(|e| format!("Failed to populate default store. {}", e))?;
        // This is a potentially expensive operation, but is needed to make TPF queries work with the models created in here
        self.build_index(true)?;
        crate::populate::create_drive(self)
            .map_err(|e| format!("Failed to populate hierarcy. {}", e))?;
        crate::populate::populate_collections(self)
            .map_err(|e| format!("Failed to populate collections. {}", e))?;
        crate::populate::populate_endpoints(self)
            .map_err(|e| format!("Failed to populate endpoints. {}", e))?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    fn remove_resource(&self, subject: &str) -> AtomicResult<()> {
        if let Ok(found) = self.get_propvals(subject) {
            for (prop, val) in found {
                let remove_atom = crate::Atom::new(subject.into(), prop, val);
                self.remove_atom_from_index(&remove_atom)?;
            }
            let binary_subject = bincode::serialize(subject).unwrap();
            let _found = self.resources.remove(&binary_subject)?;
        } else {
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
    #[tracing::instrument(skip(self))]
    fn tpf(
        &self,
        q_subject: Option<&str>,
        q_property: Option<&str>,
        q_value: Option<&str>,
        // Whether resources from outside the store should be searched through
        include_external: bool,
    ) -> AtomicResult<Vec<Atom>> {
        tracing::trace!("tpf");
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
            Some(sub) => match self.get_resource(sub) {
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
                    let key_prefix = if hasprop {
                        format!("{}\n{}\n", q_value.unwrap(), q_property.unwrap())
                    } else {
                        format!("{}\n", q_value.unwrap())
                    };
                    for item in self.reference_index.scan_prefix(key_prefix) {
                        let (k, _v) = item?;
                        let key_string = String::from_utf8(k.to_vec())?;
                        let atom = key_to_atom(&key_string)?;
                        if include_external || atom.subject.starts_with(self.get_server_url()) {
                            vec.push(atom)
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

/// Constructs the Key for the index_value cache.
fn key_for_reference_index(atom: &IndexAtom) -> String {
    format!("{}\n{}\n{}", atom.value, atom.property, atom.subject)
}

/// Parses a Value index key string, converts it into an atom. Note that the Value of the atom will allways be a single AtomicURL here.
fn key_to_atom(key: &str) -> AtomicResult<Atom> {
    let mut parts = key.split('\n');
    let val = parts.next().ok_or("Invalid key for value index")?;
    let prop = parts.next().ok_or("Invalid key for value index")?;
    let subj = parts.next().ok_or("Invalid key for value index")?;
    Ok(Atom::new(
        subj.into(),
        prop.into(),
        Value::AtomicUrl(val.into()),
    ))
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
    fn init(id: &str) -> Db {
        let tmp_dir_path = format!("tmp/db/{}", id);
        let _try_remove_existing = std::fs::remove_dir_all(&tmp_dir_path);
        let store = Db::init(
            std::path::Path::new(&tmp_dir_path),
            "https://localhost".into(),
        )
        .unwrap();
        let agent = store.create_agent(None).unwrap();
        store.set_default_agent(agent);
        store.populate().unwrap();
        store
    }

    /// Share the Db instance between tests. Otherwise, all tests try to init the same location on disk and throw errors.
    /// Note that not all behavior can be properly tested with a shared database.
    /// If you need a clean one, juts call init("someId").
    use lazy_static::lazy_static; // 1.4.0
    use std::sync::Mutex;
    lazy_static! {
        pub static ref DB: Mutex<Db> = Mutex::new(init("shared"));
    }

    #[test]
    #[timeout(30000)]
    fn basic() {
        let store = DB.lock().unwrap().clone();
        // We can create a new Resource, linked to the store.
        // Note that since this store only exists in memory, it's data cannot be accessed from the internet.
        // Let's make a new Property instance!
        let mut new_resource =
            crate::Resource::new_instance("https://atomicdata.dev/classes/Property", &store)
                .unwrap();
        // And add a description for that Property
        new_resource
            .set_propval_shortname("description", "the age of a person", &store)
            .unwrap();
        new_resource
            .set_propval_shortname("shortname", "age", &store)
            .unwrap();
        new_resource
            .set_propval_shortname("datatype", crate::urls::INTEGER, &store)
            .unwrap();
        // Changes are only applied to the store after saving them explicitly.
        new_resource.save_locally(&store).unwrap();
        // The modified resource is saved to the store after this

        // A subject URL has been created automatically.
        let subject = new_resource.get_subject();
        let fetched_new_resource = store.get_resource(subject).unwrap();
        let description_val = fetched_new_resource
            .get_shortname("description", &store)
            .unwrap()
            .to_string();
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
        let collections_collection_url = format!("{}/collections", store.get_server_url());
        let collections_resource = store
            .get_resource_extended(&collections_collection_url, false, None)
            .unwrap();
        let member_count = collections_resource
            .get(crate::urls::COLLECTION_MEMBER_COUNT)
            .unwrap()
            .to_int()
            .unwrap();
        assert!(member_count > 11);
        let nested = collections_resource
            .get(crate::urls::COLLECTION_INCLUDE_NESTED)
            .unwrap()
            .to_bool()
            .unwrap();
        assert!(nested);
    }

    #[test]
    /// Check if the cache is working
    fn add_atom_to_index() {
        let store = DB.lock().unwrap().clone();
        let subject = urls::CLASS.into();
        let property: String = urls::PARENT.into();
        let val_string = urls::AGENT;
        let value = Value::new(val_string, &crate::datatype::DataType::AtomicUrl).unwrap();
        // This atom should normally not exist - Agent is not the parent of Class.
        let atom = Atom::new(subject, property.clone(), value);
        store.add_atom_to_index(&atom).unwrap();
        let found_no_external = store
            .tpf(None, Some(&property), Some(val_string), false)
            .unwrap();
        // Don't find the atom if no_external is true.
        assert_eq!(
            found_no_external.len(),
            0,
            "found items - should ignore external items"
        );
        let found_external = store
            .tpf(None, Some(&property), Some(val_string), true)
            .unwrap();
        // If we see the atom, it's in the index.
        assert_eq!(found_external.len(), 1);
    }

    #[test]
    /// Check if a resource is properly removed from the DB after a delete command.
    /// Also counts commits.
    fn destroy_resource_and_check_collection_and_commits() {
        let store = init("counter");
        let agents_url = format!("{}/agents", store.get_server_url());
        let agents_collection_1 = store
            .get_resource_extended(&agents_url, false, None)
            .unwrap();
        let agents_collection_count_1 = agents_collection_1
            .get(crate::urls::COLLECTION_MEMBER_COUNT)
            .unwrap()
            .to_int()
            .unwrap();
        assert_eq!(
            agents_collection_count_1, 1,
            "The Agents collection is not one (we assume there is one agent already present from init)"
        );

        // We will count the commits, and check if they've incremented later on.
        let commits_url = format!("{}/commits", store.get_server_url());
        let commits_collection_1 = store
            .get_resource_extended(&commits_url, false, None)
            .unwrap();
        let commits_collection_count_1 = commits_collection_1
            .get(crate::urls::COLLECTION_MEMBER_COUNT)
            .unwrap()
            .to_int()
            .unwrap();
        println!("Commits collection count 1: {}", commits_collection_count_1);

        let mut resource = crate::agents::Agent::new(None, &store)
            .unwrap()
            .to_resource(&store)
            .unwrap();
        resource.save_locally(&store).unwrap();
        let agents_collection_2 = store
            .get_resource_extended(&agents_url, false, None)
            .unwrap();
        let agents_collection_count_2 = agents_collection_2
            .get(crate::urls::COLLECTION_MEMBER_COUNT)
            .unwrap()
            .to_int()
            .unwrap();
        assert_eq!(
            agents_collection_count_2, 2,
            "The Resource was not found in the collection."
        );

        let commits_collection_2 = store
            .get_resource_extended(&commits_url, false, None)
            .unwrap();
        let commits_collection_count_2 = commits_collection_2
            .get(crate::urls::COLLECTION_MEMBER_COUNT)
            .unwrap()
            .to_int()
            .unwrap();
        println!("Commits collection count 2: {}", commits_collection_count_2);
        assert_eq!(
            commits_collection_count_2,
            commits_collection_count_1 + 1,
            "The commits collection did not increase after saving the resource."
        );

        resource.destroy(&store).unwrap();
        let agents_collection_3 = store
            .get_resource_extended(&agents_url, false, None)
            .unwrap();
        let agents_collection_count_3 = agents_collection_3
            .get(crate::urls::COLLECTION_MEMBER_COUNT)
            .unwrap()
            .to_int()
            .unwrap();
        assert_eq!(
            agents_collection_count_3, 1,
            "The collection count did not decrease after destroying the resource."
        );

        let commits_collection_3 = store
            .get_resource_extended(&commits_url, false, None)
            .unwrap();
        let commits_collection_count_3 = commits_collection_3
            .get(crate::urls::COLLECTION_MEMBER_COUNT)
            .unwrap()
            .to_int()
            .unwrap();
        println!("Commits collection count 3: {}", commits_collection_count_3);
        assert_eq!(
            commits_collection_count_3,
            commits_collection_count_2 + 1,
            "The commits collection did not increase after destroying the resource."
        );
    }

    #[test]
    fn get_extended_resource_pagination() {
        let store = DB.lock().unwrap().clone();
        let subject = format!("{}/commits?current_page=2", store.get_server_url());
        // Should throw, because page 2 is out of bounds for default page size
        let _wrong_resource = store
            .get_resource_extended(&subject, false, None)
            .unwrap_err();
        // let subject = "https://atomicdata.dev/classes?current_page=2&page_size=1";
        let subject_with_page_size = format!("{}&page_size=1", subject);
        let resource = store
            .get_resource_extended(&subject_with_page_size, false, None)
            .unwrap();
        let cur_page = resource
            .get(urls::COLLECTION_CURRENT_PAGE)
            .unwrap()
            .to_int()
            .unwrap();
        assert_eq!(cur_page, 2);
        assert_eq!(resource.get_subject(), &subject_with_page_size);
    }
}
