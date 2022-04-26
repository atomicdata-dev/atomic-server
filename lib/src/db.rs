//! Persistent, ACID compliant, threadsafe to-disk store.
//! Powered by Sled - an embedded database.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use tracing::{instrument, trace};

use crate::{
    commit::CommitResponse,
    endpoints::{default_endpoints, Endpoint},
    errors::{AtomicError, AtomicResult},
    resources::PropVals,
    storelike::{Query, QueryResult, ResourceCollection, Storelike},
    Atom, Resource, Value,
};

use self::{
    migrations::migrate_maybe,
    query_index::{
        atom_to_indexable_atoms, check_if_atom_matches_watched_query_filters, query_indexed,
        update_indexed_member, watch_collection, IndexAtom, QueryFilter, END_CHAR,
    },
};

// A function called by the Store when a Commit is accepted
type HandleCommit = Box<dyn Fn(&CommitResponse) + Send + Sync>;

mod migrations;
mod query_index;
#[cfg(test)]
pub mod test;

/// Inside the reference_index, each value is mapped to this type.
/// The String on the left represents a Property URL, and the second one is the set of subjects.
pub type PropSubjectMap = HashMap<String, HashSet<String>>;

/// The Db is a persistent on-disk Atomic Data store.
/// It's an implementation of [Storelike].
/// It uses [sled::Tree]s as Key Value stores.
/// It stores [Resource]s as [PropVals]s by their subject as key.
/// It builds a value index for performant [Query]s.
/// It keeps track of Queries and updates their index when [Commit]s are applied.
/// You can pass a custom `on_commit` function to run at Commit time.
#[derive(Clone)]
pub struct Db {
    /// The Key-Value store that contains all data.
    /// Resources can be found using their Subject.
    /// Try not to use this directly, but use the Trees.
    db: sled::Db,
    default_agent: Arc<Mutex<Option<crate::agents::Agent>>>,
    /// Stores all resources. The Key is the Subject as a `string.as_bytes()`, the value a [PropVals]. Propvals must be serialized using [bincode].
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
    /// Function called whenever a Commit is applied.
    on_commit: Option<Arc<HandleCommit>>,
}

impl Db {
    /// Creates a new store at the specified path, or opens the store if it already exists.
    /// The server_url is the domain where the db will be hosted, e.g. http://localhost/
    /// It is used for distinguishing locally defined items from externally defined ones.
    pub fn init(path: &std::path::Path, server_url: String) -> AtomicResult<Db> {
        let db = sled::open(path).map_err(|e|format!("Failed opening DB at this location: {:?} . Is another instance of Atomic Server running? {}", path, e))?;
        let resources = db.open_tree("resources_v1").map_err(|e|format!("Failed building resources. Your DB might be corrupt. Go back to a previous version and export your data. {}", e))?;
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
            on_commit: None,
        };
        migrate_maybe(&store).map(|e| format!("Error during migration of database: {:?}", e))?;
        crate::populate::populate_base_models(&store)
            .map_err(|e| format!("Failed to populate base models. {}", e))?;
        Ok(store)
    }

    /// Create a temporary Db in `.temp/db/{id}`. Useful for testing.
    /// Populates the database, creates a default agent, and sets the server_url to "http://localhost/".
    pub fn init_temp(id: &str) -> AtomicResult<Db> {
        let tmp_dir_path = format!(".temp/db/{}", id);
        let _try_remove_existing = std::fs::remove_dir_all(&tmp_dir_path);
        let store = Db::init(
            std::path::Path::new(&tmp_dir_path),
            "https://localhost".into(),
        )?;
        let agent = store.create_agent(None)?;
        store.set_default_agent(agent);
        store.populate()?;
        Ok(store)
    }

    /// Internal method for fetching Resource data.
    #[instrument(skip(self))]
    fn set_propvals(&self, subject: &str, propvals: &PropVals) -> AtomicResult<()> {
        let resource_bin = bincode::serialize(propvals)?;
        self.resources.insert(subject.as_bytes(), resource_bin)?;
        Ok(())
    }

    /// Sets a function that is called whenever a [Commit::apply] is called.
    /// This can be used to listen to events.
    pub fn set_handle_commit(&mut self, on_commit: HandleCommit) {
        self.on_commit = Some(Arc::new(on_commit));
    }

    /// Finds resource by Subject, return PropVals HashMap
    /// Deals with the binary API of Sled
    #[instrument(skip(self))]
    fn get_propvals(&self, subject: &str) -> AtomicResult<PropVals> {
        let propval_maybe = self
            .resources
            .get(subject.as_bytes())
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

    /// Removes all values from the indexes.
    pub fn clear_index(&self) -> AtomicResult<()> {
        self.reference_index.clear()?;
        self.members_index.clear()?;
        self.watched_queries.clear()?;
        Ok(())
    }
}

impl Storelike for Db {
    #[instrument(skip(self))]
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

    #[instrument(skip(self))]
    fn add_atom_to_index(&self, atom: &Atom, resource: &Resource) -> AtomicResult<()> {
        for index_atom in atom_to_indexable_atoms(atom)? {
            // It's OK if this overwrites a value
            add_atom_to_reference_index(&index_atom, self)?;
            // Also update the query index to keep collections performant
            check_if_atom_matches_watched_query_filters(self, &index_atom, atom, false, resource)
                .map_err(|e| {
                    format!("Failed to check_if_atom_matches_watched_collections. {}", e)
                })?;
        }
        Ok(())
    }

    #[instrument(skip(self, resource), fields(sub = %resource.get_subject()))]
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
                    self.remove_atom_from_index(&remove_atom, resource)
                        .map_err(|e| {
                            format!("Failed to remove atom from index {}. {}", remove_atom, e)
                        })?;
                }
            }
            for a in resource.to_atoms()? {
                self.add_atom_to_index(&a, resource)
                    .map_err(|e| format!("Failed to add atom to index {}. {}", a, e))?;
            }
        }
        self.set_propvals(resource.get_subject(), resource.get_propvals())
    }

    #[instrument(skip(self))]
    fn remove_atom_from_index(&self, atom: &Atom, resource: &Resource) -> AtomicResult<()> {
        for index_atom in atom_to_indexable_atoms(atom)? {
            delete_atom_from_reference_index(&index_atom, self)?;

            check_if_atom_matches_watched_query_filters(self, &index_atom, atom, true, resource)
                .map_err(|e| format!("Checking atom went wrong: {}", e))?;
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

    #[instrument(skip(self))]
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

    #[instrument(skip(self))]
    fn get_resource_extended(
        &self,
        subject: &str,
        skip_dynamic: bool,
        for_agent: Option<&str>,
    ) -> AtomicResult<Resource> {
        let url_span = tracing::span!(tracing::Level::TRACE, "URL parse").entered();
        // This might add a trailing slash
        let url = url::Url::parse(subject)?;

        let mut removed_query_params = {
            let mut url_altered = url.clone();
            url_altered.set_query(None);
            url_altered.to_string()
        };

        // Remove trailing slash
        if removed_query_params.ends_with('/') {
            removed_query_params.pop();
        }

        url_span.exit();

        let endpoint_span = tracing::span!(tracing::Level::TRACE, "Endpoint").entered();
        // Check if the subject matches one of the endpoints
        for endpoint in self.endpoints.iter() {
            if url.path().starts_with(&endpoint.path) {
                // Not all Endpoints have a handle function.
                // If there is none, return the endpoint plainly.
                let mut resource = if let Some(handle) = endpoint.handle {
                    // Call the handle function for the endpoint, if it exists.
                    (handle)(url, self, for_agent).map_err(|e| {
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
        endpoint_span.exit();

        let dynamic_span = tracing::span!(tracing::Level::TRACE, "Dynamic").entered();
        let mut resource = self.get_resource(&removed_query_params)?;

        if let Some(agent) = for_agent {
            let _explanation = crate::hierarchy::check_read(self, &resource, agent)?;
        }

        // Whether the resource has dynamic properties
        let mut has_dynamic = false;
        // If a certain class needs to be extended, add it to this match statement
        for class in resource.get_classes(self)? {
            match class.subject.as_ref() {
                crate::urls::COLLECTION => {
                    has_dynamic = true;
                    if !skip_dynamic {
                        resource = crate::collections::construct_collection_from_params(
                            self,
                            url.query_pairs(),
                            &mut resource,
                            for_agent,
                        )?;
                    }
                }
                crate::urls::INVITE => {
                    has_dynamic = true;
                    if !skip_dynamic {
                        resource = crate::plugins::invite::construct_invite_redirect(
                            self,
                            url.query_pairs(),
                            &mut resource,
                            for_agent,
                        )?;
                    }
                }
                crate::urls::DRIVE => {
                    has_dynamic = true;
                    if !skip_dynamic {
                        resource = crate::hierarchy::add_children(self, &mut resource)?;
                    }
                }
                crate::urls::CHATROOM => {
                    has_dynamic = true;
                    if !skip_dynamic {
                        resource = crate::plugins::chatroom::construct_chatroom(
                            self,
                            url.clone(),
                            &mut resource,
                            for_agent,
                        )?;
                    }
                }
                _ => {}
            }
        }
        dynamic_span.exit();

        // make sure the actual subject matches the one requested - It should not be changed in the logic above
        resource.set_subject(subject.into());

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

    fn handle_commit(&self, commit_response: &CommitResponse) {
        if let Some(fun) = &self.on_commit {
            fun(commit_response);
        }
    }

    /// Search the Store, returns the matching subjects.
    /// The second returned vector should be filled if query.include_resources is true.
    /// Tries `query_cache`, which you should implement yourself.
    #[instrument(skip(self))]
    fn query(&self, q: &Query) -> AtomicResult<QueryResult> {
        if let Ok(res) = query_indexed(self, q) {
            if res.count > 0 {
                // Yay, we have a cache hit!
                // We don't have to perform a (more expansive) TPF query + sorting
                return Ok(res);
            }
        }

        // No cache hit, perform the query
        let mut atoms = self.tpf(
            None,
            q.property.as_deref(),
            q.value.as_ref(),
            // We filter later on, not here
            true,
        )?;
        let count = atoms.len();

        let mut subjects = Vec::new();
        let mut resources = Vec::new();
        for atom in atoms.iter() {
            // These nested resources are not fully calculated - they will be presented as -is
            subjects.push(atom.subject.clone());
            // We need the Resources if we want to sort by a non-subject value
            if q.include_nested || q.sort_by.is_some() {
                // We skip checking for Agent, because we don't return these results directly anyway
                match self.get_resource_extended(&atom.subject, true, None) {
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

        if atoms.is_empty() {
            return Ok(QueryResult {
                subjects: vec![],
                resources: vec![],
                count,
            });
        }

        // If there is a sort value, we need to change the atoms to contain that sorted value, instead of the one matched in the TPF query
        if let Some(sort_prop) = &q.sort_by {
            // We don't use the existing array, we clear it.
            atoms = Vec::new();
            for r in &resources {
                // Users _can_ sort by optional properties! So we need a fallback defauil
                let fallback_default = crate::Value::String(END_CHAR.into());
                let sorted_val = r.get(sort_prop).unwrap_or(&fallback_default);
                let atom = Atom {
                    subject: r.get_subject().to_string(),
                    property: sort_prop.to_string(),
                    value: sorted_val.to_owned(),
                };
                atoms.push(atom)
            }
            // Now we sort by the value that the user wants to sort by
            atoms.sort_by(|a, b| a.value.to_string().cmp(&b.value.to_string()));
        }

        let q_filter: QueryFilter = q.into();

        // Maybe make this optional?
        watch_collection(self, &q_filter)?;

        // Add the atoms to the query_index
        for atom in atoms {
            update_indexed_member(self, &q_filter, &atom.subject, &atom.value, false)?;
        }

        // Retry the same query!
        query_indexed(self, q)
    }

    #[instrument(skip(self))]
    fn all_resources(&self, include_external: bool) -> ResourceCollection {
        let mut resources: ResourceCollection = Vec::new();
        let self_url = self
            .get_self_url()
            .expect("No self URL set, is required in DB");
        for item in self.resources.into_iter() {
            let (subject, resource_bin) = item.expect(DB_CORRUPT_MSG);
            let subject: String = String::from_utf8_lossy(&subject).to_string();
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
        self.build_index(true)
            .map_err(|e| format!("Failed to build index. {}", e))?;
        crate::populate::create_drive(self)
            .map_err(|e| format!("Failed to create drive. {}", e))?;
        crate::populate::set_drive_rights(self, true)?;
        crate::populate::populate_collections(self)
            .map_err(|e| format!("Failed to populate collections. {}", e))?;
        crate::populate::populate_endpoints(self)
            .map_err(|e| format!("Failed to populate endpoints. {}", e))?;
        Ok(())
    }

    #[instrument(skip(self))]
    fn remove_resource(&self, subject: &str) -> AtomicResult<()> {
        if let Ok(found) = self.get_propvals(subject) {
            let resource = Resource::from_propvals(found, subject.to_string());
            for (prop, val) in resource.get_propvals() {
                let remove_atom = crate::Atom::new(subject.into(), prop.clone(), val.clone());
                self.remove_atom_from_index(&remove_atom, &resource)?;
            }
            let _found = self.resources.remove(&subject.as_bytes())?;
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
    #[instrument(skip(self))]
    fn tpf(
        &self,
        q_subject: Option<&str>,
        q_property: Option<&str>,
        q_value: Option<&Value>,
        // Whether resources from outside the store should be searched through
        include_external: bool,
    ) -> AtomicResult<Vec<Atom>> {
        trace!("tpf");
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
            let q = q_value.unwrap().to_sortable_string();
            val == q || {
                if val.starts_with('[') {
                    match crate::parse::parse_json_array(val) {
                        Ok(vec) => return vec.contains(&q),
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
                        // WARNING: Converts all Atoms to Strings, the datatype is lost here
                        let atom = key_to_atom(&key_string)?;
                        // NOTE: This means we'll include random values that start with the current server URL, including paragraphs for example.
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

#[instrument(skip(store))]
fn add_atom_to_reference_index(index_atom: &IndexAtom, store: &Db) -> AtomicResult<()> {
    let _existing = store
        .reference_index
        .insert(key_for_reference_index(index_atom).as_bytes(), b"")?;
    Ok(())
}

#[instrument(skip(store))]
fn delete_atom_from_reference_index(index_atom: &IndexAtom, store: &Db) -> AtomicResult<()> {
    store
        .reference_index
        .remove(&key_for_reference_index(index_atom).as_bytes())?;
    Ok(())
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
