//! Persistent, ACID compliant, threadsafe to-disk store.
//! Powered by Sled - an embedded database.

mod migrations;
mod prop_val_sub_index;
mod query_index;
#[cfg(test)]
pub mod test;
mod val_prop_sub_index;

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use tracing::{info, instrument};

use crate::{
    atoms::IndexAtom,
    commit::CommitResponse,
    db::{query_index::NO_VALUE, val_prop_sub_index::find_in_val_prop_sub_index},
    endpoints::{default_endpoints, Endpoint, HandleGetContext},
    errors::{AtomicError, AtomicResult},
    resources::PropVals,
    storelike::{Query, QueryResult, Storelike},
    values::SortableValue,
    Atom, Resource,
};

use self::{
    migrations::migrate_maybe,
    prop_val_sub_index::{
        add_atom_to_prop_val_sub_index, find_in_prop_val_sub_index,
        remove_atom_from_prop_val_sub_index,
    },
    query_index::{
        check_if_atom_matches_watched_query_filters, query_indexed, update_indexed_member,
        IndexIterator, QueryFilter,
    },
    val_prop_sub_index::{add_atom_to_reference_index, remove_atom_from_reference_index},
};

// A function called by the Store when a Commit is accepted
type HandleCommit = Box<dyn Fn(&CommitResponse) + Send + Sync>;

/// Inside the reference_index, each value is mapped to this type.
/// The String on the left represents a Property URL, and the second one is the set of subjects.
pub type PropSubjectMap = HashMap<String, HashSet<String>>;

/// The Db is a persistent on-disk Atomic Data store.
/// It's an implementation of [Storelike].
/// It uses [sled::Tree]s as Key Value stores.
/// It stores [Resource]s as [PropVals]s by their subject as key.
/// It builds a value index for performant [Query]s.
/// It keeps track of Queries and updates their index when [crate::Commit]s are applied.
/// You can pass a custom `on_commit` function to run at Commit time.
/// `Db` should be easily, cheaply clone-able, as users of this library could have one `Db` per connection.
#[derive(Clone)]
pub struct Db {
    /// The Key-Value store that contains all data.
    /// Resources can be found using their Subject.
    /// Try not to use this directly, but use the Trees.
    db: sled::Db,
    default_agent: Arc<Mutex<Option<crate::agents::Agent>>>,
    /// Stores all resources. The Key is the Subject as a `string.as_bytes()`, the value a [PropVals]. Propvals must be serialized using [bincode].
    resources: sled::Tree,
    /// Index of all Atoms, sorted by {Value}-{Property}-{Subject}.
    /// See [reference_index]
    reference_index: sled::Tree,
    /// Index sorted by property + value.
    /// Used for queries where the property is known.
    prop_val_sub_index: sled::Tree,
    /// Stores the members of Collections, easily sortable.
    query_index: sled::Tree,
    /// A list of all the Collections currently being used. Is used to update `query_index`.
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
        let reference_index = db.open_tree("reference_index_v1")?;
        let query_index = db.open_tree("members_index")?;
        let prop_val_sub_index = db.open_tree("prop_val_sub_index")?;
        let watched_queries = db.open_tree("watched_queries")?;
        let store = Db {
            db,
            default_agent: Arc::new(Mutex::new(None)),
            resources,
            reference_index,
            query_index,
            prop_val_sub_index,
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

    #[instrument(skip(self))]
    fn all_index_atoms(&self, include_external: bool) -> IndexIterator {
        Box::new(
            self.all_resources(include_external)
                .flat_map(|resource| {
                    let index_atoms: Vec<IndexAtom> = resource
                        .to_atoms()
                        .iter()
                        .flat_map(|atom| atom.to_indexable_atoms())
                        .collect();
                    index_atoms
                })
                .map(Ok),
        )
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

    /// Removes all values from the indexes.
    pub fn clear_index(&self) -> AtomicResult<()> {
        self.reference_index.clear()?;
        self.prop_val_sub_index.clear()?;
        self.query_index.clear()?;
        self.watched_queries.clear()?;
        Ok(())
    }

    fn map_sled_item_to_resource(
        item: Result<(sled::IVec, sled::IVec), sled::Error>,
        self_url: String,
        include_external: bool,
    ) -> Option<Resource> {
        let (subject, resource_bin) = item.expect(DB_CORRUPT_MSG);
        let subject: String = String::from_utf8_lossy(&subject).to_string();

        if !include_external && !subject.starts_with(&self_url) {
            return None;
        }

        let propvals: PropVals = bincode::deserialize(&resource_bin)
            .unwrap_or_else(|e| panic!("{}. {}", corrupt_db_message(&subject), e));

        Some(Resource::from_propvals(propvals, subject))
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
        for index_atom in atom.to_indexable_atoms() {
            add_atom_to_reference_index(&index_atom, self)?;
            add_atom_to_prop_val_sub_index(&index_atom, self)?;
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
            for a in resource.to_atoms() {
                self.add_atom_to_index(&a, resource)
                    .map_err(|e| format!("Failed to add atom to index {}. {}", a, e))?;
            }
        }
        self.set_propvals(resource.get_subject(), resource.get_propvals())
    }

    #[instrument(skip(self))]
    fn remove_atom_from_index(&self, atom: &Atom, resource: &Resource) -> AtomicResult<()> {
        for index_atom in atom.to_indexable_atoms() {
            remove_atom_from_reference_index(&index_atom, self)?;
            remove_atom_from_prop_val_sub_index(&index_atom, self)?;

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
            if url.path() == endpoint.path {
                // Not all Endpoints have a handle function.
                // If there is none, return the endpoint plainly.
                let mut resource = if let Some(handle) = endpoint.handle {
                    // Call the handle function for the endpoint, if it exists.
                    let context: HandleGetContext = HandleGetContext {
                        subject: url,
                        store: self,
                        for_agent,
                    };
                    (handle)(context).map_err(|e| {
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
        let q_filter: QueryFilter = q.into();
        if let Ok(res) = query_indexed(self, q) {
            if res.count > 0 || q_filter.is_watched(self) {
                // Yay, we have a cache hit!
                // We don't have to create the indexes, so we can return early.
                return Ok(res);
            }
        }

        // Maybe make this optional?
        q_filter.watch(self)?;

        info!(filter = ?q_filter, "Building query index");

        let atoms: IndexIterator = match (&q.property, q.value.as_ref()) {
            (Some(prop), val) => find_in_prop_val_sub_index(self, prop, val),
            (None, None) => self.all_index_atoms(q.include_external),
            (None, Some(val)) => find_in_val_prop_sub_index(self, val, None),
        };

        for a in atoms {
            let atom = a?;
            // Get the SortableValue either from the Atom or the Resource.
            let sort_val: SortableValue = if let Some(sort) = &q_filter.sort_by {
                if &atom.property == sort {
                    atom.sort_value
                } else {
                    // Find the sort value in the store
                    match self.get_value(&atom.subject, sort) {
                        Ok(val) => val.to_sortable_string(),
                        // If we try sorting on a value that does not exist,
                        // we'll use an empty string as the sortable value.
                        Err(_) => NO_VALUE.to_string(),
                    }
                }
            } else {
                atom.sort_value
            };

            update_indexed_member(self, &q_filter, &atom.subject, &sort_val, false)?;
        }

        // Retry the same query!
        query_indexed(self, q)
    }

    #[instrument(skip(self))]
    fn all_resources(
        &self,
        include_external: bool,
    ) -> Box<dyn std::iter::Iterator<Item = Resource>> {
        let self_url = self
            .get_self_url()
            .expect("No self URL set, is required in DB");

        let result = self.resources.into_iter().filter_map(move |item| {
            Db::map_sled_item_to_resource(item, self_url.clone(), include_external)
        });

        Box::new(result)
    }

    fn post_resource(
        &self,
        subject: &str,
        body: Vec<u8>,
        for_agent: Option<&str>,
    ) -> AtomicResult<Resource> {
        let endpoints = self.endpoints.iter().filter(|e| e.handle_post.is_some());
        let subj_url = url::Url::try_from(subject)?;
        for e in endpoints {
            if let Some(fun) = &e.handle_post {
                if subj_url.path() == e.path {
                    let handle_post_context = crate::endpoints::HandlePostContext {
                        store: self,
                        body,
                        for_agent,
                        subject: subj_url,
                    };
                    let mut resource = fun(handle_post_context)?;
                    resource.set_subject(subject.into());
                    return Ok(resource);
                }
            }
        }
        // If we get Class Handlers with POST, this is where the code goes
        // let mut r = self.get_resource(subject)?;
        // for class in r.get_classes(self)? {
        //     match class.subject.as_str() {
        //         urls::IMPORTER => {
        //             let query_params = url::Url::try_from(subject)?;
        //             return crate::plugins::importer::construct_importer(
        //                 self,
        //                 query_params.query_pairs(),
        //                 &mut r,
        //                 for_agent,
        //                 Some(body),
        //             );
        //         }
        //         _ => {}
        //     }
        // }
        Err(
            AtomicError::method_not_allowed("Cannot post here - no Endpoint Post handler found")
                .set_subject(subject),
        )
    }

    fn populate(&self) -> AtomicResult<()> {
        crate::populate::populate_all(self)
    }

    #[instrument(skip(self))]
    fn remove_resource(&self, subject: &str) -> AtomicResult<()> {
        if let Ok(found) = self.get_propvals(subject) {
            let resource = Resource::from_propvals(found, subject.to_string());
            for (prop, val) in resource.get_propvals() {
                let remove_atom = crate::Atom::new(subject.into(), prop.clone(), val.clone());
                self.remove_atom_from_index(&remove_atom, &resource)?;
            }
            let _found = self.resources.remove(subject.as_bytes())?;
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
}

fn corrupt_db_message(subject: &str) -> String {
    format!("Could not deserialize item {} from database. DB is possibly corrupt, could be due to an update or a lack of migrations. Restore to a previous version, export your data and import your data again.", subject)
}

const DB_CORRUPT_MSG: &str = "Could not deserialize item from database. DB is possibly corrupt, could be due to an update or a lack of migrations. Restore to a previous version, export your data and import your data again.";

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("server_url", &self.server_url)
            .finish()
    }
}
