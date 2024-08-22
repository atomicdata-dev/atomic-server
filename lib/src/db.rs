//! Persistent, ACID compliant, threadsafe to-disk store.
//! Powered by Sled - an embedded database.
//! See [Db]

mod migrations;
mod prop_val_sub_index;
mod query_index;
#[cfg(test)]
pub mod test;
mod trees;
mod val_prop_sub_index;

use std::{
    collections::{HashMap, HashSet},
    fs,
    sync::Arc,
    vec,
};

use mail_send::{Connected, Transport};
use tracing::info;
use tracing::instrument;
use trees::{Method, Operation, Transaction, Tree};

use crate::{
    agents::ForAgent,
    atomic_url::{AtomicUrl, Routes},
    atoms::IndexAtom,
    commit::{CommitOpts, CommitResponse},
    db::{query_index::requires_query_index, val_prop_sub_index::find_in_val_prop_sub_index},
    email::{self, MailMessage},
    endpoints::{build_default_endpoints, Endpoint, HandleGetContext},
    errors::{AtomicError, AtomicResult},
    plugins,
    query::QueryResult,
    resources::PropVals,
    storelike::Storelike,
    urls,
    values::SortableValue,
    Atom, Commit, Query, Resource, Value,
};

use self::{
    migrations::migrate_maybe,
    prop_val_sub_index::{add_atom_to_prop_val_sub_index, find_in_prop_val_sub_index},
    query_index::{
        check_if_atom_matches_watched_query_filters, query_sorted_indexed, should_include_resource,
        update_indexed_member, IndexIterator, QueryFilter, NO_VALUE,
    },
    val_prop_sub_index::add_atom_to_valpropsub_index,
};

// A function called by the Store when a Commit is accepted
type HandleCommit = Box<dyn Fn(&CommitResponse) + Send + Sync>;

/// Inside the reference_index, each value is mapped to this type.
/// The String on the left represents a Property URL, and the second one is the set of subjects.
pub type PropSubjectMap = HashMap<String, HashSet<String>>;

/// A persistent on-disk Atomic Data store.
/// It's an implementation of [Storelike].
/// It uses [sled::Tree]s as Key Value stores.
/// It stores [Resource]s as [PropVals]s by their subject as key.
/// It builds a value index for performant [Query]s.
/// It keeps track of Queries and updates their index when [crate::Commit]s are applied.
/// `Db` should be easily, cheaply clone-able, as users of this library could have one `Db` per connection.
/// Note that [plugins](crate::plugins) can add their own endpoints to the [Db],
/// and can use [tokio::spawn] to start concurrent tasks.
#[derive(Clone)]
pub struct Db {
    /// The Key-Value store that contains all data.
    /// Resources can be found using their Subject.
    /// Try not to use this directly, but use the Trees.
    db: sled::Db,
    default_agent: Arc<std::sync::Mutex<Option<crate::agents::Agent>>>,
    /// Stores all resources. The Key is the Subject as a `string.as_bytes()`, the value a [PropVals]. Propvals must be serialized using [bincode].
    resources: sled::Tree,
    /// [Tree::ValPropSub]
    reference_index: sled::Tree,
    /// [Tree::PropValSub]
    prop_val_sub_index: sled::Tree,
    /// [Tree::QueryMembers]
    query_index: sled::Tree,
    /// [Tree::WatchedQueries]
    watched_queries: sled::Tree,
    /// The address where the db will be hosted, e.g. http://localhost/
    server_url: AtomicUrl,
    /// Endpoints are checked whenever a resource is requested. They calculate (some properties of) the resource and return it.
    endpoints: Vec<Endpoint>,
    /// Where the DB is stored on disk.
    path: std::path::PathBuf,
    /// Function called whenever a Commit is applied.
    handle_commit: Option<Arc<HandleCommit>>,
    /// Email SMTP client for sending email.
    smtp_client: Option<Arc<tokio::sync::Mutex<Transport<'static, Connected>>>>,
}

impl Db {
    /// Creates a new store at the specified path, or opens the store if it already exists.
    /// The server_url is the domain where the db will be hosted, e.g. http://localhost/
    /// It is used for distinguishing locally defined items from externally defined ones.
    pub fn init(path: &std::path::Path, server_url: &str) -> AtomicResult<Db> {
        tracing::info!("Opening database at {:?}", path);

        let db = sled::open(path).map_err(|e|format!("Failed opening DB at this location: {:?} . Is another instance of Atomic Server running? {}", path, e))?;
        let resources = db.open_tree(Tree::Resources).map_err(|e| format!("Failed building resources. Your DB might be corrupt. Go back to a previous version and export your data. {}", e))?;
        let reference_index = db.open_tree(Tree::ValPropSub)?;
        let query_index = db.open_tree(Tree::QueryMembers)?;
        let prop_val_sub_index = db.open_tree(Tree::PropValSub)?;
        let watched_queries = db.open_tree(Tree::WatchedQueries)?;
        let store = Db {
            path: path.into(),
            db,
            default_agent: Arc::new(std::sync::Mutex::new(None)),
            resources,
            reference_index,
            query_index,
            prop_val_sub_index,
            server_url: AtomicUrl::try_from(server_url)?,
            watched_queries,
            endpoints: Vec::new(),
            handle_commit: None,
            smtp_client: None,
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
        let store = Db::init(std::path::Path::new(&tmp_dir_path), "https://localhost")?;
        let agent = store.create_agent(None)?;
        store.set_default_agent(agent);
        store.populate()?;
        Ok(store)
    }

    #[instrument(skip(self))]
    fn add_atom_to_index(
        &self,
        atom: &Atom,
        resource: &Resource,
        transaction: &mut Transaction,
    ) -> AtomicResult<()> {
        for index_atom in atom.to_indexable_atoms() {
            add_atom_to_valpropsub_index(&index_atom, transaction)?;
            add_atom_to_prop_val_sub_index(&index_atom, transaction)?;
            // Also update the query index to keep collections performant
            check_if_atom_matches_watched_query_filters(
                self,
                &index_atom,
                atom,
                false,
                resource,
                transaction,
            )
            .map_err(|e| format!("Failed to check_if_atom_matches_watched_collections. {}", e))?;
        }
        Ok(())
    }

    fn add_resource_tx(
        &self,
        resource: &Resource,
        transaction: &mut Transaction,
    ) -> AtomicResult<()> {
        let subject = resource.get_subject();
        let propvals = resource.get_propvals();
        let resource_bin = bincode::serialize(propvals)?;
        transaction.push(Operation {
            tree: Tree::Resources,
            method: Method::Insert,
            key: subject.as_bytes().to_vec(),
            val: Some(resource_bin),
        });
        Ok(())
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

    /// Constructs the value index from all resources in the store. Could take a while.
    pub fn build_index(&self, include_external: bool) -> AtomicResult<()> {
        tracing::info!("Building index (this could take a few minutes for larger databases)");
        for r in self.all_resources(include_external) {
            let mut transaction = Transaction::new();
            for atom in r.to_atoms() {
                self.add_atom_to_index(&atom, &r, &mut transaction)
                    .map_err(|e| format!("Failed to add atom to index {}. {}", atom, e))?;
            }
            self.apply_transaction(&mut transaction)
                .map_err(|e| format!("Failed to commit transaction. {}", e))?;
        }
        tracing::info!("Building index finished!");
        Ok(())
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
        self.handle_commit = Some(Arc::new(on_commit));
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
                "Resource {} does not exist",
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

    /// Removes the DB and all content from disk.
    /// WARNING: This is irreversible.
    pub fn clear_all_danger(self) -> AtomicResult<()> {
        self.clear_index()?;
        let path = self.path.clone();
        drop(self);
        fs::remove_dir_all(path)?;
        Ok(())
    }

    fn map_sled_item_to_resource(
        item: Result<(sled::IVec, sled::IVec), sled::Error>,
        self_url: String,
        include_external: bool,
    ) -> Option<Resource> {
        let (subject, resource_bin) = item.expect(DB_CORRUPT_MSG);
        let subject: String = String::from_utf8_lossy(&subject).to_string();

        // if !include_external && self.is_external_subject(&subject).ok()? {
        //     return None;
        // }
        if !include_external && !subject.starts_with(&self_url) {
            return None;
        }

        let propvals: PropVals = bincode::deserialize(&resource_bin)
            .unwrap_or_else(|e| panic!("{}. {}", corrupt_db_message(&subject), e));

        Some(Resource::from_propvals(propvals, subject))
    }

    pub fn register_default_endpoints(&mut self) -> AtomicResult<()> {
        // First we delete all existing endpoint resources, as they might not be there in this new run
        let found_endpoints = self.query(&Query::new_class(urls::ENDPOINT))?.resources;

        for mut found in found_endpoints {
            found.destroy(self)?;
        }

        let mut endpoints = build_default_endpoints();

        if self.smtp_client.is_some() {
            tracing::info!("SMTP client is set, adding register endpoints");
            endpoints.push(plugins::register::register_endpoint());
            endpoints.push(plugins::register::confirm_email_endpoint());
        }

        for endpoint in endpoints {
            self.register_endpoint(endpoint)?;
        }

        Ok(())
    }

    fn build_index_for_atom(
        &self,
        atom: &IndexAtom,
        query_filter: &QueryFilter,
        transaction: &mut Transaction,
    ) -> AtomicResult<()> {
        // Get the SortableValue either from the Atom or the Resource.
        let sort_val: SortableValue = if let Some(sort) = &query_filter.sort_by {
            if &atom.property == sort {
                atom.sort_value.clone()
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
            atom.sort_value.clone()
        };

        update_indexed_member(query_filter, &atom.subject, &sort_val, false, transaction)?;
        Ok(())
    }

    fn get_index_iterator_for_query(&self, q: &Query) -> IndexIterator {
        match (&q.property, q.value.as_ref()) {
            (Some(prop), val) => find_in_prop_val_sub_index(self, prop, val),
            (None, None) => self.all_index_atoms(q.include_external),
            (None, Some(val)) => find_in_val_prop_sub_index(self, val, None),
        }
    }

    /// Apply made changes to the store.
    #[instrument(skip(self))]
    fn apply_transaction(&self, transaction: &mut Transaction) -> AtomicResult<()> {
        let mut batch_resources = sled::Batch::default();
        let mut batch_propvalsub = sled::Batch::default();
        let mut batch_valpropsub = sled::Batch::default();
        let mut batch_watched_queries = sled::Batch::default();
        let mut batch_query_members = sled::Batch::default();

        for op in transaction.iter() {
            match op.tree {
                trees::Tree::Resources => match op.method {
                    trees::Method::Insert => {
                        batch_resources.insert::<&[u8], &[u8]>(&op.key, op.val.as_ref().unwrap());
                    }
                    trees::Method::Delete => {
                        batch_resources.remove(op.key.clone());
                    }
                },
                trees::Tree::PropValSub => match op.method {
                    trees::Method::Insert => {
                        batch_propvalsub.insert::<&[u8], &[u8]>(&op.key, op.val.as_ref().unwrap());
                    }
                    trees::Method::Delete => {
                        batch_propvalsub.remove(op.key.clone());
                    }
                },
                trees::Tree::ValPropSub => match op.method {
                    trees::Method::Insert => {
                        batch_valpropsub.insert::<&[u8], &[u8]>(&op.key, op.val.as_ref().unwrap());
                    }
                    trees::Method::Delete => {
                        batch_valpropsub.remove(op.key.clone());
                    }
                },
                trees::Tree::WatchedQueries => match op.method {
                    trees::Method::Insert => {
                        batch_watched_queries
                            .insert::<&[u8], &[u8]>(&op.key, op.val.as_ref().unwrap());
                    }
                    trees::Method::Delete => {
                        batch_watched_queries.remove(op.key.clone());
                    }
                },
                trees::Tree::QueryMembers => match op.method {
                    trees::Method::Insert => {
                        batch_query_members
                            .insert::<&[u8], &[u8]>(&op.key, op.val.as_ref().unwrap());
                    }
                    trees::Method::Delete => {
                        batch_query_members.remove(op.key.clone());
                    }
                },
            }
        }

        self.resources.apply_batch(batch_resources)?;
        self.prop_val_sub_index.apply_batch(batch_propvalsub)?;
        self.reference_index.apply_batch(batch_valpropsub)?;
        self.watched_queries.apply_batch(batch_watched_queries)?;
        self.query_index.apply_batch(batch_query_members)?;

        Ok(())
    }

    fn query_basic(&self, q: &Query) -> AtomicResult<QueryResult> {
        let mut subjects: Vec<String> = vec![];
        let mut resources: Vec<Resource> = vec![];
        let mut total_count = 0;

        let atoms = self.get_index_iterator_for_query(q);

        for (i, atom_res) in atoms.enumerate() {
            total_count += 1;

            if q.offset > i {
                continue;
            }

            let atom = atom_res?;

            if !q.include_external && self.is_external_subject(&atom.subject)? {
                continue;
            }

            if q.limit.is_none() || subjects.len() < q.limit.unwrap() {
                if !should_include_resource(q) {
                    subjects.push(atom.subject.clone());
                    continue;
                }

                if let Ok(resource) = self.get_resource_extended(&atom.subject, true, &q.for_agent)
                {
                    subjects.push(atom.subject.clone());
                    resources.push(resource);
                }
            }
        }

        Ok(QueryResult {
            subjects,
            resources,
            count: total_count,
        })
    }

    fn query_complex(&self, q: &Query) -> AtomicResult<QueryResult> {
        let (mut subjects, mut resources, mut total_count) = query_sorted_indexed(self, q)?;
        let q_filter: QueryFilter = q.into();

        if total_count == 0 && !q_filter.is_watched(self) {
            info!(filter = ?q_filter, "Building query index");
            let atoms = self.get_index_iterator_for_query(q);
            q_filter.watch(self)?;

            let mut transaction = Transaction::new();
            // Build indexes
            for atom in atoms.flatten() {
                self.build_index_for_atom(&atom, &q_filter, &mut transaction)?;
            }
            self.apply_transaction(&mut transaction)?;

            // Query through the new indexes.
            (subjects, resources, total_count) = query_sorted_indexed(self, q)?;
        }

        Ok(QueryResult {
            subjects,
            resources,
            count: total_count,
        })
    }

    #[instrument(skip(self))]
    fn remove_atom_from_index(
        &self,
        atom: &Atom,
        resource: &Resource,
        transaction: &mut Transaction,
    ) -> AtomicResult<()> {
        for index_atom in atom.to_indexable_atoms() {
            transaction.push(Operation::remove_atom_from_reference_index(&index_atom));
            transaction.push(Operation::remove_atom_from_prop_val_sub_index(&index_atom));

            check_if_atom_matches_watched_query_filters(
                self,
                &index_atom,
                atom,
                true,
                resource,
                transaction,
            )
            .map_err(|e| format!("Checking atom went wrong: {}", e))?;
        }
        Ok(())
    }

    /// Adds an [Endpoint] to the store. This means adding a route with custom behavior.
    pub fn register_endpoint(&mut self, endpoint: Endpoint) -> AtomicResult<()> {
        let mut resource = endpoint.to_resource(self)?;
        let endpoints_collection = self.get_server_url().set_route(Routes::Endpoints);
        resource.set(
            urls::PARENT.into(),
            Value::AtomicUrl(endpoints_collection.to_string()),
            self,
        )?;
        resource.save_locally(self)?;
        self.endpoints.push(endpoint);
        Ok(())
    }

    /// Registers an SMTP client to the store, allowing the store to send emails.
    pub async fn set_smtp_config(
        &mut self,
        smtp_config: crate::email::SmtpConfig,
    ) -> AtomicResult<()> {
        self.smtp_client = Some(Arc::new(tokio::sync::Mutex::new(
            crate::email::get_smtp_client(smtp_config).await?,
        )));
        Ok(())
    }

    pub async fn send_email(&self, message: MailMessage) -> AtomicResult<()> {
        let mut client = self
            .smtp_client
            .as_ref()
            .ok_or_else(|| {
                AtomicError::other_error(
                    "No SMTP client configured. Please call set_smtp_config first.".into(),
                )
            })?
            .lock()
            .await;
        email::send_mail(&mut client, message).await?;
        Ok(())
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        match self.db.flush() {
            Ok(..) => (),
            Err(e) => eprintln!("Failed to flush the database: {}", e),
        };
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
                        .set_string(atom.property.clone(), &atom.value.to_string(), self)
                        .map_err(|e| format!("Failed adding attom {}. {}", atom, e))?;
                }
                // Resource does not exist
                None => {
                    let mut resource = Resource::new(atom.subject.clone());
                    resource
                        .set_string(atom.property.clone(), &atom.value.to_string(), self)
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
            let mut transaction = Transaction::new();
            if let Some(pv) = existing {
                let subject = resource.get_subject();
                for (prop, val) in pv.iter() {
                    // Possible performance hit - these clones can be replaced by modifying remove_atom_from_index
                    let remove_atom = crate::Atom::new(subject.into(), prop.into(), val.clone());
                    self.remove_atom_from_index(&remove_atom, resource, &mut transaction)
                        .map_err(|e| {
                            format!("Failed to remove atom from index {}. {}", remove_atom, e)
                        })?;
                }
            }
            for a in resource.to_atoms() {
                self.add_atom_to_index(&a, resource, &mut transaction)
                    .map_err(|e| format!("Failed to add atom to index {}. {}", a, e))?;
            }
            self.apply_transaction(&mut transaction)?;
        }
        self.set_propvals(resource.get_subject(), resource.get_propvals())
    }

    /// Apply a single signed Commit to the Db.
    /// Creates, edits or destroys a resource.
    /// Allows for control over which validations should be performed.
    /// Returns the generated Commit, the old Resource and the new Resource.
    #[tracing::instrument(skip(self))]
    fn apply_commit(&self, commit: Commit, opts: &CommitOpts) -> AtomicResult<CommitResponse> {
        let store = self;

        let commit_response = commit.validate_and_build_response(opts, store)?;

        let mut transaction = Transaction::new();

        // BEFORE APPLY COMMIT HANDLERS
        // TODO: Move to something dynamic
        if let Some(resource_new) = &commit_response.resource_new {
            let _resource_new_classes = resource_new.get_classes(store)?;
            #[cfg(feature = "db")]
            for class in &_resource_new_classes {
                match class.subject.as_str() {
                    urls::COMMIT => {
                        return Err("Commits can not be edited or created directly.".into())
                    }
                    urls::INVITE => crate::plugins::invite::before_apply_commit(
                        store,
                        &commit_response.commit,
                        resource_new,
                    )?,
                    _other => {}
                };
            }
        }

        // Save the Commit to the Store. We can skip the required props checking, but we need to make sure the commit hasn't been applied before.
        store.add_resource_tx(&commit_response.commit_resource, &mut transaction)?;
        // We still need to index the Commit!
        for atom in commit_response.commit_resource.to_atoms() {
            store.add_atom_to_index(&atom, &commit_response.commit_resource, &mut transaction)?;
        }

        match (&commit_response.resource_old, &commit_response.resource_new) {
            (None, None) => {
                return Err("Neither an old nor a new resource is returned from the commit - something went wrong.".into())
            },
            (Some(_old), None) => {
                assert_eq!(_old.get_subject(), &commit_response.commit.subject);
                assert!(&commit_response.commit.destroy.expect("Resource was removed but `commit.destroy` was not set!"));
                self.remove_resource(&commit_response.commit.subject)?;
            },
            _ => {}
        };

        if let Some(new) = &commit_response.resource_new {
            self.add_resource_tx(new, &mut transaction)?;
        }

        if opts.update_index {
            if let Some(old) = &commit_response.resource_old {
                for atom in &commit_response.remove_atoms {
                    store
                        .remove_atom_from_index(atom, old, &mut transaction)
                        .map_err(|e| format!("Error removing atom from index: {e}  Atom: {e}"))?
                }
            }
            if let Some(new) = &commit_response.resource_new {
                for atom in &commit_response.add_atoms {
                    store
                        .add_atom_to_index(atom, new, &mut transaction)
                        .map_err(|e| format!("Error adding atom to index: {e}  Atom: {e}"))?
                }
            }
        }

        store.apply_transaction(&mut transaction)?;

        store.handle_commit(&commit_response);

        // AFTER APPLY COMMIT HANDLERS
        // Commit has been checked and saved.
        // Here you can add side-effects, such as creating new Commits.
        #[cfg(feature = "db")]
        if let Some(resource_new) = &commit_response.resource_new {
            let _resource_new_classes = resource_new.get_classes(store)?;
            #[cfg(feature = "db")]
            for class in &_resource_new_classes {
                match class.subject.as_str() {
                    urls::MESSAGE => crate::plugins::chatroom::after_apply_commit_message(
                        store,
                        &commit_response.commit,
                        resource_new,
                    )?,
                    _other => {}
                };
            }
        }
        Ok(commit_response)
    }

    fn get_server_url(&self) -> &AtomicUrl {
        &self.server_url
    }

    fn get_self_url(&self) -> Option<&AtomicUrl> {
        // Since the DB is often also the server, this should make sense.
        // Some edge cases might appear later on (e.g. a slave DB that only stores copies?)
        Some(self.get_server_url())
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
        for_agent: &ForAgent,
    ) -> AtomicResult<Resource> {
        let url_span = tracing::span!(tracing::Level::TRACE, "URL parse").entered();
        // This might add a trailing slash
        let url = url::Url::parse(subject)?;

        let removed_query_params = {
            let mut url_altered = url.clone();
            url_altered.set_query(None);
            url_altered.to_string()
        };

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

        let dynamic_span =
            tracing::span!(tracing::Level::TRACE, "get_resource_extended (dynamic)").entered();
        let mut resource = self.get_resource(&removed_query_params)?;

        let _explanation = crate::hierarchy::check_read(self, &resource, for_agent)?;

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
            resource.set(
                crate::urls::INCOMPLETE.into(),
                crate::Value::Boolean(true),
                self,
            )?;
        }
        Ok(resource)
    }

    fn handle_commit(&self, commit_response: &CommitResponse) {
        if let Some(fun) = &self.handle_commit {
            fun(commit_response);
        }
    }

    /// Search the Store, returns the matching subjects.
    /// The second returned vector should be filled if query.include_resources is true.
    /// Tries `query_cache`, which you should implement yourself.
    #[instrument(skip(self))]
    fn query(&self, q: &Query) -> AtomicResult<QueryResult> {
        if requires_query_index(q) {
            return self.query_complex(q);
        }

        self.query_basic(q)
    }

    #[instrument(skip(self))]
    fn all_resources(
        &self,
        include_external: bool,
    ) -> Box<dyn std::iter::Iterator<Item = Resource>> {
        let self_url = self
            .get_self_url()
            .expect("No self URL set, is required in DB")
            .to_string();

        let result = self.resources.into_iter().filter_map(move |item| {
            Db::map_sled_item_to_resource(item, self_url.clone(), include_external)
        });

        Box::new(result)
    }

    fn post_resource(
        &self,
        subject: &str,
        body: Vec<u8>,
        for_agent: &ForAgent,
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
        let mut transaction = Transaction::new();
        if let Ok(found) = self.get_propvals(subject) {
            let resource = Resource::from_propvals(found, subject.to_string());
            for (prop, val) in resource.get_propvals() {
                let remove_atom = crate::Atom::new(subject.into(), prop.clone(), val.clone());
                self.remove_atom_from_index(&remove_atom, &resource, &mut transaction)?;
            }
            let _found = self.resources.remove(subject.as_bytes())?;
        } else {
            return Err(format!(
                "Resource {} could not be deleted, because it was not found in the store.",
                subject
            )
            .into());
        }
        self.apply_transaction(&mut transaction)?;
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
