//! The Storelike Trait contains many useful methods for maniupulting / retrieving data.

use crate::{
    agents::{Agent, ForAgent},
    commit::CommitResponse,
    errors::AtomicError,
    hierarchy,
    schema::{Class, Property},
    urls,
    values::SubResource,
};
use crate::{errors::AtomicResult, parse::parse_json_ad_string};
use crate::{mapping::Mapping, values::Value, Atom, Resource, Subject};
use async_trait::async_trait;
use futures::future;

// A path can return one of many things
pub enum PathReturn {
    Subject(String),
    Atom(Box<Atom>),
}

pub enum ResourceResponse {
    Resource(Resource),
    ResourceWithReferenced(Resource, Vec<Resource>),
    /// A redirect to another subject. Used for resolving DIDs to their
    /// location-specific HTTP aliases (e.g. `did:ad:blob:` to `/download/files/`).
    Redirect(String),
}

impl ResourceResponse {
    /// Only take the main resource, discard any referenced resources.
    /// Panics if this is a Redirect.
    pub fn to_single(&self) -> Resource {
        match self {
            ResourceResponse::Resource(resource) => resource.clone(),
            ResourceResponse::ResourceWithReferenced(resource, _) => resource.clone(),
            ResourceResponse::Redirect(s) => {
                panic!("Cannot convert Redirect ({}) to Resource", s)
            }
        }
    }

    /// Re-label the main resource, so a response served from one stored
    /// subject can answer under the subject the client actually asked for.
    /// No-op for Redirects.
    pub fn set_subject(&mut self, subject: Subject) {
        match self {
            ResourceResponse::Resource(resource) => {
                resource.set_subject(subject.to_string());
            }
            ResourceResponse::ResourceWithReferenced(resource, _) => {
                resource.set_subject(subject.to_string());
            }
            ResourceResponse::Redirect(_) => {}
        }
    }

    /// Get the subject of the main resource.
    /// Returns None for Redirects.
    pub fn get_subject(&self) -> Option<&Subject> {
        match self {
            ResourceResponse::Resource(resource) => Some(resource.get_subject()),
            ResourceResponse::ResourceWithReferenced(resource, _) => Some(resource.get_subject()),
            ResourceResponse::Redirect(_) => None,
        }
    }

    pub fn to_json_ad(&self, origin: Option<&str>) -> AtomicResult<String> {
        match self {
            ResourceResponse::Resource(resource) => Ok(resource.to_json_ad(origin)?),
            ResourceResponse::ResourceWithReferenced(resource, references) => {
                let mut list = references.clone();
                list.push(resource.clone());
                Ok(Resource::vec_to_json_ad(&list, origin)?)
            }
            ResourceResponse::Redirect(s) => {
                Err(format!("Cannot convert Redirect ({}) to JSON-AD", s).into())
            }
        }
    }

    pub async fn to_json(
        &self,
        store: &impl Storelike,
        origin: Option<&str>,
    ) -> AtomicResult<String> {
        match self {
            ResourceResponse::Resource(resource) => Ok(resource.to_json(store, origin).await?),
            ResourceResponse::ResourceWithReferenced(resource, references) => {
                let mut list = references.clone();
                list.push(resource.clone());
                Ok(Resource::vec_to_json(&list, store, origin).await?)
            }
            ResourceResponse::Redirect(s) => {
                Err(format!("Cannot convert Redirect ({}) to JSON", s).into())
            }
        }
    }

    pub async fn to_json_ld(
        &self,
        store: &impl Storelike,
        origin: Option<&str>,
    ) -> AtomicResult<String> {
        match self {
            ResourceResponse::Resource(resource) => Ok(resource.to_json_ld(store, origin).await?),
            ResourceResponse::ResourceWithReferenced(resource, references) => {
                let mut list = references.clone();
                list.push(resource.clone());
                Ok(Resource::vec_to_json_ld(&list, store, origin).await?)
            }
            ResourceResponse::Redirect(s) => {
                Err(format!("Cannot convert Redirect ({}) to JSON-LD", s).into())
            }
        }
    }

    pub fn to_atoms(&self) -> Vec<Atom> {
        match self {
            ResourceResponse::Resource(resource) => resource.to_atoms(),
            ResourceResponse::ResourceWithReferenced(resource, references) => {
                let mut list = references.clone();
                list.push(resource.clone());
                Resource::vec_to_atoms(&list)
            }
            ResourceResponse::Redirect(_) => Vec::new(),
        }
    }

    #[cfg(feature = "rdf")]
    pub async fn to_n_triples(&self, store: &impl Storelike) -> AtomicResult<String> {
        match self {
            ResourceResponse::Resource(resource) => Ok(resource.to_n_triples(store).await?),
            ResourceResponse::ResourceWithReferenced(resource, references) => {
                let mut list = references.clone();
                list.push(resource.clone());
                Ok(Resource::vec_to_n_triples(&list, store).await?)
            }
            ResourceResponse::Redirect(s) => {
                Err(format!("Cannot convert Redirect ({}) to N-Triples", s).into())
            }
        }
    }

    /// Takes a vector of resources and returns a ResourceResponse::ResourceWithReferenced
    /// If the main subject is not found it will Error
    pub fn from_vec(main_subject: &str, vec: Vec<Resource>) -> AtomicResult<Self> {
        if vec.is_empty() {
            return Err("No resources found".into());
        }
        if vec.len() == 1 {
            return Ok(ResourceResponse::Resource(vec[0].clone()));
        }

        let mut resource: Option<Resource> = None;
        let mut referenced = Vec::new();

        for r in vec {
            if r.get_subject().as_str() == main_subject {
                resource = Some(r);
            } else {
                referenced.push(r);
            }
        }

        let Some(resource) = resource else {
            return Err(AtomicError::not_found(format!(
                "Resource with subject {} not found",
                main_subject
            )));
        };

        Ok(ResourceResponse::ResourceWithReferenced(
            resource, referenced,
        ))
    }
}

pub type ResourceCollection = Vec<Resource>;

/// Storelike provides many useful methods for interacting with an Atomic Store.
/// It serves as a basic store Trait, agnostic of how it functions under the hood.
/// This is useful, because we can create methods for Storelike that will work with either in-memory
/// stores, as well as with persistent on-disk stores.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Storelike: Sized + Send + Sync {
    /// Adds Atoms to the store.
    /// Will replace existing Atoms that share Subject / Property combination.
    /// Validates datatypes and required props presence.
    #[deprecated(
        since = "0.28.0",
        note = "The atoms abstraction has been deprecated in favor of Resources"
    )]
    async fn add_atoms(&self, atoms: Vec<Atom>) -> AtomicResult<()>;

    /// Maps a host (domain/subdomain) to a Drive DID.
    fn add_drive_mapping(&self, host: &str, drive_did: &Value) -> AtomicResult<()>;

    /// Removes the drive mapping for a given host.
    fn remove_drive_mapping(&self, host: &str) -> AtomicResult<()>;

    /// Returns the base domain of the store, e.g. "https://atomicdata.dev".
    fn get_base_domain(&self) -> Option<String> {
        None
    }

    /// Sets the base URL of the store.
    fn set_base_url(&self, _url: &str) {}

    /// Returns the full server URL, e.g. "http://localhost:9883" or "https://atomicdata.dev".
    /// Used by client helpers to route DID resolution requests through the server's \`/did\` endpoint.
    fn get_server_url(&self) -> String {
        self.get_base_domain()
            .unwrap_or_else(|| "http://localhost".to_string())
    }

    /// The sync admission/quota policy for this store. The default is the
    /// permissive [`crate::sync::policy::OpenPolicy`] (self-hosted / local-first,
    /// and every non-`Db` store). A managed node's `Db` returns the policy
    /// installed via `Db::set_sync_policy`, which the commit / sync paths consult
    /// to gate writes to un-enrolled drives.
    fn sync_policy(&self) -> std::sync::Arc<dyn crate::sync::policy::SyncPolicy> {
        std::sync::Arc::new(crate::sync::policy::OpenPolicy)
    }

    /// Get the active drive subject, if one is set.
    fn get_active_drive(&self) -> Option<String> {
        None
    }

    /// Clear a bulk-sync tombstone for `subject` — see
    /// [`crate::sync::tombstones::clear_tombstone`] (F11,
    /// planning/unified-sync.md): a subject that legitimately passes a
    /// rights-checked genesis again after being destroyed must not keep
    /// being invisible to future bulk sync. No-op default for stores with
    /// no tombstone concept (test doubles, non-`Db` stores); `Db` overrides
    /// this to call the real KV-backed implementation.
    fn clear_tombstone(&self, _subject: &str) {}

    /// Set the active drive subject.
    fn set_active_drive(&self, _drive: &str) -> AtomicResult<()> {
        Err("set_active_drive not implemented for this store".into())
    }

    /// Clear the default agent.
    fn clear_default_agent(&self) {}

    fn normalize_subject(&self, subject: &Subject) -> Subject {
        Subject::from_raw(subject.as_str(), self.get_base_domain().as_deref())
    }

    /// Adds a Resource to the store.
    /// Replaces existing resource with the contents.
    /// Updates the index.
    /// Validates the fields (checks required props).
    /// In most cases, you should use `resource.save()` instead, which uses Commits.
    async fn add_resource(&self, resource: &Resource) -> AtomicResult<()> {
        self.add_resource_opts(resource, true, true, true).await
    }

    /// Adds a Resource to the store.
    /// Replaces existing resource with the contents.
    /// Does not do any validations.
    async fn add_resource_opts(
        &self,
        resource: &Resource,
        check_required_props: bool,
        update_index: bool,
        overwrite_existing: bool,
    ) -> AtomicResult<()>;

    /// Returns an iterator that iterates over all resources in the store.
    /// If Include_external is false, this is filtered by selecting only resoureces that match the `self` URL of the store.
    fn all_resources(&self, include_external: bool) -> Box<dyn Iterator<Item = Resource> + Send>;

    /// Takes a Commit and applies it to the Store.
    /// This includes changing the resource, writing the changes, verifying the checks specified in your CommitOpts
    /// The returned CommitResponse contains the new resource and the saved Commit Resource.
    async fn apply_commit(
        &self,
        commit: crate::Commit,
        opts: &crate::commit::CommitOpts,
    ) -> AtomicResult<CommitResponse> {
        let applied = commit.validate_and_build_response(opts, self).await?;

        // Commits are signed envelopes, not a queryable class. Keep genesis
        // and rights/parent/destroy; drop ordinary content certificates.
        if applied.auth_impact().is_critical() {
            self.add_resource(&applied.commit_resource).await?;
        }

        match (&applied.resource_old, &applied.resource_new) {
            (None, None) => {
                if !applied.commit.destroy.unwrap_or(false) {
                    return Err(
                        "Neither an old nor a new resource is returned from the commit - something went wrong."
                            .into(),
                    );
                }
            }
            (None, Some(new)) => {
                self.add_resource(new).await?;
            }
            (Some(_old), Some(new)) => {
                self.add_resource(new).await?;
            }
            (Some(_old), None) => {
                assert_eq!(_old.get_subject().as_str(), applied.commit.subject);
                self.remove_resource(&applied.commit.subject.clone())
                    .await?;
            }
        }

        Ok(applied)
    }

    /// Returns a single [Value] from a [Resource]
    async fn get_value(&self, subject: &str, property: &str) -> AtomicResult<Value> {
        self.get_resource(&subject.into())
            .await
            .and_then(|r| r.get(property).cloned())
    }

    /// Returns the default Agent for applying commits.
    fn get_default_agent(&self) -> AtomicResult<crate::agents::Agent> {
        Err("No default agent implemented for this store".into())
    }

    /// Create an Agent, storing its public key.
    /// An Agent is required for signing Commits.
    /// Returns a tuple of (subject, private_key).
    /// Make sure to store the private_key somewhere safe!
    /// Does not create a Commit - the recommended way is to use `agent.to_resource().save_locally()`.
    async fn create_agent(&self, name: Option<&str>) -> AtomicResult<crate::agents::Agent> {
        let agent = Agent::new(name)?;
        self.add_resource(&agent.to_resource()?).await?;
        Ok(agent)
    }

    /// Exports the store to a big JSON-AD file.
    /// Sorts the export by first exporting Property Resources, which makes importing faster and more dependent.
    fn export(&self, include_external: bool) -> AtomicResult<String> {
        let resources = self.all_resources(include_external);
        let mut properties: Vec<Resource> = Vec::new();
        let mut other_resources: Vec<Resource> = Vec::new();
        for r in resources {
            if let Ok(class) = r.get_main_class() {
                if class == crate::urls::PROPERTY {
                    properties.push(r);
                    continue;
                }
            }
            other_resources.push(r);
        }
        properties.append(&mut other_resources);
        crate::serialize::resources_to_json_ad(&properties, "internal:", true)
    }

    /// Fetches a resource, makes sure its subject matches.
    /// Save to the store.
    /// Uses `client_agent` for Authentication.
    async fn fetch_resource(
        &self,
        subject: &str,
        client_agent: Option<&Agent>,
    ) -> AtomicResult<Resource> {
        let response = crate::client::fetch_resource(subject, self, client_agent).await?;

        match response {
            ResourceResponse::Resource(resource) => {
                self.add_resource_opts(&resource, true, true, true).await?;

                Ok(resource)
            }
            ResourceResponse::ResourceWithReferenced(resource, referenced) => {
                self.add_resource_opts(&resource, true, true, true).await?;
                for r in referenced {
                    self.add_resource_opts(&r, true, true, true).await?;
                }

                Ok(resource)
            }
            ResourceResponse::Redirect(target) => Err(AtomicError::not_found(format!(
                "Resource {} redirected to {}",
                subject, target
            ))),
        }
    }

    /// Performs a full-text search on the Server's /search endpoint.
    /// Requires a server URL to be set.
    async fn search(
        &self,
        query: &str,
        opts: crate::client::search::SearchOpts,
    ) -> AtomicResult<Vec<Resource>> {
        let search_base = self
            .get_base_domain()
            .unwrap_or_else(|| "internal:".to_string());
        let subject = crate::client::search::build_search_subject(&search_base, query, opts);

        let resource = self
            .fetch_resource(&subject, self.get_default_agent().ok().as_ref())
            .await?;

        let Ok(Value::ResourceArray(vec)) = resource.get(urls::ENDPOINT_RESULTS) else {
            return Err("No 'ENDPOINT_RESULTS' in response from server.".into());
        };

        // Collect all subjects for concurrent execution
        let futures: Vec<_> = vec
            .iter()
            .filter_map(|s| {
                if let SubResource::Subject(result_subject) = s {
                    Some(async move {
                        match self.get_resource(&result_subject.as_str().into()).await {
                            Ok(r) => r,
                            Err(err) => err
                                .into_resource(result_subject.to_string())
                                .unwrap_or_else(|_| Resource::new(result_subject.to_string())),
                        }
                    })
                } else {
                    None
                }
            })
            .collect();

        let results = future::join_all(futures).await;

        Ok(results)
    }

    /// Returns a full Resource with native Values.
    /// Note that this does _not_ construct dynamic Resources, such as collections.
    /// If you're not sure what to use, use `get_resource_extended`.
    /// Returns a full Resource with native Values.
    /// Note that this does _not_ construct dynamic Resources, such as collections.
    /// If you're not sure what to use, use `get_resource_extended`.
    async fn get_resource(&self, subject: &Subject) -> AtomicResult<Resource>;

    /// Returns true when the resource is present in the local backing store.
    ///
    /// This must not fetch, synthesize dynamic resources, call endpoints, or
    /// otherwise mutate the store. It exists for bootstrap guards where
    /// `get_resource` is too broad: `get_resource` may fetch external Atomic
    /// URLs and make an empty store look seeded.
    fn has_stored_resource(&self, _subject: &Subject) -> bool {
        false
    }

    /// The fingerprint of the built-in defaults (`lib/defaults/*.json` + base
    /// models) that were last seeded into this store, if the store persists
    /// one. See [`crate::populate::bootstrap`]. Stores that do not persist it
    /// return `None`, which makes every open re-run the (idempotent) seed.
    fn get_defaults_fingerprint(&self) -> AtomicResult<Option<String>> {
        Ok(None)
    }

    /// Records the defaults fingerprint after a successful seed. No-op for
    /// stores that do not persist it.
    fn set_defaults_fingerprint(&self, _fingerprint: &str) -> AtomicResult<()> {
        Ok(())
    }

    /// Returns an existing resource, or creates a new one with the given Subject
    async fn get_resource_new(&self, subject: &Subject) -> Resource {
        match self.get_resource(subject).await {
            Ok(r) => r,
            Err(_) => Resource::new(subject.to_string()),
        }
    }

    /// Retrieves a Class from the store by subject URL and converts it into a Class useful for forms
    async fn get_class(&self, subject: &str) -> AtomicResult<Class> {
        let resource = self
            .get_resource(&subject.into())
            .await
            .map_err(|e| format!("Failed getting class {}. {}", subject, e))?;
        Class::from_resource(resource)
    }

    /// Finds all classes (isA) for any subject.
    /// Returns an empty vector if there are none.
    async fn get_classes_for_subject(&self, subject: &Subject) -> AtomicResult<Vec<Class>> {
        let classes = self.get_resource(subject).await?.get_classes(self).await?;
        Ok(classes)
    }

    /// Fetches a property by URL, returns a Property instance
    #[tracing::instrument(skip_all)]
    async fn get_property(&self, subject: &str) -> AtomicResult<Property> {
        let prop = self
            .get_resource(&subject.into())
            .await
            .map_err(|e| format!("Failed getting property {}. {}", subject, e))?;
        Property::from_resource(prop)
    }

    /// Get's the resource, parses the Query parameters and calculates dynamic properties.
    /// Defaults to get_resource if store doesn't support extended resources
    /// If `for_agent` is None, no authorization checks will be done, and all resources will return.
    /// If you want public only resurces, pass `Some(crate::authentication::public_agent)` as the agent.
    /// - *skip_dynamic* Does not calculte dynamic properties. Adds an `incomplete=true` property if the resource should have been dynamic.
    async fn get_resource_extended(
        &self,
        subject: &Subject,
        skip_dynamic: bool,
        for_agent: &ForAgent,
    ) -> AtomicResult<ResourceResponse> {
        let _ignore = skip_dynamic;
        let resource = self.get_resource(subject).await?;
        hierarchy::check_read(self, &resource, for_agent).await?;
        Ok(resource.into())
    }

    /// This function is called whenever a Commit is applied.
    /// Implement this if you want to have custom handlers for Commits.
    fn handle_commit(&self, _commit_response: &CommitResponse) {}

    async fn handle_not_found(
        &self,
        subject: &str,
        _error: AtomicError,
        for_agent: Option<&Agent>,
    ) -> AtomicResult<Resource> {
        let subject_obj = Subject::from_raw(subject, self.get_base_domain().as_deref());
        if subject_obj.is_local() {
            return Err(AtomicError::not_found(format!(
                "Failed to retrieve locally: '{}'",
                subject
            )));
        }
        self.fetch_resource(subject, for_agent).await
    }

    /// Imports a JSON-AD string, returns the amount of imported resources.
    async fn import(
        &self,
        string: &str,
        parse_opts: &crate::parse::ParseOpts,
    ) -> AtomicResult<usize> {
        let vec = parse_json_ad_string(string, self, parse_opts).await?;
        let len = vec.len();
        Ok(len)
    }

    /// Removes a resource and its children from the store. Errors if not present.
    async fn remove_resource(&self, subject: &Subject) -> AtomicResult<()>;

    /// Accepts an Atomic Path string, returns the result value (resource or property value)
    /// E.g. `https://example.com description` or `thing isa 0`
    /// https://docs.atomicdata.dev/core/paths.html
    /// The `for_agent` argument is used to check if the user has rights to the resource.
    /// You can pass `None` if you don't care about the rights (e.g. in client side apps)
    /// If you want to perform read rights checks, pass Some `for_agent` subject
    //  Todo: return something more useful, give more context.
    async fn get_path(
        &self,
        atomic_path: &str,
        mapping: Option<&Mapping>,
        for_agent: &ForAgent,
    ) -> AtomicResult<PathReturn> {
        // The first item of the path represents the starting Resource, the following ones are traversing the graph / selecting properties.
        let path_items: Vec<&str> = atomic_path.split(' ').collect();
        let first_item = String::from(path_items[0]);
        let mut id_url = first_item;
        if let Some(m) = mapping {
            // For the first item, check the user mapping
            id_url = m
                .try_mapping_or_url(&id_url)
                .ok_or(&*format!("No url found for {}", path_items[0]))?;
        }
        if path_items.len() == 1 {
            return Ok(PathReturn::Subject(id_url));
        }
        // The URL of the next resource
        let mut subject = id_url;
        // Set the currently selectred resource parent, which starts as the root of the search
        let mut resource = self
            .get_resource_extended(&subject.clone().into(), false, for_agent)
            .await?
            .to_single();
        // During each of the iterations of the loop, the scope changes.
        // Try using pathreturn...
        let mut current: PathReturn = PathReturn::Subject(subject.clone());
        // Loops over every item in the list, traverses the graph
        // Skip the first one, for that is the subject (i.e. first parent) and not a property
        for item in path_items[1..].iter().cloned() {
            // In every iteration, the subject, property_url and current should be set.
            // Ignore double spaces
            if item.is_empty() {
                continue;
            }
            // If the item is a number, assume its indexing some array
            if let Ok(i) = item.parse::<u32>() {
                match current {
                    PathReturn::Atom(atom) => {
                        let vector = match resource.get(&atom.property)? {
                            Value::ResourceArray(vec) => vec,
                            _ => {
                                return Err(
                                    "Integers can only be used to traverse ResourceArrays.".into()
                                )
                            }
                        };
                        let url: String = vector
                            .get(i as usize)
                            .ok_or(format!(
                                "Too high index {} for array with length {}, max is {}",
                                i,
                                vector.len(),
                                vector.len() - 1
                            ))?
                            .to_string();
                        subject = url;
                        resource = self
                            .get_resource_extended(&subject.clone().into(), false, for_agent)
                            .await?
                            .to_single();
                        current = PathReturn::Subject(subject.clone());
                        continue;
                    }
                    PathReturn::Subject(_) => {
                        return Err("You can't do an index on a resource, only on arrays.".into())
                    }
                }
            }
            // Since the selector isn't an array index, we can assume it's a property URL
            match current {
                PathReturn::Subject(_) => {}
                PathReturn::Atom(_) => {
                    return Err("No more linked resources down this path.".into())
                }
            }
            // Set the parent for the next loop equal to the next node.
            // TODO: skip this step if the current iteration is the last one
            let value = resource.get_shortname(item, self).await?.clone();
            let property = resource.resolve_shortname_to_property(item, self).await?;
            current = PathReturn::Atom(Box::new(Atom::new(
                subject.clone().into(),
                property.subject,
                value,
            )))
        }
        Ok(current)
    }

    /// Handles a HTTP POST request to the store.
    /// This is where [crate::endpoints::Endpoint] are used.
    async fn post_resource(
        &self,
        _subject: &str,
        _body: Vec<u8>,
        _for_agent: &ForAgent,
    ) -> AtomicResult<Resource> {
        Err("`post_resource` not implemented for StoreLike. Implement it in your trait.".into())
    }

    /// Loads the default store. For DBs it also adds default Collections and Endpoints.
    async fn populate(&self) -> AtomicResult<()> {
        crate::populate::populate_base_models(self).await?;
        crate::populate::populate_default_store(self).await
    }

    /// Search the Store, returns the matching subjects.
    async fn query(&self, q: &Query) -> AtomicResult<QueryResult>;

    /// Sets the default Agent for applying commits.
    fn set_default_agent(&self, agent: crate::agents::Agent);

    /// Performs a light validation, without fetching external data
    async fn validate(&self) -> crate::validate::ValidationReport {
        crate::validate::validate_store(self, false).await
    }

    /// Start buffering writes for a single batched transaction.
    fn begin_batch(&self) {}

    /// Commit all buffered writes. No-op if not batching.
    fn commit_batch(&self) -> AtomicResult<()> {
        Ok(())
    }
}

/// How a [PropVal] constraint compares the resource's value to the filter
/// value. `Equal` keeps the historical behaviour (`contains_value`: scalar
/// equality or array membership); the rest are value-comparison predicates
/// applied during post-filtering. Index-accelerated range scans are a separate,
/// later optimisation — see `planning/table-view-filters.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum FilterOperator {
    /// Scalar equality or array membership (`contains_value`). The default.
    #[default]
    Equal,
    /// Numeric/lexical greater-than.
    GreaterThan,
    /// Numeric/lexical greater-than-or-equal.
    GreaterThanOrEqual,
    /// Numeric/lexical less-than.
    LessThan,
    /// Numeric/lexical less-than-or-equal.
    LessThanOrEqual,
    /// String prefix match.
    StartsWith,
    /// String substring match.
    Contains,
}

/// Parses a wire operator string (from a `/query` param or the WASM bridge)
/// into a [FilterOperator]. Unknown/missing → `Equal` (back-compat). Accepts
/// both short and symbolic spellings.
pub fn filter_operator_from_str(op: Option<&str>) -> FilterOperator {
    match op {
        Some("gt") | Some(">") => FilterOperator::GreaterThan,
        Some("gte") | Some(">=") => FilterOperator::GreaterThanOrEqual,
        Some("lt") | Some("<") => FilterOperator::LessThan,
        Some("lte") | Some("<=") => FilterOperator::LessThanOrEqual,
        Some("starts_with") => FilterOperator::StartsWith,
        Some("contains") => FilterOperator::Contains,
        _ => FilterOperator::Equal,
    }
}

/// A single `(property, value)` constraint used by [Query] and the query index.
/// Both are optional: property+value (the property must contain the value),
/// property-only (must have the property), or value-only (any property contains
/// the value). `operator` selects how value is compared (default `Equal`).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PropVal {
    /// Filtering by property URL
    pub property: Option<String>,
    /// Filtering by value
    pub value: Option<Value>,
    /// How `value` is compared. Defaults to `Equal` for back-compat.
    #[serde(default)]
    pub operator: FilterOperator,
}

/// Use this to construct a list of Resources
#[derive(Debug)]
pub struct Query {
    /// Filter by Property
    pub property: Option<String>,
    /// Filter by Value
    pub value: Option<Value>,
    /// Additional `(property, value)` constraints, combined with `property`/`value`
    /// and each other using **AND**. Lets a query filter on multiple properties
    /// (e.g. `isA = Commit` AND `signer = <agent>`).
    pub filters: Vec<PropVal>,
    /// Maximum of items to return, if none returns all items.
    pub limit: Option<usize>,
    /// Value at which to begin lexicographically sorting things.
    pub start_val: Option<Value>,
    /// Value at which to stop lexicographically sorting things.
    pub end_val: Option<Value>,
    /// How many items to skip from the first one
    pub offset: usize,
    /// The Property URL that is used to sort the results
    pub sort_by: Option<String>,
    /// Sort descending instead of ascending.
    pub sort_desc: bool,
    /// Whether to include non-server resources
    pub include_external: bool,
    /// Whether to include full Resources in the result, if not, will add empty vector here.
    pub include_nested: bool,
    /// For which Agent the query is executed. Pass `None` if you want to skip permission checks.
    pub for_agent: ForAgent,
    /// Scope the query to a specific drive. When set, only resources whose subjects
    /// start with the drive's prefix are included. Also scopes the query index so watched queries
    /// are drive-specific, preventing spurious cross-tenant index updates.
    pub drive: Option<Subject>,
    /// Statistics to compute over **every** matching row, independent of
    /// `limit`/`offset`. `None` (the default) costs nothing. See
    /// [crate::aggregate].
    pub aggregation: Option<crate::aggregate::Aggregation>,
    /// Constraints on values *computed* per row — a duration, an amount, a
    /// days-since — rather than stored on it. ANDed with `filters`.
    ///
    /// These can't be answered by the query index, which is keyed by stored
    /// values (and a running duration has no stable value to key by), so they are
    /// evaluated over the set the index narrows to. That costs a pass over the
    /// matching rows, the same pass an aggregation already makes — which is why
    /// they're a separate field rather than folded into `filters`: nothing else
    /// should silently lose its index.
    pub expression_filters: Vec<crate::expression::ExpressionFilter>,
}

impl Query {
    pub fn new() -> Self {
        Query {
            property: None,
            value: None,
            filters: Vec::new(),
            expression_filters: Vec::new(),
            limit: None,
            start_val: None,
            end_val: None,
            offset: 0,
            sort_by: None,
            sort_desc: false,
            include_external: false,
            include_nested: true,
            for_agent: ForAgent::Sudo,
            drive: None,
            aggregation: None,
        }
    }

    /// Search for a property-value combination
    pub fn new_prop_val(prop: &str, val: &str) -> Self {
        let mut q = Self::new();
        q.property = Some(prop.to_string());
        q.value = Some(Value::String(val.to_string()));
        q
    }

    /// Search for instances of some Class
    pub fn new_class(class: &str) -> Self {
        let mut q = Self::new();
        q.property = Some(urls::IS_A.into());
        q.value = Some(Value::AtomicUrl(class.to_string().into()));
        q
    }

    /// Add an extra `(property, value)` constraint, ANDed with the existing
    /// filters. Chainable: `Query::new_class(COMMIT).filter(SIGNER, agent_val)`.
    pub fn filter(mut self, property: &str, value: Value) -> Self {
        self.filters.push(PropVal {
            property: Some(property.to_string()),
            value: Some(value),
            operator: FilterOperator::Equal,
        });
        self
    }

    /// Add a class (`isA = class`) constraint, ANDed with the existing filters.
    /// Use this on top of another filter, e.g. to scope "subject = X" down to
    /// only Commits: `Query::new_prop_val(SUBJECT, x).class_filter(COMMIT)`.
    pub fn class_filter(self, class: &str) -> Self {
        self.filter(urls::IS_A, Value::AtomicUrl(class.to_string().into()))
    }
}

impl Default for Query {
    fn default() -> Self {
        Self::new()
    }
}

pub struct QueryResult {
    pub subjects: Vec<Subject>,
    pub resources: Vec<Resource>,
    /// The amount of hits that were found, including the ones that were out of bounds or not authorized.
    pub count: usize,
    /// One outcome per requested aggregate, in the order they were asked for.
    /// Empty unless the query carried an [crate::aggregate::Aggregation].
    pub aggregates: Vec<crate::aggregate::AggregateOutcome>,
}
