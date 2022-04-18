//! The Storelike Trait contains many useful methods for maniupulting / retrieving data.

use crate::{
    agents::Agent,
    commit::CommitResponse,
    errors::AtomicError,
    hierarchy,
    schema::{Class, Property},
    values::query_value_compare,
};
use crate::{errors::AtomicResult, parse::parse_json_ad_array};
use crate::{mapping::Mapping, values::Value, Atom, Resource};

// A path can return one of many things
pub enum PathReturn {
    Subject(String),
    Atom(Box<Atom>),
}

pub type ResourceCollection = Vec<Resource>;

/// Storelike provides many useful methods for interacting with an Atomic Store.
/// It serves as a basic store Trait, agnostic of how it functions under the hood.
/// This is useful, because we can create methods for Storelike that will work with either in-memory
/// stores, as well as with persistent on-disk stores.
pub trait Storelike: Sized {
    /// Adds Atoms to the store.
    /// Will replace existing Atoms that share Subject / Property combination.
    /// Validates datatypes and required props presence.
    #[deprecated(
        since = "0.28.0",
        note = "The atoms abstraction has been deprecated in favor of Resources"
    )]
    fn add_atoms(&self, atoms: Vec<Atom>) -> AtomicResult<()>;

    /// Adds an Atom to the PropSubjectMap. Overwrites if already present.
    /// The default implementation for this does not do anything, so overwrite it if your store needs indexing.
    fn add_atom_to_index(&self, _atom: &Atom, _resource: &Resource) -> AtomicResult<()> {
        Ok(())
    }

    /// Adds a Resource to the store.
    /// Replaces existing resource with the contents.
    /// Updates the index.
    /// Validates the fields (checks required props).
    /// In most cases, you should use `resource.save()` instead, which uses Commits.
    fn add_resource(&self, resource: &Resource) -> AtomicResult<()> {
        self.add_resource_opts(resource, true, true, true)
    }

    /// Adds a Resource to the store.
    /// Replaces existing resource with the contents.
    /// Does not do any validations.
    fn add_resource_opts(
        &self,
        resource: &Resource,
        check_required_props: bool,
        update_index: bool,
        overwrite_existing: bool,
    ) -> AtomicResult<()>;

    /// Returns a collection with all resources in the store.
    /// If Include_external is false, this is filtered by selecting only resoureces that match the `self` URL of the store.
    /// WARNING: This could be very expensive!
    fn all_resources(&self, include_external: bool) -> ResourceCollection;

    /// Constructs the value index from all resources in the store. Could take a while.
    fn build_index(&self, include_external: bool) -> AtomicResult<()> {
        for r in self.all_resources(include_external) {
            let atoms = r.to_atoms()?;
            for atom in atoms {
                self.add_atom_to_index(&atom, &r)
                    .map_err(|e| format!("Failed to add atom to index {}. {}", atom, e))?;
            }
        }
        Ok(())
    }

    /// Returns the base URL where the default store is.
    /// E.g. `https://example.com`
    /// This is where deltas should be sent to.
    /// Also useful for Subject URL generation.
    fn get_server_url(&self) -> &str;

    /// Returns the root URL where this instance of the store is hosted.
    /// Should return `None` if this is simply a client and not a server.
    /// E.g. `https://example.com`
    fn get_self_url(&self) -> Option<String> {
        None
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
    fn create_agent(&self, name: Option<&str>) -> AtomicResult<crate::agents::Agent> {
        let agent = Agent::new(name, self)?;
        self.add_resource(&agent.to_resource(self)?)?;
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
        crate::serialize::resources_to_json_ad(&properties)
    }

    /// Fetches a resource, makes sure its subject matches.
    /// Uses the default agent to sign the request.
    /// Save to the store.
    fn fetch_resource(&self, subject: &str) -> AtomicResult<Resource> {
        let resource: Resource =
            crate::client::fetch_resource(subject, self, self.get_default_agent().ok())?;
        self.add_resource_opts(&resource, true, true, true)?;
        Ok(resource)
    }

    /// Returns a full Resource with native Values.
    /// Note that this does _not_ construct dynamic Resources, such as collections.
    /// If you're not sure what to use, use `get_resource_extended`.
    fn get_resource(&self, subject: &str) -> AtomicResult<Resource>;

    /// Returns an existing resource, or creates a new one with the given Subject
    fn get_resource_new(&self, subject: &str) -> Resource {
        match self.get_resource(subject) {
            Ok(r) => r,
            Err(_) => Resource::new(subject.into()),
        }
    }

    /// Retrieves a Class from the store by subject URL and converts it into a Class useful for forms
    fn get_class(&self, subject: &str) -> AtomicResult<Class> {
        let resource = self
            .get_resource(subject)
            .map_err(|e| format!("Failed getting class {}. {}", subject, e))?;
        Class::from_resource(resource)
    }

    /// Finds all classes (isA) for any subject.
    /// Returns an empty vector if there are none.
    fn get_classes_for_subject(&self, subject: &str) -> AtomicResult<Vec<Class>> {
        let classes = self.get_resource(subject)?.get_classes(self)?;
        Ok(classes)
    }

    /// Fetches a property by URL, returns a Property instance
    #[tracing::instrument(skip(self))]
    fn get_property(&self, subject: &str) -> AtomicResult<Property> {
        let prop = self
            .get_resource(subject)
            .map_err(|e| format!("Failed getting property {}. {}", subject, e))?;
        Property::from_resource(prop)
    }

    /// Get's the resource, parses the Query parameters and calculates dynamic properties.
    /// Defaults to get_resource if store doesn't support extended resources
    /// If `for_agent` is None, no authorization checks will be done, and all resources will return.
    /// If you want public only resurces, pass `Some(crate::authentication::public_agent)` as the agent.
    /// - *skip_dynamic* Does not calculte dynamic properties. Adds an `incomplete=true` property if the resource should have been dynamic.
    fn get_resource_extended(
        &self,
        subject: &str,
        skip_dynamic: bool,
        for_agent: Option<&str>,
    ) -> AtomicResult<Resource> {
        let _ignore = skip_dynamic;
        let resource = self.get_resource(subject)?;
        if let Some(agent) = for_agent {
            hierarchy::check_read(self, &resource, agent)?;
            return Ok(resource);
        }
        Ok(resource)
    }

    /// This function is called whenever a Commit is applied.
    /// Implement this if you want to have custom handlers for Commits.
    fn handle_commit(&self, _commit_response: &CommitResponse) {}

    fn handle_not_found(&self, subject: &str, error: AtomicError) -> AtomicResult<Resource> {
        if let Some(self_url) = self.get_self_url() {
            if subject.starts_with(&self_url) {
                return Err(AtomicError::not_found(format!(
                    "Failed to retrieve locally: '{}'. {}",
                    subject, error
                )));
            }
        }
        self.fetch_resource(subject)
    }

    /// Imports a JSON-AD string, returns the amount of imported resources
    fn import(&self, string: &str) -> AtomicResult<usize> {
        let vec = parse_json_ad_array(string, self, true)
            .map_err(|e| format!("Unable to import JSON-AD. {}", e))?;
        let len = vec.len();
        Ok(len)
    }

    /// Removes a resource from the store. Errors if not present.
    fn remove_resource(&self, subject: &str) -> AtomicResult<()>;

    /// Triple Pattern Fragments interface.
    /// Use this for most queries, e.g. finding all items with some property / value combination.
    /// Returns an empty array if nothing is found.
    ///
    /// # Example
    ///
    /// For example, if I want to view all Resources that are instances of the class "Property", I'd do:
    ///
    /// ```
    /// use atomic_lib::Storelike;
    /// let mut store = atomic_lib::Store::init().unwrap();
    /// store.populate();
    /// let atoms = store.tpf(
    ///     None,
    ///     Some("https://atomicdata.dev/properties/isA"),
    ///     Some(&atomic_lib::Value::AtomicUrl("https://atomicdata.dev/classes/Class".into())),
    ///     true
    /// ).unwrap();
    /// assert!(atoms.len() > 11)
    /// ```
    // Very costly, slow implementation.
    // Does not assume any indexing.
    fn tpf(
        &self,
        q_subject: Option<&str>,
        q_property: Option<&str>,
        q_value: Option<&Value>,
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

        // Find atoms matching the TPF query in a single resource
        let mut find_in_resource = |resource: &Resource| {
            let subj = resource.get_subject();
            for (prop, val) in resource.get_propvals().iter() {
                if hasprop && q_property.as_ref().unwrap() == prop {
                    if hasval {
                        if query_value_compare(val, q_value.unwrap()) {
                            vec.push(Atom::new(subj.into(), prop.into(), val.clone()))
                        }
                        break;
                    } else {
                        vec.push(Atom::new(subj.into(), prop.into(), val.clone()))
                    }
                    break;
                } else if hasval && !hasprop && query_value_compare(val, q_value.unwrap()) {
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
                for resource in self.all_resources(include_external) {
                    find_in_resource(&resource);
                }
                Ok(vec)
            }
        }
    }

    /// Accepts an Atomic Path string, returns the result value (resource or property value)
    /// E.g. `https://example.com description` or `thing isa 0`
    /// https://docs.atomicdata.dev/core/paths.html
    /// The `for_agent` argument is used to check if the user has rights to the resource.
    /// You can pass `None` if you don't care about the rights (e.g. in client side apps)
    /// If you want to perform read rights checks, pass Some `for_agent` subject
    //  Todo: return something more useful, give more context.
    fn get_path(
        &self,
        atomic_path: &str,
        mapping: Option<&Mapping>,
        for_agent: Option<&str>,
    ) -> AtomicResult<PathReturn> {
        // The first item of the path represents the starting Resource, the following ones are traversing the graph / selecting properties.
        let path_items: Vec<&str> = atomic_path.split(' ').collect();
        let first_item = String::from(path_items[0]);
        let mut id_url = first_item;
        if mapping.is_some() {
            // For the first item, check the user mapping
            id_url = mapping
                .unwrap()
                .try_mapping_or_url(&id_url)
                .ok_or(&*format!("No url found for {}", path_items[0]))?;
        }
        if path_items.len() == 1 {
            return Ok(PathReturn::Subject(id_url));
        }
        // The URL of the next resource
        let mut subject = id_url;
        // Set the currently selectred resource parent, which starts as the root of the search
        let mut resource = self.get_resource_extended(&subject, false, for_agent)?;
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
                        resource = self.get_resource_extended(&subject, false, for_agent)?;
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
            let value = resource.get_shortname(item, self)?.clone();
            let property = resource.resolve_shortname_to_property(item, self)?;
            current = PathReturn::Atom(Box::new(Atom::new(
                subject.clone(),
                property.subject,
                value,
            )))
        }
        Ok(current)
    }

    /// Loads the default store. For DBs it also adds default Collections and Endpoints.
    fn populate(&self) -> AtomicResult<()> {
        crate::populate::populate_base_models(self)?;
        crate::populate::populate_default_store(self)
    }

    /// Search the Store, returns the matching subjects.
    /// The second returned vector should be filled if query.include_resources is true.
    /// Tries `query_cache`, which you should implement yourself.
    fn query(&self, q: &Query) -> AtomicResult<QueryResult> {
        let atoms = self.tpf(
            None,
            q.property.as_deref(),
            q.value.as_ref(),
            q.include_external,
        )?;

        // Remove duplicate subjects
        let mut subjects_deduplicated: Vec<String> = atoms
            .iter()
            .map(|atom| atom.subject.clone())
            .collect::<std::collections::HashSet<String>>()
            .into_iter()
            .collect();

        // Sort by subject, better than no sorting
        subjects_deduplicated.sort();

        // WARNING: Entering expensive loop!
        // This is needed for sorting, authorization and including nested resources.
        // It could be skipped if there is no authorization and sorting requirement.
        let mut resources = Vec::new();
        for subject in subjects_deduplicated.iter() {
            // These nested resources are not fully calculated - they will be presented as -is
            match self.get_resource_extended(subject, true, q.for_agent.as_deref()) {
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

        if let Some(sort) = &q.sort_by {
            resources = crate::collections::sort_resources(resources, sort, q.sort_desc);
        }
        let mut subjects = Vec::new();
        for r in resources.iter() {
            subjects.push(r.get_subject().clone())
        }

        Ok(QueryResult {
            count: atoms.len(),
            subjects,
            resources,
        })
    }

    /// Removes an Atom from the PropSubjectMap.
    fn remove_atom_from_index(&self, _atom: &Atom, _resource: &Resource) -> AtomicResult<()> {
        Ok(())
    }

    /// Sets the default Agent for applying commits.
    fn set_default_agent(&self, agent: crate::agents::Agent);

    /// Performs a light validation, without fetching external data
    fn validate(&self) -> crate::validate::ValidationReport {
        crate::validate::validate_store(self, false)
    }
}

/// Use this to construct a list of Resources
#[derive(Debug)]
pub struct Query {
    /// Filter by Property
    pub property: Option<String>,
    /// Filter by Value
    pub value: Option<Value>,
    /// Maximum of items to return
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
    /// For which Agent the query is executed. Pass `None`if you want to skip permission checks.
    pub for_agent: Option<String>,
}

pub struct QueryResult {
    pub subjects: Vec<String>,
    pub resources: Vec<Resource>,
    /// The amount of hits that were found, including the ones that were out of bounds or not authorized.
    pub count: usize,
}
