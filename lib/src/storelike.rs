//! Trait for all stores to use

use crate::errors::AtomicResult;
use crate::{
    agents::Agent,
    schema::{Class, Property},
    urls,
};
use crate::{mapping::Mapping, values::Value, Atom, Resource, RichAtom};

// A path can return one of many things
pub enum PathReturn {
    Subject(String),
    Atom(Box<RichAtom>),
}

pub type ResourceCollection = Vec<Resource>;

/// Storelike provides many useful methods for interacting with an Atomic Store.
/// It serves as a basic store Trait, agnostic of how it functions under the hood.
/// This is useful, because we can create methods for Storelike that will work with either in-memory
/// stores, as well as with persistend on-disk stores.
pub trait Storelike: Sized {
    /// Adds Atoms to the store.
    /// Will replace existing Atoms that share Subject / Property combination.
    /// Validates datatypes and required props presence.
    fn add_atoms(&self, atoms: Vec<Atom>) -> AtomicResult<()>;

    /// Adds a Resource to the store.
    /// Replaces existing resource with the contents.
    /// In most cases, you should use `.commit()` instead.
    fn add_resource(&self, resource: &Resource) -> AtomicResult<()>;

    /// Adds a Resource to the store.
    /// Replaces existing resource with the contents.
    /// Does not do any validations.
    fn add_resource_unsafe(&self, resource: &Resource) -> AtomicResult<()>;

    /// Returns the root URL where the store is hosted.
    /// E.g. `https://example.com`
    /// This is where deltas should be sent to.
    /// Also useful for Subject URL generation.
    fn get_base_url(&self) -> String;

    /// Returns the default Agent for applying commits.
    fn get_default_agent(&self) -> AtomicResult<crate::agents::Agent> {
        Err("No default agent implemented for this store".into())
    }

    /// Apply a single signed Commit to the store
    /// Creates, edits or destroys a resource.
    /// Checks if the signature is created by the Agent.
    /// Should check if the Agent has the correct rights.
    fn commit(&self, commit: crate::Commit) -> AtomicResult<Resource>
    where
        Self: std::marker::Sized,
    {
        let signature = match commit.signature.as_ref() {
            Some(sig) => sig,
            None => return Err("No signature set".into()),
        };
        // TODO: Check if commit.agent has the rights to update the resource
        let pubkey_b64 = self
            .get_resource(&commit.signer)?
            .get(urls::PUBLIC_KEY)?
            .to_string();
        let agent_pubkey = base64::decode(pubkey_b64)?;
        let stringified_commit = commit.serialize_deterministically()?;
        let peer_public_key =
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, agent_pubkey);
        let signature_bytes = base64::decode(signature.clone())?;
        peer_public_key
            .verify(stringified_commit.as_bytes(), &signature_bytes)
            .map_err(|_e| {
                format!(
                    "Incorrect signature for Commit. This could be due to an error during signing or serialization of the commit. Stringified commit: {}. Public key",
                    stringified_commit,
                )
            })?;
        // Check if the created_at lies in the past
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;
        let commit_resource: Resource = commit.clone().into_resource(self)?;
        if commit.created_at > now {
            return Err("Commit created_at timestamp must lie in the past.".into());
            // TODO: also check that no younger commits exist
        }
        if let Some(destroy) = commit.destroy {
            if destroy {
                self.remove_resource(&commit.subject);
                return Ok(commit_resource);
            }
        }
        let mut resource = match self.get_resource(&commit.subject) {
            Ok(rs) => rs,
            Err(_) => Resource::new(commit.subject.clone()),
        };
        if let Some(set) = commit.set.clone() {
            for (prop, val) in set.iter() {
                resource.set_propval_string(prop.into(), val, self)?;
            }
            self.add_resource(&resource)?;
        }
        if let Some(remove) = commit.remove.clone() {
            for prop in remove.iter() {
                resource.remove_propval(&prop);
            }
            self.add_resource(&resource)?;
        }
        resource.check_required_props(self)?;
        self.add_resource(&commit_resource)?;
        Ok(commit_resource)
    }

    /// Create an Agent, storing its public key.
    /// An Agent is required for signing Commits.
    /// Returns a tuple of (subject, private_key).
    /// Make sure to store the private_key somewhere safe!
    /// Does not create a Commit.
    fn create_agent(&self, name: &str) -> AtomicResult<crate::agents::Agent> {
        let agent = Agent::new(name.to_string(), self);
        self.add_resource(&agent.to_resource(self)?)?;
        Ok(agent)
    }

    /// Fetches a resource, makes sure its subject matches.
    /// Save to the store.
    fn fetch_resource(&self, subject: &str) -> AtomicResult<Resource> {
        let resource: Resource = crate::client::fetch_resource(subject, self)?;
        self.add_resource_unsafe(&resource)?;
        Ok(resource)
    }

    /// Returns a full Resource with native Values.
    /// Note that this does _not_ construct dynamic Resources, such as collections.
    /// If you're not sure what to use, use `get_resource_extended`.
    fn get_resource(&self, subject: &str) -> AtomicResult<Resource>;

    /// Retrieves a Class from the store by subject URL and converts it into a Class useful for forms
    fn get_class(&self, subject: &str) -> AtomicResult<Class> {
        let resource = self.get_resource(subject)?;
        Class::from_resource(resource)
    }

    /// Finds all classes (isA) for any subject.
    /// Returns an empty vector if there are none.
    fn get_classes_for_subject(&self, subject: &str) -> AtomicResult<Vec<Class>> {
        let classes = self.get_resource(subject)?.get_classes(self)?;
        Ok(classes)
    }

    /// Fetches a property by URL, returns a Property instance
    fn get_property(&self, subject: &str) -> AtomicResult<Property> {
        let prop = self.get_resource(subject)?;
        Property::from_resource(prop)
    }

    /// Get's the resource, parses the Query parameters and calculates dynamic properties.
    /// Currently only used for constructing Collections.
    fn get_resource_extended(&self, subject: &str) -> AtomicResult<Resource> {
        println!("got {}", subject);
        let mut url = url::Url::parse(subject)?;
        let clone = url.clone();
        let query_params = clone.query_pairs();
        url.set_query(None);
        let removed_query_params = url.to_string();
        let resource = self.get_resource(&removed_query_params)?;
        // If a certain class needs to be extended, add it to this match statement
        for class in resource.get_classes(self)? {
            match class.subject.as_ref() {
                urls::COLLECTION => {
                    return crate::collections::construct_collection(self, query_params, resource)
                }
                "example" => todo!(),
                _ => {}
            }
        }
        Ok(resource)
    }

    fn handle_not_found(&self, subject: &str) -> AtomicResult<Resource> {
        if subject.starts_with(&self.get_base_url()) {
            return Err(format!("Failed to retrieve {}, does not exist locally", subject).into());
        }

        match self.fetch_resource(subject) {
            Ok(got) => Ok(got),
            Err(e) => Err(format!("Failed to retrieve {} from the web: {}", subject, e).into()),
        }
    }

    /// Returns a collection with all resources in the store.
    /// WARNING: This could be very expensive!
    fn all_resources(&self) -> ResourceCollection;

    /// Removes a resource from the store
    fn remove_resource(&self, subject: &str);

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
    ///     Some("[\"https://atomicdata.dev/classes/Class\"]")
    /// ).unwrap();
    /// println!("Count: {}", atoms.len());
    /// assert!(atoms.len() == 6)
    /// ```
    // Very costly, slow implementation.
    // Does not assume any indexing.
    fn tpf(
        &self,
        q_subject: Option<&str>,
        q_property: Option<&str>,
        q_value: Option<&str>,
    ) -> AtomicResult<Vec<Atom>> {
        let mut vec: Vec<Atom> = Vec::new();

        let hassub = q_subject.is_some();
        let hasprop = q_property.is_some();
        let hasval = q_value.is_some();

        // Simply return all the atoms
        if !hassub && !hasprop && !hasval {
            for resource in self.all_resources() {
                for (property, value) in resource.get_propvals() {
                    vec.push(Atom::new(
                        resource.get_subject().clone(),
                        property.clone(),
                        value.to_string(),
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
                            vec.push(Atom::new(subj.into(), prop.into(), val.to_string()))
                        }
                        break;
                    } else {
                        vec.push(Atom::new(subj.into(), prop.into(), val.to_string()))
                    }
                    break;
                } else if hasval && !hasprop && val_equals(&val.to_string()) {
                    vec.push(Atom::new(subj.into(), prop.into(), val.to_string()))
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
                        // Ok(resources::resourcestring_to_atoms(sub, resource))
                        resource.to_atoms()
                    }
                }
                Err(_) => Ok(vec),
            },
            None => {
                for resource in self.all_resources() {
                    find_in_resource(&resource);
                }
                Ok(vec)
            }
        }
    }

    /// Accepts an Atomic Path string, returns the result value (resource or property value)
    /// E.g. `https://example.com description` or `thing isa 0`
    /// https://docs.atomicdata.dev/core/paths.html
    //  Todo: return something more useful, give more context.
    fn get_path(&self, atomic_path: &str, mapping: Option<&Mapping>) -> AtomicResult<PathReturn> {
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
        let mut resource = self.get_resource_extended(&subject)?;
        // During each of the iterations of the loop, the scope changes.
        // Try using pathreturn...
        let mut current: PathReturn = PathReturn::Subject(subject.clone());
        // Loops over every item in the list, traverses the graph
        // Skip the first one, for that is the subject (i.e. first parent) and not a property
        for item in path_items[1..].iter().cloned() {
            // In every iteration, the subject, property_url and current should be set.
            // Ignore double spaces
            if item == "" {
                continue;
            }
            // If the item is a number, assume its indexing some array
            if let Ok(i) = item.parse::<u32>() {
                match current {
                    PathReturn::Atom(atom) => {
                        let vector = match resource.get(&atom.property.subject)? {
                            Value::ResourceArray(vec) => vec,
                            _ => return Err("Should be Vector!".into()),
                        };
                        let url: String = vector
                            .get(i as usize)
                            .ok_or(format!("Too high index {} for array with length {}, max is {}", i, vector.len(), vector.len() - 1))?
                            .into();
                        subject = url;
                        resource = self.get_resource_extended(&subject)?;
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
            let value = resource.get_shortname(&item, self)?.clone();
            let property = resource.resolve_shortname_to_property(item, self)?;
            current = PathReturn::Atom(Box::new(RichAtom::new(
                subject.clone(),
                property,
                value.to_string(),
            )?))
        }
        Ok(current)
    }

    /// Loads the default store and constructs various default collections.
    fn populate(&self) -> AtomicResult<()> {
        crate::populate::populate_base_models(self)?;
        crate::populate::populate_default(self)?;
        crate::populate::populate_collections(self)
    }

    /// Sets the default Agent for applying commits.
    fn set_default_agent(&self, agent: crate::agents::Agent);

    /// Performs a light validation, without fetching external data
    fn validate(&self) -> crate::validate::ValidationReport {
        crate::validate::validate_store(self, false)
    }
}
