//! Trait for all stores to use

use crate::urls;
use crate::{collections::Collection, errors::AtomicResult};
use crate::{
    datatype::{match_datatype, DataType},
    mapping::Mapping,
    resources::{self, ResourceString},
    values::Value,
    Atom, Resource, RichAtom,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Property {
    // URL of the class
    pub class_type: Option<String>,
    // URL of the datatype
    pub data_type: DataType,
    pub shortname: String,
    pub subject: String,
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Class {
    pub requires: Vec<Property>,
    pub recommends: Vec<Property>,
    pub shortname: String,
    pub description: String,
    /// URL
    pub subject: String,
}

// A path can return one of many things
pub enum PathReturn {
    Subject(String),
    Atom(Box<RichAtom>),
}

pub type ResourceCollection = Vec<(String, ResourceString)>;

/// Storelike provides many useful methods for interacting with an Atomic Store.
/// It serves as a basic store Trait, agnostic of how it functions under the hood.
/// This is useful, because we can create methods for Storelike that will work with either in-memory
/// stores, as well as with persistend on-disk stores.
pub trait Storelike {
    // Not default yet
    // type Default = dyn std::marker::Sized;

    /// Add individual Atoms to the store.
    /// Will replace existing Atoms that share Subject / Property combination.
    fn add_atoms(&self, atoms: Vec<Atom>) -> AtomicResult<()>;

    /// Adds a Resource to the store.
    /// Replaces existing resource with the contents.
    /// In most cases, you should use `.commit()` instead.
    fn add_resource(&self, resource: &Resource) -> AtomicResult<()> {
        self.add_resource_string(resource.get_subject().clone(), &resource.to_plain())?;
        Ok(())
    }

    /// Replaces existing resource with the contents
    /// Accepts a simple nested string only hashmap
    /// Adds to hashmap and to the resource store
    fn add_resource_string(&self, subject: String, resource: &ResourceString) -> AtomicResult<()>;

    /// Returns a hashmap ResourceString with string Values.
    /// Fetches the resource if it is not in the store.
    fn get_resource_string(&self, subject: &str) -> AtomicResult<ResourceString>;

    /// Returns the root URL where the store is hosted.
    /// E.g. `https://example.com`
    /// This is where deltas should be sent to.
    /// Also useful for Subject URL generation.
    fn get_base_url(&self) -> String;

    /// Returns the default Agent for applying commits.
    fn get_default_agent(&self) -> Option<crate::agents::Agent> {
        None
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
        // TODO: actually use the stringified resource
        let stringified = commit.serialize_deterministically()?;
        let peer_public_key =
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, agent_pubkey);
        let signature_bytes = base64::decode(signature.clone())?;
        peer_public_key
            .verify(stringified.as_bytes(), &signature_bytes)
            .map_err(|_| "Incorrect signature")?;
        // Check if the created_at lies in the past
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;
        if commit.created_at > now {
            return Err("Commit created_at timestamp must lie in the past.".into());
            // TODO: also check that no younger commits exist
        }
        if let Some(destroy) = commit.destroy {
            if destroy {
                self.remove_resource(&commit.subject);
            }
        }
        let mut resource = match self.get_resource(&commit.subject) {
            Ok(rs) => rs,
            Err(_) => Resource::new(commit.subject.clone(), self),
        };
        if let Some(set) = commit.set.clone() {
            for (prop, val) in set.iter() {
                // Warning: this is a very inefficient operation
                resource.set_propval_string(prop.into(), val)?;
            }
            self.add_resource(&resource)?;
        }
        if let Some(remove) = commit.remove.clone() {
            for prop in remove.iter() {
                // Warning: this is a very inefficient operation
                resource.remove_propval(&prop);
            }
            self.add_resource(&resource)?;
        }
        // TOOD: Persist delta to store, use hash as ID
        let commit_resource: Resource = commit.into_resource(self)?;
        self.add_resource(&commit_resource)?;
        Ok(commit_resource)
    }

    /// Saves the changes done to a Resource.
    /// Signs the Commit using the Default Agent.
    /// Does not send it to an Atomic Server.
    /// Fails if no Default Agent is set.
    fn commit_resource_changes_locally(&self, resource: &mut Resource) -> AtomicResult<()>
    where
        Self: std::marker::Sized,
    {
        let agent = self.get_default_agent().ok_or("No default agent set!")?;
        let commit = resource.get_commit_and_reset().sign(&agent)?;
        self.commit(commit)?;
        Ok(())
    }

    /// Saves the changes done to a Resource to the Store.
    /// Signs the Commit using the Default Agent.
    /// Sends the Commit to the Atomic Server of the Subject.
    /// Fails if no Default Agent is set.
    fn commit_resource_changes_externally(&self, resource: &mut Resource) -> AtomicResult<()>
    where
        Self: std::marker::Sized,
    {
        let agent = self.get_default_agent().ok_or("No default agent set!")?;
        let commit = resource.get_commit_and_reset().sign(&agent)?;
        crate::client::post_commit(&commit)?;
        self.commit(commit)?;
        Ok(())
    }

    /// Create an Agent, storing its public key.
    /// An Agent is required for signing Commits.
    /// Returns a tuple of (subject, private_key).
    /// Make sure to store the private_key somewhere safe!
    fn create_agent(&self, name: &str) -> AtomicResult<crate::agents::Agent>
    where
        Self: std::marker::Sized,
    {
        let subject = format!("{}agents/{}", self.get_base_url(), name);
        let keypair = crate::agents::generate_keypair();
        let mut agent = Resource::new_instance(urls::AGENT, self)?;
        agent.set_subject(subject.clone());
        agent.set_propval_by_shortname("name", name)?;
        agent.set_propval_by_shortname("publickey", &keypair.public)?;
        self.add_resource(&agent)?;
        let agent = crate::agents::Agent {
            subject,
            key: keypair.private,
        };
        Ok(agent)
    }

    /// Fetches a resource, makes sure its subject matches.
    /// Save to the store.
    /// Only adds atoms with matching subjects will be added.
    fn fetch_resource(&self, subject: &str) -> AtomicResult<ResourceString> {
        let resource: ResourceString = crate::client::fetch_resource(subject)?;
        self.add_resource_string(subject.into(), &resource)?;
        Ok(resource)
    }

    /// Returns a full Resource with native Values.
    /// Note that this does _not_ construct dynamic Resources, such as collections.
    /// If you're not sure what to use, use `get_resource_extended`.
    fn get_resource(&self, subject: &str) -> AtomicResult<Resource>
    where
        Self: std::marker::Sized,
    {
        let resource_string = self.get_resource_string(subject)?;
        let mut res = Resource::new(subject.into(), self);
        for (prop_string, val_string) in resource_string {
            let propertyfull = self.get_property(&prop_string)?;
            let fullvalue = Value::new(&val_string, &propertyfull.data_type)?;
            res.set_propval(prop_string.clone(), fullvalue)?;
        }
        Ok(res)
        // Above code is a copy from:
        // let res = Resource::new_from_resource_string(subject.clone(), &resource, self)?;
        // But has some Size issues
    }

    /// Retrieves a Class from the store by subject URL and converts it into a Class useful for forms
    fn get_class(&self, subject: &str) -> AtomicResult<Class> {
        // The string representation of the Class
        let class_strings = self
            .get_resource_string(subject)
            .map_err(|e| format!("Class {} not found: {}", subject, e))?;
        let shortname = class_strings
            .get(urls::SHORTNAME)
            .ok_or("Class has no shortname")?;
        let description = class_strings
            .get(urls::DESCRIPTION)
            .ok_or("Class has no description")?;
        let requires_string = class_strings.get(urls::REQUIRES);
        let recommends_string = class_strings.get(urls::RECOMMENDS);

        let mut requires: Vec<Property> = Vec::new();
        let mut recommends: Vec<Property> = Vec::new();
        let get_properties = |resource_array: &str| -> Vec<Property> {
            let mut properties: Vec<Property> = vec![];
            let string_vec: Vec<String> = crate::parse::parse_json_array(&resource_array).unwrap();
            for prop_url in string_vec {
                properties.push(self.get_property(&prop_url).unwrap());
            }
            properties
        };
        if let Some(string) = requires_string {
            requires = get_properties(string);
        }
        if let Some(string) = recommends_string {
            recommends = get_properties(string);
        }
        let class = Class {
            requires,
            recommends,
            shortname: shortname.into(),
            subject: subject.into(),
            description: description.into(),
        };

        Ok(class)
    }

    /// Finds all classes (isA) for any subject.
    /// Returns an empty vector if there are none.
    fn get_classes_for_subject(&self, subject: &str) -> AtomicResult<Vec<Class>> {
        let resource = self.get_resource_string(subject)?;
        let classes_array_opt = resource.get(urls::IS_A);
        let classes_array = match classes_array_opt {
            Some(vec) => vec,
            None => return Ok(Vec::new()),
        };
        // .ok_or(format!("IsA property not present in {}", subject))?;
        let native = Value::new(classes_array, &DataType::ResourceArray)?;
        let vector = match native {
            Value::ResourceArray(vec) => vec,
            _ => return Err("Should be an array".into()),
        };
        let mut classes: Vec<Class> = Vec::new();
        for class in vector {
            classes.push(self.get_class(&class)?)
        }
        Ok(classes)
    }

    /// Constructs a Collection, which is a paginated list of items with some sorting applied.
    fn new_collection(
        &self,
        collection_builder: crate::collections::CollectionBuilder,
    ) -> AtomicResult<Collection>
    where
        Self: std::marker::Sized,
    {
        crate::collections::Collection::new(self, collection_builder)
    }

    /// Fetches a property by URL, returns a Property instance
    fn get_property(&self, url: &str) -> AtomicResult<Property> {
        let property_resource = self.get_resource_string(url)?;
        let property = Property {
            data_type: match_datatype(
                &property_resource
                    .get(urls::DATATYPE_PROP)
                    .ok_or(format!("Datatype not found for Property {}.", url))?,
            ),
            shortname: property_resource
                .get(urls::SHORTNAME)
                .ok_or(format!("Shortname not found for Property {}", url))?
                .into(),
            description: property_resource
                .get(urls::DESCRIPTION)
                .ok_or(format!("Description not found for Property {}", url))?
                .into(),
            class_type: property_resource.get(urls::CLASSTYPE_PROP).cloned(),
            subject: url.into(),
        };

        Ok(property)
    }

    /// Get's the resource, parses the Query parameters and calculates dynamic properties.
    /// Currently only used for constructing Collections.
    fn get_resource_extended(&self, subject: &str) -> AtomicResult<Resource>
    where
        Self: std::marker::Sized,
    {
        let mut url = url::Url::parse(subject)?;
        let clone = url.clone();
        let query_params = clone.query_pairs();
        url.set_query(None);
        let removed_query_params = url.to_string();
        let mut resource = self.get_resource(&removed_query_params)?;
        // If a certain class needs to be extended, add it to this match statement
        for class in resource.get_classes()? {
            match class.subject.as_ref() {
                urls::COLLECTION => {
                    return crate::collections::construct_collection(self, query_params, resource)
                }
                _ => {}
            }
        }
        Ok(resource)
    }

    /// Returns a collection with all resources in the store.
    /// WARNING: This could be very expensive!
    fn all_resources(&self) -> ResourceCollection;

    /// Adds an atom to the store. Does not do any validations
    fn add_atom(&self, atom: Atom) -> AtomicResult<()> {
        match self.get_resource_string(&atom.subject).as_mut() {
            Ok(resource) => {
                // Overwrites existing properties
                if let Some(_oldval) = resource.insert(atom.property, atom.value) {
                    // Remove the value from the Subject index
                    // self.index_value_remove(atom);
                };
                self.add_resource_string(atom.subject, &resource)?;
            }
            Err(_) => {
                let mut resource: ResourceString = HashMap::new();
                resource.insert(atom.property, atom.value);
                self.add_resource_string(atom.subject, &resource)?;
            }
        };
        Ok(())
    }

    /// Finds the URL of a shortname used in the context of a specific Resource.
    /// The Class, Properties and Shortnames of the Resource are used to find this URL
    fn property_shortname_to_url(
        &self,
        shortname: &str,
        resource: &ResourceString,
    ) -> AtomicResult<String> {
        for (prop_url, _value) in resource.iter() {
            let prop_resource = self.get_resource_string(&*prop_url)?;
            let prop_shortname = prop_resource
                .get(urls::SHORTNAME)
                .ok_or(format!("Property shortname for '{}' not found", prop_url))?;
            if prop_shortname == shortname {
                return Ok(prop_url.clone());
            }
        }
        Err(format!("Could not find shortname {}", shortname).into())
    }

    /// Finds the shortname for some property URL
    fn property_url_to_shortname(&self, url: &str) -> AtomicResult<String> {
        let resource = self.get_resource_string(url)?;
        let property_resource = resource
            .get(urls::SHORTNAME)
            .ok_or(format!("Could not get shortname prop for {}", url))?;

        Ok(property_resource.into())
    }

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
    /// let mut store = atomic_lib::Store::init();
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
            for (sub, resource) in self.all_resources() {
                for (property, value) in resource {
                    vec.push(Atom::new(sub.clone(), property, value))
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
        let mut find_in_resource = |subj: &str, resource: &ResourceString| {
            for (prop, val) in resource.iter() {
                if hasprop && q_property.as_ref().unwrap() == prop {
                    if hasval {
                        if val_equals(val) {
                            vec.push(Atom::new(subj.into(), prop.into(), val.into()))
                        }
                        break;
                    } else {
                        vec.push(Atom::new(subj.into(), prop.into(), val.into()))
                    }
                    break;
                } else if hasval && !hasprop && val_equals(val) {
                    vec.push(Atom::new(subj.into(), prop.into(), val.into()))
                }
            }
        };

        match q_subject {
            Some(sub) => match self.get_resource_string(&sub) {
                Ok(resource) => {
                    if hasprop | hasval {
                        find_in_resource(&sub, &resource);
                        Ok(vec)
                    } else {
                        Ok(resources::resourcestring_to_atoms(sub, resource))
                    }
                }
                Err(_) => Ok(vec),
            },
            None => {
                for (subj, properties) in self.all_resources() {
                    find_in_resource(&subj, &properties);
                }
                Ok(vec)
            }
        }
    }

    /// Accepts an Atomic Path string, returns the result value (resource or property value)
    /// E.g. `https://example.com description` or `thing isa 0`
    /// https://docs.atomicdata.dev/core/paths.html
    //  Todo: return something more useful, give more context.
    fn get_path(&self, atomic_path: &str, mapping: Option<&Mapping>) -> AtomicResult<PathReturn>
    where
        Self: std::marker::Sized,
    {
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
        // let mut resource = self.get_resource_string(&subject)?;
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
                        if vector.len() <= i as usize {
                            eprintln!(
                                "Too high index ({}) for array with length {}",
                                i,
                                vector.len()
                            );
                        }
                        let url = &vector[i as usize];
                        subject = url.into();
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
            let value = resource.get_shortname(&item).unwrap();
            let property = resource.resolve_shortname_to_property(item)?.unwrap();
            current = PathReturn::Atom(Box::new(RichAtom::new(
                subject.clone(),
                property,
                value.to_string(),
            )?))
        }
        Ok(current)
    }

    /// Loads the default store.
    /// Constructs various default collections.
    // Maybe these two functionalities should be split?
    fn populate(&self) -> AtomicResult<()>
    where
        Self: std::marker::Sized,
    {
        let ad3 = include_str!("../defaults/default_store.ad3");
        let atoms = crate::parse::parse_ad3(&String::from(ad3))?;
        self.add_atoms(atoms)?;

        use crate::collections::CollectionBuilder;

        let classes = CollectionBuilder {
            subject: format!("{}classes", self.get_base_url()),
            property: Some(urls::IS_A.into()),
            value: Some(urls::CLASS.into()),
            sort_by: None,
            sort_desc: false,
            page_size: 1000,
            current_page: 0,
        };
        self.add_resource(&self.new_collection(classes)?.to_resource(self)?)?;

        let properties = CollectionBuilder {
            subject: format!("{}properties", self.get_base_url()),
            property: Some(urls::IS_A.into()),
            value: Some(urls::PROPERTY.into()),
            sort_by: None,
            sort_desc: false,
            page_size: 1000,
            current_page: 0,
        };
        self.add_resource(&self.new_collection(properties)?.to_resource(self)?)?;

        let commits = CollectionBuilder {
            subject: format!("{}commits", self.get_base_url()),
            property: Some(urls::IS_A.into()),
            value: Some(urls::COMMIT.into()),
            sort_by: None,
            sort_desc: false,
            page_size: 1000,
            current_page: 0,
        };
        self.add_resource(&self.new_collection(commits)?.to_resource(self)?)?;

        let agents = CollectionBuilder {
            subject: format!("{}agents", self.get_base_url()),
            property: Some(urls::IS_A.into()),
            value: Some(urls::AGENT.into()),
            sort_by: None,
            sort_desc: false,
            page_size: 1000,
            current_page: 0,
        };
        self.add_resource(&self.new_collection(agents)?.to_resource(self)?)?;

        let collections = CollectionBuilder {
            subject: format!("{}collections", self.get_base_url()),
            property: Some(urls::IS_A.into()),
            value: Some(urls::COLLECTION.into()),
            sort_by: None,
            sort_desc: false,
            page_size: 1000,
            current_page: 0,
        };
        self.add_resource(&self.new_collection(collections)?.to_resource(self)?)?;

        Ok(())
    }

    /// Sets the default Agent for applying commits.
    fn set_default_agent(&self, agent: crate::agents::Agent);

    /// Performs a light validation, without fetching external data
    fn validate(&self) -> crate::validate::ValidationReport
    where
        Self: std::marker::Sized,
    {
        crate::validate::validate_store(self, false)
    }
}
