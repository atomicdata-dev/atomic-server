//! A resource is a set of Atoms that share a URL

use crate::commit::{CommitOpts, CommitResponse};
use crate::urls;
use crate::utils::random_string;
use crate::values::{SubResource, Value};
use crate::{commit::CommitBuilder, errors::AtomicResult};
use crate::{
    mapping::is_url,
    schema::{Class, Property},
    Atom, Storelike,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::instrument;

/// A Resource is a set of Atoms that shares a single Subject.
/// A Resource only contains valid Values, but it _might_ lack required properties.
/// All changes to the Resource are applied after committing them (e.g. by using).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Resource {
    /// A hashMap of all the Property Value combinations
    propvals: PropVals,
    subject: String,
    commit: CommitBuilder,
}

/// Maps Property URLs to their values
pub type PropVals = HashMap<String, Value>;

impl Resource {
    /// Fetches all 'required' properties. Returns an error if any are missing in this Resource.
    pub fn check_required_props(&self, store: &impl Storelike) -> AtomicResult<()> {
        let classvec = self.get_classes(store)?;
        for class in classvec.iter() {
            for required_prop in class.requires.clone() {
                self.get(&required_prop).map_err(|_e| {
                    format!(
                        "Property {} missing. Is required in class {} ",
                        &required_prop, class.subject
                    )
                })?;
            }
        }
        Ok(())
    }

    /// Removes / deletes the resource from the store by performing a Commit.
    pub fn destroy(
        &mut self,
        store: &impl Storelike,
    ) -> AtomicResult<crate::commit::CommitResponse> {
        self.commit.destroy(true);
        self.save(store)
            .map_err(|e| format!("Failed to destroy {} : {}", self.subject, e).into())
    }

    pub fn from_propvals(propvals: PropVals, subject: String) -> Resource {
        Resource {
            propvals,
            commit: CommitBuilder::new(subject.clone()),
            subject,
        }
    }

    /// Get a value by property URL
    pub fn get(&self, property_url: &str) -> AtomicResult<&Value> {
        Ok(self.propvals.get(property_url).ok_or(format!(
            "Property {} for resource {} not found",
            property_url, self.subject
        ))?)
    }

    pub fn get_commit_builder(&self) -> &CommitBuilder {
        &self.commit
    }

    /// Checks if the classes are there, if not, fetches them.
    /// Returns an empty vector if there are no classes found.
    pub fn get_classes(&self, store: &impl Storelike) -> AtomicResult<Vec<Class>> {
        let mut classes: Vec<Class> = Vec::new();
        if let Ok(val) = self.get(crate::urls::IS_A) {
            for class in val.to_subjects(None)? {
                classes.push(store.get_class(&class)?)
            }
        }
        Ok(classes)
    }

    /// Returns the first item of the is_ array
    pub fn get_main_class(&self) -> AtomicResult<String> {
        if let Ok(val) = self.get(crate::urls::IS_A) {
            Ok(val.to_subjects(None)?[0].clone())
        } else {
            Err(format!("Resource {} has no class", self.subject).into())
        }
    }

    /// Returns the `Parent` of this Resource.
    /// Throws in case of recursion
    pub fn get_parent(&self, store: &impl Storelike) -> AtomicResult<Resource> {
        match self.get(urls::PARENT) {
            Ok(parent_val) => {
                match store.get_resource(&parent_val.to_string()) {
                    Ok(parent) => {
                        if self.get_subject() == parent.get_subject() {
                            return Err(format!(
                                "There is a circular relationship in {} (parent = same resource).",
                                self.get_subject()
                            )
                            .into());
                        }
                        // Check write right
                        Ok(parent)
                    }
                    Err(_err) => Err(format!(
                        "Parent of {} ({}) not found: {}",
                        self.get_subject(),
                        parent_val,
                        _err
                    )
                    .into()),
                }
            }
            Err(e) => Err(format!("Parent of {} not found: {}", self.get_subject(), e).into()),
        }
    }

    /// Returns all PropVals.
    /// Useful if you want to iterate over all Atoms / Properties.
    pub fn get_propvals(&self) -> &PropVals {
        &self.propvals
    }

    /// Gets a value by its property shortname or property URL.
    // Todo: should use both the Classes AND the existing props
    pub fn get_shortname(&self, shortname: &str, store: &impl Storelike) -> AtomicResult<&Value> {
        let prop = self.resolve_shortname_to_property(shortname, store)?;
        self.get(&prop.subject)
    }

    pub fn get_subject(&self) -> &String {
        &self.subject
    }

    /// Returns all PropVals.
    pub fn into_propvals(self) -> PropVals {
        self.propvals
    }

    /// Create a new, empty Resource.
    pub fn new(subject: String) -> Resource {
        let propvals: PropVals = HashMap::new();
        Resource {
            propvals,
            subject: subject.clone(),
            commit: CommitBuilder::new(subject),
        }
    }

    /// Create a new resource with a generated Subject
    pub fn new_generate_subject(store: &impl Storelike) -> Resource {
        let generated = format!("{}/{}", store.get_server_url(), random_string(10));

        Resource::new(generated)
    }

    /// Create a new instance of some Class.
    /// The subject is generated, but can be changed.
    /// Does not save the resource to the store.
    pub fn new_instance(class_url: &str, store: &impl Storelike) -> AtomicResult<Resource> {
        let propvals: PropVals = HashMap::new();
        let class = store.get_class(class_url)?;
        let subject = format!(
            "{}/{}/{}",
            store.get_server_url(),
            &class.shortname,
            random_string(10)
        );
        let mut resource = Resource {
            propvals,
            subject: subject.clone(),
            commit: CommitBuilder::new(subject),
        };
        let class_urls = Vec::from([String::from(class_url)]);
        resource.set_propval(crate::urls::IS_A.into(), class_urls.into(), store)?;
        Ok(resource)
    }

    /// Appends a Resource to a specific property through the commitbuilder.
    /// Useful if you want to have compact Commits that add things to existing ResourceArrays.
    pub fn push_propval(
        &mut self,
        property: &str,
        value: SubResource,
        skip_existing: bool,
        // TODO: Use Store to validate datatype
        _store: &impl Storelike,
    ) -> AtomicResult<()> {
        let mut vec = match self.propvals.get(property) {
            Some(some) => match some {
                Value::ResourceArray(vec) => {
                    if skip_existing {
                        let str_val = value.to_string();
                        for i in vec {
                            if i.to_string() == str_val {
                                // Value already exists
                                return Ok(());
                            }
                        }
                    }
                    vec.to_owned()
                }
                _other => return Err("Wrong datatype, expected ResourceArray".into()),
            },
            None => Vec::new(),
        };
        vec.push(value.clone());
        self.propvals.insert(property.into(), vec.into());
        self.commit.push_propval(property, value)?;
        Ok(())
    }

    /// Remove a propval from a resource by property URL.
    pub fn remove_propval(&mut self, property_url: &str) {
        self.propvals.remove_entry(property_url);
        self.commit.remove(property_url.into())
    }

    /// Remove a propval from a resource by property URL or shortname.
    /// Returns error if propval does not exist in this resource or its class.
    pub fn remove_propval_shortname(
        &mut self,
        property_shortname: &str,
        store: &impl Storelike,
    ) -> AtomicResult<()> {
        let property_url = self.resolve_shortname_to_property(property_shortname, store)?;
        self.remove_propval(&property_url.subject);
        Ok(())
    }

    /// Tries to resolve the shortname of a Property to a Property.
    /// Currently only tries the shortnames for linked classes - not for other properties.
    // TODO: Not spec compliant - does not use the correct order (required, recommended, other)
    // TODO: Seems more costly then needed. Maybe resources need to keep a hashmap for resolving shortnames?
    pub fn resolve_shortname_to_property(
        &self,
        shortname: &str,
        store: &impl Storelike,
    ) -> AtomicResult<Property> {
        // If it's a URL, were done quickly!
        if is_url(shortname) {
            return store.get_property(shortname);
        }
        // First, iterate over all existing properties, see if any of these work.
        for (url, _val) in self.propvals.iter() {
            if let Ok(prop) = store.get_property(url) {
                if prop.shortname == shortname {
                    return Ok(prop);
                }
            }
        }
        // If that fails, load the classes for the resource, iterate over these
        let classes = self.get_classes(store)?;
        // Loop over all Requires and Recommends props
        for class in classes {
            for required_prop_subject in class.requires {
                let required_prop = store.get_property(&required_prop_subject)?;
                if required_prop.shortname == shortname {
                    return Ok(required_prop);
                }
            }
            for recommended_prop_subject in class.recommends {
                let recommended_prop = store.get_property(&recommended_prop_subject)?;
                if recommended_prop.shortname == shortname {
                    return Ok(recommended_prop);
                }
            }
        }
        Err(format!("Shortname '{}' for '{}' not found", shortname, self.subject).into())
    }

    pub fn reset_commit_builder(&mut self) {
        self.commit = CommitBuilder::new(self.get_subject().clone());
    }

    /// Saves the resource (with all the changes) to the store by creating a Commit.
    /// Uses default Agent to sign the Commit.
    /// Stores changes on the Subject's Server by sending a Commit.
    /// Returns the generated Commit, the new Resource and the old Resource.
    pub fn save(&mut self, store: &impl Storelike) -> AtomicResult<crate::commit::CommitResponse> {
        let agent = store.get_default_agent()?;
        let commit_builder = self.get_commit_builder().clone();
        let commit = commit_builder.sign(&agent, store, self)?;
        // If the current client is a server, and the subject is hosted here, don't post
        let should_post = if let Some(self_url) = store.get_self_url() {
            !self.subject.starts_with(&self_url)
        } else {
            // Current client is not a server, has no own persisted store
            true
        };
        if should_post {
            crate::client::post_commit(&commit, store)?;
        }
        let opts = CommitOpts {
            validate_schema: true,
            validate_signature: false,
            validate_timestamp: false,
            validate_rights: false,
            // TODO: auto-merge should work before we enable this https://github.com/atomicdata-dev/atomic-data-rust/issues/412
            validate_previous_commit: false,
            update_index: true,
        };
        let commit_response = commit.apply_opts(store, &opts)?;
        if let Some(new) = &commit_response.resource_new {
            self.subject = new.subject.clone();
            self.propvals = new.propvals.clone();
        }
        self.reset_commit_builder();
        Ok(commit_response)
    }

    /// Saves the resource (with all the changes) to the store by creating a Commit.
    /// Uses default Agent to sign the Commit.
    /// Returns the generated Commit and the new Resource.
    /// Does not validate rights / hierarchy.
    /// Does not store these changes on the server of the Subject - the Commit will be lost, unless you handle it manually.
    pub fn save_locally(&mut self, store: &impl Storelike) -> AtomicResult<CommitResponse> {
        let agent = store.get_default_agent()?;
        let commitbuilder = self.get_commit_builder().clone();
        let commit = commitbuilder.sign(&agent, store, self)?;
        let opts = CommitOpts {
            validate_schema: true,
            validate_signature: false,
            validate_timestamp: false,
            validate_rights: false,
            // https://github.com/atomicdata-dev/atomic-data-rust/issues/412
            validate_previous_commit: false,
            update_index: true,
        };
        let commit_response = commit.apply_opts(store, &opts)?;
        if let Some(new) = &commit_response.resource_new {
            self.subject = new.subject.clone();
            self.propvals = new.propvals.clone();
        }
        self.reset_commit_builder();
        Ok(commit_response)
    }

    /// Overwrites the is_a (Class) of the Resource.
    pub fn set_class(&mut self, is_a: &str, store: &impl Storelike) -> AtomicResult<()> {
        self.set_propval(
            crate::urls::IS_A.into(),
            Value::ResourceArray([is_a.into()].into()),
            store,
        )?;
        Ok(())
    }

    /// Insert a Property/Value combination.
    /// Overwrites existing Property/Value.
    /// Validates the datatype.
    pub fn set_propval_string(
        &mut self,
        property_url: String,
        value: &str,
        store: &impl Storelike,
    ) -> AtomicResult<()> {
        let fullprop = store.get_property(&property_url).map_err(|e| {
            format!(
                "Failed setting propval for '{}' because property '{}' could not be found. {}",
                self.get_subject(),
                property_url,
                e
            )
        })?;
        let val = Value::new(value, &fullprop.data_type)?;
        self.set_propval_unsafe(property_url, val);
        Ok(())
    }

    /// Inserts a Property/Value combination.
    /// Checks datatype.
    /// Overwrites existing.
    /// Adds the change to the commit builder's `set` map.
    pub fn set_propval(
        &mut self,
        property: String,
        value: Value,
        store: &impl Storelike,
    ) -> AtomicResult<()> {
        let full_prop = store.get_property(&property)?;
        if let Some(allowed) = full_prop.allows_only {
            if !allowed.contains(&value.to_string()) {
                return Err(format!(
                    "Property '{}' does not allow value '{}'. Allowed: {:?}",
                    property, value, allowed
                )
                .into());
            }
        }
        if full_prop.data_type == value.datatype() {
            self.set_propval_unsafe(property, value);
            Ok(())
        } else {
            Err(format!("Datatype for subject '{}', property '{}', value '{}' did not match. Wanted '{}', got '{}'",
                self.get_subject(),
                property,
                value,
                full_prop.data_type,
                value.datatype()
            ).into())
        }
    }

    /// Does not validate property / datatype combination.
    /// Inserts a Property/Value combination.
    /// Overwrites existing.
    /// Adds it to the CommitBuilder.
    pub fn set_propval_unsafe(&mut self, property: String, value: Value) {
        self.propvals.insert(property.clone(), value.clone());
        self.commit.set(property, value);
    }

    /// Sets a property / value combination.
    /// Property can be a shortname (e.g. 'description' instead of the full URL).
    /// Returns error if propval does not exist in this resource or its class.
    pub fn set_propval_shortname(
        &mut self,
        property: &str,
        value: &str,
        store: &impl Storelike,
    ) -> AtomicResult<()> {
        let fullprop = self.resolve_shortname_to_property(property, store)?;
        let fullval = Value::new(value, &fullprop.data_type)?;
        self.set_propval_unsafe(fullprop.subject, fullval);
        Ok(())
    }

    /// Overwrites all current PropVals. Does not perform validation.
    pub fn set_propvals_unsafe(&mut self, propvals: PropVals) {
        self.propvals = propvals;
    }

    /// Changes the subject of the Resource.
    /// Does not 'move' the Resource
    /// See https://github.com/joepio/atomic/issues/44
    pub fn set_subject(&mut self, url: String) {
        self.commit.set_subject(url.clone());
        self.subject = url;
    }

    /// Converts Resource to JSON-AD string.
    #[instrument(skip_all)]
    pub fn to_json_ad(&self) -> AtomicResult<String> {
        let obj = crate::serialize::propvals_to_json_ad_map(
            self.get_propvals(),
            Some(self.get_subject().clone()),
        )?;
        serde_json::to_string_pretty(&obj).map_err(|_| "Could not serialize to JSON-AD".into())
    }

    /// Converts Resource to plain JSON string.
    #[instrument(skip_all)]
    pub fn to_json(&self, store: &impl Storelike) -> AtomicResult<String> {
        let obj = crate::serialize::propvals_to_json_ld(
            self.get_propvals(),
            Some(self.get_subject().clone()),
            store,
            false,
        )?;
        serde_json::to_string_pretty(&obj).map_err(|_| "Could not serialize to JSON".into())
    }

    /// Converts Resource to JSON-LD string, with @context object and RDF compatibility.
    #[instrument(skip_all)]
    pub fn to_json_ld(&self, store: &impl Storelike) -> AtomicResult<String> {
        let obj = crate::serialize::propvals_to_json_ld(
            self.get_propvals(),
            Some(self.get_subject().clone()),
            store,
            true,
        )?;
        serde_json::to_string_pretty(&obj).map_err(|_| "Could not serialize to JSON-LD".into())
    }

    #[instrument(skip_all)]
    pub fn to_atoms(&self) -> AtomicResult<Vec<Atom>> {
        let mut atoms: Vec<Atom> = Vec::new();
        for (property, value) in self.propvals.iter() {
            let atom = Atom::new(self.subject.to_string(), property.clone(), value.clone());
            atoms.push(atom);
        }
        Ok(atoms)
    }

    #[instrument(skip_all)]
    #[cfg(feature = "rdf")]
    /// Serializes the Resource to the RDF N-Triples format.
    pub fn to_n_triples(&self, store: &impl Storelike) -> AtomicResult<String> {
        crate::serialize::atoms_to_ntriples(self.to_atoms()?, store)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{test_utils::init_store, urls};

    #[test]
    fn get_and_set_resource_props() {
        let store = init_store();
        let mut resource = store.get_resource(urls::CLASS).unwrap();
        assert!(
            resource
                .get_shortname("shortname", &store)
                .unwrap()
                .to_string()
                == "class"
        );
        resource
            .set_propval_shortname("shortname", "something-valid", &store)
            .unwrap();
        assert!(
            resource
                .get_shortname("shortname", &store)
                .unwrap()
                .to_string()
                == "something-valid"
        );
        resource
            .set_propval_shortname("shortname", "should not contain spaces", &store)
            .unwrap_err();
    }

    #[test]
    fn check_required_props() {
        let store = init_store();
        let mut new_resource = Resource::new_instance(urls::CLASS, &store).unwrap();
        new_resource
            .set_propval_shortname("shortname", "should-fail", &store)
            .unwrap();
        new_resource.check_required_props(&store).unwrap_err();
        new_resource
            .set_propval_shortname("description", "Should succeed!", &store)
            .unwrap();
        new_resource.check_required_props(&store).unwrap();
    }

    #[test]
    fn new_instance() {
        let store = init_store();
        let mut new_resource = Resource::new_instance(urls::CLASS, &store).unwrap();
        new_resource
            .set_propval_shortname("shortname", "person", &store)
            .unwrap();
        assert!(
            new_resource
                .get_shortname("shortname", &store)
                .unwrap()
                .to_string()
                == "person"
        );
        new_resource
            .set_propval_shortname("shortname", "human", &store)
            .unwrap();
        new_resource
            .set_propval_shortname("description", "A real human being", &store)
            .unwrap();
        new_resource.save_locally(&store).unwrap();
        assert!(
            new_resource
                .get_shortname("shortname", &store)
                .unwrap()
                .to_string()
                == "human"
        );
        let resource_from_store = store.get_resource(new_resource.get_subject()).unwrap();
        assert!(
            resource_from_store
                .get_shortname("shortname", &store)
                .unwrap()
                .to_string()
                == "human"
        );
        println!(
            "{}",
            resource_from_store.get_shortname("is-a", &store).unwrap()
        );
        assert_eq!(
            resource_from_store
                .get_shortname("is-a", &store)
                .unwrap()
                .to_string(),
            "https://atomicdata.dev/classes/Class"
        );
        assert!(resource_from_store.get_classes(&store).unwrap()[0].shortname == "class");
    }

    #[test]
    fn new_instance_using_commit() {
        let store = init_store();
        let agent = store.get_default_agent().unwrap();
        let mut new_resource = Resource::new_instance(urls::CLASS, &store).unwrap();
        new_resource
            .set_propval_shortname("shortname", "person", &store)
            .unwrap();
        assert!(
            new_resource
                .get_shortname("shortname", &store)
                .unwrap()
                .to_string()
                == "person"
        );
        new_resource
            .set_propval_shortname("shortname", "human", &store)
            .unwrap();
        new_resource
            .set_propval_shortname("description", "A real human being", &store)
            .unwrap();
        let commit = new_resource
            .get_commit_builder()
            .clone()
            .sign(&agent, &store, &new_resource)
            .unwrap();
        commit
            .apply_opts(
                &store,
                &CommitOpts {
                    validate_schema: true,
                    validate_signature: true,
                    validate_timestamp: true,
                    validate_rights: false,
                    validate_previous_commit: true,
                    update_index: true,
                },
            )
            .unwrap();
        assert!(
            new_resource
                .get_shortname("shortname", &store)
                .unwrap()
                .to_string()
                == "human"
        );
        let resource_from_store = store.get_resource(new_resource.get_subject()).unwrap();
        assert!(
            resource_from_store
                .get_shortname("shortname", &store)
                .unwrap()
                .to_string()
                == "human"
        );
        println!(
            "{}",
            resource_from_store.get_shortname("is-a", &store).unwrap()
        );
        assert_eq!(
            resource_from_store
                .get_shortname("is-a", &store)
                .unwrap()
                .to_string(),
            "https://atomicdata.dev/classes/Class"
        );
        assert!(resource_from_store.get_classes(&store).unwrap()[0].shortname == "class");
    }

    #[test]
    fn iterate() {
        let store = init_store();
        let new_resource = Resource::new_instance(urls::CLASS, &store).unwrap();
        let mut success = false;
        for (prop, val) in new_resource.get_propvals() {
            if prop == urls::IS_A {
                assert!(val.to_subjects(None).unwrap()[0] == urls::CLASS);
                success = true;
            }
        }
        assert!(success);
    }

    #[test]
    fn save() {
        let store = init_store();
        let property: String = urls::DESCRIPTION.into();
        let value = Value::Markdown("joe".into());
        let mut new_resource = Resource::new_instance(urls::CLASS, &store).unwrap();
        new_resource
            .set_propval(property.clone(), value.clone(), &store)
            .unwrap();
        // Should fail, because a propval is missing
        assert!(new_resource.save_locally(&store).is_err());
        new_resource
            .set_propval(urls::SHORTNAME.into(), Value::Slug("joe".into()), &store)
            .unwrap();
        let subject = new_resource.get_subject().clone();
        println!("subject new {}", new_resource.get_subject());
        new_resource.save_locally(&store).unwrap();
        let found_resource = store.get_resource(&subject).unwrap();
        println!("subject found {}", found_resource.get_subject());
        println!("subject all {:?}", found_resource.get_propvals());

        let found_prop = found_resource.get(&property).unwrap().clone();
        assert_eq!(found_prop.to_string(), value.to_string());
    }

    #[test]
    fn push_propval() {
        let store = init_store();
        let property: String = urls::CHILDREN.into();
        let append_value = "http://localhost/someURL";
        let mut resource = Resource::new_generate_subject(&store);
        resource
            .push_propval(&property, append_value.into(), false, &store)
            .unwrap();
        let vec = resource.get(&property).unwrap().to_subjects(None).unwrap();
        assert_eq!(
            append_value,
            vec.first().unwrap(),
            "The first element should be the appended value"
        );
        let resp = resource.save_locally(&store).unwrap();
        assert!(resp.commit_struct.push.is_some());

        let new_val = resp
            .resource_new
            .unwrap()
            .get(&property)
            .unwrap()
            .to_subjects(None)
            .unwrap();
        assert_eq!(new_val.first().unwrap(), append_value);
    }
}
