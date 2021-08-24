//! A resource is a set of Atoms that share a URL

use crate::values::Value;
use crate::{commit::CommitBuilder, errors::AtomicResult};
use crate::{
    mapping::is_url,
    schema::{Class, Property},
    Atom, Storelike,
};
use std::collections::HashMap;

/// A Resource is a set of Atoms that shares a single Subject.
/// A Resource only contains valid Values, but it _might_ lack required properties.
/// All changes to the Resource are applied after committing them (e.g. by using).
// #[derive(Clone, Debug, Serialize, Deserialize)]
#[derive(Clone, Debug)]
pub struct Resource {
    /// A hashMap of all the Property Value combinations
    propvals: PropVals,
    subject: String,
    commit: CommitBuilder,
}

/// Maps Property URLs to their values
pub type PropVals = HashMap<String, Value>;

impl Resource {
    /// Fetches all 'required' properties. Fails is any are missing in this Resource.
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
            for class in val.to_vec()? {
                classes.push(store.get_class(&class)?)
            }
        }
        Ok(classes)
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

    /// Create a new, empty Resource.
    pub fn new(subject: String) -> Resource {
        let propvals: PropVals = HashMap::new();
        Resource {
            propvals,
            subject: subject.clone(),
            commit: CommitBuilder::new(subject),
        }
    }

    /// Create a new instance of some Class.
    /// The subject is generated, but can be changed.
    /// Does not save the resource to the store.
    pub fn new_instance(class_url: &str, store: &impl Storelike) -> AtomicResult<Resource> {
        let propvals: PropVals = HashMap::new();
        let class = store.get_class(class_url)?;
        use rand::Rng;
        let random_string: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();
        let subject = format!(
            "{}/{}/{}",
            store.get_base_url(),
            &class.shortname,
            random_string
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
    /// Returns the generated Commit.
    pub fn save(&mut self, store: &impl Storelike) -> AtomicResult<crate::Commit> {
        let agent = store.get_default_agent()?;
        let commitbuilder = self.get_commit_builder().clone();
        let commit = commitbuilder.sign(&agent, store)?;
        let should_post = store.get_self_url().is_none();
        if should_post {
            // First, post it to the store where the data must reside
            crate::client::post_commit(&commit, store)?;
        }
        // If that succeeds, save it locally;
        commit.apply(store)?;
        // then, reset the internal CommitBuiler.
        self.reset_commit_builder();
        Ok(commit)
    }

    /// Saves the resource (with all the changes) to the store by creating a Commit.
    /// Uses default Agent to sign the Commit.
    /// Returns the generated Commit.
    /// Does not validate rights / hierarchy.
    /// Does not store these changes on the server of the Subject - the Commit will be lost, unless you handle it manually.
    pub fn save_locally(&mut self, store: &impl Storelike) -> AtomicResult<crate::Resource> {
        let agent = store.get_default_agent()?;
        let commitbuilder = self.get_commit_builder().clone();
        let commit = commitbuilder.sign(&agent, store)?;
        commit.apply(store)?;
        self.reset_commit_builder();
        let resource = commit.into_resource(store)?;
        Ok(resource)
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
        self.set_propval_unsafe(property_url, val)?;
        Ok(())
    }

    /// Inserts a Property/Value combination.
    /// Overwrites existing.
    /// Adds it to the commit builder.
    pub fn set_propval(
        &mut self,
        property: String,
        value: Value,
        store: &impl Storelike,
    ) -> AtomicResult<()> {
        let required_datatype = store.get_property(&property)?.data_type;
        if required_datatype == value.datatype() {
            self.set_propval_unsafe(property, value)
        } else {
            Err(format!("Datatype for subject '{}', property '{}', value '{}' did not match. Wanted '{}', got '{}'",
                self.get_subject(),
                property,
                value.to_string(),
                required_datatype,
                value.datatype()
            ).into())
        }
    }

    /// Does not validate property / datatype combination.
    /// Inserts a Property/Value combination.
    /// Overwrites existing.
    /// Adds it to the CommitBuilder.
    pub fn set_propval_unsafe(&mut self, property: String, value: Value) -> AtomicResult<()> {
        self.propvals.insert(property.clone(), value.clone());
        self.commit.set(property, value);
        Ok(())
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
        self.set_propval_unsafe(fullprop.subject, fullval)?;
        Ok(())
    }

    /// Changes the subject of the Resource.
    /// Does not 'move' the Resource
    /// See https://github.com/joepio/atomic/issues/44
    pub fn set_subject(&mut self, url: String) {
        self.commit.set_subject(url.clone());
        self.subject = url;
    }

    /// Converts Resource to JSON-AD string.
    pub fn to_json_ad(&self) -> AtomicResult<String> {
        let obj = crate::serialize::propvals_to_json_map(
            self.get_propvals(),
            Some(self.get_subject().clone()),
        )?;
        serde_json::to_string_pretty(&obj).map_err(|_| "Could not serialize to JSON-AD".into())
    }

    /// Converts Resource to plain JSON string.
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
    pub fn to_json_ld(&self, store: &impl Storelike) -> AtomicResult<String> {
        let obj = crate::serialize::propvals_to_json_ld(
            self.get_propvals(),
            Some(self.get_subject().clone()),
            store,
            true,
        )?;
        serde_json::to_string_pretty(&obj).map_err(|_| "Could not serialize to JSON-LD".into())
    }

    // This turned out to be more difficult than I though. I need the full Property, which the Resource does not possess.
    pub fn to_atoms(&self) -> AtomicResult<Vec<Atom>> {
        let mut atoms: Vec<Atom> = Vec::new();
        for (property, value) in self.propvals.iter() {
            let atom = Atom::new(self.subject.to_string(), property.clone(), value.clone());
            atoms.push(atom);
        }
        Ok(atoms)
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
            resource_from_store
                .get_shortname("is-a", &store)
                .unwrap()
                .to_string()
        );
        assert!(
            resource_from_store
                .get_shortname("is-a", &store)
                .unwrap()
                .to_string()
                == r#"["https://atomicdata.dev/classes/Class"]"#
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
            .sign(&agent, &store)
            .unwrap();
        commit.apply(&store).unwrap();
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
            resource_from_store
                .get_shortname("is-a", &store)
                .unwrap()
                .to_string()
        );
        assert!(
            resource_from_store
                .get_shortname("is-a", &store)
                .unwrap()
                .to_string()
                == r#"["https://atomicdata.dev/classes/Class"]"#
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
                assert!(val.to_vec().unwrap()[0] == urls::CLASS);
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
}
