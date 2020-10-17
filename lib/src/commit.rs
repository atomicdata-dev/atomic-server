//! Describe changes / mutations to data

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::{
    datatype::DataType, errors::AtomicResult, resources::PropVals, urls, Resource,
    Storelike, Value,
};

/// A Commit is a set of changes to a Resource.
/// Use CommitBuilder if you're programmatically constructing a Delta.
#[derive(Debug, Deserialize, Serialize)]
pub struct Commit {
    /// The subject URL that is to be modified by this Delta
    pub subject: String,
    /// The date it was created, as a unix timestamp
    pub created_at: u128,
    /// The URL of the one suggesting this Commit
    pub actor: String,
    /// The set of PropVals that need to be added.
    /// Overwrites existing values
    pub set: Option<std::collections::HashMap<String, String>>,
    /// The set of property URLs that need to be removed
    pub remove: Option<Vec<String>>,
    /// If set to true, deletes the entire resource
    pub destroy: Option<bool>,
    /// Hash signed by the actor
    pub signature: String,
}

impl Commit {
    /// Converts the Commit into a HashMap of strings.
    pub fn into_resource<'a>(&self, store: &'a dyn Storelike) -> AtomicResult<Resource<'a>> {
        let subject = format!(
            "{}/{}",
            store.get_base_url().unwrap_or("https://localhost".into()),
            self.signature
        );
        let mut resource = Resource::new_instance(urls::COMMIT, store)?;
        resource.set_subject(subject);
        resource.set_propval(
            urls::SUBJECT.into(),
            Value::new(&self.subject, &DataType::AtomicUrl).unwrap(),
        )?;
        resource.set_propval(
            urls::CREATED_AT.into(),
            Value::new(&self.created_at.to_string(), &DataType::Timestamp).unwrap(),
        )?;
        resource.set_propval(
            urls::ACTOR.into(),
            Value::new(&self.actor, &DataType::AtomicUrl).unwrap(),
        )?;
        if self.set.is_some() {
            let mut newset = PropVals::new();
            for (prop, stringval) in self.set.clone().unwrap() {
                let datatype = store.get_property(&prop)?.data_type;
                let val = Value::new(&stringval, &datatype)?;
                newset.insert(prop, val);
            }
            resource.set_propval(urls::SET.into(), newset.into())?;
        };
        if self.remove.is_some() && !self.remove.clone().unwrap().is_empty() {
            let remove_vec: Vec<String> = self.remove.clone().unwrap();
            resource.set_propval(urls::REMOVE.into(), remove_vec.into())?;
        };
        if self.destroy.is_some() && self.destroy.unwrap() {
            resource.set_propval(urls::DESTROY.into(), true.into())?;
        }
        resource.set_propval(
            urls::ACTOR.into(),
            Value::new(&self.actor, &DataType::AtomicUrl).unwrap(),
        )?;
        resource.set_propval(
            urls::SIGNATURE.into(),
            self.signature.clone().into(),
        )?;
        Ok(resource)
    }
}

/// Use this for creating Commits
pub struct CommitBuilder {
    /// The subject URL that is to be modified by this Delta
    subject: String,
    /// The date it was created, as a unix timestamp
    // pub created_at: u128,
    /// The URL of the one suggesting this Commit
    actor: String,
    /// The set of PropVals that need to be added.
    /// Overwrites existing values
    set: std::collections::HashMap<String, String>,
    /// The set of property URLs that need to be removed
    remove: HashSet<String>,
    /// If set to true, deletes the entire resource
    destroy: bool,
    // pub signature: String,
}

impl CommitBuilder {
    pub fn new(subject: String, actor: String) -> Self {
        CommitBuilder {
            subject,
            actor,
            set: HashMap::new(),
            remove: HashSet::new(),
            destroy: false,
        }
    }

    /// Creates the Commit.
    /// Does not send it - see atomic_lib::client::post_commit
    pub fn sign(self, _private_key: &str) -> Commit {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();

        Commit {
            subject: self.subject,
            actor: self.actor,
            set: Some(self.set),
            remove: Some(self.remove.into_iter().collect()),
            destroy: Some(self.destroy),
            created_at,
            // TODO: Hashing signature logic
            signature: "correct_signature".into(),
        }
    }

    pub fn set(&mut self, prop: String, val: String) {
        self.set.insert(prop, val);
    }

    pub fn remove(&mut self, prop: String) {
        self.remove.insert(prop);
    }

    /// Whether the resource needs to be removed fully
    pub fn destroy(&mut self, destroy: bool) {
        self.destroy = destroy
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Storelike;

    #[test]
    fn apply_commit() {
        let store = crate::Store::init();
        store.populate().unwrap();
        let subject = String::from("https://example.com/somesubject");
        let actor = "HashedThing".into();
        let mut partial_commit = CommitBuilder::new(subject.clone(), actor);
        let property = crate::urls::DESCRIPTION;
        let value = "Some value";
        partial_commit.set(property.into(), value.into());
        let full_commit = partial_commit.sign("correct_signature");
        let stored_commit = store.commit(full_commit).unwrap();
        let resource = store.get_resource(&subject).unwrap();
        assert!(resource.get(property).unwrap().to_string() == value);
        let found_commit = store.get_resource(stored_commit.get_subject()).unwrap();
        println!("{}",found_commit.get_subject());
        assert!(found_commit.get_shortname("subject").unwrap().to_string() == subject);
    }
}
