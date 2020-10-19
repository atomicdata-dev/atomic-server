//! Describe changes / mutations to data

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::{
    datatype::DataType, errors::AtomicResult, resources::PropVals, urls, Resource, Storelike, Value,
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
    pub signer: String,
    /// The set of PropVals that need to be added.
    /// Overwrites existing values
    pub set: Option<std::collections::HashMap<String, String>>,
    /// The set of property URLs that need to be removed
    pub remove: Option<Vec<String>>,
    /// If set to true, deletes the entire resource
    pub destroy: Option<bool>,
    /// Base64 encoded signature of the JSON serialized Commit
    pub signature: String,
}

impl Commit {
    /// Converts the Commit into a HashMap of strings.
    /// Creates an identifier using the base_url or a default.
    pub fn into_resource<'a>(self, store: &'a dyn Storelike) -> AtomicResult<Resource<'a>> {
        let subject = format!("{}commits/{}", store.get_base_url(), self.signature);
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
            urls::SIGNER.into(),
            Value::new(&self.signer, &DataType::AtomicUrl).unwrap(),
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
            urls::SIGNER.into(),
            Value::new(&self.signer, &DataType::AtomicUrl).unwrap(),
        )?;
        resource.set_propval(urls::SIGNATURE.into(), self.signature.into())?;
        Ok(resource)
    }
}

/// Use this for creating Commits
#[derive(Serialize)]
pub struct CommitBuilder {
    /// The subject URL that is to be modified by this Delta
    subject: String,
    /// The date it was created, as a unix timestamp
    created_at: Option<u128>,
    /// The URL of the one suggesting this Commit
    signer: String,
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
    pub fn new(subject: String, signer: String) -> Self {
        CommitBuilder {
            subject,
            created_at: None,
            signer,
            set: HashMap::new(),
            remove: HashSet::new(),
            destroy: false,
        }
    }

    /// Creates the Commit and signs it using a signature.
    /// Does not send it - see atomic_lib::client::post_commit
    pub fn sign(mut self, private_key: &str) -> AtomicResult<Commit> {
        self.created_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("You're a time traveler")
                .as_millis(),
        );

        // TODO: use actual stringified resource, also change in Storelike::commit
        // let stringified = serde_json::to_string(&self)?;
        let stringified = "full_resource";
        let private_key_bytes = base64::decode(private_key)?;
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(&private_key_bytes)
            .map_err(|_| "Can't create keypair")?;
        // let signature = some_lib::sign(string, private_key);
        let signature = base64::encode(key_pair.sign(&stringified.as_bytes()));

        Ok(Commit {
            subject: self.subject,
            signer: self.signer,
            set: Some(self.set),
            remove: Some(self.remove.into_iter().collect()),
            destroy: Some(self.destroy),
            created_at: self.created_at.unwrap(),
            // TODO: Hashing signature logic
            signature,
        })
    }

    /// Set Property / Value combinations that will either be created or overwritten.
    pub fn set(&mut self, prop: String, val: String) {
        self.set.insert(prop, val);
    }

    /// Set Property URLs which values to be removed
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
    fn agent_and_commit() {
        let store = crate::Store::init();
        store.populate().unwrap();
        // Creates a new Agent with some crypto stuff
        let (agent_subject, private_key) = store.create_agent("test_actor").unwrap();
        let subject = "https://localhost/new_thing";
        let mut commitbuiler = crate::commit::CommitBuilder::new(subject.into(), agent_subject);
        let property = crate::urls::DESCRIPTION;
        let value = "Some value";
        commitbuiler.set(property.into(), value.into());
        let commit = commitbuiler.sign(&private_key).unwrap();
        let commit_subject = commit.subject.clone();
        let _created_resource = store.commit(commit).unwrap();

        let resource = store.get_resource(&subject).unwrap();
        assert!(resource.get(property).unwrap().to_string() == value);
        let found_commit = store.get_resource(&commit_subject).unwrap();
        println!("{}", found_commit.get_subject());
        assert!(found_commit.get_shortname("description").unwrap().to_string() == value);
    }
}
