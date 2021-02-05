//! Describe changes / mutations to data

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::{
    datatype::DataType, errors::AtomicResult, resources::PropVals, urls, Resource, Storelike, Value,
};

/// A Commit is a set of changes to a Resource.
/// Use CommitBuilder if you're programmatically constructing a Delta.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Commit {
    /// The subject URL that is to be modified by this Delta
    #[serde(rename="https://atomicdata.dev/properties/subject")]
    pub subject: String,
    /// The date it was created, as a unix timestamp
    #[serde(rename="https://atomicdata.dev/properties/createdAt")]
    pub created_at: u64,
    /// The URL of the one signing this Commit
    #[serde(rename="https://atomicdata.dev/properties/signer")]
    pub signer: String,
    /// The set of PropVals that need to be added.
    /// Overwrites existing values
    #[serde(rename="https://atomicdata.dev/properties/set")]
    pub set: Option<std::collections::HashMap<String, String>>,
    /// The set of property URLs that need to be removed
    #[serde(rename="https://atomicdata.dev/properties/remove")]
    pub remove: Option<Vec<String>>,
    /// If set to true, deletes the entire resource
    #[serde(rename="https://atomicdata.dev/properties/destroy")]
    pub destroy: Option<bool>,
    /// Base64 encoded signature of the JSON serialized Commit
    #[serde(rename="https://atomicdata.dev/properties/signature")]
    pub signature: Option<String>,
}

impl Commit {
    /// Converts the Commit into a Resource with Atomic Values.
    /// Creates an identifier using the base_url or a default.
    pub fn into_resource(self, store: &impl Storelike) -> AtomicResult<Resource> {
        let subject = match self.signature.as_ref() {
            Some(sig) => format!("{}/commits/{}", store.get_base_url(), sig),
            None => {
                return Err("No signature set".into());
            }
        };
        let mut resource = Resource::new_instance(urls::COMMIT, store)?;
        resource.set_subject(subject);
        resource.set_propval(
            urls::SUBJECT.into(),
            Value::new(&self.subject, &DataType::AtomicUrl).unwrap(),
            store,
        )?;
        let mut classes: Vec<String> = Vec::new();
        classes.push(urls::COMMIT.into());
        resource.set_propval(urls::IS_A.into(), classes.into(), store)?;
        resource.set_propval(
            urls::CREATED_AT.into(),
            Value::new(&self.created_at.to_string(), &DataType::Timestamp).unwrap(),
            store,
        )?;
        resource.set_propval(
            urls::SIGNER.into(),
            Value::new(&self.signer, &DataType::AtomicUrl).unwrap(),
            store,
        )?;
        if self.set.is_some() {
            let mut newset = PropVals::new();
            for (prop, stringval) in self.set.clone().unwrap() {
                let datatype = store.get_property(&prop)?.data_type;
                let val = Value::new(&stringval, &datatype)?;
                newset.insert(prop, val);
            }
            resource.set_propval(urls::SET.into(), newset.into(), store)?;
        };
        if self.remove.is_some() && !self.remove.clone().unwrap().is_empty() {
            let remove_vec: Vec<String> = self.remove.clone().unwrap();
            resource.set_propval(urls::REMOVE.into(), remove_vec.into(), store)?;
        };
        if self.destroy.is_some() && self.destroy.unwrap() {
            resource.set_propval(urls::DESTROY.into(), true.into(), store)?;
        }
        resource.set_propval(
            urls::SIGNER.into(),
            Value::new(&self.signer, &DataType::AtomicUrl).unwrap(),
            store,
        )?;
        resource.set_propval(
            urls::SIGNATURE.into(),
            self.signature.unwrap().into(),
            store,
        )?;
        Ok(resource)
    }

    pub fn get_subject(&self) -> &str {
        &self.subject
    }

    /// Generates a deterministic serialized JSON representation of the Commit.
    /// Does not contain the signature, since this function is used to check if the signature is correct.
    pub fn serialize_deterministically(&self) -> AtomicResult<String> {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "subject".into(),
            serde_json::Value::String(self.subject.clone()),
        );
        obj.insert(
            "createdAt".into(),
            serde_json::Value::Number(self.created_at.into()),
        );
        obj.insert(
            "signer".into(),
            serde_json::Value::String(self.signer.clone()),
        );
        if let Some(set) = self.set.clone() {
            if !set.is_empty() {
                let mut collect: Vec<(String, String)> = set.into_iter().collect();
                // All keys should be ordered alphabetically
                collect.sort();
                // Make sure that the serializer does not mess up the order!
                let mut set_map = serde_json::Map::new();
                for (k, v) in collect.iter() {
                    set_map.insert(k.into(), serde_json::Value::String(v.into()));
                }
                obj.insert("set".into(), serde_json::Value::Object(set_map));
            }
        }
        if let Some(mut remove) = self.remove.clone() {
            if !remove.is_empty() {
                // These, too, should be sorted alphabetically
                remove.sort();
                obj.insert("remove".into(), remove.into());
            }
        }
        if let Some(destroy) = self.destroy {
            // Only include this key if it is true
            if destroy {
                obj.insert("destroy".into(), serde_json::Value::Bool(true));
            }
        }
        let string = serde_json::to_string(&obj)?;
        Ok(string)
    }
}

/// Use this for creating Commits.
#[derive(Clone, Serialize)]
pub struct CommitBuilder {
    /// The subject URL that is to be modified by this Delta
    subject: String,
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
    /// Start constructing a Commit.
    pub fn new(subject: String) -> Self {
        CommitBuilder {
            subject,
            set: HashMap::new(),
            remove: HashSet::new(),
            destroy: false,
        }
    }

    /// Creates the Commit and signs it using a signature.
    /// Does not send it - see atomic_lib::client::post_commit
    /// Private key is the base64 encoded pkcs8 for the signer
    pub fn sign(self, agent: &crate::agents::Agent) -> AtomicResult<Commit> {
        let now = crate::datetime_helpers::now();
        sign_at(self, agent, now)
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

/// Signs a CommitBuilder at a specific unix timestamp.
fn sign_at(commitbuilder: CommitBuilder, agent: &crate::agents::Agent, sign_date: u64) -> AtomicResult<Commit> {
    let mut commit = Commit {
        subject: commitbuilder.subject,
        signer: agent.subject.clone(),
        set: Some(commitbuilder.set),
        remove: Some(commitbuilder.remove.into_iter().collect()),
        destroy: Some(commitbuilder.destroy),
        created_at: sign_date as u64,
        signature: None,
    };
    let stringified = commit
        .serialize_deterministically()
        .map_err(|e| format!("Failed serializing commit: {}", e))?;
    let private_key_bytes = base64::decode(agent.private_key.clone())
        .map_err(|e| format!("Failed decoding private key {}: {}", agent.private_key.clone(), e))?;
    let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(&private_key_bytes)
        .map_err(|_| "Can't create Ed25519 keypair from Agent's Private Key.")?;
    let signature = base64::encode(key_pair.sign(&stringified.as_bytes()));
    commit.signature = Some(signature);
    Ok(commit)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Storelike, agents::Agent};

    #[test]
    fn agent_and_commit() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let agent = store.create_agent("test_actor").unwrap();
        let subject = "https://localhost/new_thing";
        let mut commitbuiler = crate::commit::CommitBuilder::new(subject.into());
        let property1 = crate::urls::DESCRIPTION;
        let value1 = "Some value";
        commitbuiler.set(property1.into(), value1.into());
        let property2 = crate::urls::SHORTNAME;
        let value2 = "someval";
        commitbuiler.set(property2.into(), value2.into());
        let commit = commitbuiler.sign(&agent).unwrap();
        let commit_subject = commit.get_subject().to_string();
        let _created_resource = store.commit(commit).unwrap();

        let resource = store.get_resource(&subject).unwrap();
        assert!(resource.get(property1).unwrap().to_string() == value1);
        let found_commit = store.get_resource(&commit_subject).unwrap();
        println!("{}", found_commit.get_subject());

        assert!(
            found_commit
                .get_shortname("description", &store)
                .unwrap()
                .to_string()
                == value1
        );
    }

    #[test]
    fn serialize_commit() {
        let mut set: HashMap<String, String> = HashMap::new();
        set.insert(urls::SHORTNAME.into(), "shortname".into());
        set.insert(urls::DESCRIPTION.into(), "Some description".into());
        let mut remove = Vec::new();
        remove.push(String::from(urls::IS_A));
        let destroy = false;
        let commit = Commit {
            subject: String::from("https://localhost/test"),
            created_at: 1603638837,
            signer: String::from("https://localhost/author"),
            set: Some(set),
            remove: Some(remove),
            destroy: Some(destroy),
            signature: None,
        };
        let serialized = commit.serialize_deterministically().unwrap();
        let should_be = r#"{"createdAt":1603638837,"remove":["https://atomicdata.dev/properties/isA"],"set":{"https://atomicdata.dev/properties/description":"Some description","https://atomicdata.dev/properties/shortname":"shortname"},"signer":"https://localhost/author","subject":"https://localhost/test"}"#;
        assert!(serialized == should_be)
    }

    #[test]
    fn signature_matches() {
        let private_key = "MFMCAQEwBQYDK2VwBCIEIItEZm3wbIpx7qK/+UPT2DqsZWwsD50M3QDLyTwPGVKEoSMDIQAivODlyb+pfdNQGbu7EJ2w3f8+2suBNenGNsE8KsI6pA==";
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let agent = Agent::new_from_private_key("name".into(), &store, private_key.into());
        assert_eq!(&agent.subject, "http://localhost/agents/Irzg5cm/qX3TUBm7uxCdsN3/PtrLgTXpxjbBPCrCOqQ=");
        store.add_resource(&agent.to_resource(&store).unwrap()).unwrap();
        let subject = "https://localhost/new_thing";
        let mut commitbuilder = crate::commit::CommitBuilder::new(subject.into());
        let property1 = crate::urls::DESCRIPTION;
        let value1 = "Some value";
        commitbuilder.set(property1.into(), value1.into());
        let property2 = crate::urls::SHORTNAME;
        let value2 = "someval";
        commitbuilder.set(property2.into(), value2.into());
        let commit = sign_at(commitbuilder, &agent, 0).unwrap();
        let signature = commit.signature.clone().unwrap();
        assert_eq!(signature, "Nmyp7gmLhf5GZw2mCOXjXqfsSDeA4GIiYFQh2P/0xsJENwetnzmDDA1lUyzr9mpc32JxIzCVEgTsyi2GzK/ACQ==");
    }
}
