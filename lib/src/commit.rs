//! Describe changes / mutations to data

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use urls::{SET, SIGNER};

use crate::{
    datatype::DataType, errors::AtomicResult, resources::PropVals, urls, Atom, Resource, Storelike,
    Value,
};

/// A Commit is a set of changes to a Resource.
/// Use CommitBuilder if you're programmatically constructing a Delta.
#[derive(Clone, Debug, Serialize)]
pub struct Commit {
    /// The subject URL that is to be modified by this Delta
    #[serde(rename = "https://atomicdata.dev/properties/subject")]
    pub subject: String,
    /// The date it was created, as a unix timestamp
    #[serde(rename = "https://atomicdata.dev/properties/createdAt")]
    pub created_at: i64,
    /// The URL of the one signing this Commit
    #[serde(rename = "https://atomicdata.dev/properties/signer")]
    pub signer: String,
    /// The set of PropVals that need to be added.
    /// Overwrites existing values
    #[serde(rename = "https://atomicdata.dev/properties/set")]
    pub set: Option<std::collections::HashMap<String, Value>>,
    /// The set of property URLs that need to be removed
    #[serde(rename = "https://atomicdata.dev/properties/remove")]
    pub remove: Option<Vec<String>>,
    /// If set to true, deletes the entire resource
    #[serde(rename = "https://atomicdata.dev/properties/destroy")]
    pub destroy: Option<bool>,
    /// Base64 encoded signature of the JSON serialized Commit
    #[serde(rename = "https://atomicdata.dev/properties/signature")]
    pub signature: Option<String>,
    /// The URL of the Commit
    pub url: Option<String>,
}

impl Commit {
    /// Apply a single signed Commit to the store.
    /// Creates, edits or destroys a resource.
    /// Checks if the signature is created by the Agent, and validates the data shape.
    /// Does not check if the correct rights are present.
    /// If you need more control over which checks to perform, use apply_opts
    pub fn apply(&self, store: &impl Storelike) -> AtomicResult<Resource> {
        self.apply_opts(store, true, true, false, false)
    }

    /// Apply a single signed Commit to the store.
    /// Creates, edits or destroys a resource.
    /// Allows for control over which validations should be performed.
    /// TODO: Should check if the Agent has the correct rights.
    pub fn apply_opts(
        &self,
        store: &impl Storelike,
        validate_schema: bool,
        validate_signature: bool,
        validate_timestamp: bool,
        validate_rights: bool,
    ) -> AtomicResult<Resource> {
        let subject_url =
            url::Url::parse(&self.subject).map_err(|e| format!("Subject is not a URL. {}", e))?;
        if subject_url.query().is_some() {
            return Err("Subject URL cannot have query parameters".into());
        }

        if validate_signature {
            let signature = match self.signature.as_ref() {
                Some(sig) => sig,
                None => return Err("No signature set".into()),
            };
            // TODO: Check if commit.agent has the rights to update the resource
            let pubkey_b64 = store
                .get_resource(&self.signer)?
                .get(urls::PUBLIC_KEY)?
                .to_string();
            let agent_pubkey = base64::decode(pubkey_b64)?;
            let stringified_commit = self.serialize_deterministically_json_ad(store)?;
            let peer_public_key =
                ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, agent_pubkey);
            let signature_bytes = base64::decode(signature.clone())?;
            peer_public_key
                .verify(stringified_commit.as_bytes(), &signature_bytes)
                .map_err(|_e| {
                    format!(
                        "Incorrect signature for Commit. This could be due to an error during signing or serialization of the commit. Compare this to the serialized commit in the client: {}",
                        stringified_commit,
                    )
                })?;
        }
        // Check if the created_at lies in the past
        if validate_timestamp {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as i64;
            let acceptable_ms_difference = 10000;
            if self.created_at > now + acceptable_ms_difference {
                return Err(format!(
                    "Commit CreatedAt timestamp must lie in the past. Check your clock. Timestamp now: {} CreatedAt is: {}",
                    now, self.created_at
                )
                .into());
                // TODO: also check that no younger commits exist
            }
        }
        let commit_resource: Resource = self.clone().into_resource(store)?;
        let mut is_new = false;
        // Create a new resource if it doens't exist yet
        let mut resource_old = match store.get_resource(&self.subject) {
            Ok(rs) => rs,
            Err(_) => {
                is_new = true;
                Resource::new(self.subject.clone())
            }
        };

        let resource_new = self.apply_changes(resource_old.clone(), store, false)?;

        if validate_rights {
            if is_new {
                if !crate::hierarchy::check_write(store, &resource_new, self.signer.clone())? {
                    return Err(format!("Agent {} is not permitted to create {}. There should be a write right referring to this Agent in this Resource or its parent.",
                    &self.signer, self.subject).into());
                }
            } else {
                // Set a parent only if the rights checks are to be validated.
                // If there is no explicit parent set on the previous resource, use a default.
                // Unless it's a Drive!
                if resource_old.get(urls::PARENT).is_err() {
                    let default_parent = store.get_self_url().ok_or("There is no self_url set, and no parent in the Commit. The commit can not be applied.")?;
                    resource_old.set_propval(
                        urls::PARENT.into(),
                        Value::AtomicUrl(default_parent),
                        store,
                    )?;
                }
                // This should use the _old_ resource, no the new one, as the new one might maliciously give itself write rights.
                if !crate::hierarchy::check_write(store, &resource_old, self.signer.clone())? {
                    return Err(format!("Agent {} is not permitted to edit {}. There should be a write right referring to this Agent in this Resource or its parent.",
                    &self.signer, self.subject).into());
                }
            }
        };
        // Check if all required props are there
        if validate_schema {
            resource_new.check_required_props(store)?;
        }
        // If a Destroy field is found, remove the resource and return early
        // TODO: Should we remove the existing commits too? Probably.
        if let Some(destroy) = self.destroy {
            if destroy {
                // Note: the value index is updated before this action, in resource.apply_changes()
                store.remove_resource(&self.subject)?;
                store.add_resource_opts(&commit_resource, false, true, false)?;
                return Ok(commit_resource);
            }
        }
        self.apply_changes(resource_old, store, true)?;

        // Save the Commit to the Store. We can skip the required props checking, but we need to make sure the commit hasn't been applied before.
        store.add_resource_opts(&commit_resource, false, true, false)?;
        // Save the resource, but skip updating the index - that has been done in a previous step.
        store.add_resource_opts(&resource_new, false, false, true)?;
        Ok(commit_resource)
    }

    /// Updates the values in the Resource according to the `set`, `remove` and `destroy` attributes in the Commit.
    /// Optionally also updates the index in the Store.
    pub fn apply_changes(
        &self,
        mut resource: Resource,
        store: &impl Storelike,
        update_index: bool,
    ) -> AtomicResult<Resource> {
        if let Some(set) = self.set.clone() {
            for (prop, val) in set.iter() {
                if update_index {
                    let atom = Atom::new(resource.get_subject().clone(), prop.into(), val.clone());
                    if let Ok(_v) = resource.get(prop) {
                        store.remove_atom_from_index(&atom)?;
                    }
                    store.add_atom_to_index(&atom)?;
                }
                resource.set_propval(prop.into(), val.to_owned(), store)?;
            }
        }
        if let Some(remove) = self.remove.clone() {
            for prop in remove.iter() {
                if update_index {
                    let val = resource.get(prop)?;
                    let atom = Atom::new(resource.get_subject().clone(), prop.into(), val.clone());
                    store.remove_atom_from_index(&atom)?;
                }
                resource.remove_propval(prop);
            }
        }
        if let Some(destroy) = self.destroy {
            if destroy {
                for atom in resource.to_atoms()?.iter() {
                    store.remove_atom_from_index(atom)?;
                }
            }
        }
        Ok(resource)
    }

    /// Applies a commit without performing authorization / signature / schema checks.
    pub fn apply_unsafe(&self, store: &impl Storelike) -> AtomicResult<Resource> {
        self.apply_opts(store, false, false, false, false)
    }

    /// Converts a Resource of a Commit into a Commit
    pub fn from_resource(resource: Resource) -> AtomicResult<Commit> {
        let subject = resource.get(urls::SUBJECT)?.to_string();
        let created_at = resource.get(urls::CREATED_AT)?.to_int()?;
        let signer = resource.get(SIGNER)?.to_string();
        let set = match resource.get(SET) {
            Ok(found) => Some(found.to_nested()?.to_owned()),
            Err(_) => None,
        };
        let remove = match resource.get(urls::REMOVE) {
            Ok(found) => Some(found.to_subjects(None)?),
            Err(_) => None,
        };
        let destroy = match resource.get(urls::DESTROY) {
            Ok(found) => Some(found.to_bool()?),
            Err(_) => None,
        };
        let signature = resource.get(urls::SIGNATURE)?.to_string();
        let url = Some(resource.get_subject().into());

        Ok(Commit {
            subject,
            created_at,
            signer,
            set,
            remove,
            destroy,
            signature: Some(signature),
            url,
        })
    }

    /// Converts the Commit into a Resource with Atomic Values.
    /// Creates an identifier using the base_url
    /// Works for both Signed and Unsigned Commits
    pub fn into_resource(self, store: &impl Storelike) -> AtomicResult<Resource> {
        let commit_subject = match self.signature.as_ref() {
            Some(sig) => format!("{}/commits/{}", store.get_base_url(), sig),
            None => {
                let now = crate::datetime_helpers::now();
                format!("{}/commitsUnsigned/{}", store.get_base_url(), now)
            }
        };
        let mut resource = Resource::new_instance(urls::COMMIT, store)?;
        resource.set_subject(commit_subject);
        resource.set_propval(
            urls::SUBJECT.into(),
            Value::new(&self.subject, &DataType::AtomicUrl)?,
            store,
        )?;
        let classes = vec![urls::COMMIT.to_string()];
        resource.set_propval(urls::IS_A.into(), classes.into(), store)?;
        resource.set_propval(
            urls::CREATED_AT.into(),
            Value::new(&self.created_at.to_string(), &DataType::Timestamp)?,
            store,
        )?;
        resource.set_propval(
            SIGNER.into(),
            Value::new(&self.signer, &DataType::AtomicUrl)?,
            store,
        )?;
        if let Some(set) = self.set {
            let mut newset = PropVals::new();
            for (prop, val) in set.clone() {
                newset.insert(prop, val);
            }
            resource.set_propval(urls::SET.into(), newset.into(), store)?;
        };
        if let Some(remove) = self.remove {
            if !remove.is_empty() {
                resource.set_propval(urls::REMOVE.into(), remove.into(), store)?;
            }
        };
        if let Some(destroy) = self.destroy {
            if destroy {
                resource.set_propval(urls::DESTROY.into(), true.into(), store)?;
            }
        }
        resource.set_propval(
            SIGNER.into(),
            Value::new(&self.signer, &DataType::AtomicUrl)?,
            store,
        )?;
        if let Some(signature) = self.signature {
            resource.set_propval(urls::SIGNATURE.into(), signature.into(), store)?;
        }
        Ok(resource)
    }

    pub fn get_subject(&self) -> &str {
        &self.subject
    }

    /// Generates a deterministic serialized JSON-AD representation of the Commit.
    /// Removes the signature from the object before serializing, since this function is used to check if the signature is correct.
    pub fn serialize_deterministically_json_ad(
        &self,
        store: &impl Storelike,
    ) -> AtomicResult<String> {
        let mut commit_resource = self.clone().into_resource(store)?;
        // A deterministic serialization should not contain the hash (signature), since that would influence the hash.
        commit_resource.remove_propval(urls::SIGNATURE);
        let json_obj =
            crate::serialize::propvals_to_json_ad_map(commit_resource.get_propvals(), None)?;
        serde_json::to_string(&json_obj).map_err(|_| "Could not serialize to JSON-AD".into())
    }
}

/// Use this for creating Commits.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitBuilder {
    /// The subject URL that is to be modified by this Delta
    subject: String,
    /// The set of PropVals that need to be added.
    /// Overwrites existing values
    set: std::collections::HashMap<String, Value>,
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
    pub fn sign(
        self,
        agent: &crate::agents::Agent,
        store: &impl Storelike,
    ) -> AtomicResult<Commit> {
        let now = crate::datetime_helpers::now();
        sign_at(self, agent, now, store)
    }

    /// Set Property / Value combinations that will either be created or overwritten.
    pub fn set(&mut self, prop: String, val: Value) {
        self.set.insert(prop, val);
    }

    /// Set a new subject for this Commit
    pub fn set_subject(&mut self, subject: String) {
        self.subject = subject;
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
fn sign_at(
    commitbuilder: CommitBuilder,
    agent: &crate::agents::Agent,
    sign_date: i64,
    store: &impl Storelike,
) -> AtomicResult<Commit> {
    let mut commit = Commit {
        subject: commitbuilder.subject,
        signer: agent.subject.clone(),
        set: Some(commitbuilder.set),
        remove: Some(commitbuilder.remove.into_iter().collect()),
        destroy: Some(commitbuilder.destroy),
        created_at: sign_date,
        signature: None,
        url: None,
    };
    let stringified = commit
        .serialize_deterministically_json_ad(store)
        .map_err(|e| format!("Failed serializing commit: {}", e))?;
    let private_key = agent.private_key.clone().ok_or("No private key in agent")?;
    let signature = sign_message(&stringified, &private_key, &agent.public_key).map_err(|e| {
        format!(
            "Failed to sign message for resource {} with agent {}: {}",
            commit.subject, agent.subject, e
        )
    })?;
    commit.signature = Some(signature);
    Ok(commit)
}

/// Signs a string using a base64 encoded ed25519 private key. Outputs a base64 encoded ed25519 signature.
fn sign_message(message: &str, private_key: &str, public_key: &str) -> AtomicResult<String> {
    let private_key_bytes = base64::decode(private_key.to_string()).map_err(|e| {
        format!(
            "Failed decoding private key {}: {}",
            private_key.to_string(),
            e
        )
    })?;
    let public_key_bytes = base64::decode(public_key.to_string()).map_err(|e| {
        format!(
            "Failed decoding public key {}: {}",
            public_key.to_string(),
            e
        )
    })?;
    let key_pair = ring::signature::Ed25519KeyPair::from_seed_and_public_key(
        &private_key_bytes,
        &public_key_bytes,
    )
    .map_err(|_| "Can't create Ed25519 keypair from Agent's Private Key.")?;
    let message_bytes = message.as_bytes();
    let signature = key_pair.sign(message_bytes);
    let signature_bytes = signature.as_ref();
    let signatureb64 = base64::encode(signature_bytes);
    Ok(signatureb64)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{agents::Agent, Storelike};

    #[test]
    fn agent_and_commit() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let agent = store.create_agent(Some("test_actor")).unwrap();
        let subject = "https://localhost/new_thing";
        let mut commitbuiler = crate::commit::CommitBuilder::new(subject.into());
        let property1 = crate::urls::DESCRIPTION;
        let value1 = Value::new("Some value", &DataType::Markdown).unwrap();
        commitbuiler.set(property1.into(), value1.clone());
        let property2 = crate::urls::SHORTNAME;
        let value2 = Value::new("someval", &DataType::Slug).unwrap();
        commitbuiler.set(property2.into(), value2);
        let commit = commitbuiler.sign(&agent, &store).unwrap();
        let commit_subject = commit.get_subject().to_string();
        let _created_resource = commit.apply(&store).unwrap();

        let resource = store.get_resource(subject).unwrap();
        assert!(resource.get(property1).unwrap().to_string() == value1.to_string());
        let found_commit = store.get_resource(&commit_subject).unwrap();
        println!("{}", found_commit.get_subject());

        assert!(
            found_commit
                .get_shortname("description", &store)
                .unwrap()
                .to_string()
                == value1.to_string()
        );
    }

    #[test]
    fn serialize_commit() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let mut set: HashMap<String, Value> = HashMap::new();
        let shortname = Value::new("shortname", &DataType::String).unwrap();
        let description = Value::new("Some description", &DataType::String).unwrap();
        set.insert(urls::SHORTNAME.into(), shortname);
        set.insert(urls::DESCRIPTION.into(), description);
        let remove = vec![String::from(urls::IS_A)];
        let destroy = false;
        let commit = Commit {
            subject: String::from("https://localhost/test"),
            created_at: 1603638837,
            signer: String::from("https://localhost/author"),
            set: Some(set),
            remove: Some(remove),
            destroy: Some(destroy),
            signature: None,
            url: None,
        };
        let serialized = commit.serialize_deterministically_json_ad(&store).unwrap();
        let should_be = "{\"https://atomicdata.dev/properties/createdAt\":1603638837,\"https://atomicdata.dev/properties/isA\":[\"https://atomicdata.dev/classes/Commit\"],\"https://atomicdata.dev/properties/remove\":[\"https://atomicdata.dev/properties/isA\"],\"https://atomicdata.dev/properties/set\":{\"https://atomicdata.dev/properties/description\":\"Some description\",\"https://atomicdata.dev/properties/shortname\":\"shortname\"},\"https://atomicdata.dev/properties/signer\":\"https://localhost/author\",\"https://atomicdata.dev/properties/subject\":\"https://localhost/test\"}";
        assert_eq!(serialized, should_be)
    }

    #[test]
    fn signature_matches() {
        let private_key = "CapMWIhFUT+w7ANv9oCPqrHrwZpkP2JhzF9JnyT6WcI=";
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let agent = Agent::new_from_private_key(None, &store, private_key);
        assert_eq!(
            &agent.subject,
            "http://localhost/agents/7LsjMW5gOfDdJzK/atgjQ1t20J/rw8MjVg6xwqm+h8U="
        );
        store
            .add_resource(&agent.to_resource(&store).unwrap())
            .unwrap();
        let subject = "https://localhost/new_thing";
        let mut commitbuilder = crate::commit::CommitBuilder::new(subject.into());
        let property1 = crate::urls::DESCRIPTION;
        let value1 = Value::new("Some value", &DataType::String).unwrap();
        commitbuilder.set(property1.into(), value1);
        let property2 = crate::urls::SHORTNAME;
        let value2 = Value::new("someval", &DataType::String).unwrap();
        commitbuilder.set(property2.into(), value2);
        let commit = sign_at(commitbuilder, &agent, 0, &store).unwrap();
        let signature = commit.signature.clone().unwrap();
        let serialized = commit.serialize_deterministically_json_ad(&store).unwrap();

        assert_eq!(serialized, "{\"https://atomicdata.dev/properties/createdAt\":0,\"https://atomicdata.dev/properties/isA\":[\"https://atomicdata.dev/classes/Commit\"],\"https://atomicdata.dev/properties/set\":{\"https://atomicdata.dev/properties/description\":\"Some value\",\"https://atomicdata.dev/properties/shortname\":\"someval\"},\"https://atomicdata.dev/properties/signer\":\"http://localhost/agents/7LsjMW5gOfDdJzK/atgjQ1t20J/rw8MjVg6xwqm+h8U=\",\"https://atomicdata.dev/properties/subject\":\"https://localhost/new_thing\"}");
        assert_eq!(signature, "kLh+mxy/lgFD6WkbIbhJANgRhyu39USL9up1zCmqU8Jmc+4rlvLZwxSlfxKTISP2BiXLSiz/5NJZrN5XpXJ/Cg==");
    }

    #[test]
    fn signature_basics() {
        let private_key = "CapMWIhFUT+w7ANv9oCPqrHrwZpkP2JhzF9JnyT6WcI=";
        let public_key = "7LsjMW5gOfDdJzK/atgjQ1t20J/rw8MjVg6xwqm+h8U=";
        let signature_expected = "YtDR/xo0272LHNBQtDer4LekzdkfUANFTI0eHxZhITXnbC3j0LCqDWhr6itNvo4tFnep6DCbev5OKAHH89+TDA==";
        let message = "val";
        let signature = sign_message(message, private_key, public_key).unwrap();
        assert_eq!(signature, signature_expected);
    }

    #[test]

    fn invalid_subjects() {
        let store = crate::Store::init().unwrap();
        let agent = store.create_agent(Some("test_actor")).unwrap();

        {
            let subject = "invalid URL";
            let commitbuiler = crate::commit::CommitBuilder::new(subject.into());
            let _ = commitbuiler.sign(&agent, &store).unwrap_err();
        }
        {
            let subject = "https://invalid.com?q=invalid";
            let commitbuiler = crate::commit::CommitBuilder::new(subject.into());
            let commit = commitbuiler.sign(&agent, &store).unwrap();
            commit.apply(&store).unwrap_err();
        }
        {
            let subject = "https://valid.com/valid";
            let commitbuiler = crate::commit::CommitBuilder::new(subject.into());
            let commit = commitbuiler.sign(&agent, &store).unwrap();
            commit.apply(&store).unwrap();
        }
    }
}
