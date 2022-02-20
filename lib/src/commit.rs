//! Describe changes / mutations to data

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use urls::{SET, SIGNER};

use crate::{
    datatype::DataType, errors::AtomicResult, hierarchy, resources::PropVals, urls, Atom, Resource,
    Storelike, Value,
};

/// Contains two resources. The first is the Resource representation of the applied Commits.
/// The second is the New resource, if it's not deleted.
/// The third is the Old resource.
#[derive(Clone, Debug)]
pub struct CommitResponse {
    pub commit_resource: Resource,
    pub resource_new: Option<Resource>,
    pub resource_old: Resource,
    pub commit_struct: Commit,
}

#[derive(Clone, Debug)]
/// Describes options for applying a Commit.
/// Skip the checks you don't need to get better performance, or if you want to break the rules a little.
pub struct CommitOpts {
    /// Makes sure all `required` properties are present.
    pub validate_schema: bool,
    /// Checks the public key and the signature of the Commit.
    pub validate_signature: bool,
    /// Checks whether the Commit isn't too old, or has been created in the future.
    pub validate_timestamp: bool,
    /// Checks whether the creator of the Commit has the rights to edit the Resource.
    pub validate_rights: bool,
    /// Checks whether the previous Commit applied to the resource matches the one mentioned in the Commit/
    /// This makes sure that the Commit is not applied twice, or that the one creating it had a faulty state.
    pub validate_previous_commit: bool,
    /// Updates the indexes in the Store. Is a bit more costly.
    pub update_index: bool,
}

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
    /// The previously applied commit to this Resource.
    #[serde(rename = "https://atomicdata.dev/properties/previousCommit")]
    pub previous_commit: Option<String>,
    /// The URL of the Commit
    pub url: Option<String>,
}

impl Commit {
    /// Apply a single signed Commit to the store.
    /// Creates, edits or destroys a resource.
    /// Allows for control over which validations should be performed.
    /// Returns the generated Commit, the old Resource and the new Resource.
    #[tracing::instrument(skip(store))]
    pub fn apply_opts(
        &self,
        store: &impl Storelike,
        opts: &CommitOpts,
    ) -> AtomicResult<CommitResponse> {
        let subject_url = url::Url::parse(&self.subject)
            .map_err(|e| format!("Subject '{}' is not a URL. {}", &self.subject, e))?;

        if subject_url.query().is_some() {
            return Err("Subject URL cannot have query parameters".into());
        }

        if opts.validate_signature {
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
        if opts.validate_timestamp {
            check_timestamp(self.created_at)?;
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

        // Make sure the one creating the commit had the same idea of what the current state is.
        if opts.validate_previous_commit {
            if let Ok(last_resource_val) = resource_old.get(urls::LAST_COMMIT) {
                let prev_resource = last_resource_val.to_string();

                if let Some(commit_prev) = self.previous_commit.clone() {
                    if prev_resource != commit_prev {
                        return Err(format!(
                            "previousCommit mismatch. Expected '{}' from Commit, but got in the Resource '{}'. Perhaps you created the Commit based on an outdated version of the Resource.",
                            commit_prev, prev_resource,
                        )
                        .into());
                    }
                } else {
                    return Err(format!("Resource {} already exists, and it has a `lastCommit` field, so a `previousCommit` field is required in your Commit. It's currently missing.", self.subject).into());
                }
            } else {
                // If there is no lastCommit in the Resource, we'll accept the Commit.
                tracing::warn!("No `lastCommit` in Resource. This can be a bug, or it could be that the resource was never properly updated.");
            }
        };

        let mut resource_new = self.apply_changes(resource_old.clone(), store, false)?;

        if opts.validate_rights {
            if is_new {
                hierarchy::check_write(store, &resource_new, &self.signer)?;
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
                hierarchy::check_write(store, &resource_old, &self.signer)?;
            }
        };
        // Check if all required props are there
        if opts.validate_schema {
            resource_new.check_required_props(store)?;
        }

        // TODO: before_apply_commit hooks plugins
        // This is where users should extend commits
        for class in resource_new.get_classes(store)? {
            match class.subject.as_str() {
                urls::COMMIT => return Err("Commits can not be edited or created directly.".into()),
                urls::INVITE => {
                    // Check if the creator has rights to invite people (= write) to the target resource
                    let target = resource_new
                        .get(urls::TARGET)
                        .map_err(|_e| "Invite does not have required Target attribute")?;
                    let target_resource = store.get_resource(&target.to_string())?;
                    hierarchy::check_write(store, &target_resource, &self.signer)?;
                }
                _other => {}
            };
        }

        // If a Destroy field is found, remove the resource and return early
        // TODO: Should we remove the existing commits too? Probably.
        if let Some(destroy) = self.destroy {
            if destroy {
                // Note: the value index is updated before this action, in resource.apply_changes()
                store.remove_resource(&self.subject)?;
                store.add_resource_opts(&commit_resource, false, opts.update_index, false)?;
                return Ok(CommitResponse {
                    resource_new: None,
                    resource_old,
                    commit_resource,
                    commit_struct: self.clone(),
                });
            }
        }

        // We apply the changes again, but this time also update the index
        self.apply_changes(resource_old.clone(), store, opts.update_index)?;

        // Set the `lastCommit` to the newly created Commit
        resource_new.set_propval(
            urls::LAST_COMMIT.to_string(),
            Value::AtomicUrl(commit_resource.get_subject().into()),
            store,
        )?;

        // Save the Commit to the Store. We can skip the required props checking, but we need to make sure the commit hasn't been applied before.
        store.add_resource_opts(&commit_resource, false, opts.update_index, false)?;
        // Save the resource, but skip updating the index - that has been done in a previous step.
        store.add_resource_opts(&resource_new, false, false, true)?;
        Ok(CommitResponse {
            resource_new: Some(resource_new),
            resource_old,
            commit_resource,
            commit_struct: self.clone(),
        })
    }

    /// Updates the values in the Resource according to the `set`, `remove` and `destroy` attributes in the Commit.
    /// Optionally also updates the index in the Store.
    /// The Old Resource is only needed when `update_index` is true, and is used for checking
    #[tracing::instrument(skip(store))]
    pub fn apply_changes(
        &self,
        mut resource: Resource,
        store: &impl Storelike,
        update_index: bool,
    ) -> AtomicResult<Resource> {
        let resource_unedited = resource.clone();
        if let Some(set) = self.set.clone() {
            for (prop, new_val) in set.iter() {
                resource.set_propval(prop.into(), new_val.to_owned(), store)?;

                if update_index {
                    let new_atom =
                        Atom::new(resource.get_subject().clone(), prop.into(), new_val.clone());
                    if let Ok(old_val) = resource_unedited.get(prop) {
                        let old_atom =
                            Atom::new(resource.get_subject().clone(), prop.into(), old_val.clone());
                        store.remove_atom_from_index(&old_atom, &resource_unedited)?;
                    }
                    store.add_atom_to_index(&new_atom, &resource)?;
                }
            }
        }
        if let Some(remove) = self.remove.clone() {
            for prop in remove.iter() {
                resource.remove_propval(prop);
                if update_index {
                    let val = resource_unedited.get(prop)?;
                    let atom = Atom::new(resource.get_subject().clone(), prop.into(), val.clone());
                    store.remove_atom_from_index(&atom, &resource_unedited)?;
                }
            }
        }
        // Remove all atoms from index if destroy
        if let Some(destroy) = self.destroy {
            if destroy {
                for atom in resource.to_atoms()?.iter() {
                    store.remove_atom_from_index(atom, &resource_unedited)?;
                }
            }
        }
        Ok(resource)
    }

    /// Applies a commit without performing authorization / signature / schema checks.
    /// Does not update the index.
    pub fn apply_unsafe(&self, store: &impl Storelike) -> AtomicResult<CommitResponse> {
        let opts = CommitOpts {
            validate_schema: false,
            validate_signature: false,
            validate_timestamp: false,
            validate_rights: false,
            validate_previous_commit: false,
            update_index: false,
        };
        self.apply_opts(store, &opts)
    }

    /// Converts a Resource of a Commit into a Commit
    #[tracing::instrument]
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
        let previous_commit = match resource.get(urls::PREVIOUS_COMMIT) {
            Ok(found) => Some(found.to_string()),
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
            previous_commit,
            signature: Some(signature),
            url,
        })
    }

    /// Converts the Commit into a Resource with Atomic Values.
    /// Creates an identifier using the server_url
    /// Works for both Signed and Unsigned Commits
    #[tracing::instrument(skip(store))]
    pub fn into_resource(self, store: &impl Storelike) -> AtomicResult<Resource> {
        let commit_subject = match self.signature.as_ref() {
            Some(sig) => format!("{}/commits/{}", store.get_server_url(), sig),
            None => {
                let now = crate::utils::now();
                format!("{}/commitsUnsigned/{}", store.get_server_url(), now)
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
            for (prop, val) in set {
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
        if let Some(previous_commit) = self.previous_commit {
            resource.set_propval(
                urls::PREVIOUS_COMMIT.into(),
                Value::AtomicUrl(previous_commit),
                store,
            )?;
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
    #[tracing::instrument(skip(store))]
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
    /// The subject URL that is to be modified by this Delta.
    /// Not the URL of the Commit itself.
    /// https://atomicdata.dev/properties/subject
    subject: String,
    /// The set of PropVals that need to be added.
    /// Overwrites existing values
    /// https://atomicdata.dev/properties/set
    set: std::collections::HashMap<String, Value>,
    /// The set of property URLs that need to be removed
    /// https://atomicdata.dev/properties/remove
    remove: HashSet<String>,
    /// If set to true, deletes the entire resource
    /// https://atomicdata.dev/properties/destroy
    destroy: bool,
    // pub signature: String,
    /// The previous Commit that was applied to the target resource (the subject) of this Commit. You should be able to follow these from Commit to Commit to establish an audit trail.
    /// https://atomicdata.dev/properties/previousCommit
    previous_commit: Option<String>,
}

impl CommitBuilder {
    /// Start constructing a Commit.
    pub fn new(subject: String) -> Self {
        CommitBuilder {
            subject,
            set: HashMap::new(),
            remove: HashSet::new(),
            destroy: false,
            previous_commit: None,
        }
    }

    /// Creates the Commit and signs it using a signature.
    /// Does not send it - see [atomic_lib::client::post_commit].
    /// Private key is the base64 encoded pkcs8 for the signer.
    /// Sets the `previousCommit` using the `lastCommit`.
    pub fn sign(
        mut self,
        agent: &crate::agents::Agent,
        store: &impl Storelike,
        resource: &Resource,
    ) -> AtomicResult<Commit> {
        if let Ok(last) = resource.get(urls::LAST_COMMIT) {
            self.previous_commit = Some(last.to_string());
        }

        let now = crate::utils::now();
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
#[tracing::instrument(skip(store))]
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
        previous_commit: commitbuilder.previous_commit,
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
#[tracing::instrument]
pub fn sign_message(message: &str, private_key: &str, public_key: &str) -> AtomicResult<String> {
    let private_key_bytes = base64::decode(private_key.to_string())
        .map_err(|e| format!("Failed decoding private key {}: {}", private_key, e))?;
    let public_key_bytes = base64::decode(public_key.to_string())
        .map_err(|e| format!("Failed decoding public key {}: {}", public_key, e))?;
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

/// The amount of milliseconds that a Commit signature is valid for.
const ACCEPTABLE_TIME_DIFFERENCE: i64 = 10000;

/// Checks if the Commit has been created in the future or if it is expired.
pub fn check_timestamp(timestamp: i64) -> AtomicResult<()> {
    let now = crate::utils::now();
    if timestamp > now + ACCEPTABLE_TIME_DIFFERENCE {
        return Err(format!(
                    "Commit CreatedAt timestamp must lie in the past. Check your clock. Timestamp now: {} CreatedAt is: {}",
                    now, timestamp
                )
                .into());
        // TODO: also check that no younger commits exist
    }
    Ok(())
}

#[cfg(test)]
mod test {
    lazy_static::lazy_static! {
        pub static ref OPTS: CommitOpts = CommitOpts {
            validate_schema: true,
            validate_signature: true,
            validate_timestamp: true,
            validate_previous_commit: true,
            validate_rights: false,
            update_index: true,
        };
    }

    use super::*;
    use crate::{agents::Agent, Storelike};

    #[test]
    fn agent_and_commit() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let agent = store.create_agent(Some("test_actor")).unwrap();
        let subject = "https://localhost/new_thing";
        let resource = Resource::new(subject.into());
        let mut commitbuiler = crate::commit::CommitBuilder::new(subject.into());
        let property1 = crate::urls::DESCRIPTION;
        let value1 = Value::new("Some value", &DataType::Markdown).unwrap();
        commitbuiler.set(property1.into(), value1.clone());
        let property2 = crate::urls::SHORTNAME;
        let value2 = Value::new("someval", &DataType::Slug).unwrap();
        commitbuiler.set(property2.into(), value2);
        let commit = commitbuiler.sign(&agent, &store, &resource).unwrap();
        let commit_subject = commit.get_subject().to_string();
        let _created_resource = commit.apply_opts(&store, &OPTS).unwrap();

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
            previous_commit: None,
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
        let resource = Resource::new("https://localhost/test_resource".into());

        {
            let subject = "invalid URL";
            let commitbuiler = crate::commit::CommitBuilder::new(subject.into());
            let _ = commitbuiler.sign(&agent, &store, &resource).unwrap_err();
        }
        {
            let subject = "https://invalid.com?q=invalid";
            let commitbuiler = crate::commit::CommitBuilder::new(subject.into());
            let commit = commitbuiler.sign(&agent, &store, &resource).unwrap();
            commit.apply_opts(&store, &OPTS).unwrap_err();
        }
        {
            let subject = "https://valid.com/valid";
            let commitbuiler = crate::commit::CommitBuilder::new(subject.into());
            let commit = commitbuiler.sign(&agent, &store, &resource).unwrap();
            commit.apply_opts(&store, &OPTS).unwrap();
        }
    }
}
