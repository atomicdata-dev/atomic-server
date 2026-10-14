//! Describe changes / mutations to data

use crate::{
    agents::{decode_base64, encode_base64},
    datatype::DataType,
    errors::AtomicResult,
    urls,
    values::SubResource,
    Atom, Resource, Storelike, Subject, Value,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use urls::SIGNER;

mod apply;
mod builder;
/// Owner mode: only the node's owner may put a *new* drive here.
///
/// The managed-node tests above cover an allowlist a control plane populates.
/// These cover the self-hosted gate, where the answer turns on *who is signing*
/// rather than on what some other system already enrolled.
#[cfg(all(test, feature = "db"))]
mod owner_mode_tests;
mod signature;
#[cfg(test)]
mod test;
mod validate;

pub use builder::sign_message;

/// The `resource_new`, `resource_old` and `commit_resource` fields are only created if the Commit is persisted.
/// When the Db is only notifying other of changes (e.g. if a new Message was added to a ChatRoom), these fields are not created.
/// When deleting a resource, the `resource_new` field is None.
#[derive(Clone, Debug)]
pub struct CommitResponse {
    pub commit: Commit,
    pub commit_resource: Resource,
    pub resource_new: Option<Resource>,
    pub resource_old: Option<Resource>,
    pub add_atoms: Vec<Atom>,
    pub remove_atoms: Vec<Atom>,
    /// The property URLs that were changed by this commit's Loro update.
    pub changed_props: HashSet<String>,
    /// Optional transport/source identity for echo suppression.
    pub source_id: Option<String>,
    /// Every op the stored doc gained while applying this commit: the
    /// author's own ops plus what the server wrote on top (the `lastCommit`
    /// stamp, `createdAt` at genesis). This, not `commit.loro_update`, is
    /// what live subscribers must receive — see [`Self::fanout_delta`].
    pub broadcast_update: Option<Vec<u8>>,
}

impl CommitResponse {
    /// The delta to push to live subscribers.
    ///
    /// The server stamps `lastCommit` on the resource after importing the
    /// author's update. That stamp is a Loro op under the server's own peer,
    /// and the next edit by anyone who loaded a snapshot depends on it. A
    /// subscriber that only ever received `commit.loro_update` lacks the
    /// stamp, parks that edit as pending, and every later delta parks behind
    /// it: the document quietly stops being live. Falls back to the commit's
    /// own bytes when the apply did not go through a Loro doc.
    pub fn fanout_delta(&self) -> Option<&[u8]> {
        self.broadcast_update
            .as_deref()
            .or(self.commit.loro_update.as_deref())
    }

    /// The authorization relevance of this commit — which authority-defining
    /// facts it establishes or mutates. See [`crate::hierarchy::AuthImpact`].
    /// Whether this commit brought its resource into being.
    pub fn creates_resource(&self) -> bool {
        self.commit.is_genesis == Some(true)
            || (self.resource_old.is_none() && self.resource_new.is_some())
    }

    pub fn auth_impact(&self) -> crate::hierarchy::AuthImpact {
        // A creation is genesis whether or not the client flagged it: Rust
        // `save_locally`, agent first-commits and HTTP-subject creations
        // arrive with `is_genesis: None`, and the commit that brought a
        // resource into being is retained like an explicit genesis.
        let created = self.resource_old.is_none() && self.resource_new.is_some();
        crate::hierarchy::classify_auth_impact(
            &self.changed_props,
            self.commit.is_genesis == Some(true) || created,
            self.commit.destroy.unwrap_or(false),
        )
    }
}

pub struct CommitApplied {
    /// The resource before the Commit was applied
    pub resource_old: Resource,
    /// The modified resources where the commit has been applied to
    pub resource_new: Resource,
    /// The atoms that should be added to the store (for updating indexes)
    pub add_atoms: Vec<Atom>,
    /// The atoms that should be removed from the store (for updating indexes)
    pub remove_atoms: Vec<Atom>,
    /// The property URLs that were changed by this commit's Loro update.
    pub changed_props: HashSet<String>,
    /// True when importing the commit's `loroUpdate` actually advanced the
    /// doc's oplog — i.e. the ops were new. False means every op was already
    /// present (an idempotent replay), so producing no state change is
    /// expected and correct, not a silent LWW loss.
    pub imported_new_ops: bool,
    /// The doc's version before the commit's `loroUpdate` was imported, so
    /// the caller can export everything the apply added — including what
    /// the server writes afterwards — as one delta for live subscribers.
    pub vv_before: Option<loro::VersionVector>,
    /// True when the commit's `loroUpdate` carried ops whose causal
    /// dependencies are missing from the stored doc. Loro parks those ops
    /// as *pending*: they don't advance the version vector and contribute
    /// nothing to state, so without an explicit check they masquerade as
    /// an idempotent replay while the client's writes silently vanish.
    pub imported_pending_ops: bool,
    /// Raw `properties` keys the update changed (a superset of
    /// `changed_props`: includes values that do not materialize into atoms).
    pub changed_property_keys: Vec<String>,
    /// True when the update changed the `datatypes` map.
    pub datatypes_changed: bool,
    /// Chat log `entries` the update added, changed or removed.
    pub entry_changes: Vec<crate::chat_log::EntryChange>,
}

#[derive(Clone, Debug)]
/// Describes options for applying a Commit.
/// Skip the checks you don't need to get better performance, or if you want to break the rules a little.
pub struct CommitOpts {
    /// Makes sure all `required` properties are present.
    pub validate_schema: bool,
    /// Checks values against the `constraints` of the resource's classes (and
    /// the shape of a Class's own map). Needs `validate_schema`. Off for peer
    /// transports: a replica must accept what another node already accepted.
    pub validate_constraints: bool,
    /// Checks the public key and the signature of the Commit.
    pub validate_signature: bool,
    /// Checks whether the Commit isn't too old, or has been created in the future.
    pub validate_timestamp: bool,
    /// Checks whether the creator of the Commit has the rights to edit the Resource.
    pub validate_rights: bool,
    /// Detects commits whose Loro update's writes silently lost LWW against
    /// the stored state — i.e. the client's Loro doc wasn't seeded from the
    /// server's current state, so its ops are concurrent with stored ops and
    /// get dropped by Loro's conflict resolution. When this happens, the
    /// commit would "succeed" but the server-visible state wouldn't reflect
    /// the client's intent. With this enabled, we reject such commits so the
    /// client can refetch and retry.
    ///
    /// Turn off for true multi-peer sync (mesh/Iroh) where concurrent writes
    /// are expected and LWW is the correct resolution.
    pub validate_loro_causality: bool,
    /// Updates the indexes in the Store. Is a bit more costly.
    pub update_index: bool,
    /// For who the right checks will be perormed. If empty, the signer of the Commit will be used.
    pub validate_for_agent: Option<String>,
    /// Optional transport/source identity for echo suppression.
    pub source_id: Option<String>,
}

impl CommitOpts {
    pub fn no_validations_no_index() -> Self {
        Self {
            validate_schema: false,
            validate_constraints: false,
            validate_signature: false,
            validate_timestamp: false,
            validate_rights: false,
            validate_loro_causality: false,
            update_index: false,
            validate_for_agent: None,
            source_id: None,
        }
    }
}

/// A Commit is a set of changes to a Resource.
/// Use CommitBuilder if you're programmatically constructing a Delta.
#[derive(Clone, Serialize)]
pub struct Commit {
    /// The subject URL that is to be modified by this Delta
    #[serde(rename = "https://atomicdata.dev/properties/subject")]
    pub subject: Subject,
    /// The date it was created, as a unix timestamp
    #[serde(rename = "https://atomicdata.dev/properties/createdAt")]
    pub created_at: i64,
    /// The URL of the one signing this Commit
    #[serde(rename = "https://atomicdata.dev/properties/signer")]
    pub signer: Subject,
    /// A Loro CRDT binary update for the entire resource document
    #[serde(rename = "https://atomicdata.dev/properties/loroUpdate")]
    pub loro_update: Option<Vec<u8>>,
    /// If set to true, deletes the entire resource
    #[serde(rename = "https://atomicdata.dev/properties/destroy")]
    pub destroy: Option<bool>,
    /// Base64 encoded signature of the JSON serialized Commit
    #[serde(rename = "https://atomicdata.dev/properties/signature")]
    pub signature: Option<String>,
    /// Optional audit pointer at an earlier envelope. Not a causal gate.
    #[serde(rename = "https://atomicdata.dev/properties/previousCommit")]
    pub previous_commit: Option<String>,
    /// Whether this is the first commit for a Resource.
    #[serde(rename = "https://atomicdata.dev/properties/isGenesis")]
    pub is_genesis: Option<bool>,
    /// The URL of the Commit
    pub url: Option<String>,
}

impl std::fmt::Debug for Commit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Commit")
            .field("subject", &self.subject)
            .field("created_at", &self.created_at)
            .field("signer", &self.signer)
            .field(
                "loro_update",
                &self
                    .loro_update
                    .as_ref()
                    .map(|v| format!("<{} bytes>", v.len())),
            )
            .field("destroy", &self.destroy)
            .field("signature", &self.signature)
            .field("previous_commit", &self.previous_commit)
            .field("is_genesis", &self.is_genesis)
            .field("url", &self.url)
            .finish()
    }
}

/// Check a Property ID against the namespace, shortname and datatype in the
/// propvals of the resource it names. All three must be present.
fn verify_property_genesis(
    subject: &str,
    propvals: &crate::resources::PropVals,
) -> AtomicResult<()> {
    let field = |prop: &str, name: &str| -> AtomicResult<String> {
        propvals
            .get(prop)
            .map(|v| v.to_string())
            .ok_or_else(|| format!("Property {subject} has no {name}; its ID is derived from parent, shortname and datatype").into())
    };
    let parent = field(urls::PARENT, "parent")?;
    let shortname = field(urls::SHORTNAME, "shortname")?;
    let datatype = field(urls::DATATYPE_PROP, "datatype")?;
    crate::property_identity::verify_property_id(subject, &parent, &shortname, &datatype)
}

/// True for the content-addressed kinds: Property and Lens IDs name no
/// signature and carry no genesis certificate.
fn is_content_addressed_id(subject: &str) -> bool {
    crate::identifiers::is_prop_id(subject) || crate::identifiers::is_lens_id(subject)
}

/// Check a content-addressed ID (`atomic:prop:` or `atomic:lens:`) against the
/// fields in the propvals it names.
fn verify_content_addressed_genesis(
    subject: &str,
    propvals: &crate::resources::PropVals,
) -> AtomicResult<()> {
    if crate::identifiers::is_lens_id(subject) {
        crate::lens::verify_lens_genesis(subject, propvals)
    } else {
        verify_property_genesis(subject, propvals)
    }
}

/// Derive lens values into `new` and bring the index atoms in line.
///
/// The doc diff knows only what the doc really holds. For every property a
/// lens touches, the index must instead follow what the resource shows: the
/// real value, or the derived one. So drop the diff's atoms for that property
/// and file the change between what `old` showed and what `new` shows.
fn reconcile_lens_atoms(
    lenses: &crate::lens::LensIndex,
    old: Option<&Resource>,
    new: &mut Resource,
    add_atoms: &mut Vec<Atom>,
    remove_atoms: &mut Vec<Atom>,
) {
    new.apply_lenses(lenses);
    let subject = new.get_subject().clone();
    for prop in lenses.properties() {
        let is_prop =
            |atom: &Atom| crate::identifiers::canonicalize_scheme(&atom.property) == *prop;
        add_atoms.retain(|atom| !is_prop(atom));
        remove_atoms.retain(|atom| !is_prop(atom));
        let before = old.and_then(|r| r.get(prop).ok()).cloned();
        let after = new.get(prop).ok().cloned();
        let same = match (&before, &after) {
            (None, None) => true,
            (Some(a), Some(b)) => a.datatype() == b.datatype() && a.to_string() == b.to_string(),
            _ => false,
        };
        if same {
            continue;
        }
        if let Some(value) = before {
            remove_atoms.push(Atom::new(subject.clone(), prop.clone(), value));
        }
        if let Some(value) = after {
            add_atoms.push(Atom::new(subject.clone(), prop.clone(), value));
        }
    }
}

/// A Property's identity is hashed into its ID, so `parent`, `shortname` and
/// `datatype` can never change after creation.
fn check_property_identity_unchanged(old: &Resource, new: &Resource) -> AtomicResult<()> {
    for (prop, name) in [
        (urls::PARENT, "parent"),
        (urls::SHORTNAME, "shortname"),
        (urls::DATATYPE_PROP, "datatype"),
    ] {
        let norm = |r: &Resource| {
            r.get(prop)
                .ok()
                .map(|v| crate::identifiers::canonicalize_scheme(&v.to_string()))
        };
        if norm(old) != norm(new) {
            return Err(format!(
                "Cannot change the {name} of property {}: a property's identity cannot change",
                new.get_subject()
            )
            .into());
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitBuilderJSON {
    pub subject: String,
    pub loro_update: Option<String>,
    pub destroy: bool,
    pub previous_commit: Option<String>,
}

/// Use this for creating Commits.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitBuilder {
    /// The subject URL that is to be modified by this Delta.
    pub subject: Subject,
    /// Property changes accumulated on the server side.
    /// These get converted to a Loro update at sign time.
    set: std::collections::HashMap<String, Value>,
    /// Properties to remove. Converted to Loro operations at sign time.
    remove: HashSet<String>,
    /// A Loro CRDT binary update (from client). Takes precedence over set/remove.
    loro_update: Option<Vec<u8>>,
    /// If set to true, deletes the entire resource
    destroy: bool,
    /// Optional audit pointer at an earlier envelope. Not a causal gate.
    previous_commit: Option<String>,
    /// Whether this is a genesis commit (the first commit for a DID resource).
    pub is_genesis: bool,
}

/// The amount of milliseconds that a Commit signature is valid for.
const ACCEPTABLE_TIME_DIFFERENCE: i64 = 10000;
