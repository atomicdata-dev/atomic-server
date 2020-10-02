//! Describe changes / mutations to data

/// A set of changes to a resource.
use std::collections::HashMap;

use serde::Deserialize;
#[derive(Debug, Deserialize)]
pub struct Commit {
    /// The subject URL that is to be modified by this Delta
    pub subject: String,
    /// The date it was created, as a unix timestamp
    pub created_at: u128,
    /// The URL of the one suggesting this Commit
    pub actor: String,
    /// The set of PropVals that need to be added.
    /// Overwrites existing values
    pub set: std::collections::HashMap<String, String>,
    /// The set of property URLs that need to be removed
    pub remove: Vec<String>,
    /// If set to true, deletes the entire resource
    pub destroy: bool,
    /// Hash signed by the actor
    pub signature: String,
}

pub struct PartialCommit {
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
    remove: Vec<String>,
    /// If set to true, deletes the entire resource
    destroy: bool,
    // pub signature: String,
}

impl PartialCommit {
    pub fn new(subject: String, actor: String) -> Self {
        PartialCommit {
            subject,
            actor,
            set: HashMap::new(),
            remove: Vec::new(),
            destroy: false,
        }
    }

    pub fn sign(&self, _private_key: String) -> Commit {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();

        Commit {
            subject: self.subject.clone(),
            actor: self.actor.clone(),
            set: self.set.clone(),
            remove: self.remove.clone(),
            destroy: self.destroy,
            created_at,
            // TODO: Hashing signature logic
            signature: "correct_signature".into(),
        }
    }

    pub fn set(&mut self, prop: String, val: String) {
        self.set.insert(prop, val);
    }
}

/// Individual change to a resource. Unvalidated.
pub struct DeltaLine {
    pub method: String,
    pub property: String,
    pub value: String,
}

impl DeltaLine {
    /// Creates a single, unvalidated Delta
    pub fn new(method: String, property: String, value: String) -> DeltaLine {
        DeltaLine {
            method,
            property,
            value,
        }
    }
}

pub struct DeltaDeprecated {
    // The set of changes
    pub lines: Vec<DeltaLine>,
    // Who issued the changes
    pub actor: String,
    pub subject: String,
}

// Should a delta only contain changes to a _single resource_?
// That would make things easier regarding hashes.
impl DeltaDeprecated {
    /// Creates a single, unvalidated Delta
    // pub fn new() -> Delta {
    //     Delta {
    //         lines: Vec::new(),
    //         actor: String::from("_:localActor"),
    //     }
    // }

    pub fn new_from_lines(subject: String, lines: Vec<DeltaLine>) -> DeltaDeprecated {
        DeltaDeprecated {
            subject,
            lines,
            actor: String::from("_:localActor"),
        }
    }
}

impl Default for DeltaDeprecated {
    /// Creates a single, unvalidated Delta
    fn default() -> Self {
        DeltaDeprecated {
            subject: "Default".into(),
            lines: Vec::new(),
            actor: String::from("_:localActor"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Storelike;

    #[test]
    fn apply_commit() {
        let store = crate::Store::init();
        let subject = String::from("https://example.com/somesubject");
        let actor = "HashedThing".into();
        let mut partial_commit = PartialCommit::new(subject.clone(), actor);
        let property = crate::urls::DESCRIPTION;
        let value = "Some value";
        partial_commit.set(property.into(), value.into());
        let full_commit = partial_commit.sign("correct_signature".into());
        store.commit(full_commit).unwrap();
        let resource = store.get_resource(&subject).unwrap();
        assert!(resource.get(property).unwrap().to_string() == value);
    }
}
