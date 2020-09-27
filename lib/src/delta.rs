//! Describe changes / mutations to data

/// A set of changes to a resource.
use serde::Deserialize;
#[derive(Debug, Deserialize)]
pub struct Commit {
    /// The subject URL that is to be modified by this Delta
    pub subject: String,
    /// The date it was created, as a unix timestamp
    pub created_at: u32,
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

type PropVals = std::collections::HashMap<String, String>;

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
