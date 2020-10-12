//! Describe changes / mutations to data
//! Deprecated in favor or Commit

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

/// Describes a change to an atom.
/// Deprecated in favor or Commit
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
