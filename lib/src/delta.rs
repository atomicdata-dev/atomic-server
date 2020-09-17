//! Describe changes / mutations to data

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

pub struct Delta {
    // The set of changes
    pub lines: Vec<DeltaLine>,
    // Who issued the changes
    pub actor: String,
    pub subject: String,
}

// Should a delta only contain changes to a _single resource_?
// That would make things easier regarding hashes.
impl Delta {
    /// Creates a single, unvalidated Delta
    // pub fn new() -> Delta {
    //     Delta {
    //         lines: Vec::new(),
    //         actor: String::from("_:localActor"),
    //     }
    // }

    pub fn new_from_lines(subject: String, lines: Vec<DeltaLine>) -> Delta {
        Delta {
            subject,
            lines,
            actor: String::from("_:localActor"),
        }
    }
}

impl Default for Delta {
    /// Creates a single, unvalidated Delta
    fn default() -> Self {
        Delta {
            subject: "Default".into(),
            lines: Vec::new(),
            actor: String::from("_:localActor"),
        }
    }
}
