//! The smallest units of data, consiting of a Subject, a Property and a Value

use crate::values::Value;
use serde::Serialize;

/// The Atom is the (non-validated) string representation of a piece of data.
/// It's RichAtom sibling provides some extra methods.
#[derive(Clone, Debug, Serialize)]
pub struct Atom {
    pub subject: String,
    pub property: String,
    pub value: Value,
}

impl Atom {
    pub fn new(subject: String, property: String, value: Value) -> Self {
        Atom {
            subject,
            property,
            value,
        }
    }
}

impl std::fmt::Display for Atom {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.write_str(&format!("<{}> <{}> '{}'", self.subject, self.property, self.value))?;
        Ok(())
    }
}
