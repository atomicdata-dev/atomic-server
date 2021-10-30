//! The smallest units of data, consiting of a Subject, a Property and a Value

use crate::{errors::AtomicResult, values::Value};

/// The Atom is the (non-validated) string representation of a piece of data.
/// It's RichAtom sibling provides some extra methods.
#[derive(Clone, Debug)]
pub struct Atom {
    /// The URL where the resource is located
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

    /// If the Atom's Value is an Array, this will try to convert it into a set of Subjects.
    /// Used for indexing.
    pub fn values_to_subjects(&self) -> AtomicResult<Vec<String>> {
        let base_path = format!("{} {}", self.subject, self.property);
        self.value.to_subjects(Some(base_path))
    }
}

impl std::fmt::Display for Atom {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.write_str(&format!(
            "<{}> <{}> '{}'",
            self.subject, self.property, self.value
        ))?;
        Ok(())
    }
}
