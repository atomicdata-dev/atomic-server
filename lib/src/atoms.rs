//! The smallest units of data, consiting of a Subject, a Property and a Value

use crate::errors::AtomicResult;
use crate::schema::Property;
use crate::values::Value;
use serde::Serialize;

/// The Atom is the (non-validated) string representation of a piece of data.
/// It's RichAtom sibling provides some extra methods.
#[derive(Clone, Debug, Serialize)]
pub struct Atom {
    pub subject: String,
    pub property: String,
    pub value: String,
}

impl Atom {
    pub fn new(subject: String, property: String, value: String) -> Self {
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

/// A more heavyweight atom that is validated,
/// converted to a native value and has various property details.
#[derive(Clone, Debug, Serialize)]
pub struct RichAtom {
    pub subject: String,
    pub property: Property,
    pub value: String,
    pub native_value: Value,
}

impl RichAtom {
    pub fn new(subject: String, property: Property, value: String) -> AtomicResult<Self> {
        Ok(RichAtom {
            subject,
            property: property.clone(),
            value: value.clone(),
            native_value: Value::new(&value, &property.data_type)?,
        })
    }
}

impl From<RichAtom> for Atom {
    fn from(richatom: RichAtom) -> Self {
        Atom::new(
            richatom.subject,
            richatom.property.subject,
            richatom.value,
        )
    }
}
