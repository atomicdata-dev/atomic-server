use crate::errors::AtomicResult;
use crate::storelike::Property;
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
            subject: subject.clone(),
            property: property.clone(),
            value: value.clone(),
        }
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
            subject: subject.clone(),
            property: property.clone(),
            value: value.clone(),
            native_value: Value::new(&value, &property.data_type)?,
        })
    }
}

/// Individual change to a resource
pub struct Delta {
    pub subject: String,
    pub property: String,
    pub value: String,
    pub method: String,
}

impl From<&Delta> for Atom {
    fn from(delta: &Delta) -> Self {
        Atom::new(
            delta.subject.clone(),
            delta.property.clone(),
            delta.value.clone(),
        )
    }
}

impl From<&RichAtom> for Atom {
    fn from(richatom: &RichAtom) -> Self {
        Atom::new(
            richatom.subject.clone(),
            richatom.property.subject.clone(),
            richatom.value.clone(),
        )
    }
}
