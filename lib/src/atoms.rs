use crate::errors::AtomicResult;
use crate::storelike::Property;
use crate::values::Value;
use crate::DeltaLine;
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

impl From<DeltaLine> for Atom {
    fn from(delta: DeltaLine) -> Self {
        Atom::new(
            delta.subject,
            delta.property,
            delta.value,
        )
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
