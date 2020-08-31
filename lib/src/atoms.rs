use crate::store::Store;
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
  pub fn new(subject: String, property: String, value: String, store: &Store) -> Self {
    let rich_prop = store.get_property(&property).unwrap();
    RichAtom {
      subject: subject.clone(),
      property: rich_prop.clone(),
      value: value.clone(),
      native_value: Value::new(
        &value,
        &rich_prop.data_type)
        .expect(&*format!("Could not convert to native value {} {} {}", subject, property, value)),
    }
  }
}

pub fn plain_to_rich(plainatom: Atom, store: &Store) -> RichAtom {
  RichAtom::new(
    plainatom.subject,
    plainatom.property,
    plainatom.value,
    store,
  )
}

pub fn rich_to_plain(richatom: &RichAtom) -> Atom {
  return Atom {
    subject: richatom.subject.clone(),
    property: richatom.property.subject.clone(),
    value: richatom.value.clone(),
  }
}
