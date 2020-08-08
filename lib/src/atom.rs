use crate::store::{Store, Value};

#[derive(Debug)]
pub struct Atom {
    pub subject: String,
    pub property: String,
    pub value: String,
    pub native_value: Value,
}

impl Atom {
  pub fn new(subject: String, property: String, value: String, store: &Store) -> Self {
    Atom {
      subject,
      property: property.clone(),
      value: value.clone(),
      native_value: store.get_native_value(&value, &property).unwrap(),
    }
  }
}
