use crate::store::{Store, Value};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Atom {
    pub subject: String,
    pub property: String,
    pub value: String,
    pub native_value: Value,
}

impl Atom {
  pub fn new(subject: String, property: String, value: String, store: &Store) -> Self {
    Atom {
      subject: subject.clone(),
      property: property.clone(),
      value: value.clone(),
      native_value: store.get_native_value(
        &value,
        &store.get_property(&property).unwrap().data_type)
        .expect(&*format!("Could not convert to native value {} {} {}", subject, property, value)),
    }
  }
}
