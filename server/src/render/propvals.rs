use super::atom::value_to_html;
use crate::errors::BetterResult;
use atomic_lib::{storelike::Property, Storelike, Value};
use serde::Serialize;
use std::collections::HashMap;

/// Useful for rendering Atomic Data
#[derive(Serialize)]
pub struct PropVal {
    pub property: Property,
    pub value: String,
    pub value_html: String,
    pub subject: String,
}

pub type PropVals = Vec<PropVal>;

/// Creates a vector of PropVals, which have easy to print HTML values
pub fn from_hashmap_resource(
    resource: &HashMap<String, String>,
    store: &mut dyn Storelike,
    subject: String,
) -> BetterResult<PropVals> {
    let mut hashmap: PropVals = Vec::new();

    for (property, value) in resource.iter() {
        let fullprop = store.get_property(property)?;
        let val = Value::new(value, &fullprop.data_type)?;
        hashmap.push(PropVal {
            property: fullprop,
            value: value.into(),
            value_html: value_to_html(&val),
            subject: subject.clone(),
        });
    }
    Ok(hashmap)
}
