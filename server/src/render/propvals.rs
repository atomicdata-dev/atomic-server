use atomic_lib::{Storelike, storelike::Property, Value};
use serde::Serialize;
use std::collections::HashMap;
use crate::errors::BetterResult;
use super::atom::value_to_html;

/// Useful for rendering Atomic Data
#[derive(Serialize)]
pub struct PropVal {
    pub property: Property,
    pub value: String,
}

pub type PropVals = Vec<PropVal>;

pub fn from_hashmap_resource(resource: &HashMap<String, String>, store: &dyn Storelike) -> BetterResult<PropVals> {
    let mut hashmap: PropVals = Vec::new();

    for (property, value) in resource.iter() {
        let fullprop =  store.get_property(property)?;
        let val =  Value::new(value, &fullprop.data_type)?;
        hashmap.push(PropVal {
            property: fullprop,
            value: value_to_html(val)
        });
    }
    Ok(hashmap)
}
