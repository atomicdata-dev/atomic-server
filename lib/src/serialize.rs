use serde_json;
use crate::store::{self, Store};
use crate::errors::Result;

pub fn deserialize_json_array(string: &String) -> Result<Vec<String>> {
    let vector: Vec<String> = serde_json::from_str(string).expect(&*format!("Can't parse value {} as array", string));
    return Ok(vector);
}

pub fn serialize_json_array(items: &Vec<String>) -> Result<String> {
    let string = serde_json::to_string(items).expect("Can't serialize to string");
    return Ok(string);
}

// Should list all the supported serialization formats
pub enum SerialializationFormats {
    JSON,
    AD3,
}

/// The depth is useful, since atomic data allows for cyclical (infinite-depth) relationships
pub fn resource_to_json(resource_url: &String, store: &Store, _depth: u32) -> Result<String> {
    use serde_json::{Map, Value};

    let resource = store.get(resource_url).ok_or("Resource not found")?;

    // Initiate JSON object
    let mut map = Map::new();

    // For every atom, find the key, datatype and add it to the @context
    for (prop_url, value) in resource.iter() {
        // Add it to the JSON object
        // Very naive implementation, should actually turn:
        // [ ] ResourceArrays into arrrays
        // [ ] URLS into @id things
        // [ ] Numbers into native numbers
        // [ ] Resoures into objects, if the nesting depth allows it
        let property = store::get_property(prop_url, store).unwrap();
        map.insert(property.shortname, Value::String(value.into()));
    }

    let obj = Value::Object(map);
    let string = serde_json::to_string_pretty(&obj).unwrap();

    return Ok(string);
}

pub fn resource_to_ad3(subject: &String, store: &Store, domain: Option<&String>) -> Result<String> {
    let mut string = String::new();
    let resource = store.get(subject).ok_or("Resource not found")?;
    let mut mod_subject = subject.clone();
    // Replace local schema with actual local domain
    if subject.starts_with("_:") && domain.is_some() {
        // Remove first two characters
        let mut chars = subject.chars();
        chars.next();
        chars.next();
        mod_subject = format!("{}{}", &domain.unwrap(), &chars.as_str());
    }
    for (property, value) in resource {
        let mut ad3_atom =
        serde_json::to_string(&vec![&mod_subject, property, value]).expect("Can't serialize");
        ad3_atom.push_str("\n");
        &string.push_str(&*ad3_atom);
    }
    return Ok(string);
}
