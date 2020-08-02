use serde_json::from_str;
use crate::store::Store;
use crate::errors::{BetterResult};

pub fn deserialize_json_array(string: &String) -> Vec<String> {
    let vector: Vec<String> = from_str(string).unwrap();
    return vector;
}

/// The depth is useful, since atomic data allows for cyclical (infinite-depth) relationships
pub fn resource_to_json(resource_url: String, store: &Store, depth: u32) -> String {
    todo!("");
    use serde_json::{Map, Value};

    let keys_vals = vec![(String::from("someKey"), String::from("someVal"))];

    let mut map = Map::new();

    // assuming keys_vals is a Vec<(String, String)>
    for (key, val) in keys_vals.into_iter() {
        map.insert(key, Value::String(val));
    }

    let obj = Value::Object(map);

    return obj.to_string();
}

pub fn resource_to_ad3(subject: &String, store: &Store, domain: &String) -> BetterResult<String> {
    let mut string = String::new();
    let resource = store.get(subject).ok_or("Resource not found")?;
    let mut mod_subject = subject.clone();
    // Replace local schema with actual local domain
    if subject.starts_with("_:") {
        // Remove first two characters
        let mut chars = subject.chars();
        chars.next();
        chars.next();
        mod_subject = format!("{}{}", &domain, &chars.as_str());
    }
    for (property, value) in resource {
        let mut ad3_atom =
        serde_json::to_string(&vec![&mod_subject, property, value]).expect("Can't serialize");
        ad3_atom.push_str("\n");
        &string.push_str(&*ad3_atom);
    }
    return Ok(string);
}
