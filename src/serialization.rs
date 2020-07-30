use serde_json::from_str;
use crate::store::Store;

pub fn deserialize_json_array(string: &String) -> Vec<String> {
    let vector: Vec<String> = from_str(string).unwrap();
    return vector;
}

/// TODO
/// The depth is useful, since atomic data allows for cyclical (infinite-depth) relationships
pub fn resource_to_json(resource_url: String, store: &Store, depth: u32) -> String {
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
