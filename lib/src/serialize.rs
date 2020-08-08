use serde_json;
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
