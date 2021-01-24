//! Parsing / deserialization / decoding

use crate::{errors::AtomicResult, resources::PropVals, Atom, Resource, Value};

pub const AD3_MIME: &str = "application/ad3-ndjson";

/// Parses an Atomic Data Triples (.ad3) string and adds the Atoms to the store.
/// Allows comments and empty lines.
pub fn parse_ad3(string: &str) -> AtomicResult<Vec<Atom>> {
    let mut atoms: Vec<Atom> = Vec::new();
    for line in string.lines() {
        match line.chars().next() {
            // These are comments
            Some('#') => {}
            Some(' ') => {}
            // That's an array, awesome
            Some('[') => {
                let string_vec: Vec<String> = match parse_json_array(line) {
                    Ok(vec) => vec,
                    Err(e) => {return Err(format!("Parsing error in {:?}. Needs to be a JSON array of three strings. {}", line, e).into())}
                };
                if string_vec.len() != 3 {
                    return Err(format!(
                        "Wrong length of array at line {:?}: wrong length of array, should be 3",
                        line
                    )
                    .into());
                }
                let subject = string_vec[0].clone();
                let property = string_vec[1].clone();
                let value = string_vec[2].clone();
                atoms.push(Atom::new(subject, property, value));
            }
            Some(char) => {
                return Err(format!(
                    "AD3 Parsing error at '{}', line cannot start with {}. Should start with JSON Array '['",
                    line, char
                )
                .into())
            }
            None => {}
        };
    }
    Ok(atoms)
}

pub fn parse_json_array(string: &str) -> AtomicResult<Vec<String>> {
    let vector: Vec<String> = serde_json::from_str(string)?;
    Ok(vector)
}

use serde_json::Map;

/// Parse a single Json AD string, convert to Atoms
/// Does not match all props to datatypes, so it could result in invalid data.
pub fn parse_json_ad_resource(
    string: &str,
    store: &impl crate::Storelike,
) -> AtomicResult<Resource> {
    let json: Map<String, serde_json::Value> = serde_json::from_str(string)?;
    let subject = json
        .get("@id")
        .ok_or("Missing `@id` value in top level JSON. Could not determine Subject of Resource.")?
        .as_str()
        .ok_or("`@id` is not a string - should be the Subject of the Resource (a URL)")?;
    let mut resource = Resource::new(subject.to_string());
    for (key, val) in json {

        if key == "@id" {
        } else {
            println!("k: {} v: {}", key, val.to_string());
            match val {
                serde_json::Value::Null => return Err("Null not allowed in JSON-AD".into()),
                serde_json::Value::Bool(bool) => {
                    resource.set_propval(key, Value::Boolean(bool), store)
                }
                serde_json::Value::Number(num) => {
                    // Turns invalid numbers into valid strings - not cool.
                    resource.set_propval_string(key, &num.to_string(), store)
                }
                serde_json::Value::String(str) => {
                    println!("STRING: {} TO_STRING: {}", str, str.to_string());
                    resource.set_propval_string(key, &str.to_string(), store)
                }
                // In Atomic Data, all arrays are Resource Arrays which are serialized JSON things.
                // Maybe this step could be simplified? Just serialize to string?
                serde_json::Value::Array(arr) => {
                    let mut newvec: Vec<String> = Vec::new();
                    for v in arr {
                        match v {
                            serde_json::Value::String(str) => newvec.push(str),
                            _err => return Err("Found non-string item in resource array.".into()),
                        }
                    }
                    resource.set_propval(key, Value::ResourceArray(newvec), store)
                }
                serde_json::Value::Object(map) => {
                    let atomic_val =
                        Value::NestedResource(parse_json_ad_map_to_propvals(map, store)?);
                    resource.set_propval(key, atomic_val, store)
                }
            }?;
        }
    }
    // parse_json_ad_map_to_propvals(json)
    resource.validate_datatypes(store)?;
    Ok(resource)
}

/// Parse a single Json AD string, convert to Atoms
/// Does not match all props to datatypes, so it could result in invalid data.
pub fn parse_json_ad_map_to_propvals(
    json: Map<String, serde_json::Value>,
    store: &impl crate::Storelike,
) -> AtomicResult<PropVals> {
    let mut propvals = PropVals::new();
    for (prop, val) in json {
        if prop == "@id" {
            // Not sure if this is the correct behavior.
            // This will turn named resources into nested ones!
            // To fix this, we need to use an Enum for Value::ResourceArray(enum)
            continue;
        }
        let atomic_val = match val {
            serde_json::Value::Null => return Err("Null not allowed in JSON-AD".into()),
            serde_json::Value::Bool(bool) => Value::Boolean(bool),
            serde_json::Value::Number(num) => {
                let property = store.get_property(&prop)?;
                Value::new(&num.to_string(), &property.data_type)?
            }
            serde_json::Value::String(str) => {
                let property = store.get_property(&prop)?;
                Value::new(&str.to_string(), &property.data_type)?
            }
            // In Atomic Data, all arrays are Resource Arrays which are serialized JSON things.
            // Maybe this step could be simplified? Just serialize to string?
            serde_json::Value::Array(arr) => {
                let mut newvec: Vec<String> = Vec::new();
                for v in arr {
                    match v {
                        serde_json::Value::String(str) => newvec.push(str),
                        _err => return Err("Found non-string item in resource array.".into()),
                    }
                }
                Value::ResourceArray(newvec)
            }
            serde_json::Value::Object(map) => {
                Value::NestedResource(parse_json_ad_map_to_propvals(map, store)?)
            }
        };
        // Some of these values are _not correctly matched_ to the datatype.
        propvals.insert(prop, atomic_val);
    }
    Ok(propvals)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Storelike;

    #[test]
    fn parse_and_serialize_json_ad() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let json_input = r#"{
            "@id": "https://atomicdata.dev/classes/Agent",
            "https://atomicdata.dev/properties/description": "An Agent is a user that can create or modify data. It has two keys: a private and a public one. The private key should be kept secret. The publik key is for proving that the ",
            "https://atomicdata.dev/properties/isA": [
               "https://atomicdata.dev/classes/Class"
            ],
            "https://atomicdata.dev/properties/recommends": [
              "https://atomicdata.dev/properties/description",
              "https://atomicdata.dev/properties/remove",
              "https://atomicdata.dev/properties/destroy"
            ],
              "https://atomicdata.dev/properties/requires": [
              "https://atomicdata.dev/properties/createdAt",
              "https://atomicdata.dev/properties/name",
              "https://atomicdata.dev/properties/publicKey"
            ],
            "https://atomicdata.dev/properties/shortname": "agent"
          }"#;
        let resource = parse_json_ad_resource(json_input, &store).unwrap();
        let json_output = resource.to_json_ad(&store).unwrap();
        let in_value: serde_json::Value = serde_json::from_str(json_input).unwrap();
        let out_value: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        assert_eq!(in_value, out_value);
    }

    #[test]
    #[should_panic(expected = "`@id` is not a string - should be the Subject of the Resource (a URL)")]
    fn parse_and_serialize_json_ad_wrong_id() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let json_input = r#"{"@id": 5}"#;
        parse_json_ad_resource(json_input, &store).unwrap();
    }

    #[test]
    // This test should actually fail, I think, because the datatype should match the property.
    #[should_panic(expected = "Datatype")]
    fn parse_and_serialize_json_ad_wrong_datatype() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let json_input = r#"{
            "@id": "https://atomicdata.dev/classes/Agent",
            "https://atomicdata.dev/properties/description": 1
          }"#;
        parse_json_ad_resource(json_input, &store).unwrap();
    }
}
