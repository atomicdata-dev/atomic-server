//! Parsing / deserialization / decoding

use crate::{errors::AtomicResult, resources::PropVals, urls, Resource, Storelike, Value};

pub const JSON_AD_MIME: &str = "application/ad+json";

pub fn parse_json_array(string: &str) -> AtomicResult<Vec<String>> {
    let vector: Vec<String> = serde_json::from_str(string)?;
    Ok(vector)
}

use serde_json::Map;

/// Parse a single Json AD string, convert to Atoms
/// WARNING: Does not match all props to datatypes (in Nested Resources), so it could result in invalid data, if the input data does not match the required datatypes.
pub fn parse_json_ad_resource(
    string: &str,
    store: &impl crate::Storelike,
) -> AtomicResult<Resource> {
    let json: Map<String, serde_json::Value> = serde_json::from_str(string)?;
    json_ad_object_to_resource(json, store)
}

/// Parses a JSON-AD object, converts it to an Atomic Resource
fn json_ad_object_to_resource(
    json: Map<String, serde_json::Value>,
    store: &impl crate::Storelike,
) -> AtomicResult<Resource> {
    let subject = get_id(json.clone()).map_err(|e| format!("Unable to get @id. {}", e))?;
    let mut resource = Resource::new(subject.clone());
    let propvals = parse_json_ad_map_to_propvals(json, store)
        .map_err(|e| format!("Unable to parse JSON-AD for {}. {}", &subject, e))?;
    for (prop, val) in propvals {
        // I'd like to get rid of these clones! But I want to use them in the error, too...
        resource
            .set_propval(prop.clone(), val.clone(), store)
            .map_err(|e| {
                format!(
                    "Unable to set prop: {}, val: {} for subject {}. {}",
                    prop, val, subject, e
                )
            })?
    }
    Ok(resource)
}

/// Returns the @id in a JSON object
fn get_id(object: serde_json::Map<String, serde_json::Value>) -> AtomicResult<String> {
    Ok(object
        .get("@id")
        .ok_or("Missing `@id` value in top level JSON. Could not determine Subject of Resource.")?
        .as_str()
        .ok_or("`@id` is not a string - should be the Subject of the Resource (a URL)")?
        .to_string())
}

/// Parses JSON-AD strings to resources, adds them to the store
pub fn parse_json_ad_array(
    string: &str,
    store: &impl Storelike,
    add: bool,
) -> AtomicResult<Vec<Resource>> {
    let parsed: serde_json::Value = serde_json::from_str(string)?;
    let mut vec = Vec::new();
    match parsed {
        serde_json::Value::Array(arr) => {
            for item in arr {
                match item {
                    serde_json::Value::Object(obj) => {
                        let resource = json_ad_object_to_resource(obj, store)
                            .map_err(|e| format!("Unable to parse resource. {}", e))?;
                        if add {
                            store.add_resource(&resource)?
                        };
                        vec.push(resource);
                    }
                    wrong => {
                        return Err(
                            format!("Wrong datatype, expected object, got: {:?}", wrong).into()
                        )
                    }
                }
            }
        }
        serde_json::Value::Object(obj) => vec.push(
            json_ad_object_to_resource(obj, store)
                .map_err(|e| format!("Unable to parse resource {}", e))?,
        ),
        _other => return Err("Root JSON element must be an object or array.".into()),
    }
    Ok(vec)
}

/// Parse a single Json AD string, convert to Atoms
/// WARNING: Does not match all props to datatypes (in Nested Resources), so it could result in invalid data, if the input data does not match the required datatypes.
pub fn parse_json_ad_commit_resource(
    string: &str,
    store: &impl crate::Storelike,
) -> AtomicResult<Resource> {
    let json: Map<String, serde_json::Value> = serde_json::from_str(string)?;
    let signature = json
        .get(urls::SUBJECT)
        .ok_or("No subject field in Commit.")?
        .to_string();
    let subject = format!("{}/commits/{}", store.get_base_url(), signature);
    let mut resource = Resource::new(subject);
    let propvals = parse_json_ad_map_to_propvals(json, store)?;
    for (prop, val) in propvals {
        resource.set_propval(prop, val, store)?
    }
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
                // Also converts numbers to strings, not sure what to think about this.
                // Does not result in invalid atomic data, but does allow for weird inputs
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
                Value::ResourceArraySubjects(newvec)
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
        let json_output = resource.to_json_ad().unwrap();
        let in_value: serde_json::Value = serde_json::from_str(json_input).unwrap();
        let out_value: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        assert_eq!(in_value, out_value);
    }

    #[test]
    #[should_panic(
        expected = "`@id` is not a string - should be the Subject of the Resource (a URL)"
    )]
    fn parse_and_serialize_json_ad_wrong_id() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let json_input = r#"{"@id": 5}"#;
        parse_json_ad_resource(json_input, &store).unwrap();
    }

    #[test]
    // This test should actually fail, I think, because the datatype should match the property.
    // #[should_panic(expected = "Datatype")]
    fn parse_and_serialize_json_ad_wrong_datatype_int_to_str() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let json_input = r#"{
            "@id": "https://atomicdata.dev/classes/Agent",
            "https://atomicdata.dev/properties/description": 1
          }"#;
        parse_json_ad_resource(json_input, &store).unwrap();
    }

    #[test]
    #[should_panic(expected = "Not a valid Timestamp: 1.124. invalid digit found in string")]
    fn parse_and_serialize_json_ad_wrong_datatype_float() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let json_input = r#"{
            "@id": "https://atomicdata.dev/classes/Agent",
            "https://atomicdata.dev/properties/createdAt": 1.124
          }"#;
        parse_json_ad_resource(json_input, &store).unwrap();
    }

    #[test]
    fn serialize_parse_roundtrip() {
        use crate::Storelike;
        let store1 = crate::Store::init().unwrap();
        store1.populate().unwrap();
        let serialized =
            crate::serialize::resources_to_json_ad(&store1.all_resources(true)).unwrap();
        let store2 = crate::Store::init().unwrap();
        store2.import(&serialized).unwrap();
        let all1 = store1.all_resources(true);
        let all2 = store2.all_resources(true);
        assert_eq!(all1.len(), all2.len());
        let found_shortname = store2
            .get_resource(urls::CLASS)
            .unwrap()
            .get(urls::SHORTNAME)
            .unwrap()
            .clone();
        assert_eq!(found_shortname.to_string(), "class");
    }
}
