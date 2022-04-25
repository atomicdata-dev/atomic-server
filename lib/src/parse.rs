//! Parsing / deserialization / decoding

use crate::{
    errors::AtomicResult, resources::PropVals, urls, values::SubResource, Resource, Storelike,
    Value,
};

pub const JSON_AD_MIME: &str = "application/ad+json";

pub fn parse_json_array(string: &str) -> AtomicResult<Vec<String>> {
    let vector: Vec<String> = serde_json::from_str(string)?;
    Ok(vector)
}

use serde_json::Map;

/// Parse a single Json AD string, convert to Atoms
/// WARNING: Does not match all props to datatypes (in Nested Resources), so it could result in invalid data, if the input data does not match the required datatypes.
#[tracing::instrument(skip(store))]
pub fn parse_json_ad_resource(
    string: &str,
    store: &impl crate::Storelike,
) -> AtomicResult<Resource> {
    let json: Map<String, serde_json::Value> = serde_json::from_str(string)?;
    json_ad_object_to_resource(json, store)
}

/// Parses a JSON-AD object, converts it to an Atomic Resource
#[tracing::instrument(skip(store))]
fn json_ad_object_to_resource(
    json: Map<String, serde_json::Value>,
    store: &impl crate::Storelike,
) -> AtomicResult<Resource> {
    match parse_json_ad_map_to_propvals(json, store)? {
        SubResource::Resource(r) => Ok(*r),
        SubResource::Nested(_) => Err("It's a nested Resource, no @id found".into()),
        SubResource::Subject(_) => Err("It's a string, not a nested resource".into()),
    }
}

/// Parses JSON-AD strings to resources, adds them to the store
#[tracing::instrument(skip(store))]
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
                            store.add_resource_opts(&resource, true, true, true)?
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

/// Parse a single Json AD string that represents an incoming Commit.
/// WARNING: Does not match all props to datatypes (in Nested Resources), so it could result in invalid data, if the input data does not match the required datatypes.
#[tracing::instrument(skip(store))]
pub fn parse_json_ad_commit_resource(
    string: &str,
    store: &impl crate::Storelike,
) -> AtomicResult<Resource> {
    let json: Map<String, serde_json::Value> = serde_json::from_str(string)?;
    let signature = json
        .get(urls::SUBJECT)
        .ok_or("No subject field in Commit.")?
        .to_string();
    let subject = format!("{}/commits/{}", store.get_server_url(), signature);
    let mut resource = Resource::new(subject);
    let propvals = match parse_json_ad_map_to_propvals(json, store)? {
        SubResource::Resource(r) => r.into_propvals(),
        SubResource::Nested(pv) => pv,
        SubResource::Subject(_) => {
            return Err("Commit resource is a string, should be a resource.".into())
        }
    };
    for (prop, val) in propvals {
        resource.set_propval(prop, val, store)?
    }
    Ok(resource)
}

/// Parse a single Json AD string, convert to Atoms
/// Does not match all props to datatypes, so it could result in invalid data.
#[tracing::instrument(skip(store))]
pub fn parse_json_ad_map_to_propvals(
    json: Map<String, serde_json::Value>,
    store: &impl crate::Storelike,
) -> AtomicResult<SubResource> {
    let mut propvals = PropVals::new();
    let mut subject = None;
    for (prop, val) in json {
        if prop == "@id" {
            subject = if let serde_json::Value::String(s) = val {
                Some(s.to_string())
            } else {
                return Err("@id must be a string".into());
            };
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
                let mut newvec: Vec<SubResource> = Vec::new();
                for v in arr {
                    match v {
                        serde_json::Value::String(str) => newvec.push(SubResource::Subject(str)),
                        // If it's an Object, it can be either an anonymous or a full resource.
                        serde_json::Value::Object(map) => {
                            let propvals = parse_json_ad_map_to_propvals(map, store)?;
                            newvec.push(propvals)
                        }
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
    if let Some(subj) = { subject } {
        let mut r = Resource::new(subj);
        r.set_propvals_unsafe(propvals);
        Ok(SubResource::Resource(r.into()))
    } else {
        Ok(SubResource::Nested(propvals))
    }
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
    #[should_panic(expected = "@id must be a strin")]
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

    #[test]
    fn parse_nested_resource_map_roundtrip() {
        let store = crate::Store::init().unwrap();

        let json = r#"{
            "@id": "https://atomicdata.dev/thingWithNestedMaps",
            "https://atomicdata.dev/properties/classtype": "https://atomicdata.dev/linkedThing",
            "https://atomicdata.dev/properties/datatype": {
                "https://atomicdata.dev/properties/name": "Anonymous nested resource"
            },
            "https://atomicdata.dev/properties/parent": {
                "@id": "https://atomicdata.dev/nestedThing",
                "https://atomicdata.dev/properties/name": "Named Nested Resource"
            }
          }"#;
        let parsed = parse_json_ad_resource(json, &store).unwrap();
        let serialized = parsed.to_json_ad().unwrap();
        println!("{}", serialized);
        assert_eq!(json.replace(' ', ""), serialized.replace(' ', ""));
    }

    #[test]
    fn parse_nested_resource_array() {
        let store = crate::Store::init().unwrap();

        let json = r#"{
            "@id": "https://atomicdata.dev/classes",
            "https://atomicdata.dev/properties/collection/members": [
              {
                "@id": "https://atomicdata.dev/classes/FirstThing",
                "https://atomicdata.dev/properties/description": "Named nested resource"
              },
              {
                "https://atomicdata.dev/properties/description": "Anonymous nested resource"
              },
              "https://atomicdata.dev/classes/ThirdThing"
            ]
          }"#;
        let parsed = parse_json_ad_resource(json, &store).unwrap();
        let members = parsed
            .get(urls::COLLECTION_MEMBERS)
            .unwrap()
            .to_subjects(Some("https://atomicdata.dev/classes https://atomicdata.dev/properties/collection/members".into()))
            .unwrap();
        let should_be = vec![
            "https://atomicdata.dev/classes/FirstThing",
            "https://atomicdata.dev/classes https://atomicdata.dev/properties/collection/members 1",
            "https://atomicdata.dev/classes/ThirdThing",
        ];
        assert_eq!(members, should_be);
    }
}
