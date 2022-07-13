//! Parsing / deserialization / decoding

use crate::{
    datatype::DataType, errors::AtomicResult, resources::PropVals, urls, utils::check_valid_url,
    values::SubResource, AtomicError, Resource, Storelike, Value,
};

pub const JSON_AD_MIME: &str = "application/ad+json";

pub fn parse_json_array(string: &str) -> AtomicResult<Vec<String>> {
    let vector: Vec<String> = serde_json::from_str(string)?;
    Ok(vector)
}

use serde_json::Map;

/// Options for parsing (JSON-AD) resources
#[derive(Debug, Clone)]
pub struct ParseOpts {
    /// URL of the parent / Importer. This is where all the imported data will be placed under, hierarchically.
    /// If imported resources do not have an `@id`, we create new `@id` using the `localId` and the `parent`.
    pub importer: Option<String>,
    /// Who will perform the importing. If set to none, all possible commits will be signed by the default agent.
    pub for_agent: Option<String>,
    /// If true, will generate [crate::Commit]s for every single imported resource
    pub create_commits: bool,
    /// If the parsed resources should be added to the store.
    pub add: bool,
}

impl std::default::Default for ParseOpts {
    fn default() -> Self {
        Self {
            importer: None,
            for_agent: None,
            create_commits: false,
            add: true,
        }
    }
}

/// Parse a single Json AD string, convert to Atoms
/// WARNING: Does not match all props to datatypes (in Nested Resources),
/// so it could result in invalid data, if the input data does not match the required datatypes.
#[tracing::instrument(skip(store))]
pub fn parse_json_ad_resource(
    string: &str,
    store: &impl crate::Storelike,
    parse_opts: &ParseOpts,
) -> AtomicResult<Resource> {
    let json: Map<String, serde_json::Value> = serde_json::from_str(string)?;
    json_ad_object_to_resource(json, store, parse_opts)
}

/// Parses a JSON-AD object, converts it to an Atomic Resource
#[tracing::instrument(skip(store))]
fn json_ad_object_to_resource(
    json: Map<String, serde_json::Value>,
    store: &impl crate::Storelike,
    parse_opts: &ParseOpts,
) -> AtomicResult<Resource> {
    match parse_json_ad_map_to_propvals(json, store, parse_opts)? {
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
    parse_opts: &ParseOpts,
) -> AtomicResult<Vec<Resource>> {
    let parsed: serde_json::Value = serde_json::from_str(string)
        .map_err(|e| AtomicError::parse_error(&format!("JSON Parsing error: {}", e), None, None))?;
    let mut vec = Vec::new();
    match parsed {
        serde_json::Value::Array(arr) => {
            for item in arr {
                match item {
                    serde_json::Value::Object(obj) => {
                        let resource = json_ad_object_to_resource(obj, store, parse_opts)
                            .map_err(|e| format!("Unable to parse resource in array. {}", e))?;
                        if parse_opts.add {
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
            json_ad_object_to_resource(obj, store, parse_opts)
                .map_err(|e| format!("Unable to parse object. {}", e))?,
        ),
        _other => return Err("Root JSON element must be an object or array.".into()),
    }
    if parse_opts.add {
        for r in &vec {
            store.add_resource_opts(r, true, true, true)?
        }
    };
    Ok(vec)
}

/// Parse a single Json AD string that represents an incoming Commit.
/// WARNING: Does not match all props to datatypes (in Nested Resources), so it could result in invalid data,
/// if the input data does not match the required datatypes.
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
    let propvals = match parse_json_ad_map_to_propvals(json, store, &ParseOpts::default())? {
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
    parse_opts: &ParseOpts,
) -> AtomicResult<SubResource> {
    let mut propvals = PropVals::new();
    let mut subject: Option<String> = None;

    // Converts a string to a URL (subject), check for localid
    let try_to_subject = |s: &str, prop: &str| -> AtomicResult<String> {
        if check_valid_url(s).is_ok() {
            Ok(s.into())
        } else if let Some(importer) = &parse_opts.importer {
            Ok(generate_id_from_local_id(importer, s))
        } else {
            Err(AtomicError::parse_error(
                &format!("Unable to parse string as URL: {}", s),
                None,
                Some(prop),
            ))
        }
    };

    for (prop, val) in json {
        if prop == "@id" {
            subject = if let serde_json::Value::String(s) = val {
                check_valid_url(&s).map_err(|e| {
                    AtomicError::parse_error(
                        &format!("Unable to parse @id {s}: {e}"),
                        subject.as_deref(),
                        Some(&prop),
                    )
                })?;
                Some(s)
            } else {
                return Err(AtomicError::parse_error(
                    "@id must be a string",
                    subject.as_deref(),
                    Some(&prop),
                ));
            };
            continue;
        }

        let atomic_val = match val {
            serde_json::Value::Null => {
                return Err(AtomicError::parse_error(
                    "Null not allowed in JSON-AD",
                    subject.as_deref(),
                    Some(&prop),
                ));
            }
            serde_json::Value::Bool(bool) => Value::Boolean(bool),
            serde_json::Value::Number(num) => {
                let property = store.get_property(&prop)?;
                // Also converts numbers to strings, not sure what to think about this.
                // Does not result in invalid atomic data, but does allow for weird inputs
                Value::new(&num.to_string(), &property.data_type)?
            }
            serde_json::Value::String(str) => {
                // LocalIDs are mapped to @ids by appending the `localId` to the `importer`'s `parent`.
                if prop == urls::LOCAL_ID {
                    let parent = parse_opts.importer.as_ref()
                        .ok_or_else(|| AtomicError::parse_error(
                            "Encountered `localId`, which means we need a `parent` in the parsing options.",
                            subject.as_deref(),
                            Some(&prop),
                        ))?;
                    subject = Some(generate_id_from_local_id(parent, &str));
                }
                let property = store.get_property(&prop).map_err(|e| {
                    AtomicError::parse_error(
                        &format!("Unable to find property {prop}: {e}"),
                        subject.as_deref(),
                        Some(&prop),
                    )
                })?;

                match property.data_type {
                    DataType::AtomicUrl => {
                        // If the value is not a valid URL, and we have an importer, we can generate_id_from_local_id
                        let url = try_to_subject(&str, &prop)?;
                        Value::new(&url, &property.data_type)?
                    }
                    other => Value::new(&str.to_string(), &other).map_err(|e| {
                        AtomicError::parse_error(
                            &format!("Unable to parse value for prop {prop}: {e}. Value: {str}"),
                            subject.as_deref(),
                            Some(&prop),
                        )
                    })?,
                }
            }
            // In Atomic Data, all arrays are Resource Arrays which are serialized JSON things.
            // Maybe this step could be simplified? Just serialize to string?
            serde_json::Value::Array(arr) => {
                let mut newvec: Vec<SubResource> = Vec::new();
                for v in arr {
                    match v {
                        serde_json::Value::String(str) => {
                            let url = try_to_subject(&str, &prop)?;
                            newvec.push(SubResource::Subject(url))
                        }
                        // If it's an Object, it can be either an anonymous or a full resource.
                        serde_json::Value::Object(map) => {
                            let propvals = parse_json_ad_map_to_propvals(map, store, parse_opts)?;
                            newvec.push(propvals)
                        }
                        err => {
                            return Err(AtomicError::parse_error(
                                &format!("Found non-string item in resource array: {err}."),
                                subject.as_deref(),
                                Some(&prop),
                            ))
                        }
                    }
                }
                Value::ResourceArray(newvec)
            }
            serde_json::Value::Object(map) => {
                Value::NestedResource(parse_json_ad_map_to_propvals(map, store, parse_opts)?)
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

fn generate_id_from_local_id(importer_subject: &str, local_id: &str) -> String {
    format!("{}/{}", importer_subject, local_id)
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
        let resource = parse_json_ad_resource(json_input, &store, &ParseOpts::default()).unwrap();
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
        parse_json_ad_resource(json_input, &store, &ParseOpts::default()).unwrap();
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
        parse_json_ad_resource(json_input, &store, &ParseOpts::default()).unwrap();
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
        parse_json_ad_resource(json_input, &store, &ParseOpts::default()).unwrap();
    }

    #[test]
    fn serialize_parse_roundtrip() {
        use crate::Storelike;
        let store1 = crate::Store::init().unwrap();
        store1.populate().unwrap();
        let serialized =
            crate::serialize::resources_to_json_ad(&store1.all_resources(true)).unwrap();
        let store2 = crate::Store::init().unwrap();
        store2.import(&serialized, &ParseOpts::default()).unwrap();
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
        store.populate().unwrap();

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
        let parsed = parse_json_ad_resource(json, &store, &ParseOpts::default()).unwrap();
        let serialized = parsed.to_json_ad().unwrap();
        println!("{}", serialized);
        assert_eq!(json.replace(' ', ""), serialized.replace(' ', ""));
    }

    #[test]
    fn parse_nested_resource_array() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();

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
        let parsed = parse_json_ad_resource(json, &store, &ParseOpts::default()).unwrap();
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

    #[test]
    fn import_resource_with_localid() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let agent = store.create_agent(None).unwrap();
        store.set_default_agent(agent);

        let local_id = "my-local-id";

        let json = r#"{
            "https://atomicdata.dev/properties/localId": "my-local-id",
            "https://atomicdata.dev/properties/name": "My resource"
          }"#;

        let mut importer = Resource::new_instance(urls::IMPORTER, &store).unwrap();
        importer.save_locally(&store).unwrap();

        let parse_opts = ParseOpts {
            create_commits: true,
            for_agent: None,
            importer: Some(importer.get_subject().into()),
            add: true,
        };

        store.import(json, &parse_opts).unwrap();

        let imported_subject = generate_id_from_local_id(importer.get_subject(), local_id);

        let found = store.get_resource(&imported_subject).unwrap();
        assert_eq!(found.get(urls::NAME).unwrap().to_string(), "My resource");
        assert_eq!(found.get(urls::LOCAL_ID).unwrap().to_string(), local_id);
    }

    #[test]
    fn import_resources_localid_references() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let agent = store.create_agent(None).unwrap();
        store.set_default_agent(agent);

        let json = r#"[
        {
            "https://atomicdata.dev/properties/localId": "reference",
            "https://atomicdata.dev/properties/name": "My referenced resource"
        },
        {
            "https://atomicdata.dev/properties/localId": "my-local-id",
            "https://atomicdata.dev/properties/name": "My resource that refers",
            "https://atomicdata.dev/properties/parent": "reference",
            "https://atomicdata.dev/properties/write": ["reference"]
        }
        ]"#;

        let mut importer = Resource::new_instance(urls::IMPORTER, &store).unwrap();
        importer.save_locally(&store).unwrap();

        let parse_opts = ParseOpts {
            create_commits: true,
            for_agent: None,
            importer: Some(importer.get_subject().into()),
            add: true,
        };

        store.import(json, &parse_opts).unwrap();

        let reference_subject = generate_id_from_local_id(importer.get_subject(), "reference");
        let my_subject = generate_id_from_local_id(importer.get_subject(), "my-local-id");
        let found = store.get_resource(&my_subject).unwrap();

        assert_eq!(
            found.get(urls::PARENT).unwrap().to_string(),
            reference_subject
        );
        assert_eq!(
            found
                .get(urls::WRITE)
                .unwrap()
                .to_subjects(None)
                .unwrap()
                .first()
                .unwrap(),
            &reference_subject
        );
    }
}
