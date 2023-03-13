//! Parsing / deserialization / decoding

use crate::{
    commit::CommitOpts, datatype::DataType, errors::AtomicResult, resources::PropVals, urls,
    utils::check_valid_url, values::SubResource, AtomicError, Resource, Storelike, Value,
};

pub const JSON_AD_MIME: &str = "application/ad+json";

pub fn parse_json_array(string: &str) -> AtomicResult<Vec<String>> {
    let vector: Vec<String> = serde_json::from_str(string)?;
    Ok(vector)
}

use serde_json::Map;

/// Options for parsing (JSON-AD) resources.
/// Many of these are related to rights, as parsing often implies overwriting / setting resources.
#[derive(Debug, Clone)]
pub struct ParseOpts {
    /// URL of the parent / Importer. This is where all the imported data will be placed under, hierarchically.
    /// If imported resources do not have an `@id`, we create new `@id` using the `localId` and the `parent`.
    /// If the importer resources already have a `parent` set, we'll use that one.
    pub importer: Option<String>,
    /// Who's rights will be checked when creating the imported resources.
    /// Is only used when `save` is set to [SaveOpts::Commit].
    /// If [None] is passed, all resources will be
    pub for_agent: Option<String>,
    /// Who will perform the importing. If set to none, all possible commits will be signed by the default agent.
    /// Note that this Agent needs a private key to sign the commits.
    /// Is only used when `save` is set to `Commit`.
    pub signer: Option<crate::agents::Agent>,
    /// How you want to save the Resources, if you want to add Commits for every Resource.
    pub save: SaveOpts,
    /// Overwrites existing resources with the same `@id`, even if they are not children of the `importer`.
    /// This can be a dangerous value if true, because it can overwrite _all_ resources where the `for_agen` has write rights.
    /// Only parse items from sources that you trust!
    pub overwrite_outside: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SaveOpts {
    /// Don't save the parsed resources to the store.
    /// No authorization checks will be performed.
    DontSave,
    /// Save the parsed resources to the store, but don't create Commits for every change.
    /// Removes existing properties that are not present in the imported resource.
    /// Does not perform authorization checks.
    Save,
    /// Create Commits for every change.
    /// Does not remove existing properties.
    /// Performs authorization cheks (if enabled)
    Commit,
}

impl std::default::Default for ParseOpts {
    fn default() -> Self {
        Self {
            signer: None,
            importer: None,
            for_agent: None,
            overwrite_outside: true,
            save: SaveOpts::Save,
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
    match parse_json_ad_map_to_resource(json, store, parse_opts)? {
        SubResource::Resource(r) => Ok(*r),
        SubResource::Nested(_) => Err("It's a nested Resource, no @id found".into()),
        SubResource::Subject(_) => Err("It's a string, not a nested resource".into()),
    }
}

/// Parses JSON-AD string.
/// Accepts an array containing multiple objects, or one single object.
#[tracing::instrument(skip(store))]
pub fn parse_json_ad_string(
    string: &str,
    store: &impl Storelike,
    parse_opts: &ParseOpts,
) -> AtomicResult<Vec<Resource>> {
    let parsed: serde_json::Value = serde_json::from_str(string)
        .map_err(|e| AtomicError::parse_error(&format!("Invalid JSON: {}", e), None, None))?;
    let mut vec = Vec::new();
    match parsed {
        serde_json::Value::Array(arr) => {
            for item in arr {
                match item {
                    serde_json::Value::Object(obj) => {
                        let resource = json_ad_object_to_resource(obj, store, parse_opts)
                            .map_err(|e| format!("Unable to process resource in array. {}", e))?;
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
    // For most save menthods, we need to add the atoms to the index here.
    // The `Commit` feature adds to index by itself, so we can skip that step here.
    if parse_opts.save != SaveOpts::Commit {
        for res in &vec {
            for atom in res.to_atoms() {
                store.add_atom_to_index(&atom, res)?;
            }
        }
    }
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
    let propvals = match parse_json_ad_map_to_resource(json, store, &ParseOpts::default())? {
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
/// Adds to the store if `add` is true.
#[tracing::instrument(skip(store))]
fn parse_json_ad_map_to_resource(
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
                            let propvals = parse_json_ad_map_to_resource(map, store, parse_opts)?;
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
                Value::NestedResource(parse_json_ad_map_to_resource(map, store, parse_opts)?)
            }
        };
        // Some of these values are _not correctly matched_ to the datatype.
        propvals.insert(prop, atomic_val);
    }
    // if there is no parent set, we set it to the Importer
    if let Some(importer) = &parse_opts.importer {
        if !propvals.contains_key(urls::PARENT) {
            propvals.insert(urls::PARENT.into(), Value::AtomicUrl(importer.into()));
        }
    }
    if let Some(subj) = { subject } {
        let r = match &parse_opts.save {
            SaveOpts::DontSave => {
                let mut r = Resource::new(subj);
                r.set_propvals_unsafe(propvals);
                r
            }
            SaveOpts::Save => {
                let mut r = Resource::new(subj);
                r.set_propvals_unsafe(propvals);
                store.add_resource(&r)?;
                r
            }
            SaveOpts::Commit => {
                let mut r = if let Ok(orig) = store.get_resource(&subj) {
                    // If the resource already exists, and overwrites outside are not permitted, and it does not have the importer as parent...
                    // Then we throw!
                    // Because this would enable malicious users to overwrite resources that they shouldn't.
                    if !parse_opts.overwrite_outside {
                        let importer = parse_opts.importer.as_deref().unwrap();
                        if !orig.has_parent(store, importer) {
                            Err(
                                format!("Cannot overwrite {subj} outside of importer! Enable `overwrite_outside`"),
                            )?
                        }
                    };
                    orig
                } else {
                    Resource::new(subj)
                };
                for (prop, val) in propvals {
                    r.set_propval(prop, val, store)?;
                }
                let signer = parse_opts
                    .signer
                    .clone()
                    .ok_or("No agent to sign Commit with. Either pass a `for_agent` or ")?;
                let commit = r.get_commit_builder().clone().sign(&signer, store, &r)?;
                let opts = CommitOpts {
                    validate_schema: true,
                    validate_signature: true,
                    validate_timestamp: false,
                    validate_rights: parse_opts.for_agent.is_some(),
                    validate_previous_commit: false,
                    validate_for_agent: parse_opts.for_agent.clone(),
                    update_index: true,
                };

                commit
                    .apply_opts(store, &opts)
                    .map_err(|e| format!("Failed to save {}: {}", r.get_subject(), e))?
                    .resource_new
                    .unwrap()
            }
        };
        Ok(r.into())
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

    // Roundtrip test requires fixing, because the order of imports can get problematic.
    // We should first import all Properties, then Classes, then other things.
    // See https://github.com/atomicdata-dev/atomic-data-rust/issues/614
    #[ignore]
    #[test]
    fn serialize_parse_roundtrip() {
        use crate::Storelike;
        let store1 = crate::Store::init().unwrap();
        store1.populate().unwrap();
        let store2 = crate::Store::init().unwrap();
        let all1: Vec<Resource> = store1.all_resources(true).collect();
        let serialized = crate::serialize::resources_to_json_ad(&all1).unwrap();

        store2
            .import(&serialized, &ParseOpts::default())
            .expect("import failed");
        let all2_count = store2.all_resources(true).count();

        assert_eq!(all1.len(), all2_count);
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

    fn create_store_and_importer() -> (crate::Store, String) {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let agent = store.create_agent(None).unwrap();
        store.set_default_agent(agent);
        let mut importer = Resource::new_instance(urls::IMPORTER, &store).unwrap();
        importer.save_locally(&store).unwrap();
        (store, importer.get_subject().into())
    }

    #[test]
    fn import_resource_with_localid() {
        let (store, importer) = create_store_and_importer();

        let local_id = "my-local-id";

        let json = r#"{
            "https://atomicdata.dev/properties/localId": "my-local-id",
            "https://atomicdata.dev/properties/name": "My resource"
          }"#;

        let parse_opts = ParseOpts {
            save: SaveOpts::Commit,
            signer: Some(store.get_default_agent().unwrap()),
            for_agent: None,
            overwrite_outside: false,
            importer: Some(importer.clone()),
        };

        store.import(json, &parse_opts).unwrap();

        let imported_subject = generate_id_from_local_id(&importer, local_id);

        let found = store.get_resource(&imported_subject).unwrap();
        println!("{:?}", found);
        assert_eq!(found.get(urls::NAME).unwrap().to_string(), "My resource");
        assert_eq!(found.get(urls::LOCAL_ID).unwrap().to_string(), local_id);
    }

    #[test]
    fn import_resources_localid_references() {
        let (store, importer) = create_store_and_importer();

        let parse_opts = ParseOpts {
            save: SaveOpts::Commit,
            for_agent: None,
            signer: Some(store.get_default_agent().unwrap()),
            overwrite_outside: false,
            importer: Some(importer.clone()),
        };

        store
            .import(include_str!("../test_files/local_id.json"), &parse_opts)
            .unwrap();

        let reference_subject = generate_id_from_local_id(&importer, "reference");
        let my_subject = generate_id_from_local_id(&importer, "my-local-id");
        let found = store.get_resource(&my_subject).unwrap();
        let found_ref = store.get_resource(&reference_subject).unwrap();

        assert_eq!(
            found.get(urls::PARENT).unwrap().to_string(),
            reference_subject
        );
        assert_eq!(&found_ref.get(urls::PARENT).unwrap().to_string(), &importer);
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

    #[test]
    fn import_resource_malicious() {
        let (store, importer) = create_store_and_importer();

        // Try to overwrite the main drive with some malicious data
        let agent = store.get_default_agent().unwrap();
        let mut resource = Resource::new_generate_subject(&store);
        resource
            .set_propval(
                urls::WRITE.into(),
                vec![agent.subject.clone()].into(),
                &store,
            )
            .unwrap();
        resource.save_locally(&store).unwrap();

        let json = format!(
            r#"{{
            "@id": "{}",
            "https://atomicdata.dev/properties/write": ["https://some-malicious-actor"]
        }}"#,
            resource.get_subject()
        );

        let mut parse_opts = ParseOpts {
            save: SaveOpts::Commit,
            signer: Some(agent.clone()),
            for_agent: Some(agent.subject),
            overwrite_outside: false,
            importer: Some(importer),
        };

        // We can't allow this to happen, so we expect an error
        store.import(&json, &parse_opts).unwrap_err();

        // If we explicitly allow overwriting resources outside scope, we should be able to import it
        parse_opts.overwrite_outside = true;
        store.import(&json, &parse_opts).unwrap();
    }
}
