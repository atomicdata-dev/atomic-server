//! Serialization / formatting / encoding (JSON, RDF, N-Triples)

use serde_json::Map;
use serde_json::Value as SerdeValue;
use tracing::instrument;

use crate::{
    datatype::DataType, errors::AtomicResult, resources::PropVals, Resource, Storelike, Value,
};

/// Serializes a vector or Resources to a JSON-AD string
pub fn resources_to_json_ad(resources: &[Resource]) -> AtomicResult<String> {
    let mut vec: Vec<serde_json::Value> = Vec::new();
    for r in resources {
        vec.push(crate::serialize::propvals_to_json_ad_map(
            r.get_propvals(),
            Some(r.get_subject().clone()),
        )?)
    }
    let serde_array = serde_json::Value::from(vec);
    serde_json::to_string_pretty(&serde_array).map_err(|_| "Could not serialize to JSON-AD".into())
}

/// Converts an Atomic Value to a Serde Value.
// TODO: Accept JSON-LD / JSON as options
// https://github.com/joepio/atomic-data-rust/issues/315
fn val_to_serde(value: Value) -> AtomicResult<SerdeValue> {
    let json_val: SerdeValue = match value {
        Value::AtomicUrl(val) => SerdeValue::String(val),
        Value::Date(val) => SerdeValue::String(val),
        // TODO: Handle big numbers
        Value::Integer(val) => serde_json::from_str(&val.to_string()).unwrap_or_default(),
        Value::Float(val) => serde_json::from_str(&val.to_string()).unwrap_or_default(),
        Value::Markdown(val) => SerdeValue::String(val),
        Value::ResourceArray(val) => {
            let mut vec: Vec<SerdeValue> = Vec::new();
            for resource in val {
                match resource {
                    crate::values::SubResource::Resource(r) => {
                        vec.push(crate::serialize::propvals_to_json_ad_map(
                            r.get_propvals(),
                            Some(r.get_subject().clone()),
                        )?);
                    }
                    crate::values::SubResource::Nested(pv) => {
                        vec.push(crate::serialize::propvals_to_json_ad_map(&pv, None)?);
                    }
                    crate::values::SubResource::Subject(s) => {
                        vec.push(SerdeValue::String(s.clone()))
                    }
                }
            }
            SerdeValue::Array(vec)
        }
        Value::Slug(val) => SerdeValue::String(val),
        Value::String(val) => SerdeValue::String(val),
        Value::Timestamp(val) => SerdeValue::Number(val.into()),
        Value::Unsupported(val) => SerdeValue::String(val.value),
        Value::Boolean(val) => SerdeValue::Bool(val),
        // TODO: fix this for nested resources in json and json-ld serialization, because this will cause them to fall back to json-ad
        Value::NestedResource(res) => match res {
            crate::values::SubResource::Resource(r) => crate::serialize::propvals_to_json_ad_map(
                r.get_propvals(),
                Some(r.get_subject().clone()),
            )?,
            crate::values::SubResource::Nested(propvals) => {
                propvals_to_json_ad_map(&propvals, None)?
            }
            crate::values::SubResource::Subject(s) => SerdeValue::String(s),
        },
        Value::Resource(_) => todo!(),
    };
    Ok(json_val)
}

/// Serializes a Resource to a Serde JSON Map according to the JSON-AD spec.
/// https://docs.atomicdata.dev/core/json-ad.html
#[instrument(skip_all)]
pub fn propvals_to_json_ad_map(
    propvals: &PropVals,
    subject: Option<String>,
) -> AtomicResult<serde_json::Value> {
    let mut root = Map::new();
    for (prop_url, value) in propvals.iter() {
        root.insert(prop_url.clone(), val_to_serde(value.clone())?);
    }
    if let Some(sub) = subject {
        root.insert("@id".into(), SerdeValue::String(sub));
    }
    let obj = SerdeValue::Object(root);
    Ok(obj)
}

/// Serializes a Resource to a Serde JSON Map.
/// Supports both JSON and JSON-LD.
/// If you opt in for JSON-LD, an @context object is created mapping the shortnames to URLs.
/// https://docs.atomicdata.dev/interoperability/json.html#from-atomic-data-to-json-ld
pub fn propvals_to_json_ld(
    propvals: &PropVals,
    subject: Option<String>,
    store: &impl Storelike,
    json_ld: bool,
) -> AtomicResult<serde_json::Value> {
    // Initiate JSON object
    let mut root = Map::new();
    // For JSON-LD serialization
    let mut context = Map::new();
    // For every atom, find the key, datatype and add it to the @context
    for (prop_url, value) in propvals.iter() {
        // The property is only needed in JSON-LD and JSON for shortnames
        let property = store.get_property(prop_url)?;
        if json_ld {
            // In JSON-LD, the value of a Context Item can be a string or an object.
            // This object can contain information about the translation or datatype of the value
            let ctx_value: SerdeValue = match value.datatype() {
                DataType::AtomicUrl => {
                    let mut obj = Map::new();
                    obj.insert("@id".into(), prop_url.as_str().into());
                    obj.insert("@type".into(), "@id".into());
                    obj.into()
                }
                DataType::Date => {
                    let mut obj = Map::new();
                    obj.insert("@id".into(), prop_url.as_str().into());
                    obj.insert(
                        "@type".into(),
                        "http://www.w3.org/2001/XMLSchema#date".into(),
                    );
                    obj.into()
                }
                DataType::Integer => {
                    let mut obj = Map::new();
                    obj.insert("@id".into(), prop_url.as_str().into());
                    // I'm not sure whether we should use XSD or Atomic Datatypes
                    obj.insert(
                        "@type".into(),
                        "http://www.w3.org/2001/XMLSchema#integer".into(),
                    );
                    obj.into()
                }
                DataType::Markdown => prop_url.as_str().into(),
                DataType::ResourceArray => {
                    let mut obj = Map::new();
                    obj.insert("@id".into(), prop_url.as_str().into());
                    // Plain JSON-LD Arrays are not ordered. Here, they are converted into an RDF List.
                    obj.insert("@container".into(), "@list".into());
                    obj.into()
                }
                _other => prop_url.as_str().into(),
            };
            context.insert(property.shortname.as_str().into(), ctx_value);
        }
        let key = property.shortname;

        root.insert(key, val_to_serde(value.clone())?);
    }

    if let Some(sub) = subject {
        root.insert("@id".into(), SerdeValue::String(sub));
    }

    if json_ld {
        root.insert("@context".into(), context.into());
    }
    let obj = SerdeValue::Object(root);
    // let string = serde_json::to_string_pretty(&obj).expect("Could not serialize to JSON");
    Ok(obj)
}

pub fn serialize_json_array(items: &[String]) -> AtomicResult<String> {
    let string = serde_json::to_string(items)?;
    Ok(string)
}

#[cfg(feature = "rdf")]
/// Serializes Atoms to Ntriples (which is also valid Turtle / Notation3).
pub fn atoms_to_ntriples(atoms: Vec<crate::Atom>, store: &impl Storelike) -> AtomicResult<String> {
    use rio_api::formatter::TriplesFormatter;
    use rio_api::model::{Literal, NamedNode, Term, Triple};
    use rio_turtle::NTriplesFormatter;

    let mut formatter = NTriplesFormatter::new(Vec::default());
    for atom in atoms {
        let subject = NamedNode { iri: &atom.subject }.into();
        let predicate = NamedNode {
            iri: &atom.property,
        };
        let datatype = store.get_property(&atom.property)?.data_type;
        let value = &atom.value.to_string();
        let datatype_url = datatype.to_string();
        let object: Term = match &datatype {
            DataType::AtomicUrl => NamedNode { iri: value }.into(),
            // Maybe these should be converted to RDF collections / lists?
            // DataType::ResourceArray => {}
            DataType::String => Literal::Simple { value }.into(),
            _dt => Literal::Typed {
                value,
                datatype: NamedNode { iri: &datatype_url },
            }
            .into(),
        };

        formatter.format(&Triple {
            subject,
            predicate,
            object,
        })?
    }
    let out = String::from_utf8(formatter.finish()?)?;
    Ok(out)
}

#[cfg(feature = "rdf")]
/// Serializes Atoms to Ntriples (which is also valid Turtle / Notation3).
pub fn atoms_to_turtle(atoms: Vec<crate::Atom>, store: &impl Storelike) -> AtomicResult<String> {
    use rio_api::formatter::TriplesFormatter;
    use rio_api::model::{Literal, NamedNode, Term, Triple};
    use rio_turtle::TurtleFormatter;

    let mut formatter = TurtleFormatter::new(Vec::default());

    for atom in atoms {
        let subject = NamedNode { iri: &atom.subject }.into();
        let predicate = NamedNode {
            iri: &atom.property,
        };
        let datatype = store.get_property(&atom.property)?.data_type;
        let value = &atom.value.to_string();
        let datatype_url = datatype.to_string();
        let object: Term = match &datatype {
            DataType::AtomicUrl => NamedNode { iri: value }.into(),
            // Maybe these should be converted to RDF collections / lists?
            // DataType::ResourceArray => {}
            DataType::String => Literal::Simple { value }.into(),
            _dt => Literal::Typed {
                value,
                datatype: NamedNode { iri: &datatype_url },
            }
            .into(),
        };

        formatter.format(&Triple {
            subject,
            predicate,
            object,
        })?
    }
    let out = String::from_utf8(formatter.finish()?)?;
    Ok(out)
}

/// Should list all the supported serialization formats
pub enum Format {
    Json,
    JsonAd,
    JsonLd,
    NTriples,
    Pretty,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Storelike;

    #[test]
    fn serialize_json_ad() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let json = store
            .get_resource(crate::urls::AGENT)
            .unwrap()
            .to_json_ad()
            .unwrap();
        println!("json-ad: {}", json);
        let correct_json = r#"{
  "@id": "https://atomicdata.dev/classes/Agent",
  "https://atomicdata.dev/properties/description": "An Agent is a user that can create or modify data. It has two keys: a private and a public one. The private key should be kept secret. The public key is used to verify signatures (on [Commits](https://atomicdata.dev/classes/Commit)) set by the of the Agent.",
  "https://atomicdata.dev/properties/isA": [
     "https://atomicdata.dev/classes/Class"
  ],
  "https://atomicdata.dev/properties/parent": "https://atomicdata.dev/classes",
  "https://atomicdata.dev/properties/recommends": [
    "https://atomicdata.dev/properties/name",
    "https://atomicdata.dev/properties/description",
    "https://atomicdata.dev/properties/drives"
  ],
    "https://atomicdata.dev/properties/requires": [
    "https://atomicdata.dev/properties/publicKey"
  ],
  "https://atomicdata.dev/properties/shortname": "agent"
}"#;
        let correct_value: serde_json::Value = serde_json::from_str(correct_json).unwrap();
        let our_value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(our_value, correct_value)
    }

    #[test]
    fn serialize_json_ad_multiple() {
        let vec = vec![Resource::new("subjet".into())];
        let serialized = resources_to_json_ad(&vec).unwrap();
        let correct_json = r#"[
  {
    "@id": "subjet"
  }
]"#;
        assert_eq!(serialized, correct_json);
    }

    #[test]
    fn serialize_json() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let json = store
            .get_resource(crate::urls::AGENT)
            .unwrap()
            .to_json(&store)
            .unwrap();
        println!("json: {}", json);
        let correct_json = r#"{
            "@id": "https://atomicdata.dev/classes/Agent",
            "description": "An Agent is a user that can create or modify data. It has two keys: a private and a public one. The private key should be kept secret. The public key is used to verify signatures (on [Commits](https://atomicdata.dev/classes/Commit)) set by the of the Agent.",
            "is-a": [
              "https://atomicdata.dev/classes/Class"
            ],
            "parent": "https://atomicdata.dev/classes",
            "recommends": [
              "https://atomicdata.dev/properties/name",
              "https://atomicdata.dev/properties/description",
              "https://atomicdata.dev/properties/drives"
            ],
            "requires": [
              "https://atomicdata.dev/properties/publicKey"
            ],
            "shortname": "agent"
          }"#;
        let correct_value: serde_json::Value = serde_json::from_str(correct_json).unwrap();
        let our_value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(our_value, correct_value)
    }

    #[test]
    fn serialize_json_ld() {
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let json = store
            .get_resource(crate::urls::AGENT)
            .unwrap()
            .to_json_ld(&store)
            .unwrap();
        println!("json: {}", json);
        let correct_json = r#"{
            "@context": {
              "description": "https://atomicdata.dev/properties/description",
              "is-a": {
                "@container": "@list",
                "@id": "https://atomicdata.dev/properties/isA"
              },
              "parent": {
                "@id": "https://atomicdata.dev/properties/parent",
                "@type": "@id"
              },
              "recommends": {
                "@container": "@list",
                "@id": "https://atomicdata.dev/properties/recommends"
              },
              "requires": {
                "@container": "@list",
                "@id": "https://atomicdata.dev/properties/requires"
              },
              "shortname": "https://atomicdata.dev/properties/shortname"
            },
            "@id": "https://atomicdata.dev/classes/Agent",
            "description": "An Agent is a user that can create or modify data. It has two keys: a private and a public one. The private key should be kept secret. The public key is used to verify signatures (on [Commits](https://atomicdata.dev/classes/Commit)) set by the of the Agent.",
            "is-a": [
              "https://atomicdata.dev/classes/Class"
            ],
            "parent": "https://atomicdata.dev/classes",
            "recommends": [
              "https://atomicdata.dev/properties/name",
              "https://atomicdata.dev/properties/description",
              "https://atomicdata.dev/properties/drives"
            ],
            "requires": [
              "https://atomicdata.dev/properties/publicKey"
            ],
            "shortname": "agent"
          }"#;
        let correct_value: serde_json::Value = serde_json::from_str(correct_json).unwrap();
        let our_value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(our_value, correct_value)
    }

    #[test]
    #[cfg(feature = "rdf")]
    fn serialize_ntriples() {
        use crate::Storelike;
        let store = crate::Store::init().unwrap();
        store.populate().unwrap();
        let subject = crate::urls::DESCRIPTION;
        let resource = store.get_resource(subject).unwrap();
        let atoms = resource.to_atoms().unwrap();
        let serialized = atoms_to_ntriples(atoms, &store).unwrap();
        let _out = r#"
        <https://atomicdata.dev/properties/description> <https://atomicdata.dev/properties/description> "A textual description of the thing."^^<https://atomicdata.dev/datatypes/markdown> .
<https://atomicdata.dev/properties/description> <https://atomicdata.dev/properties/isA> "[\"https://atomicdata.dev/classes/Property\"]"^^<https://atomicdata.dev/datatypes/resourceArray> .
<https://atomicdata.dev/properties/description> <https://atomicdata.dev/properties/datatype> <https://atomicdata.dev/datatypes/markdown> .
<https://atomicdata.dev/properties/description> <https://atomicdata.dev/properties/shortname> "description"^^<https://atomicdata.dev/datatypes/slug> ."#;
        assert!(serialized.contains(r#""description"^^<https://atomicdata.dev/datatypes/slug>"#));
        // This could fail when the `description` resource changes
        assert!(serialized.lines().count() == 5);
    }
}
