//! Serialization / formatting / encoding (JSON, RDF, N-Triples, AD3)

use crate::{
    datatype::DataType, errors::AtomicResult, resources::PropVals, Atom, Storelike, Value,
};

/// Possible JSON-like serializations
#[derive(PartialEq)]
pub enum JsonType {
    /// Plain JSON with human readable keys
    JSON,
    /// RDF / Linked Data compatible JSON-LD with an @context
    JSONLD,
    /// Atomic Data JSON, most performant
    JSONAD,
}

/// Serializes a Resource to a Serde JSON Map
pub fn propvals_to_json_map(
    propvals: &PropVals,
    subject: Option<String>,
    store: &impl Storelike,
    json_type: &JsonType,
) -> AtomicResult<serde_json::Value> {
    use serde_json::{Map, Value as SerdeValue};
    // Initiate JSON object
    let mut root = Map::new();
    // For JSON-LD serialization
    let mut context = Map::new();
    // For every atom, find the key, datatype and add it to the @context
    for (prop_url, value) in propvals.iter() {
        // The property is only needed in JSON-LD and JSON for shortnames
        let property = if json_type == &JsonType::JSONAD {
            None
        } else {
            Some(store.get_property(prop_url)?)
        };
        if json_type == &JsonType::JSONLD {
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
            context.insert(
                property.clone().unwrap().shortname.as_str().into(),
                ctx_value,
            );
        }
        let key = if json_type == &JsonType::JSONAD {
            prop_url.clone()
        } else {
            property.clone().unwrap().shortname
        };
        let json_val = match value.to_owned() {
            Value::AtomicUrl(val) => SerdeValue::String(val),
            Value::Date(val) => SerdeValue::String(val),
            // TODO: Handle big numbers
            Value::Integer(val) => serde_json::from_str(&val.to_string()).unwrap_or_default(),
            Value::Markdown(val) => SerdeValue::String(val),
            Value::ResourceArray(val) => SerdeValue::Array(
                val.iter()
                    .map(|item| SerdeValue::String(item.clone()))
                    .collect(),
            ),
            Value::Slug(val) => SerdeValue::String(val),
            Value::String(val) => SerdeValue::String(val),
            Value::Timestamp(val) => SerdeValue::Number(val.into()),
            Value::Unsupported(val) => SerdeValue::String(val.value),
            Value::Boolean(val) => SerdeValue::Bool(val),
            Value::NestedResource(res) => propvals_to_json_map(&res, None, store, &json_type)?,
        };
        root.insert(key, json_val);
    }

    if let Some(sub) = subject {
        root.insert("@id".into(), SerdeValue::String(sub));
    }

    if json_type == &JsonType::JSONLD {
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

pub fn serialize_json_array_owned(items: &[String]) -> AtomicResult<String> {
    let string = serde_json::to_string(items)?;
    Ok(string)
}

/// Serializes Atoms to .ad3.
/// It is a newline-delimited JSON file (ndjson), where each line is a JSON Array with three string values.
pub fn serialize_atoms_to_ad3(atoms: Vec<Atom>) -> AtomicResult<String> {
    let mut string = String::new();
    for atom in atoms {
        let mut ad3_atom =
            serde_json::to_string(&vec![&atom.subject, &atom.property, &atom.value])?;
        ad3_atom.push('\n');
        string.push_str(&*ad3_atom);
    }
    Ok(string)
}

#[cfg(feature = "rdf")]
/// Serializes Atoms to Ntriples (which is also valid Turtle / Notation3).
pub fn atoms_to_ntriples(atoms: Vec<Atom>, store: &impl Storelike) -> AtomicResult<String> {
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
        let value = &atom.value;
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
    let turtle = formatter.finish();
    let out = String::from_utf8(turtle)?;
    Ok(out)
}

/// Should list all the supported serialization formats
pub enum Format {
    JSON,
    JSONAD,
    JSONLD,
    AD3,
    NT,
    PRETTY,
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
            .to_json_ad(&store)
            .unwrap();
        println!("json: {}", json);
        let correct_json = r#"{
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
        let correct_value: serde_json::Value = serde_json::from_str(correct_json).unwrap();
        let our_value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(our_value, correct_value)
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
            "description": "An Agent is a user that can create or modify data. It has two keys: a private and a public one. The private key should be kept secret. The publik key is for proving that the ",
            "is-a": [
              "https://atomicdata.dev/classes/Class"
            ],
            "recommends": [
              "https://atomicdata.dev/properties/description",
              "https://atomicdata.dev/properties/remove",
              "https://atomicdata.dev/properties/destroy"
            ],
            "requires": [
              "https://atomicdata.dev/properties/createdAt",
              "https://atomicdata.dev/properties/name",
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
            "description": "An Agent is a user that can create or modify data. It has two keys: a private and a public one. The private key should be kept secret. The publik key is for proving that the ",
            "is-a": [
              "https://atomicdata.dev/classes/Class"
            ],
            "recommends": [
              "https://atomicdata.dev/properties/description",
              "https://atomicdata.dev/properties/remove",
              "https://atomicdata.dev/properties/destroy"
            ],
            "requires": [
              "https://atomicdata.dev/properties/createdAt",
              "https://atomicdata.dev/properties/name",
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
        assert!(serialized.lines().count() == 4);
    }
}
