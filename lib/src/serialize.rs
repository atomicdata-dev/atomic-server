//! Serialization / formatting / encoding (JSON, RDF, N-Triples, AD3)

use crate::{Atom, Storelike, datatype::DataType, errors::AtomicResult};

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
pub fn atoms_to_ntriples(atoms: Vec<Atom>, store: &mut dyn Storelike) -> AtomicResult<String> {
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
    JSONLD,
    AD3,
    NT,
    PRETTY,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[cfg(feature = "rdf")]
    fn serialize_ntriples() {
        use crate::Storelike;
        let mut store = crate::Store::init();
        store.populate().unwrap();
        let subject = crate::urls::DESCRIPTION;
        let resource = store.get_resource_string(subject).unwrap();
        let atoms = crate::resources::resourcestring_to_atoms(subject, resource);
        let serialized = atoms_to_ntriples(atoms, &mut store).unwrap();
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
